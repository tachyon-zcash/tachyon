extern crate alloc;

use alloc::{collections::BTreeSet, vec, vec::Vec};

use ragu::{Pcd, ProductionRank, pasta::Pasta};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, Note, Tachygram,
    pasta::Fp,
    pczt::{self, CombineError, ExtractError, NoteOpening, Slot},
    stamp::proof::{App, delegation, spendable},
    value,
};

use crate::fixtures::{
    application, mock_sighash,
    pool::PoolSim,
    wallet::{WalletSim, shared_sk},
};

fn spendables(
    app: &App<'_>,
    notes: &[(&WalletSim, Note)],
) -> (
    Vec<(
        Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
        Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
    )>,
    Anchor,
) {
    let mut pool = PoolSim::genesis_with(vec![]);
    let tachygrams = notes
        .iter()
        .map(|&(_, note)| Tachygram::from(note.commitment()))
        .collect();
    pool.mine(vec![tachygrams]);
    let height = pool.height();
    let inputs: Vec<_> = notes
        .iter()
        .map(|&(wallet, note)| {
            (
                wallet.note_secret(app, note),
                wallet.spendable_init(app, &pool, &note, height),
            )
        })
        .collect();
    let anchor = inputs[0].1.data().2;
    (inputs, anchor)
}

fn spend_bundle(rng: &mut StdRng, wallet: &WalletSim, spend_note: Note) -> pczt::Bundle {
    let ak = wallet.sk.derive_auth_private().derive_auth_public();
    let mut bundle = pczt::Bundle::new(
        NoteOpening {
            pk: None,
            ..wallet.random_note(10).into()
        },
        Some(ak),
        vec![7; 3],
    );
    bundle.add_spend(spend_note, None);
    bundle.add_output(WalletSim::random(rng).random_note(60).into(), None);
    bundle.add_output(
        NoteOpening {
            pk: None,
            ..wallet.random_note(30).into()
        },
        Some(ak),
    );
    bundle
}

#[test]
fn custody_authorizes_and_planner_binds() {
    let app = application();
    let mut rng = StdRng::seed_from_u64(0x9C27);
    let wallet = WalletSim::new(shared_sk());
    let spend_note = wallet.random_note(100);
    let (inputs, anchor) = spendables(&app, &[(&wallet, spend_note)]);

    let mut bundle = spend_bundle(&mut rng, &wallet, spend_note);
    let sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .unwrap();

    let own_pk = Fp::from(wallet.sk.derive_payment_key());
    assert_eq!(bundle.outputs[1].note.pk.map(Fp::from), Some(own_pk));
    assert_eq!(bundle.max_fee_note.pk.map(Fp::from), Some(own_pk));
    assert_eq!(mock_sighash(bundle.commitment().unwrap()), sighash);

    bundle.sign_binding(&mut rng, &sighash).unwrap();
    bundle
        .prove_partial(
            &mut rng,
            &app,
            anchor,
            Some(&wallet.pak),
            vec![(0, inputs[0].0.clone(), inputs[0].1.clone(), vec![])],
            BTreeSet::from([0, 1]),
        )
        .unwrap();
    bundle.stamp(&mut rng, &app, 4.try_into().unwrap()).unwrap();

    let extracted = bundle.clone().extract(&mut rng, &app, &sighash).unwrap();
    assert_eq!(extracted.fee.v_fee, 4.try_into().unwrap());
    assert_eq!(mock_sighash(extracted.commitment()), sighash);

    let mut missing_pair = bundle.clone();
    missing_pair.stamp.as_mut().unwrap().1.pop_first().unwrap();
    assert!(matches!(
        missing_pair.extract(&mut rng, &app, &sighash),
        Err(ExtractError::ActionMismatch)
    ));

    bundle.stamp(&mut rng, &app, 9.try_into().unwrap()).unwrap();
    let refeed = bundle.extract(&mut rng, &app, &sighash).unwrap();
    assert_eq!(refeed.fee.v_fee, 9.try_into().unwrap());
    assert_eq!(refeed.actions, extracted.actions);
    assert_eq!(refeed.action_auth, extracted.action_auth);
    assert_ne!(refeed.fee_auth, extracted.fee_auth);
    assert_eq!(refeed.binding_sig, extracted.binding_sig);
}

#[test]
fn planner_fixes_effects_before_custody() {
    let app = application();
    let mut rng = StdRng::seed_from_u64(0x9C28);
    let wallet = WalletSim::new(shared_sk());
    let spend_note = wallet.random_note(100);
    let (inputs, anchor) = spendables(&app, &[(&wallet, spend_note)]);

    let mut bundle = spend_bundle(&mut rng, &wallet, spend_note);
    let commitment = bundle.finalize_effects(&mut rng, &wallet.pak).unwrap();
    let sighash = mock_sighash(commitment);
    let theta = bundle.spends[0].theta.unwrap().to_bytes();
    bundle.sign_outputs(&mut rng, &sighash).unwrap();
    let output_sig = bundle.outputs[0].sig;

    let custody_sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .unwrap();
    assert_eq!(custody_sighash, sighash);
    assert_eq!(bundle.spends[0].theta.unwrap().to_bytes(), theta);
    assert_eq!(bundle.outputs[0].sig, output_sig);

    bundle.sign_binding(&mut rng, &sighash).unwrap();
    bundle
        .prove_partial(
            &mut rng,
            &app,
            anchor,
            Some(&wallet.pak),
            vec![(0, inputs[0].0.clone(), inputs[0].1.clone(), vec![])],
            BTreeSet::from([0, 1]),
        )
        .unwrap();
    bundle.stamp(&mut rng, &app, value::Positive::ZERO).unwrap();
    bundle.extract(&mut rng, &app, &sighash).unwrap();
}

#[test]
fn custody_derives_from_preimages_not_stored_effects() {
    let mut rng = StdRng::seed_from_u64(0x9C29);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = spend_bundle(&mut rng, &wallet, wallet.random_note(100));
    let commitment = bundle.finalize_effects(&mut rng, &wallet.pak).unwrap();
    bundle.outputs[0].rk = bundle.outputs[1].rk;

    let sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .unwrap();
    assert_eq!(sighash, mock_sighash(commitment));
    assert_ne!(mock_sighash(bundle.commitment().unwrap()), sighash);
}

#[test]
fn custodies_sign_their_own_spends_and_provers_their_own_actions() {
    let app = application();
    let mut rng = StdRng::seed_from_u64(0x9C2A);
    let alice = WalletSim::new(shared_sk());
    let bob = WalletSim::random(&mut rng);
    let alice_ak = alice.sk.derive_auth_private().derive_auth_public();
    let bob_ak = bob.sk.derive_auth_private().derive_auth_public();
    let alice_note = alice.random_note(70);
    let bob_note = bob.random_note(50);
    let (inputs, anchor) = spendables(&app, &[(&alice, alice_note), (&bob, bob_note)]);

    let mut bundle = pczt::Bundle::new(
        NoteOpening {
            pk: None,
            ..alice.random_note(10).into()
        },
        Some(alice_ak),
        vec![],
    );
    bundle.add_spend(alice_note, None);
    bundle.add_spend(bob_note, Some(bob_ak));
    bundle.add_output(WalletSim::random(&mut rng).random_note(110).into(), None);

    let sighash = bundle
        .authorize(&mut rng, &alice.sk, |digest| mock_sighash(*digest))
        .unwrap();
    assert_eq!(bundle.spends[0].owner, Some(alice_ak));
    let alice_sig = bundle.spends[0].sig.unwrap();
    assert!(bundle.spends[1].sig.is_none());

    let bob_sighash = bundle
        .authorize(&mut rng, &bob.sk, |digest| mock_sighash(*digest))
        .unwrap();
    assert_eq!(bob_sighash, sighash);
    assert_eq!(bundle.spends[0].owner, Some(alice_ak));
    assert_eq!(bundle.spends[0].sig, Some(alice_sig));
    assert!(bundle.spends[1].sig.is_some());
    bundle.sign_binding(&mut rng, &sighash).unwrap();

    let mut bob_copy = bundle.clone();
    bundle
        .prove_partial(
            &mut rng,
            &app,
            anchor,
            Some(&alice.pak),
            vec![(0, inputs[0].0.clone(), inputs[0].1.clone(), vec![])],
            BTreeSet::new(),
        )
        .unwrap();
    bundle
        .prove_partial(&mut rng, &app, anchor, None, vec![], BTreeSet::from([0]))
        .unwrap();
    bob_copy
        .prove_partial(
            &mut rng,
            &app,
            anchor,
            Some(&bob.pak),
            vec![(1, inputs[1].0.clone(), inputs[1].1.clone(), vec![])],
            BTreeSet::new(),
        )
        .unwrap();

    let mut combined = bundle.combine(bob_copy).unwrap();
    assert_eq!(combined.partials.len(), 3);
    combined.merge_partials(&mut rng, &app).unwrap();
    combined
        .stamp(&mut rng, &app, 10.try_into().unwrap())
        .unwrap();
    combined.extract(&mut rng, &app, &sighash).unwrap();
}

#[test]
fn parallel_custodies_conflict() {
    let mut rng = StdRng::seed_from_u64(0x9C2B);
    let wallet = WalletSim::new(shared_sk());
    let bundle = spend_bundle(&mut rng, &wallet, wallet.random_note(100));

    let mut left = bundle.clone();
    let mut right = bundle;
    left.authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .unwrap();
    right
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .unwrap();

    assert!(matches!(
        left.combine(right),
        Err(CombineError::Conflict(Slot::Spend(0)))
    ));
}

#[test]
fn redacted_copy_combines_and_extracts() {
    let app = application();
    let mut rng = StdRng::seed_from_u64(0x9C2C);
    let wallet = WalletSim::new(shared_sk());
    let spend_note = wallet.random_note(100);
    let (inputs, anchor) = spendables(&app, &[(&wallet, spend_note)]);

    let mut bundle = spend_bundle(&mut rng, &wallet, spend_note);
    let sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .unwrap();
    bundle.sign_binding(&mut rng, &sighash).unwrap();
    bundle
        .prove_partial(
            &mut rng,
            &app,
            anchor,
            Some(&wallet.pak),
            vec![(0, inputs[0].0.clone(), inputs[0].1.clone(), vec![])],
            BTreeSet::from([0, 1]),
        )
        .unwrap();
    bundle.stamp(&mut rng, &app, 1.try_into().unwrap()).unwrap();

    let mut redacted = bundle.clone();
    redacted.redact();
    assert!(redacted.spends[0].note.psi.is_none());
    assert!(redacted.spends[0].theta.is_none());
    assert!(redacted.partials.is_empty());

    let combined = redacted.clone().combine(bundle).unwrap();
    assert!(combined.spends[0].theta.is_some());
    redacted.extract(&mut rng, &app, &sighash).unwrap();
}

#[test]
fn zero_action_bundle_stamps_with_fee_seed() {
    let app = application();
    let mut rng = StdRng::seed_from_u64(0x9C2D);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = pczt::Bundle::new(
        NoteOpening {
            pk: None,
            ..wallet.random_note(0).into()
        },
        Some(wallet.sk.derive_auth_private().derive_auth_public()),
        vec![],
    );

    let sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .unwrap();
    bundle.sign_binding(&mut rng, &sighash).unwrap();

    assert!(matches!(
        bundle.stamp(&mut rng, &app, value::Positive::ZERO),
        Err(pczt::ProverError::Incomplete)
    ));
    let anchor = PoolSim::genesis_with(vec![]).anchor();
    bundle.seed_stamp(&mut rng, &app, anchor).unwrap();
    bundle.extract(&mut rng, &app, &sighash).unwrap();
}

#[test]
fn extraction_requires_every_signature() {
    let app = application();
    let mut rng = StdRng::seed_from_u64(0x9C2E);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = spend_bundle(&mut rng, &wallet, wallet.random_note(100));
    let sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .unwrap();

    assert!(matches!(
        bundle.clone().extract(&mut rng, &app, &sighash),
        Err(ExtractError::MissingBindingSignature)
    ));

    bundle.spends[0].sig = None;
    assert!(matches!(
        bundle.extract(&mut rng, &app, &sighash),
        Err(ExtractError::MissingSignature(Slot::Spend(0)))
    ));
}

#[test]
fn binding_rejects_unbalanced_effects() {
    let mut rng = StdRng::seed_from_u64(0x9C2F);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = spend_bundle(&mut rng, &wallet, wallet.random_note(100));
    let sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .unwrap();
    bundle.value_balance = value::Balance::try_from(1).unwrap();

    assert!(matches!(
        bundle.sign_binding(&mut rng, &sighash),
        Err(pczt::SignerError::Unbalanced)
    ));
}
