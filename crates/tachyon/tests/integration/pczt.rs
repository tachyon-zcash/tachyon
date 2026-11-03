extern crate alloc;

use alloc::{collections::BTreeSet, vec, vec::Vec};

use ragu::Pcd;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, Note,
    keys::{SpendValidatingKey, private},
    pasta::Fp,
    pczt::{self, CombineError, ExtractError, NoteOpening, Slot},
    stamp::proof::{delegation, spendable},
    value,
};

use crate::fixtures::{PoolSim, WalletSim, mock_sighash, random_block_with, shared_sk};

fn zat(amount: u64) -> value::Positive {
    value::Positive::try_from(amount).expect("in range")
}

fn spend_key(sk: &private::SpendingKey) -> SpendValidatingKey {
    sk.derive_auth_private().derive_auth_public()
}

/// An opening of `note` whose payment key the owner's custody fills.
fn unaddressed(note: Note) -> NoteOpening {
    NoteOpening {
        pk: None,
        ..NoteOpening::from(note)
    }
}

/// Mine `notes` into one stamp, and return each owner's secret and spendable
/// for its note, at their shared anchor.
fn spendables(
    rng: &mut StdRng,
    notes: &[(&WalletSim, Note)],
) -> (
    Vec<(Pcd<delegation::NoteSecret>, Pcd<spendable::NoteSpendable>)>,
    Anchor,
) {
    let mut pool = PoolSim::genesis(rng);
    let cms = notes.iter().map(|&(_, note)| note.commitment()).collect();
    pool.mine(random_block_with(rng, &[cms], 50));
    let height = pool.height();
    let inputs: Vec<_> = notes
        .iter()
        .map(|&(wallet, note)| {
            (
                wallet.secret_pcd(rng, note),
                wallet.fresh_spend(rng, &pool, height, &note),
            )
        })
        .collect();
    let anchor = inputs[0].1.data().2;
    (inputs, anchor)
}

/// A bundle spending a 100 note of `wallet` into a 60 output to another
/// wallet, a 30 change output and a 10 max fee note, both owned by
/// `wallet`'s custody.
fn spend_bundle(rng: &mut StdRng, wallet: &WalletSim, spend_note: Note) -> pczt::Bundle {
    let ak = spend_key(&wallet.sk);
    let mut bundle = pczt::Bundle::new(unaddressed(wallet.random_note(10)), Some(ak), vec![7; 3]);
    bundle.add_spend(spend_note, None);
    bundle.add_output(WalletSim::random(rng).random_note(60).into(), None);
    bundle.add_output(unaddressed(wallet.random_note(30)), Some(ak));
    bundle
}

#[test]
fn custody_authorizes_and_planner_binds() {
    let mut rng = StdRng::seed_from_u64(0x9C27);
    let wallet = WalletSim::new(shared_sk());
    let spend_note = wallet.random_note(100);
    let (inputs, anchor) = spendables(&mut rng, &[(&wallet, spend_note)]);

    let mut bundle = spend_bundle(&mut rng, &wallet, spend_note);
    let sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .expect("authorize");

    let own_pk = Fp::from(wallet.sk.derive_payment_key());
    assert_eq!(bundle.outputs[1].note.pk.map(Fp::from), Some(own_pk));
    assert_eq!(bundle.max_fee_note.pk.map(Fp::from), Some(own_pk));
    assert_eq!(
        mock_sighash(bundle.commitment().expect("effects")),
        sighash,
        "the planner's commitment matches custody's derivation"
    );

    bundle.sign_binding(&mut rng, &sighash).expect("binding");
    bundle
        .prove_partial(
            &mut rng,
            anchor,
            Some(&wallet.pak),
            vec![(0, inputs[0].0.clone(), inputs[0].1.clone(), vec![])],
            BTreeSet::from([0, 1]),
        )
        .expect("prove");
    bundle.stamp(&mut rng, zat(4)).expect("stamp");

    let extracted = bundle.clone().extract(&mut rng, &sighash).expect("extract");
    assert_eq!(extracted.stamp.fee, zat(4));

    bundle.stamp(&mut rng, zat(9)).expect("re-fee");
    let refeed = bundle.extract(&mut rng, &sighash).expect("extract re-fee");
    assert_eq!(refeed.stamp.fee, zat(9));
    assert_eq!(refeed.actions, extracted.actions);
    assert_eq!(refeed.binding_sig, extracted.binding_sig);
}

#[test]
fn planner_fixes_effects_before_custody() {
    let mut rng = StdRng::seed_from_u64(0x9C28);
    let wallet = WalletSim::new(shared_sk());
    let spend_note = wallet.random_note(100);
    let (inputs, anchor) = spendables(&mut rng, &[(&wallet, spend_note)]);

    let mut bundle = spend_bundle(&mut rng, &wallet, spend_note);
    let commitment = bundle
        .finalize_effects(&mut rng, &wallet.pak)
        .expect("effects");
    let sighash = mock_sighash(commitment);
    let theta = bundle.spends[0].theta.expect("theta").to_bytes();
    bundle.sign_outputs(&mut rng, &sighash).expect("outputs");
    let output_sig = bundle.outputs[0].sig;

    let custody_sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .expect("authorize");
    assert_eq!(custody_sighash, sighash);
    assert_eq!(bundle.spends[0].theta.expect("theta").to_bytes(), theta);
    assert_eq!(bundle.outputs[0].sig, output_sig);

    bundle.sign_binding(&mut rng, &sighash).expect("binding");
    bundle
        .prove_partial(
            &mut rng,
            anchor,
            Some(&wallet.pak),
            vec![(0, inputs[0].0.clone(), inputs[0].1.clone(), vec![])],
            BTreeSet::from([0, 1]),
        )
        .expect("prove");
    bundle.stamp(&mut rng, zat(0)).expect("stamp");
    bundle.extract(&mut rng, &sighash).expect("extract");
}

#[test]
fn custody_derives_from_preimages_not_stored_effects() {
    let mut rng = StdRng::seed_from_u64(0x9C29);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = spend_bundle(&mut rng, &wallet, wallet.random_note(100));
    let commitment = bundle
        .finalize_effects(&mut rng, &wallet.pak)
        .expect("effects");
    bundle.outputs[0].rk = bundle.outputs[1].rk;

    let sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .expect("authorize");
    assert_eq!(sighash, mock_sighash(commitment));
    assert_ne!(
        mock_sighash(bundle.commitment().expect("effects")),
        sighash,
        "the stored descriptors no longer match custody's"
    );
}

#[test]
fn custodies_sign_their_own_spends_and_provers_their_own_actions() {
    let mut rng = StdRng::seed_from_u64(0x9C2A);
    let alice = WalletSim::new(shared_sk());
    let bob = WalletSim::random(&mut rng);
    let (alice_ak, bob_ak) = (spend_key(&alice.sk), spend_key(&bob.sk));
    let alice_note = alice.random_note(70);
    let bob_note = bob.random_note(50);
    let (inputs, anchor) = spendables(&mut rng, &[(&alice, alice_note), (&bob, bob_note)]);

    let mut bundle = pczt::Bundle::new(unaddressed(alice.random_note(10)), Some(alice_ak), vec![]);
    bundle.add_spend(alice_note, Some(alice_ak));
    bundle.add_spend(bob_note, Some(bob_ak));
    bundle.add_output(WalletSim::random(&mut rng).random_note(110).into(), None);

    let sighash = bundle
        .authorize(&mut rng, &alice.sk, |digest| mock_sighash(*digest))
        .expect("alice authorizes");
    assert!(bundle.spends[0].sig.is_some());
    assert!(
        bundle.spends[1].sig.is_none(),
        "alice does not sign bob's spend"
    );

    let bob_sighash = bundle
        .authorize(&mut rng, &bob.sk, |digest| mock_sighash(*digest))
        .expect("bob authorizes");
    assert_eq!(bob_sighash, sighash);
    assert!(bundle.spends[1].sig.is_some());
    bundle.sign_binding(&mut rng, &sighash).expect("binding");

    let mut bob_copy = bundle.clone();
    bundle
        .prove_partial(
            &mut rng,
            anchor,
            Some(&alice.pak),
            vec![(0, inputs[0].0.clone(), inputs[0].1.clone(), vec![])],
            BTreeSet::new(),
        )
        .expect("alice proves");
    bundle
        .prove_partial(&mut rng, anchor, None, vec![], BTreeSet::from([0]))
        .expect("anyone proves the output");
    bob_copy
        .prove_partial(
            &mut rng,
            anchor,
            Some(&bob.pak),
            vec![(1, inputs[1].0.clone(), inputs[1].1.clone(), vec![])],
            BTreeSet::new(),
        )
        .expect("bob proves");

    let mut combined = bundle.combine(bob_copy).expect("combine");
    assert_eq!(combined.partials.len(), 3);
    combined.merge_partials(&mut rng).expect("merge");
    combined.stamp(&mut rng, zat(10)).expect("stamp");
    combined.extract(&mut rng, &sighash).expect("extract");
}

#[test]
fn parallel_custodies_conflict() {
    let mut rng = StdRng::seed_from_u64(0x9C2B);
    let wallet = WalletSim::new(shared_sk());
    let bundle = spend_bundle(&mut rng, &wallet, wallet.random_note(100));

    let mut left = bundle.clone();
    let mut right = bundle;
    left.authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .expect("left");
    right
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .expect("right");

    let Err(CombineError::Conflict(Slot::Spend(0))) = left.combine(right) else {
        panic!("independently chosen entropy must conflict");
    };
}

#[test]
fn redacted_copy_combines_and_extracts() {
    let mut rng = StdRng::seed_from_u64(0x9C2C);
    let wallet = WalletSim::new(shared_sk());
    let spend_note = wallet.random_note(100);
    let (inputs, anchor) = spendables(&mut rng, &[(&wallet, spend_note)]);

    let mut bundle = spend_bundle(&mut rng, &wallet, spend_note);
    let sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .expect("authorize");
    bundle.sign_binding(&mut rng, &sighash).expect("binding");
    bundle
        .prove_partial(
            &mut rng,
            anchor,
            Some(&wallet.pak),
            vec![(0, inputs[0].0.clone(), inputs[0].1.clone(), vec![])],
            BTreeSet::from([0, 1]),
        )
        .expect("prove");
    bundle.stamp(&mut rng, zat(1)).expect("stamp");

    let mut redacted = bundle.clone();
    redacted.redact();
    assert!(redacted.spends[0].note.psi.is_none());
    assert!(redacted.spends[0].theta.is_none());
    assert!(redacted.partials.is_empty());

    let combined = redacted.clone().combine(bundle).expect("combine");
    assert!(
        combined.spends[0].theta.is_some(),
        "combining restores secrets"
    );
    redacted
        .extract(&mut rng, &sighash)
        .expect("extract redacted");
}

#[test]
fn zero_action_bundle_stamps_with_fee_seed() {
    let mut rng = StdRng::seed_from_u64(0x9C2D);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = pczt::Bundle::new(
        unaddressed(wallet.random_note(0)),
        Some(spend_key(&wallet.sk)),
        vec![],
    );

    let sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .expect("authorize");
    bundle.sign_binding(&mut rng, &sighash).expect("binding");

    let Err(pczt::ProverError::Incomplete) = bundle.stamp(&mut rng, zat(0)) else {
        panic!("a bundle with no actions has no partial to stamp");
    };
    let anchor = PoolSim::genesis(&mut rng).anchor();
    bundle.seed_stamp(&mut rng, anchor).expect("seed stamp");
    bundle.extract(&mut rng, &sighash).expect("extract");
}

#[test]
fn extraction_requires_every_signature() {
    let mut rng = StdRng::seed_from_u64(0x9C2E);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = spend_bundle(&mut rng, &wallet, wallet.random_note(100));
    let sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .expect("authorize");

    let Err(ExtractError::MissingBindingSignature) = bundle.clone().extract(&mut rng, &sighash)
    else {
        panic!("extraction needs the binding signature");
    };

    bundle.spends[0].sig = None;
    let Err(ExtractError::MissingSignature(Slot::Spend(0))) = bundle.extract(&mut rng, &sighash)
    else {
        panic!("extraction needs every action signature");
    };
}

#[test]
fn binding_rejects_unbalanced_effects() {
    let mut rng = StdRng::seed_from_u64(0x9C2F);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = spend_bundle(&mut rng, &wallet, wallet.random_note(100));
    let sighash = bundle
        .authorize(&mut rng, &wallet.sk, |digest| mock_sighash(*digest))
        .expect("authorize");
    bundle.value_balance = value::Balance::try_from(1).expect("in range");

    let Err(pczt::SignerError::Unbalanced) = bundle.sign_binding(&mut rng, &sighash) else {
        panic!("a value balance the commitments do not open to must not be signed");
    };
}
