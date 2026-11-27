extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString as _,
    vec,
    vec::Vec,
};
use core::{assert_matches, cmp::Reverse, mem};

use corez::io;
use ragu::{
    Rank as _, WalletRank,
    udon::{
        curve::{Affine as _, Projective as _},
        field::Field as _,
    },
};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    BlockHeight, SignatureError, Tachygram, action,
    bundle::{Plan, PlanError, Signature},
    constants::MAX_MONEY,
    digest::blake2b,
    effect,
    entropy::ActionEntropy,
    fee,
    keys::private,
    pasta::{Ep, EqAffine, Fp},
    stamp::{self, Stamp},
    value, *,
};

use super::fixtures::application;
use crate::fixtures::{
    mock_sighash, mock_txid,
    pool::PoolSim,
    wallet::{
        WalletSim, alice, compressed, entry_spends, merged, output_plan, random_action, shared_sk,
        spend, zero_action,
    },
};

#[test]
fn sign_and_apply_signatures_verify_every_plan_shape() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    for (spends, outputs) in [
        (&[200][..], &[100][..]),
        (&[200][..], &[][..]),
        (&[][..], &[200][..]),
        (&[][..], &[][..]),
    ] {
        let plan = Plan::new(
            spends
                .iter()
                .map(|&amount| spend_plan_at(rng, &wallet, &ask, amount))
                .collect(),
            outputs
                .iter()
                .map(|&amount| output_plan(rng, wallet.random_note(amount)))
                .collect(),
            wallet.random_note(0),
        );
        let sighash = mock_sighash(plan.commitment().unwrap());
        let signatures = plan.sign(rng, &sighash, &ask).unwrap();
        plan.verify_signatures(&sighash, &signatures).unwrap();
        let applied = plan
            .apply_signatures(rng, &sighash, signatures.actions)
            .unwrap();
        plan.verify_signatures(&sighash, &applied).unwrap();
    }
}

#[test]
fn apply_signatures_rejects_wrong_sig_count() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let ask = wallet.sk.derive_auth_private();
    let spend_a = spend_plan_at(rng, &wallet, &ask, 200);
    let spend_b = spend_plan_at(rng, &wallet, &ask, 100);
    let spend_c = spend_plan_at(rng, &wallet, &ask, 300);
    let plan = Plan::new(vec![spend_a, spend_b], vec![], wallet.random_note(0));
    let sighash = mock_sighash(plan.commitment().unwrap());
    let sig = ask
        .derive_action_private(
            &spend_a
                .theta
                .randomizer::<effect::Spend>(spend_a.note.commitment()),
        )
        .sign(rng, &sighash);

    for authorized in [
        BTreeMap::from([(spend_a.descriptor(), sig)]),
        BTreeMap::from([
            (spend_a.descriptor(), sig),
            (spend_b.descriptor(), sig),
            (spend_c.descriptor(), sig),
        ]),
    ] {
        assert_eq!(
            plan.apply_signatures(rng, &sighash, authorized)
                .unwrap_err(),
            PlanError::ActionSigMismatch
        );
    }
}

#[test]
fn apply_signatures_with_shuffled_sigs_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();

    let spend_a = spend_plan_at(rng, &wallet, &ask, 200);
    let spend_b = spend_plan_at(rng, &wallet, &ask, 100);
    let plan = Plan::new(vec![spend_a, spend_b], vec![], wallet.random_note(0));

    let sighash = mock_sighash(plan.commitment().unwrap());
    let signed = plan.sign(rng, &sighash, &ask).unwrap();
    let mut sigs: Vec<action::Signature> = signed.actions.into_values().collect();

    sigs.reverse();
    let authorized = plan.descriptors().into_iter().zip(sigs).collect();

    let signatures = plan.apply_signatures(rng, &sighash, authorized).unwrap();

    assert_matches!(
        plan.verify_signatures(&sighash, &signatures),
        Err(SignatureError::Action(_))
    );
}

#[test]
fn assemble_joins_by_descriptor() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (plan, original) = spend(app);
    let wallet = WalletSim::new(shared_sk());
    let signatures = plan
        .sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap();
    let pairs: BTreeMap<_, _> = original
        .actions
        .iter()
        .map(|action| (action.descriptor, action.tachygrams))
        .collect();
    let joined = plan.assemble(
        signatures,
        original.stamp,
        pairs.clone(),
        original.fee.v_fee,
    );
    assert_eq!(joined.fee_auth, original.fee_auth);
    assert!(
        joined
            .actions
            .iter()
            .map(|action| (action.descriptor, action.tachygrams))
            .eq(pairs)
    );
    joined
        .verify(rng, app, &mock_sighash(joined.commitment()), &[])
        .unwrap();
}

#[test]
#[should_panic(expected = "action descriptors do not match")]
fn assemble_panics_on_mismatched_descriptors() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (plan, original) = spend(app);
    let wallet = WalletSim::new(shared_sk());
    let signatures = plan
        .sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap();
    let _bundle = plan.assemble(
        signatures,
        original.stamp,
        BTreeMap::new(),
        original.fee.v_fee,
    );
}

#[test]
fn edited_bundles_fail_binding_verification() {
    let app = &application();
    let (_, original) = spend(app);
    for edited in [
        {
            let mut permuted = original.clone();
            permuted.actions.swap(0, 1);
            permuted
        },
        {
            let mut tampered = original.clone();
            tampered.value_balance = value::Balance::try_from(999).unwrap();
            tampered
        },
    ] {
        assert_ne!(edited.commitment(), original.commitment());
        assert_matches!(
            edited.verify_signatures(&mock_sighash(edited.commitment())),
            Err(SignatureError::Binding(_))
        );
    }
}

#[test]
fn no_bundle_commitment_differs_from_empty_bundle() {
    let empty_plan = Plan::new(vec![], vec![], WalletSim::new(shared_sk()).random_note(0));
    assert_ne!(*blake2b::COMMIT_NO_BUNDLE, empty_plan.commitment().unwrap());
}

#[test]
fn zero_action_bundle_requires_a_zero_balance() {
    let rng = &mut StdRng::seed_from_u64(0);
    let max_fee_note = WalletSim::new(shared_sk()).random_note(0);
    let plan = Plan::new(vec![], vec![], max_fee_note);
    let sighash = mock_sighash(plan.commitment().unwrap());
    for value_balance in [0i64, 1] {
        let bundle = Bundle {
            actions: vec![],
            value_balance: value::Balance::try_from(value_balance).unwrap(),
            binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
            memo: Vec::new(),
            fee: fee::Descriptor {
                cv_feemax: max_fee_note.cv_feemax(),
                v_fee: value::Positive::ZERO,
            },
            fee_auth: max_fee_note.commitment().into(),
            stamp: (),
        };
        let mut buf = Vec::new();
        bundle.write(&mut buf).unwrap();
        if value_balance == 0 {
            bundle.verify_signatures(&sighash).unwrap();
            for decoded in [
                Bundle::<()>::read(&*buf).unwrap(),
                Bundle::<()>::try_from(TachyonBundle::read(&*buf).unwrap()).unwrap(),
            ] {
                assert_eq!(decoded.commitment(), bundle.commitment());
                assert_eq!(decoded.auth_digest(), bundle.auth_digest());
            }
        } else {
            assert_matches!(
                bundle.verify_signatures(&sighash),
                Err(SignatureError::Binding(_))
            );
            for err in [
                Bundle::<()>::read(&*buf).unwrap_err(),
                TachyonBundle::read(&*buf).unwrap_err(),
            ] {
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                assert_eq!(
                    err.to_string(),
                    "bundle with no actions must have zero value balance"
                );
            }
        }
    }
}

#[test]
#[should_panic(expected = "duplicate action descriptor")]
fn plan_rejects_a_descriptor_shared_by_a_spend_and_an_output() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let output = output_plan(rng, wallet.random_note(0));
    let spend = action::Plan::spend(output.note, output.theta, output.rcv, |_| output.rk);
    let _plan = Plan::new(vec![spend], vec![output], wallet.random_note(0));
}

#[test]
fn duplicated_spend_cannot_inflate() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(1000);
    let pool = PoolSim::shared();
    let spendable = wallet.spendable_init(app, pool, &note, BlockHeight(1));
    let anchor = spendable.data().2;
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let plan = action::Plan::spend(note, theta, rcv, |alpha| {
        wallet.pak.ak.derive_action_public(&alpha)
    });
    let descriptor = plan.descriptor();
    let secret = wallet.note_secret(app, note);
    let max_fee_note = wallet.random_note(0);
    let cv_feemax = max_fee_note.cv_feemax();
    let (honest_stamp, pairs) = Plan::new(vec![plan], vec![], max_fee_note)
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(rng, app, &wallet.pak, vec![(secret, spendable, vec![])])
        .unwrap();
    let doubled = 2 * i64::try_from(u64::from(note.value)).unwrap();
    let value_balance = value::Balance::try_from(doubled).unwrap();
    let action_bytes: Vec<[u8; 64]> = [descriptor, descriptor].into_iter().collect();
    let sighash = mock_sighash(blake2b::bundle_commitment(
        &blake2b::action_descriptor_digest(&action_bytes),
        doubled,
        &cv_feemax.into(),
        &blake2b::memo_digest(&[]),
    ));
    let alpha = theta.randomizer::<effect::Spend>(note.commitment());
    let sig = wallet
        .sk
        .derive_auth_private()
        .derive_action_private(&alpha)
        .sign(rng, &sighash);
    let pair = pairs[&descriptor];
    let binding_sig =
        private::BindingSigningKey::from([rcv, rcv, max_fee_note.derive_feemax_blind()])
            .sign(rng, &sighash);
    let bundle = Bundle {
        actions: vec![
            action::Action {
                descriptor,
                signature: sig,
                tachygrams: pair
            };
            2
        ],
        value_balance,
        binding_sig,
        memo: Vec::new(),
        fee: fee::Descriptor {
            cv_feemax,
            v_fee: value::Positive::ZERO,
        },
        fee_auth: max_fee_note.commitment().into(),
        stamp: honest_stamp,
    };

    let mut buf = Vec::new();
    bundle.clone().strip().write(&mut buf).unwrap();
    let err = Bundle::<()>::read(&*buf).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(err.to_string(), "tachygrams are not unique");

    bundle
        .verify_signatures(&mock_sighash(bundle.commitment()))
        .unwrap();
    let action_digest = descriptor.digest(pair);
    let fee_digest = bundle.fee.digest(bundle.fee_auth);
    assert!(
        !bundle
            .verify_proof(rng, app, &[action_digest, action_digest, fee_digest])
            .unwrap()
    );

    assert_matches!(
        bundle.verify(rng, app, &mock_sighash(bundle.commitment()), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::DuplicateActions
        ))
    );
}

#[test]
fn based_aggregate_with_two_adjuncts() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let [(_, autonome_a), (_, autonome_b), (_, mut becomes_based)] = entry_spends(app);

    let sighash = mock_sighash(becomes_based.commitment());

    let based_desc = becomes_based
        .actions
        .iter()
        .map(|action| (action.descriptor, action.tachygrams))
        .collect();
    let based_fees = BTreeMap::from([(becomes_based.fee, becomes_based.fee_auth)]);
    let innocent_desc = [&autonome_a, &autonome_b]
        .into_iter()
        .flat_map(|bundle| {
            bundle
                .actions
                .iter()
                .map(|action| (action.descriptor, action.tachygrams))
        })
        .collect();
    let innocent_fees = [&autonome_a, &autonome_b]
        .into_iter()
        .map(|bundle| (bundle.fee, bundle.fee_auth))
        .collect();
    let innocent_stamp = merged(app, &autonome_a, &autonome_b).stamp;
    let (txid_a, txid_b) = (mock_txid(&autonome_a), mock_txid(&autonome_b));
    assert_eq!(innocent_stamp.adjuncts, BTreeSet::from([txid_b]));

    let based_stamp = becomes_based
        .stamp
        .merge(
            rng,
            app,
            (&based_desc, &based_fees),
            (innocent_stamp, txid_a, &innocent_desc, &innocent_fees),
        )
        .unwrap();

    becomes_based.stamp = based_stamp;

    let adjunct_a = autonome_a.strip();
    let adjunct_b = autonome_b.strip();
    let adjuncts = [&adjunct_a, &adjunct_b];

    assert!(becomes_based.is_aggregate());
    assert_eq!(
        becomes_based.stamp.adjuncts,
        BTreeSet::from([txid_a, txid_b])
    );
    becomes_based.verify(rng, app, &sighash, &adjuncts).unwrap();

    {
        let mut edited = becomes_based.clone();
        let mut adjunct = adjunct_a.clone();
        mem::swap(
            &mut edited.actions[0].tachygrams.1,
            &mut adjunct.actions[0].tachygrams.1,
        );
        assert_matches!(
            edited.verify(rng, app, &sighash, &[&adjunct, &adjunct_b]),
            Err(VerificationError::Disproved)
        );
    }
    {
        let mut edited = becomes_based.clone();
        let mut adjunct = adjunct_a.clone();
        mem::swap(&mut edited.fee_auth, &mut adjunct.fee_auth);
        assert_matches!(
            edited.verify(rng, app, &sighash, &[&adjunct, &adjunct_b]),
            Err(VerificationError::Disproved)
        );
    }

    assert_matches!(
        becomes_based.verify(rng, app, &sighash, &adjuncts[..1]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::WrongTachygramSet
        ))
    );
    assert_matches!(
        becomes_based.verify(rng, app, &sighash, &[&adjunct_a, &adjunct_b, &adjunct_a]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::DuplicateActions
        ))
    );
}

#[test]
fn autonome_verify_rejects_flipped_signatures() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, bundle) = spend(app);
    let sighash = mock_sighash(bundle.commitment());
    bundle.verify(rng, app, &sighash, &[]).unwrap();

    let mut binding_bytes = Vec::new();
    bundle.binding_sig.write(&mut binding_bytes).unwrap();
    binding_bytes[0] ^= 0xFF;
    let mut bad_binding = bundle.clone();
    bad_binding.binding_sig = Signature::read(&mut binding_bytes.as_slice()).unwrap();
    assert_matches!(
        bad_binding.verify(rng, app, &sighash, &[]),
        Err(VerificationError::Signatures(SignatureError::Binding(_)))
    );

    let mut action_bytes = Vec::new();
    bundle.actions[0]
        .signature
        .write(&mut action_bytes)
        .unwrap();
    action_bytes[0] ^= 0xFF;
    let bad_sig = action::Signature::read(&mut action_bytes.as_slice()).unwrap();
    let mut bad_action = bundle;
    bad_action.actions[0].signature = bad_sig;
    assert_matches!(
        bad_action.verify(rng, app, &sighash, &[]),
        Err(VerificationError::Signatures(SignatureError::Action(sig))) if sig == bad_sig
    );
}

#[test]
fn autonome_verify_rejects_exchanged_tachygrams() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, mut bundle) = spend(app);
    let (first, rest) = bundle.actions.split_at_mut(1);
    mem::swap(&mut first[0].tachygrams.1, &mut rest[0].tachygrams.1);
    assert_matches!(
        bundle.verify(rng, app, &mock_sighash(bundle.commitment()), &[]),
        Err(VerificationError::Disproved)
    );
}

#[test]
fn stamped_bundle_round_trips() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, uncompressed) = spend(app);
    let sighash = mock_sighash(uncompressed.commitment());
    uncompressed.verify(rng, app, &sighash, &[]).unwrap();
    // The stripped body under the 0x01 byte, then the uncompressed stamp's
    // own trailer: its proof exceeds the compressed transport bound.
    let mut uncompressed_bytes = Vec::new();
    uncompressed
        .clone()
        .strip()
        .write(&mut uncompressed_bytes)
        .unwrap();
    uncompressed_bytes[0] = 0x01;
    uncompressed.stamp.write(&mut uncompressed_bytes).unwrap();
    for err in [
        Bundle::<Stamp<stamp::Compressed>>::read(&*uncompressed_bytes).unwrap_err(),
        TachyonBundle::read(&*uncompressed_bytes).unwrap_err(),
    ] {
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "proof size exceeds transport bound");
    }
    let mut bytes = Vec::new();
    compressed(app, &uncompressed).write(&mut bytes).unwrap();
    let mut erased_buf = Vec::new();
    let erased = TachyonBundle::from(compressed(app, &uncompressed));
    erased.write(&mut erased_buf).unwrap();
    assert_eq!(erased_buf, bytes);
    let mut block = Bundle::<Stamp<stamp::Compressed>>::read(&*bytes).unwrap();
    assert_eq!(block.actions, uncompressed.actions);
    assert_eq!(block.value_balance, uncompressed.value_balance);
    assert_eq!(block.fee.v_fee, uncompressed.fee.v_fee);
    assert_eq!(block.fee_auth, uncompressed.fee_auth);
    assert_eq!(block.stamp.anchor, uncompressed.stamp.anchor);
    assert_eq!(TachyonBundle::read(&*bytes).unwrap(), erased);
    Bundle::<()>::try_from(erased).unwrap_err();
    block.verify(rng, app, &sighash, &[]).unwrap();
    let (mut stripped_block, mut stripped_uncompressed) = (Vec::new(), Vec::new());
    block.clone().strip().write(&mut stripped_block).unwrap();
    uncompressed
        .strip()
        .write(&mut stripped_uncompressed)
        .unwrap();
    assert_eq!(stripped_block, stripped_uncompressed);
    block.stamp.anchor = Anchor::random(rng);
    assert_matches!(
        block.verify(rng, app, &sighash, &[]),
        Err(VerificationError::Disproved)
    );
}

#[test]
fn read_preserves_action_order() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);

    let note_a = wallet.random_note(200);
    let note_b = wallet.random_note(300);
    let plan_a = output_plan(rng, note_a);
    let plan_b = output_plan(rng, note_b);
    let alpha_a = plan_a
        .theta
        .randomizer::<effect::Output>(note_a.commitment());
    let alpha_b = plan_b
        .theta
        .randomizer::<effect::Output>(note_b.commitment());
    let mut items = [
        (plan_a.descriptor(), alpha_a, plan_a.rcv),
        (plan_b.descriptor(), alpha_b, plan_b.rcv),
    ];
    items.sort_by_key(|item| Reverse(item.0));

    let value_balance = value::Balance::try_from(-500i64).unwrap();
    let descriptors: Vec<[u8; 64]> = items.iter().map(|item| item.0).collect();
    let max_fee_note = wallet.random_note(0);
    let cv_feemax = max_fee_note.cv_feemax();
    let sighash = mock_sighash(blake2b::bundle_commitment(
        &blake2b::action_descriptor_digest(&descriptors),
        value_balance.into(),
        &cv_feemax.into(),
        &blake2b::memo_digest(&[]),
    ));
    let actions = items
        .iter()
        .map(|item| action::Action {
            descriptor: item.0,
            signature: private::ActionSigningKey::new(&item.1).sign(rng, &sighash),
            tachygrams: (Tachygram::random(rng), Tachygram::random(rng)),
        })
        .collect();
    let binding_sig = Plan::new(vec![], vec![plan_a, plan_b], max_fee_note)
        .derive_bsk_private()
        .sign(rng, &sighash);

    let bundle = Bundle {
        actions,
        value_balance,
        binding_sig,
        memo: Vec::new(),
        fee: fee::Descriptor {
            cv_feemax,
            v_fee: value::Positive::ZERO,
        },
        fee_auth: max_fee_note.commitment().into(),
        stamp: (),
    };

    let mut buf = Vec::new();
    bundle.write(&mut buf).unwrap();
    let decoded = Bundle::<()>::read(&*buf).unwrap();

    assert_eq!(bundle.actions, decoded.actions);
    decoded.verify_signatures(&sighash).unwrap();
}

#[test]
fn stripped_bundle_round_trips() {
    let app = &application();
    let stamped = compressed(app, &spend(app).1);
    let mut stamped_bytes = Vec::new();
    stamped.write(&mut stamped_bytes).unwrap();
    let mut trailer = Vec::new();
    stamped.stamp.write(&mut trailer).unwrap();
    let stripped = stamped.strip();
    let mut buf = Vec::new();
    stripped.write(&mut buf).unwrap();
    assert_eq!(buf.len(), stamped_bytes.len() - trailer.len());
    assert_eq!(&buf[1..], &stamped_bytes[1..buf.len()]);
    let mut erased_buf = Vec::new();
    TachyonBundle::from(stripped.clone())
        .write(&mut erased_buf)
        .unwrap();
    assert_eq!(erased_buf, buf);

    for decoded in [
        Bundle::<()>::read(&*buf).unwrap(),
        Bundle::<()>::try_from(TachyonBundle::read(&*buf).unwrap()).unwrap(),
    ] {
        assert_eq!(decoded.commitment(), stripped.commitment());
        assert_eq!(decoded.auth_digest(), stripped.auth_digest());
        assert_eq!(decoded.actions, stripped.actions);
        assert_eq!(decoded.fee.v_fee, stripped.fee.v_fee);
        assert_eq!(decoded.fee_auth, stripped.fee_auth);
        decoded
            .verify_signatures(&mock_sighash(decoded.commitment()))
            .unwrap();
    }
}

#[test]
fn phase_order_wire_offsets_and_empty_stripped_trailer() {
    let app = &application();
    let mut bundle = compressed(app, &spend(app).1);
    bundle.memo = vec![0xA5, 0x5A, 0x23];
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).unwrap();
    assert_eq!(bytes[0], 0x01);
    assert_eq!(&bytes[1..9], &i64::from(bundle.value_balance).to_le_bytes());
    let mut expected = Vec::new();
    CompactSize::try_from(bundle.actions.len())
        .unwrap()
        .write(&mut expected)
        .unwrap();
    assert_eq!(&bytes[9..9 + expected.len()], expected);
    let mut offset = 9 + expected.len();
    for action in &bundle.actions {
        expected.clear();
        action.descriptor.write(&mut expected).unwrap();
        assert_eq!(&bytes[offset..offset + 64], expected);
        offset += 64;
    }
    assert_eq!(
        &bytes[offset..offset + 32],
        &<[u8; 32]>::from(bundle.fee.cv_feemax)
    );
    offset += 32;
    assert_eq!(bytes[offset], 3);
    offset += 1;
    assert_eq!(&bytes[offset..offset + 3], bundle.memo);
    offset += 3;
    for action in &bundle.actions {
        expected.clear();
        action.signature.write(&mut expected).unwrap();
        assert_eq!(&bytes[offset..offset + 64], expected);
        offset += 64;
    }
    expected.clear();
    bundle.binding_sig.write(&mut expected).unwrap();
    assert_eq!(&bytes[offset..offset + 64], expected);
    offset += 64;
    for action in &bundle.actions {
        for tachygram in <[Tachygram; 2]>::from(action.tachygrams) {
            assert_eq!(&bytes[offset..offset + 32], &Fp::from(tachygram).to_bytes());
            offset += 32;
        }
    }
    assert_eq!(
        &bytes[offset..offset + 8],
        &u64::from(bundle.fee.v_fee).to_le_bytes()
    );
    offset += 8;
    assert_eq!(
        &bytes[offset..offset + 32],
        &Fp::from(bundle.fee_auth).to_bytes()
    );
    offset += 32;
    expected.clear();
    bundle.stamp.write(&mut expected).unwrap();
    assert_eq!(&bytes[offset..], expected);
    let mut stripped = Vec::new();
    bundle.strip().write(&mut stripped).unwrap();
    assert_eq!(stripped[0], 0x02);
    assert_eq!(stripped.len(), offset);
}

#[test]
fn read_bounds_the_fee() {
    let app = &application();
    let bundle = compressed(app, &spend(app).1);
    let mut count = Vec::new();
    CompactSize::try_from(bundle.actions.len())
        .unwrap()
        .write(&mut count)
        .unwrap();
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).unwrap();
    // This fixture has an empty memo, whose CompactSize occupies one byte.
    assert_eq!(bundle.memo, Vec::<u8>::new());
    let effecting_end = 9 + count.len() + 64 * bundle.actions.len() + 32 + 1;
    let signing_end = effecting_end + 64 * bundle.actions.len() + 64;
    let fee_at = signing_end + 64 * bundle.actions.len();
    let mut stripped = Vec::new();
    bundle.strip().write(&mut stripped).unwrap();

    let mut maximum_fee = bytes.clone();
    maximum_fee[fee_at..fee_at + 8].copy_from_slice(&MAX_MONEY.to_le_bytes());
    assert_eq!(
        u64::from(
            Bundle::<Stamp<stamp::Compressed>>::read(&*maximum_fee)
                .unwrap()
                .fee
                .v_fee
        ),
        MAX_MONEY
    );
    let mut maximum_stripped = stripped.clone();
    maximum_stripped[fee_at..fee_at + 8].copy_from_slice(&MAX_MONEY.to_le_bytes());
    assert_eq!(
        u64::from(
            Bundle::<()>::try_from(TachyonBundle::read(&*maximum_stripped).unwrap())
                .unwrap()
                .fee
                .v_fee
        ),
        MAX_MONEY
    );
    for amount in [MAX_MONEY + 1, u64::MAX] {
        let mut invalid = bytes.clone();
        invalid[fee_at..fee_at + 8].copy_from_slice(&amount.to_le_bytes());
        let mut invalid_stripped = stripped.clone();
        invalid_stripped[fee_at..fee_at + 8].copy_from_slice(&amount.to_le_bytes());
        for err in [
            Bundle::<Stamp<stamp::Compressed>>::read(&*invalid).unwrap_err(),
            TachyonBundle::read(&*invalid).unwrap_err(),
            Bundle::<()>::read(&*invalid_stripped).unwrap_err(),
            TachyonBundle::read(&*invalid_stripped).unwrap_err(),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "fee out of range");
        }
    }
}

#[test]
fn read_rejects_identity_action_and_fee_points() {
    let app = &application();
    let bundle = compressed(app, &spend(app).1);
    let mut count = Vec::new();
    CompactSize::try_from(bundle.actions.len())
        .unwrap()
        .write(&mut count)
        .unwrap();
    let actions_at = 9 + count.len();
    let cv_feemax_at = actions_at + 64 * bundle.actions.len();
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).unwrap();
    let mut stripped = Vec::new();
    bundle.strip().write(&mut stripped).unwrap();
    let identity = <[u8; 32]>::from(value::Commitment::from(Ep::identity()));
    for (point_at, message) in [
        (actions_at, "action commitment is the identity"),
        (actions_at + 32, "action verification key is the identity"),
    ] {
        let mut invalid_action = bytes.clone();
        invalid_action[point_at..point_at + 32].copy_from_slice(&identity);
        let mut stripped_action = stripped.clone();
        stripped_action[point_at..point_at + 32].copy_from_slice(&identity);
        for action_error in [
            Bundle::<Stamp<stamp::Compressed>>::read(&*invalid_action).unwrap_err(),
            TachyonBundle::read(&*stripped_action).unwrap_err(),
        ] {
            assert_eq!(action_error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(action_error.to_string(), message);
        }
    }
    let mut invalid = bytes;
    invalid[cv_feemax_at..cv_feemax_at + 32].copy_from_slice(&identity);
    let mut invalid_stripped = stripped;
    invalid_stripped[cv_feemax_at..cv_feemax_at + 32].copy_from_slice(&identity);
    for err in [
        Bundle::<Stamp<stamp::Compressed>>::read(&*invalid).unwrap_err(),
        TachyonBundle::read(&*invalid).unwrap_err(),
        Bundle::<()>::read(&*invalid_stripped).unwrap_err(),
        TachyonBundle::read(&*invalid_stripped).unwrap_err(),
    ] {
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "fee commitment is the identity");
    }
}

#[test]
fn bundles_round_trip_at_action_count_limits() {
    let app = &application();
    let stamped = compressed(app, &alice(app).1);
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_fee_note = wallet.random_note(0);
    let plan = Plan::new(vec![], vec![], max_fee_note);
    let binding_sig = plan
        .sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap()
        .binding;
    let (descriptor, signature) = random_action(rng);
    let max_actions = (WalletRank::num_coeffs() - 2) / 2;
    for n in [0, max_actions] {
        // Read enforces wire shape and uniqueness, not signature validity or
        // descriptor multiplicity; those belong to later verification.
        let bundle = Bundle {
            value_balance: value::Balance::ZERO,
            actions: (0..n)
                .map(|i| {
                    let first = u64::try_from(2 * i + 1).unwrap();
                    action::Action {
                        descriptor,
                        signature,
                        tachygrams: (
                            Tachygram::from(Fp::from(first)),
                            Tachygram::from(Fp::from(first + 1)),
                        ),
                    }
                })
                .collect(),
            fee: fee::Descriptor {
                cv_feemax: max_fee_note.cv_feemax(),
                v_fee: value::Positive::ZERO,
            },
            fee_auth: Tachygram::from(Fp::from(0u64)),
            binding_sig,
            memo: Vec::new(),
            stamp: (),
        };
        let mut bytes = Vec::new();
        bundle.write(&mut bytes).unwrap();
        for decoded in [
            Bundle::<()>::read(&*bytes).unwrap(),
            Bundle::<()>::try_from(TachyonBundle::read(&*bytes).unwrap()).unwrap(),
        ] {
            assert_eq!(decoded.actions, bundle.actions);
            assert_eq!(decoded.fee_auth, bundle.fee_auth);
            let mut round_trip = Vec::new();
            decoded.write(&mut round_trip).unwrap();
            assert_eq!(round_trip, bytes);
        }
        let proof_bundle = Bundle {
            value_balance: bundle.value_balance,
            actions: bundle.actions,
            fee: bundle.fee,
            fee_auth: bundle.fee_auth,
            binding_sig: bundle.binding_sig,
            memo: bundle.memo,
            stamp: stamped.stamp.clone(),
        };
        bytes.clear();
        proof_bundle.write(&mut bytes).unwrap();
        let decoded = Bundle::<Stamp<stamp::Compressed>>::read(&*bytes).unwrap();
        assert_eq!(decoded.actions.len(), n);
        assert_eq!(decoded.actions, proof_bundle.actions);
        let mut round_trip = Vec::new();
        decoded.write(&mut round_trip).unwrap();
        assert_eq!(round_trip, bytes);
    }
}

#[test]
fn bundle_state_mismatches_are_rejected() {
    let app = &application();

    let buf: &[u8] = &[0x03];
    for err in [
        Bundle::<Stamp<stamp::Compressed>>::read(buf).unwrap_err(),
        Bundle::<()>::read(buf).unwrap_err(),
        TachyonBundle::read(buf).unwrap_err(),
    ] {
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "invalid bundle state");
    }

    assert!(TachyonBundle::read(&[0x00][..]).unwrap().is_no_bundle());

    let stamped = compressed(app, &spend(app).1);
    let adjunct = stamped.clone().strip();
    let mut stamped_buf = Vec::new();
    stamped.write(&mut stamped_buf).unwrap();
    let mut adjunct_buf = Vec::new();
    adjunct.write(&mut adjunct_buf).unwrap();
    assert_eq!(
        Bundle::<()>::read(&*stamped_buf).unwrap_err().to_string(),
        "unexpected tachyonBundleState"
    );
    assert_eq!(
        Bundle::<Stamp<stamp::Compressed>>::read(&*adjunct_buf)
            .unwrap_err()
            .to_string(),
        "unexpected tachyonBundleState"
    );
    Bundle::<Stamp<stamp::Compressed>>::try_from(TachyonBundle::from(adjunct)).unwrap_err();
}

#[test]
fn auth_digest_invariants() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let stamped = compressed(app, &spend(app).1);
    let (commitment, auth_digest) = (stamped.commitment(), stamped.auth_digest());
    let stripped = stamped.clone().strip();
    // Set by hand so that only the list differs from `stamped`. A merge would
    // also change the proof and the tachygram set.
    let mut aggregate_a = stamped.clone();
    aggregate_a.stamp.adjuncts.insert(mock_txid(&stripped));
    let mut aggregate_b = stamped.clone();
    aggregate_b.stamp.adjuncts.insert(mock_txid(&stripped));
    aggregate_b.stamp.adjuncts.insert([0x11u8; 32]);
    assert_eq!(stripped.commitment(), commitment);
    assert_ne!(stripped.auth_digest(), auth_digest);
    let erased_stripped: TachyonBundle = stripped.clone().into();
    assert_eq!(erased_stripped.auth_digest(), stripped.auth_digest());
    let mut refeed = stripped.clone();
    refeed.fee.v_fee = value::Positive::try_from(u64::from(stripped.fee.v_fee) + 1).unwrap();
    assert_ne!(refeed.auth_digest(), stripped.auth_digest());
    let mut stripped_pair = stripped.clone();
    stripped_pair.actions[0].tachygrams = (Tachygram::random(rng), Tachygram::random(rng));
    let mut stripped_change = stripped.clone();
    stripped_change.fee_auth = Tachygram::random(rng);
    for edited in [stripped_pair, stripped_change] {
        assert_eq!(edited.commitment(), commitment);
        assert_ne!(edited.auth_digest(), stripped.auth_digest());
    }

    assert_ne!(aggregate_a.auth_digest(), aggregate_b.auth_digest());
    let mut fee = stamped.clone();
    fee.fee.v_fee = value::Positive::try_from(u64::from(stamped.fee.v_fee) + 1).unwrap();
    let mut pair = stamped.clone();
    pair.actions[0].tachygrams = (Tachygram::random(rng), Tachygram::random(rng));
    let mut flipped = stamped.clone();
    let flipped_pair = &mut flipped.actions[0].tachygrams;
    mem::swap(&mut flipped_pair.0, &mut flipped_pair.1);
    let mut anchor = stamped.clone();
    anchor.stamp.anchor = Anchor::random(rng);
    let mut tachygram_set = stamped.clone();
    tachygram_set.stamp.tachygram_set = TachygramSetPoly::try_from_roots([Tachygram::random(rng)])
        .unwrap()
        .commit();
    let mut proof = stamped.clone();
    proof.stamp.proof = compressed(app, &alice(app).1).stamp.proof;
    let mut fee_change = stamped;
    fee_change.fee_auth = Tachygram::random(rng);
    for edited in [
        aggregate_a,
        aggregate_b,
        fee,
        pair,
        flipped,
        anchor,
        tachygram_set,
        proof,
        fee_change,
    ] {
        assert_eq!(edited.commitment(), commitment);
        assert_ne!(edited.auth_digest(), auth_digest);
    }
}

#[test]
fn a_pair_verifies_in_either_order_but_not_repeated() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let mut bundle = compressed(app, &spend(app).1);
    let (first, second) = bundle.actions[0].tachygrams;
    let action_digest = bundle.actions[0].digest();
    let mut bytes = Vec::new();

    bundle.actions[0].tachygrams = (second, first);
    assert_eq!(bundle.actions[0].digest(), action_digest);
    bundle.write(&mut bytes).unwrap();
    let decoded = Bundle::<Stamp<stamp::Compressed>>::read(&*bytes).unwrap();
    assert_eq!(decoded.actions, bundle.actions);
    let verified = decoded.verify(rng, app, &mock_sighash(decoded.commitment()), &[]);
    assert_eq!(verified.unwrap(), decoded.stamp.tachygram_set);

    bundle.actions[0].tachygrams = (first, first);
    bytes.clear();
    bundle.write(&mut bytes).unwrap();
    let err = Bundle::<Stamp<stamp::Compressed>>::read(&*bytes).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(err.to_string(), "tachygrams are not unique");
    assert_matches!(
        bundle.verify_covered(&[]),
        Err(VerifyCoverageError::DuplicateTachygrams)
    );
}

#[test]
fn read_bounds_the_action_count() {
    let most = (WalletRank::num_coeffs() - 2) / 2;
    for (n_actions, kind) in [
        (most, io::ErrorKind::UnexpectedEof),
        (most + 1, io::ErrorKind::InvalidData),
    ] {
        let mut bytes = vec![0x01];
        bytes.extend_from_slice(&1i64.to_le_bytes());
        CompactSize::try_from(n_actions)
            .unwrap()
            .write(&mut bytes)
            .unwrap();
        for err in [
            Bundle::<Stamp<stamp::Compressed>>::read(&*bytes).unwrap_err(),
            TachyonBundle::read(&*bytes).unwrap_err(),
        ] {
            assert_eq!(err.kind(), kind);
            if kind == io::ErrorKind::InvalidData {
                assert_eq!(err.to_string(), "too many actions");
            }
        }
    }
}

#[test]
fn adjunct_list_round_trips_and_read_rejects_noncanonical_lists() {
    let app = &application();
    let alice = compressed(app, &alice(app).1);
    let mut empty = Vec::new();
    alice.write(&mut empty).unwrap();
    let (low, high) = ([0x11u8; 32], [0x22u8; 32]);
    let mut bundle = alice.clone();
    bundle.stamp.adjuncts.extend([low, high]);
    let mut buf = Vec::new();
    bundle.write(&mut buf).unwrap();
    let decoded = Bundle::<Stamp<stamp::Compressed>>::read(&*buf).unwrap();
    assert_eq!(decoded.stamp.adjuncts, bundle.stamp.adjuncts);
    assert_eq!(decoded.auth_digest(), bundle.auth_digest());
    assert!(decoded.is_aggregate());

    let proof_len = alice.stamp.proof.to_bytes().unwrap().len();
    let mut proof_prefix = Vec::new();
    CompactSize::try_from(proof_len)
        .unwrap()
        .write(&mut proof_prefix)
        .unwrap();
    let list_end = buf.len() - proof_len - proof_prefix.len();
    let list = list_end - 64..list_end;
    assert_eq!(&buf[list.clone()], [low, high].concat());
    for edited_list in [[high, low].concat(), [low, low].concat()] {
        let mut edited = buf.clone();
        edited[list.clone()].copy_from_slice(&edited_list);
        for err in [
            Bundle::<Stamp<stamp::Compressed>>::read(&*edited).unwrap_err(),
            TachyonBundle::read(&*edited).unwrap_err(),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "adjunct txids are not strictly ascending");
        }
    }

    let count_at = empty.len() - proof_len - proof_prefix.len() - 1;
    assert_eq!(empty[count_at], 0);
    let most = WalletRank::num_coeffs() - 2 - 2 * alice.actions.len();
    for n_adjuncts in [most, most + 1] {
        let mut bytes = empty[..count_at].to_vec();
        CompactSize::try_from(n_adjuncts)
            .unwrap()
            .write(&mut bytes)
            .unwrap();
        for err in [
            Bundle::<Stamp<stamp::Compressed>>::read(&*bytes).unwrap_err(),
            TachyonBundle::read(&*bytes).unwrap_err(),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    // The combined cap is checked only after a complete, valid trailer.
    let mut oversized = alice.clone();
    oversized.stamp.adjuncts = (0..=most)
        .map(|i| {
            let mut txid = [0u8; 32];
            txid[..8].copy_from_slice(&u64::try_from(i).unwrap().to_le_bytes());
            txid
        })
        .collect();
    let mut complete = Vec::new();
    oversized.write(&mut complete).unwrap();
    for overcap_error in [
        Bundle::<Stamp<stamp::Compressed>>::read(&*complete).unwrap_err(),
        TachyonBundle::read(&*complete).unwrap_err(),
    ] {
        assert_eq!(overcap_error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(overcap_error.to_string(), "too many adjuncts");
    }

    // The standalone cap is enforced immediately, before reading the list.
    let mut trailer = Vec::new();
    alice.stamp.write(&mut trailer).unwrap();
    trailer.truncate(64);
    CompactSize::try_from(WalletRank::num_coeffs() - 1)
        .unwrap()
        .write(&mut trailer)
        .unwrap();
    let count_error = Stamp::<stamp::Compressed>::read(&*trailer).unwrap_err();
    assert_eq!(count_error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(count_error.to_string(), "too many adjuncts");
    let mut bytes = empty[..count_at - 64].to_vec();
    bytes.extend_from_slice(&trailer);
    for standalone_error in [
        Bundle::<Stamp<stamp::Compressed>>::read(&*bytes).unwrap_err(),
        TachyonBundle::read(&*bytes).unwrap_err(),
    ] {
        assert_eq!(standalone_error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(standalone_error.to_string(), "too many adjuncts");
    }
}

#[test]
fn read_rejects_an_identity_tachygram_set() {
    let app = &application();
    let mut bundle = compressed(app, &spend(app).1);
    bundle.stamp.tachygram_set = TachygramSetCommit::from(EqAffine::identity());
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).unwrap();
    for err in [
        Bundle::<Stamp<stamp::Compressed>>::read(&*bytes).unwrap_err(),
        TachyonBundle::read(&*bytes).unwrap_err(),
    ] {
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "tachygram set commitment is the identity");
    }
}

#[test]
fn verify_covered_bounds_the_covered_tachygrams() {
    let app = &application();
    let (_, bundle) = alice(app);
    let adjunct = bundle.clone().strip();
    // Two bundles' fee changes leave room for this many actions' pairs.
    let most = (WalletRank::num_coeffs() - 3) / 2;
    for (n_actions, expected) in [
        (most, VerifyCoverageError::DuplicateActions),
        (most + 1, VerifyCoverageError::WrongTachygramSet),
    ] {
        let n_adjunct = n_actions - bundle.actions.len();
        let mut oversized = adjunct.clone();
        oversized.actions = vec![adjunct.actions[0]; n_adjunct];
        assert_eq!(
            bundle
                .verify_covered(&[&oversized])
                .unwrap_err()
                .to_string(),
            expected.to_string()
        );
    }
}

fn spend_plan_at(
    rng: &mut StdRng,
    wallet: &WalletSim,
    ask: &private::SpendAuthorizingKey,
    value: u64,
) -> action::Plan<effect::Spend> {
    let note = wallet.random_note(value);
    let (rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    action::Plan::spend(note, theta, rcv, |alpha| {
        ask.derive_action_private(&alpha).derive_action_public()
    })
}

#[test]
fn plan_value_balance_is_bounded_by_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let max_money = i64::try_from(MAX_MONEY).unwrap();
    for (spends, outputs, expected) in [
        (&[300][..], &[200][..], Some(100)),
        (&[MAX_MONEY][..], &[][..], Some(max_money)),
        (&[][..], &[MAX_MONEY][..], Some(-max_money)),
        (&[MAX_MONEY, MAX_MONEY][..], &[][..], None),
        (&[][..], &[MAX_MONEY, MAX_MONEY][..], None),
    ] {
        let plan = Plan::new(
            spends
                .iter()
                .map(|&amount| spend_plan_at(rng, &wallet, &ask, amount))
                .collect(),
            outputs
                .iter()
                .map(|&amount| output_plan(rng, wallet.random_note(amount)))
                .collect(),
            wallet.random_note(0),
        );
        if let Some(balance) = expected {
            assert_eq!(
                plan.value_balance(),
                Ok(value::Balance::try_from(balance).unwrap())
            );
        } else {
            assert_eq!(plan.value_balance(), Err(value::OutOfRange));
            assert_eq!(plan.commitment().unwrap_err(), value::OutOfRange);
            assert_eq!(
                plan.sign(rng, &[0u8; 32], &ask).unwrap_err(),
                value::OutOfRange
            );
            let signature = random_action(rng).1;
            let authorized = plan
                .descriptors()
                .into_iter()
                .map(|descriptor| (descriptor, signature))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(
                plan.apply_signatures(rng, &[0u8; 32], authorized)
                    .unwrap_err(),
                PlanError::BalanceOverflow
            );
        }
    }
}

#[test]
fn read_bounds_the_value_balance() {
    let app = &application();
    let mut buf = Vec::new();
    compressed(app, &spend(app).1).write(&mut buf).unwrap();
    let max_money = i64::try_from(MAX_MONEY).unwrap();

    for value_balance in [max_money, -max_money] {
        buf[1..9].copy_from_slice(&value_balance.to_le_bytes());
        let decoded: i64 = Bundle::<Stamp<stamp::Compressed>>::read(&*buf)
            .unwrap()
            .value_balance
            .into();
        assert_eq!(decoded, value_balance);
    }
    for value_balance in [max_money + 1, -max_money - 1, i64::MAX, i64::MIN] {
        buf[1..9].copy_from_slice(&value_balance.to_le_bytes());
        for err in [
            Bundle::<Stamp<stamp::Compressed>>::read(&*buf).unwrap_err(),
            TachyonBundle::read(&*buf).unwrap_err(),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "value balance out of range");
        }
    }
}

#[test]
fn verify_covered_rejects_an_edited_tachygram() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (plan, stamped) = alice(app);

    let mut change = stamped.clone();
    change.fee_auth = Tachygram::random(rng);
    assert_matches!(
        change.verify_covered(&[]),
        Err(VerifyCoverageError::WrongTachygramSet)
    );

    let wallet = WalletSim::new(shared_sk());
    let signatures = plan
        .sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap();
    let mut pairs: BTreeMap<_, _> = stamped
        .actions
        .iter()
        .map(|action| (action.descriptor, action.tachygrams))
        .collect();
    pairs.first_entry().unwrap().get_mut().1 = Tachygram::random(rng);
    let bundle = plan.assemble(signatures, stamped.stamp, pairs, stamped.fee.v_fee);
    assert_matches!(
        bundle.verify_covered(&[]),
        Err(VerifyCoverageError::WrongTachygramSet)
    );
}

#[test]
fn memo_binds_the_commitment_but_not_the_auth_digest() {
    let app = &application();
    let mut bundle = compressed(app, &spend(app).1);
    let (commitment, auth_digest) = (bundle.commitment(), bundle.auth_digest());

    bundle.memo = vec![0x5Au8; 128];
    assert_ne!(bundle.commitment(), commitment);
    assert_eq!(bundle.auth_digest(), auth_digest);

    let adjunct = bundle.clone().strip();
    assert_eq!(adjunct.memo, bundle.memo);
    assert_eq!(adjunct.commitment(), bundle.commitment());
}

#[test]
fn memo_round_trips_and_rejects_truncation() {
    let app = &application();
    let mut bundle = compressed(app, &spend(app).1);

    for memo in [Vec::new(), vec![0xABu8; 1500]] {
        bundle.memo = memo.clone();
        let mut buf = Vec::new();
        bundle.write(&mut buf).unwrap();
        assert_eq!(
            Bundle::<Stamp<stamp::Compressed>>::read(&*buf)
                .unwrap()
                .memo,
            memo
        );
    }

    bundle.memo = vec![0x33u8; 8192];
    let mut buf = Vec::new();
    bundle.write(&mut buf).unwrap();
    buf.truncate(1024);
    let err = Bundle::<Stamp<stamp::Compressed>>::read(&*buf).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn plan_memo_reaches_the_signed_bundle() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let memo = vec![0x7Fu8; 900];
    let (plan, original) = alice(app);
    let bundle_plan = plan.with_memo(memo.clone());
    let sighash = mock_sighash(bundle_plan.commitment().unwrap());

    let signatures = bundle_plan
        .sign(rng, &sighash, &wallet.sk.derive_auth_private())
        .unwrap();
    let pairs = original
        .actions
        .iter()
        .map(|action| (action.descriptor, action.tachygrams))
        .collect();
    let bundle = bundle_plan.assemble(signatures, original.stamp, pairs, original.fee.v_fee);

    assert_eq!(bundle.memo, memo);
    assert_eq!(bundle.commitment(), bundle_plan.commitment().unwrap());
    bundle.verify_signatures(&sighash).unwrap();
}

#[test]
fn bundle_lift_preserves_coverage() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let (_, bundle) = spend(app);

    let covered = bundle.verify_covered(&[]).unwrap();

    let mut stamp_bytes = Vec::new();
    bundle.stamp.write(&mut stamp_bytes).unwrap();
    let unchanged = bundle.clone().lift(rng, app, &[], vec![]).unwrap();
    let mut unchanged_bytes = Vec::new();
    unchanged.stamp.write(&mut unchanged_bytes).unwrap();
    assert_eq!(unchanged_bytes, stamp_bytes);
    let unchanged_stamp = bundle
        .stamp
        .clone()
        .lift(rng, app, &BTreeMap::new(), &BTreeMap::new(), vec![])
        .unwrap();
    let mut unchanged_stamp_bytes = Vec::new();
    unchanged_stamp.write(&mut unchanged_stamp_bytes).unwrap();
    assert_eq!(unchanged_stamp_bytes, stamp_bytes);
    let mut body_before = Vec::new();
    bundle.clone().strip().write(&mut body_before).unwrap();

    let span = pool.anchor_span(app, BlockHeight(1)..=BlockHeight(2));

    let lifted = bundle.lift(rng, app, &[], vec![span]).unwrap();
    let mut body_after = Vec::new();
    lifted.clone().strip().write(&mut body_after).unwrap();
    assert_eq!(body_after, body_before);

    assert_eq!(lifted.stamp.anchor, pool.block(BlockHeight(2)).anchor());
    assert!(lifted.is_autonome());
    assert_eq!(lifted.verify_covered(&[]).unwrap(), covered);
    assert!(lifted.verify_proof(rng, app, &covered.0).unwrap());
}

#[test]
fn bundle_lift_over_an_aggregate() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch1 = EpochIndex::new(1);
    let [(_, autonome_a), (_, autonome_b), _] = entry_spends(app);
    let (_, zero) = zero_action(app, pool.entry_anchor(epoch1));

    let seed = zero.stamp.clone();
    let zero_desc = zero
        .actions
        .iter()
        .map(|action| (action.descriptor, action.tachygrams))
        .collect();
    let zero_fees = BTreeMap::from([(zero.fee, zero.fee_auth)]);
    let adjunct_desc = [&autonome_a, &autonome_b]
        .into_iter()
        .flat_map(|bundle| {
            bundle
                .actions
                .iter()
                .map(|action| (action.descriptor, action.tachygrams))
        })
        .collect();
    let adjunct_fees = [&autonome_a, &autonome_b]
        .into_iter()
        .map(|bundle| (bundle.fee, bundle.fee_auth))
        .collect();
    let adjunct_stamp = merged(app, &autonome_a, &autonome_b).stamp;
    let innocent = Bundle {
        stamp: seed
            .merge(
                rng,
                app,
                (&zero_desc, &zero_fees),
                (
                    adjunct_stamp,
                    mock_txid(&autonome_a),
                    &adjunct_desc,
                    &adjunct_fees,
                ),
            )
            .unwrap(),
        ..zero
    };
    assert_eq!(
        innocent.stamp.adjuncts,
        BTreeSet::from([mock_txid(&autonome_a), mock_txid(&autonome_b)])
    );

    let adjunct_a = autonome_a.strip();
    let adjunct_b = autonome_b.strip();
    innocent
        .verify(
            rng,
            app,
            &mock_sighash(innocent.commitment()),
            &[&adjunct_a, &adjunct_b],
        )
        .unwrap();
    let adjuncts = [&adjunct_a, &adjunct_b];
    let adjunct_txids = innocent.stamp.adjuncts.clone();

    let first = epoch1.first_block();
    let span = pool.anchor_span(app, first..=first);

    let lifted = innocent.lift(rng, app, &adjuncts, vec![span]).unwrap();

    assert_eq!(lifted.stamp.anchor, pool.block(first).anchor());
    assert_eq!(lifted.stamp.adjuncts, adjunct_txids);

    let (digests, tachygram_set) = lifted.verify_covered(&adjuncts).unwrap();
    assert_eq!(tachygram_set, lifted.stamp.tachygram_set);
    assert!(lifted.verify_proof(rng, app, &digests).unwrap());

    let mut bytes = Vec::new();
    lifted.stamp.write(&mut bytes).unwrap();
    let decoded = Stamp::<stamp::Uncompressed>::read(&*bytes).unwrap();
    assert_eq!(decoded.adjuncts, adjunct_txids);
    assert!(
        decoded
            .verify_proof(rng, app, digests.iter().copied())
            .unwrap()
    );
    bytes.clear();
    decoded
        .compress(rng, app)
        .unwrap()
        .write(&mut bytes)
        .unwrap();
    let decoded_stamp = Stamp::<stamp::Compressed>::read(&*bytes).unwrap();
    assert_eq!(decoded_stamp.adjuncts, adjunct_txids);
    assert!(decoded_stamp.verify_proof(rng, app, digests).unwrap());
}
