#![allow(clippy::panic, reason = "test code")]

use alloc::{string::ToString as _, vec, vec::Vec};

use pasta_curves::Fp;
use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    constants::{EPOCH_SIZE, MAX_MONEY},
    digest::blake2b::COMMIT_NO_BUNDLE,
    entropy::ActionEntropy,
    fixtures::{
        PoolSim, WalletSim, build_autonome, build_output_plan, build_output_stamp, mock_sighash,
        mock_wtxid, random_action, random_block, random_block_with, shared_sk, spend_witness,
    },
    primitives::{BlockHeight, Tachygram},
    stamp::VerificationError,
    value,
};

#[test]
fn plan_value_balance_sums_spends_and_outputs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let spend = spend_plan_at(rng, &wallet, &ask, 300);
    let note = wallet.random_note(200);
    let (_rcv, _alpha, output) = build_output_plan(rng, note);
    let bundle_plan = Plan::new(alloc::vec![spend], alloc::vec![output]);

    assert_eq!(
        bundle_plan.value_balance(),
        Ok(value::Balance::try_from(100).unwrap())
    );
}

#[test]
fn wrong_value_balance_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());

    bundle.value_balance = value::Balance::try_from(999).unwrap();
    let err = bundle.verify_signatures(&sighash).unwrap_err();
    let SignatureError::Binding(_) = err else {
        panic!("expected SignatureError::Binding, got {err:?}");
    };
}

/// No separate range assertion is needed in `verify_signatures`: even a
/// `value::Balance` built directly with a magnitude far outside
/// `-MAX_MONEY..=MAX_MONEY` (bypassing `TryFrom`'s range check entirely, the
/// same way `read_rejects_value_balance_out_of_range` forges an otherwise
/// unconstructible wire encoding) is caught by the binding signature check
/// alone, same as any other mismatched value.
#[test]
fn verify_signatures_rejects_out_of_range_value_balance_mutation() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());

    bundle.value_balance = value::Balance::new_unchecked(i64::MAX);
    let err = bundle.verify_signatures(&sighash).unwrap_err();
    let SignatureError::Binding(_) = err else {
        panic!("expected SignatureError::Binding, got {err:?}");
    };
}

#[test]
fn stripped_bundle_retains_signatures() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());

    let covering = build_autonome(rng, &wallet, 500, 300);
    let adjunct = bundle.strip(mock_wtxid(&covering));
    adjunct.verify_signatures(&sighash).unwrap();
}

#[test]
fn plan_commitment_matches_bundle_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(200);
    let pool = PoolSim::genesis(rng);
    let (stamp, output_plan) = build_output_stamp(rng, pool.anchor(), note);

    let bundle_plan = Plan::new(alloc::vec![], alloc::vec![output_plan]);
    let sighash = mock_sighash(bundle_plan.commitment().unwrap());

    let bundle = bundle_plan
        .sign(&sighash, &ask, rng)
        .expect("sign output bundle")
        .stamp(stamp);

    assert_eq!(bundle_plan.commitment().unwrap(), bundle.commitment());
}

#[test]
fn sign_reports_global_action_index_on_rk_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();

    // A valid spend at global index 0 — derive its rk exactly as `sign` does,
    // so it passes the spend check and signing reaches the outputs.
    let spend = action::Plan::spend(
        wallet.random_note(200),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
        |alpha| ask.derive_action_private(&alpha).derive_action_public(),
    );

    // An output at global index 1 whose rk is corrupted to a foreign key.
    let mut output = action::Plan::output(
        wallet.random_note(100),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    let wrong_rk = action::Plan::output(
        wallet.random_note(50),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    )
    .rk;
    output.rk = wrong_rk;

    let plan = Plan::new(alloc::vec![spend], alloc::vec![output]);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let err = plan.sign(&sighash, &ask, rng).unwrap_err();
    let SignError::RkMismatch { idx, rk } = err else {
        panic!("expected RkMismatch, got {err:?}");
    };
    // Global index = spends.len() (1) + output index (0): the offset is retained,
    // and the error carries the offending rk alongside it.
    assert_eq!(idx, 1);
    assert_eq!(rk, wrong_rk.0.into());
}

#[test]
fn no_bundle_commitment_differs_from_empty_bundle() {
    let empty_plan = Plan::new(alloc::vec![], alloc::vec![]);
    assert_ne!(
        *COMMIT_NO_BUNDLE,
        empty_plan.commitment().unwrap(),
        "absent bundle must differ from empty bundle"
    );
}

#[test]
fn zero_action_bundle_is_valid() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let covering = build_autonome(rng, &wallet, 1000, 700);

    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let bundle = Bundle {
        actions: alloc::vec![],
        value_balance: value::Balance::ZERO,
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        stamp: mock_wtxid(&covering),
    };

    bundle.verify_signatures(&sighash).unwrap();
}

#[test]
fn payment_bundle_verifies() {
    let rng = &mut StdRng::seed_from_u64(0);
    let sender = WalletSim::random(rng);
    let recipient = WalletSim::random(rng);
    let input_note = sender.random_note(500);
    let output_note = recipient.random_note(200);
    let change_note = sender.random_note(300);

    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(rng, &[vec![input_note.commitment()]], 50));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = sender.fresh_spend(rng, &pool, height, &input_note);
    let anchor = spendable_pcd.data().2;
    let stamped = sender.autonome(
        rng,
        anchor,
        alloc::vec![(input_note, spendable_pcd, spend_epoch)],
        alloc::vec![output_note, change_note],
    );
    let sighash = mock_sighash(stamped.commitment());
    stamped
        .verify_signatures(&sighash)
        .expect("payment bundle must verify");
}

#[test]
fn stamp_verify_action_multiset_invariants() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let stamped = build_autonome(rng, &wallet, 1000, 700);

    let descriptors: Vec<action::Descriptor> =
        stamped.actions.iter().map(Action::descriptor).collect();

    // Permutation accepts.
    {
        stamped
            .stamp
            .verify(rng, &[descriptors[1], descriptors[0]])
            .expect("permuted actions must verify");
    }

    // Drop rejects.
    {
        let mut dropped = descriptors.clone();
        dropped.pop();
        let err = stamped.stamp.verify(rng, &dropped).unwrap_err();
        let VerificationError::ActionsMismatch = err else {
            panic!("drop: expected ActionsMismatch, got {err:?}");
        };
    }

    // Duplicate rejects.
    {
        let mut duplicated = descriptors.clone();
        duplicated.push(duplicated[0]);
        let err = stamped.stamp.verify(rng, &duplicated).unwrap_err();
        let VerificationError::ActionsMismatch = err else {
            panic!("duplicate: expected ActionsMismatch, got {err:?}");
        };
    }

    // Foreign-extra rejects.
    {
        let mut extended = descriptors.clone();
        extended.push(random_action(rng).descriptor());
        let err = stamped.stamp.verify(rng, &extended).unwrap_err();
        let VerificationError::ActionsMismatch = err else {
            panic!("extra: expected ActionsMismatch, got {err:?}");
        };
    }

    // Replace-with-foreign rejects.
    {
        let mut replaced = descriptors;
        replaced[0] = random_action(rng).descriptor();
        let err = stamped.stamp.verify(rng, &replaced).unwrap_err();
        let VerificationError::ActionsMismatch = err else {
            panic!("replaced: expected ActionsMismatch, got {err:?}");
        };
    }
}

#[test]
fn innocent_aggregate_from_two_autonomes() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let spend_a = wallet.random_note(1000);
    let output_a = wallet.random_note(700);
    let spend_b = wallet.random_note(500);
    let output_b = wallet.random_note(200);

    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(
        rng,
        &[vec![spend_a.commitment()], vec![spend_b.commitment()]],
        50,
    ));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let init_a = wallet.spendable_init(rng, &spend_a, &pool, cm_height);
    let sp_a = wallet.lift_over_creation_epoch(rng, &pool, &spend_a, cm_height, init_a);
    let init_b = wallet.spendable_init(rng, &spend_b, &pool, cm_height);
    let sp_b = wallet.lift_over_creation_epoch(rng, &pool, &spend_b, cm_height, init_b);
    let anchor_a = sp_a.data().2;
    let anchor_b = sp_b.data().2;
    assert_eq!(anchor_a, anchor_b, "lifts land on a common anchor");

    let spend_epoch = cm_height.epoch().next();
    let autonome_a = wallet.autonome(
        rng,
        anchor_a,
        alloc::vec![(spend_a, sp_a, spend_epoch)],
        alloc::vec![output_a],
    );
    let autonome_b = wallet.autonome(
        rng,
        anchor_b,
        alloc::vec![(spend_b, sp_b, spend_epoch)],
        alloc::vec![output_b],
    );

    let descriptors_a: Vec<action::Descriptor> =
        autonome_a.actions.iter().map(Action::descriptor).collect();
    let descriptors_b: Vec<action::Descriptor> =
        autonome_b.actions.iter().map(Action::descriptor).collect();
    let stamp_a = autonome_a.stamp.clone();
    let stamp_b = autonome_b.stamp.clone();

    let innocent = {
        let innocent_plan = Plan::new(alloc::vec![], alloc::vec![]);
        let innocent_sighash = mock_sighash(innocent_plan.commitment().unwrap());

        let stamp = ProofStamp::merge(rng, (stamp_a, descriptors_a), (stamp_b, descriptors_b))
            .expect("merge");

        Bundle {
            actions: alloc::vec![],
            value_balance: value::Balance::ZERO,
            binding_sig: innocent_plan
                .derive_bsk_private()
                .sign(rng, &innocent_sighash),
            stamp,
        }
    };

    let adjunct_a = autonome_a.strip(mock_wtxid(&innocent));
    let adjunct_b = autonome_b.strip(mock_wtxid(&innocent));

    innocent
        .verify_signatures(&mock_sighash(innocent.commitment()))
        .expect("innocent binding sig should verify");

    let adjunct_descriptors: Vec<action::Descriptor> = [adjunct_a.actions, adjunct_b.actions]
        .concat()
        .iter()
        .map(Action::descriptor)
        .collect();
    innocent
        .stamp
        .verify(rng, &adjunct_descriptors)
        .expect("innocent stamp should verify against adjunct actions");
}

#[test]
fn based_aggregate_with_two_adjuncts() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let based_spend = wallet.random_note(800);
    let based_output = wallet.random_note(400);
    let a_spend = wallet.random_note(1000);
    let a_output = wallet.random_note(700);
    let b_spend = wallet.random_note(500);
    let b_output = wallet.random_note(200);

    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(
        rng,
        &[
            vec![based_spend.commitment()],
            vec![a_spend.commitment()],
            vec![b_spend.commitment()],
        ],
        50,
    ));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let based_init = wallet.spendable_init(rng, &based_spend, &pool, cm_height);
    let based_sp = wallet.lift_over_creation_epoch(rng, &pool, &based_spend, cm_height, based_init);
    let a_init = wallet.spendable_init(rng, &a_spend, &pool, cm_height);
    let a_sp = wallet.lift_over_creation_epoch(rng, &pool, &a_spend, cm_height, a_init);
    let b_init = wallet.spendable_init(rng, &b_spend, &pool, cm_height);
    let b_sp = wallet.lift_over_creation_epoch(rng, &pool, &b_spend, cm_height, b_init);
    let anchor = based_sp.data().2;
    assert_eq!(anchor, a_sp.data().2, "lifts land on a common anchor");
    assert_eq!(anchor, b_sp.data().2, "lifts land on a common anchor");

    let spend_epoch = cm_height.epoch().next();
    let mut becomes_based = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(based_spend, based_sp, spend_epoch)],
        alloc::vec![based_output],
    );
    let autonome_a = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(a_spend, a_sp, spend_epoch)],
        alloc::vec![a_output],
    );
    let autonome_b = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(b_spend, b_sp, spend_epoch)],
        alloc::vec![b_output],
    );

    let sighash = mock_sighash(becomes_based.commitment());

    let based_descriptors: Vec<action::Descriptor> = becomes_based
        .actions
        .iter()
        .map(Action::descriptor)
        .collect();
    let descriptors_a: Vec<action::Descriptor> =
        autonome_a.actions.iter().map(Action::descriptor).collect();
    let descriptors_b: Vec<action::Descriptor> =
        autonome_b.actions.iter().map(Action::descriptor).collect();

    let stamp_a = autonome_a.stamp.clone();
    let stamp_b = autonome_b.stamp.clone();

    let innocent_descriptors = [descriptors_a.as_slice(), descriptors_b.as_slice()].concat();
    let innocent_stamp = ProofStamp::merge(rng, (stamp_a, descriptors_a), (stamp_b, descriptors_b))
        .expect("innocent merge");

    let based_stamp = ProofStamp::merge(
        rng,
        (becomes_based.stamp, based_descriptors),
        (innocent_stamp, innocent_descriptors),
    )
    .expect("based merge");

    becomes_based.stamp = based_stamp;

    let adjunct_a = autonome_a.strip(mock_wtxid(&becomes_based));
    let adjunct_b = autonome_b.strip(mock_wtxid(&becomes_based));

    becomes_based
        .verify_signatures(&sighash)
        .expect("based aggregate binding sig should verify");

    let all_descriptors: Vec<action::Descriptor> = [
        becomes_based.actions.clone(),
        adjunct_a.actions,
        adjunct_b.actions,
    ]
    .concat()
    .iter()
    .map(Action::descriptor)
    .collect();

    becomes_based
        .stamp
        .verify(rng, &all_descriptors)
        .expect("based aggregate stamp should verify against all actions");
}

#[test]
fn invalid_action_sig_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());

    let mut sig_bytes: [u8; 64] = bundle.actions[0].sig.into();
    sig_bytes[0] ^= 0xFF;
    let bad_sig = action::Signature::from(sig_bytes);
    bundle.actions[0].sig = bad_sig;

    let err = bundle.verify_signatures(&sighash).unwrap_err();
    let SignatureError::Action(sig) = err else {
        panic!("expected SignatureError::Action, got {err:?}");
    };
    assert_eq!(sig, bad_sig);
}

#[test]
fn stamped_read_write_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let original = build_autonome(rng, &wallet, 1000, 700);
    let mut buf = Vec::new();
    original.write(&mut buf).expect("write");
    let deserialized = Bundle::<ProofStamp>::read(&*buf).expect("read");

    assert_eq!(original.actions, deserialized.actions);
    assert_eq!(original.value_balance, deserialized.value_balance);
    assert_eq!(original.stamp.tachygrams, deserialized.stamp.tachygrams);
    assert_eq!(original.stamp.anchor, deserialized.stamp.anchor);

    let sighash = mock_sighash(deserialized.commitment());
    deserialized
        .verify_signatures(&sighash)
        .expect("deserialized bundle must verify");
}

#[test]
fn stripped_read_write_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let covering = build_autonome(rng, &wallet, 500, 300);
    let wtxid = mock_wtxid(&covering);
    let stripped = build_autonome(rng, &wallet, 1000, 700).strip(wtxid);

    let mut buf = Vec::new();
    stripped.write(&mut buf).expect("write");
    let deserialized = Bundle::<PointerStamp>::read(&*buf).expect("read");

    assert_eq!(stripped, deserialized);
    assert_eq!(deserialized.stamp, wtxid);
}

#[test]
fn tachyon_bundle_conversions() {
    // Stamped Ok: actions, value_balance, tachygrams, anchor preserved.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let original = build_autonome(rng, &wallet, 1000, 700);
        let erased: TachyonBundle = original.clone().into();
        let back = Bundle::<ProofStamp>::try_from(erased).expect("stamped variant");

        assert_eq!(original.actions, back.actions);
        assert_eq!(original.value_balance, back.value_balance);
        assert_eq!(original.stamp.tachygrams, back.stamp.tachygrams);
        assert_eq!(original.stamp.anchor, back.stamp.anchor);
    }

    // Stripped Ok: wtxid preserved.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let covering = build_autonome(rng, &wallet, 500, 300);
        let wtxid = mock_wtxid(&covering);
        let stripped = build_autonome(rng, &wallet, 1000, 700).strip(wtxid);

        let erased: TachyonBundle = stripped.clone().into();
        let back = Bundle::<PointerStamp>::try_from(erased).expect("stripped variant");

        assert_eq!(stripped, back);
        assert_eq!(back.stamp, wtxid);
    }

    // Err: TryFrom rejects the wrong variant in both directions.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let adjunct = build_autonome(rng, &wallet, 1000, 700).strip(mock_wtxid(&stamped));

        let stamped_erased: TachyonBundle = stamped.into();
        Bundle::<PointerStamp>::try_from(stamped_erased).expect_err("stamped is not an adjunct");

        let adjunct_erased: TachyonBundle = adjunct.into();
        Bundle::<ProofStamp>::try_from(adjunct_erased).expect_err("adjunct is not stamped");
    }
}

#[test]
fn tachyon_bundle_wire_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    // Stamped variant (0x01).
    {
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let erased: TachyonBundle = stamped.clone().into();
        let mut buf = Vec::new();
        erased.write(&mut buf).expect("write");
        let decoded = TachyonBundle::read(&*buf).expect("read");
        let back = Bundle::<ProofStamp>::try_from(decoded).expect("stamped variant");

        // Stamp carries a proof and is not PartialEq, so compare fields.
        assert_eq!(stamped.actions, back.actions);
        assert_eq!(stamped.value_balance, back.value_balance);
        assert_eq!(stamped.stamp.tachygrams, back.stamp.tachygrams);
        assert_eq!(stamped.stamp.anchor, back.stamp.anchor);
    }

    // Stripped variant (0x02).
    {
        let covering = build_autonome(rng, &wallet, 500, 300);
        let stripped = build_autonome(rng, &wallet, 1000, 700).strip(mock_wtxid(&covering));
        let erased: TachyonBundle = stripped.clone().into();
        let mut buf = Vec::new();
        erased.write(&mut buf).expect("write");
        let decoded = TachyonBundle::read(&*buf).expect("read");
        let back = Bundle::<PointerStamp>::try_from(decoded).expect("stripped variant");

        assert_eq!(stripped, back);
    }
}

#[test]
fn aggregate_id_try_from_rejects_zero() {
    PointerStamp::try_from([0u8; 64]).unwrap_err();
}

#[test]
fn wire_state_byte_dispatch() {
    // Garbage state byte: rejected by every reader.
    {
        let buf: &[u8] = &[0x03];
        for err in [
            Bundle::<ProofStamp>::read(buf).expect_err("invalid state byte must be rejected"),
            Bundle::<PointerStamp>::read(buf).expect_err("invalid state byte must be rejected"),
            TachyonBundle::read(buf).expect_err("invalid state byte must be rejected"),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "invalid bundle state");
        }
    }

    // No-bundle (0x00): the enum reader decodes to NoBundle, not an error.
    {
        let buf: &[u8] = &[0x00];
        let decoded = TachyonBundle::read(buf).expect("read");
        assert!(decoded.is_no_bundle(), "0x00 must decode to NoBundle");
    }

    // Valid-but-mismatched state byte: each definite reader rejects the other's.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());

        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let mut stamped_buf = Vec::new();
        stamped.write(&mut stamped_buf).expect("write stamped");

        let adjunct = build_autonome(rng, &wallet, 1000, 700).strip(mock_wtxid(&stamped));
        let mut adjunct_buf = Vec::new();
        adjunct.write(&mut adjunct_buf).expect("write adjunct");

        let adjunct_on_stamped = Bundle::<PointerStamp>::read(&*stamped_buf)
            .expect_err("Adjunct::read must reject a stamped (0x01) buffer");
        assert_eq!(
            adjunct_on_stamped.to_string(),
            "unexpected tachyonBundleState"
        );
        let stamped_on_adjunct = Bundle::<ProofStamp>::read(&*adjunct_buf)
            .expect_err("Stamped::read must reject a stripped (0x02) buffer");
        assert_eq!(
            stamped_on_adjunct.to_string(),
            "unexpected tachyonBundleState"
        );
    }
}

/// Both wire readers must reject the all-zero wtxid trailer for every stripped
/// bundle, innocent or adjunct: the spec requires each to name a covering
/// aggregate. `AggregateId` cannot construct zero, so forge the invalid shape
/// by zeroing the trailer of a valid encoding.
#[test]
fn read_rejects_zero_wtxid() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let covering = build_autonome(rng, &wallet, 500, 300);
    let wtxid = mock_wtxid(&covering);

    // Adjunct (non-empty actions) and innocent (empty actions) both reject.
    let adjunct = {
        let adjunct = build_autonome(rng, &wallet, 1000, 700).strip(wtxid);
        assert!(!adjunct.actions.is_empty());
        adjunct
    };

    let innocent = {
        let plan = Plan::new(alloc::vec![], alloc::vec![]);
        let sighash = mock_sighash(plan.commitment().unwrap());
        let bundle = Bundle {
            actions: alloc::vec![],
            value_balance: value::Balance::ZERO,
            binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
            stamp: wtxid,
        };
        assert!(bundle.actions.is_empty());
        bundle
    };

    for stripped in [adjunct, innocent] {
        let mut buf = Vec::new();
        stripped.write(&mut buf).expect("write");

        // The wtxid is the trailing 64 bytes; zero it to forge the invalid shape.
        for byte in buf.iter_mut().rev().take(64) {
            *byte = 0;
        }

        let adjunct_err =
            Bundle::<PointerStamp>::read(&*buf).expect_err("Adjunct::read must reject zero wtxid");
        assert_eq!(adjunct_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            adjunct_err.to_string(),
            "aggregate id is zero and refers to no aggregate"
        );

        let enum_err =
            TachyonBundle::read(&*buf).expect_err("TachyonBundle::read must reject zero wtxid");
        assert_eq!(enum_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            enum_err.to_string(),
            "aggregate id is zero and refers to no aggregate"
        );
    }
}

/// A stripped innocent (empty actions) remains representable: assigned a
/// nonzero covering wtxid, it serializes and round-trips through both readers.
#[test]
fn innocent_round_trips_with_nonzero_wtxid() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let covering = build_autonome(rng, &wallet, 1000, 700);

    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let innocent = Bundle {
        actions: alloc::vec![],
        value_balance: value::Balance::ZERO,
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        stamp: mock_wtxid(&covering),
    };

    let mut buf = Vec::new();
    innocent.write(&mut buf).expect("write innocent");

    let via_adjunct = Bundle::<PointerStamp>::read(&*buf).expect("Adjunct::read innocent");
    assert_eq!(innocent, via_adjunct);

    let decoded = TachyonBundle::read(&*buf).expect("TachyonBundle::read");
    let via_enum = Bundle::<PointerStamp>::try_from(decoded).expect("adjunct variant");
    assert_eq!(innocent, via_enum);
}

#[test]
fn auth_digest_invariants() {
    // Stamped vs stripped: distinct auth_digests — the property that makes
    // wtxid discriminate across aggregation forms.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let stamped_digest = stamped.auth_digest();

        let covering = build_autonome(rng, &wallet, 500, 300);
        let stripped = stamped.strip(mock_wtxid(&covering));
        assert_ne!(stamped_digest, stripped.auth_digest());
    }

    // wtxid binds: distinct wtxids on otherwise-identical stripped bundles
    // produce distinct digests.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let autonome = build_autonome(rng, &wallet, 1000, 700);

        let covering_a = build_autonome(rng, &wallet, 500, 300);
        let covering_b = build_autonome(rng, &wallet, 800, 600);
        assert_ne!(mock_wtxid(&covering_a), mock_wtxid(&covering_b));

        let stripped_aa = autonome.clone().strip(mock_wtxid(&covering_a));
        let digest_aa = stripped_aa.auth_digest();
        let stripped_bb = autonome.strip(mock_wtxid(&covering_b));
        let digest_bb = stripped_bb.auth_digest();
        assert_ne!(digest_aa, digest_bb);
    }

    // TachyonBundle dispatch matches the concrete-variant methods, for both
    // stamped and stripped.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let stamped_direct = stamped.auth_digest();
        let covering_wtxid = mock_wtxid(&stamped);
        let erased: TachyonBundle = stamped.into();
        assert_eq!(erased.auth_digest(), stamped_direct);

        let wallet2 = WalletSim::new(shared_sk());
        let stripped = build_autonome(rng, &wallet2, 1000, 700).strip(covering_wtxid);
        let stripped_direct = stripped.auth_digest();
        let erased_stripped: TachyonBundle = stripped.into();
        assert_eq!(erased_stripped.auth_digest(), stripped_direct);
    }

    // The proof stamp's digest commits its contents: perturbing the carried
    // covered-actions digest or the tachygram set changes the auth_digest.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let baseline = stamped.auth_digest();

        let mut altered_actions = stamped.clone();
        altered_actions.stamp.actions[0] ^= 0x01;
        assert_ne!(baseline, altered_actions.auth_digest());

        let mut extra_tachygram = stamped;
        extra_tachygram
            .stamp
            .tachygrams
            .push(Tachygram::from(Fp::from(7u64)));
        // Tachygrams must stay canonically sorted for the stamp digest.
        extra_tachygram.stamp.tachygrams.sort_unstable();
        assert_ne!(baseline, extra_tachygram.auth_digest());
    }
}

/// Coverage-check protocol: an observer reconstructs the covered-actions
/// digest from a based aggregate's own actions plus all covered adjuncts'
/// visible actions, and checks it against the stamped aggregate's
/// serialized `hStampActionsTachyon`.
#[test]
fn coverage_check_matches_stamp_actions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);

    let based_spend = wallet.random_note(800);
    let based_output = wallet.random_note(400);
    let a_spend = wallet.random_note(1000);
    let a_output = wallet.random_note(700);
    let b_spend = wallet.random_note(500);
    let b_output = wallet.random_note(200);

    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(
        rng,
        &[
            vec![based_spend.commitment()],
            vec![a_spend.commitment()],
            vec![b_spend.commitment()],
        ],
        50,
    ));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let based_init = wallet.spendable_init(rng, &based_spend, &pool, cm_height);
    let based_sp = wallet.lift_over_creation_epoch(rng, &pool, &based_spend, cm_height, based_init);
    let a_init = wallet.spendable_init(rng, &a_spend, &pool, cm_height);
    let a_sp = wallet.lift_over_creation_epoch(rng, &pool, &a_spend, cm_height, a_init);
    let b_init = wallet.spendable_init(rng, &b_spend, &pool, cm_height);
    let b_sp = wallet.lift_over_creation_epoch(rng, &pool, &b_spend, cm_height, b_init);
    let anchor = based_sp.data().2;

    let spend_epoch = cm_height.epoch().next();
    let mut becomes_based = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(based_spend, based_sp, spend_epoch)],
        alloc::vec![based_output],
    );
    let autonome_a = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(a_spend, a_sp, spend_epoch)],
        alloc::vec![a_output],
    );
    let autonome_b = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(b_spend, b_sp, spend_epoch)],
        alloc::vec![b_output],
    );

    let based_descriptors: Vec<action::Descriptor> = becomes_based
        .actions
        .iter()
        .map(Action::descriptor)
        .collect();
    let descriptors_a: Vec<action::Descriptor> =
        autonome_a.actions.iter().map(Action::descriptor).collect();
    let descriptors_b: Vec<action::Descriptor> =
        autonome_b.actions.iter().map(Action::descriptor).collect();

    let stamp_a = autonome_a.stamp.clone();
    let stamp_b = autonome_b.stamp.clone();

    let innocent_descriptors = [descriptors_a.as_slice(), descriptors_b.as_slice()].concat();
    let innocent_stamp = ProofStamp::merge(rng, (stamp_a, descriptors_a), (stamp_b, descriptors_b))
        .expect("innocent merge");

    let based_stamp = ProofStamp::merge(
        rng,
        (becomes_based.stamp, based_descriptors),
        (innocent_stamp, innocent_descriptors),
    )
    .expect("based merge");
    becomes_based.stamp = based_stamp;

    let adjunct_a = autonome_a.strip(mock_wtxid(&becomes_based));
    let adjunct_b = autonome_b.strip(mock_wtxid(&becomes_based));

    // Coverage confirmation: the based aggregate's carried digest matches
    // its own actions plus both covered adjuncts'.
    assert!(
        becomes_based.covers(&[&adjunct_a, &adjunct_b]),
        "full covered set matches hStampActionsTachyon"
    );

    // Missing an adjunct: fewer descriptors, no match.
    assert!(
        !becomes_based.covers(&[&adjunct_a]),
        "missing adjunct must mismatch"
    );

    // Extra (duplicated) adjunct: more descriptors, no match.
    assert!(
        !becomes_based.covers(&[&adjunct_a, &adjunct_b, &adjunct_a]),
        "extra adjunct must mismatch"
    );
}

/// A bundle whose actions are not in canonical order is rejected on read: the
/// order-committing sighash plus this check close action reordering as a
/// malleability vector.
#[test]
fn read_rejects_noncanonical_actions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);
    assert!(
        bundle.actions.len() >= 2,
        "need at least two actions to permute"
    );
    assert_ne!(bundle.actions[0], bundle.actions[1]);

    // A canonical (signed) bundle round-trips.
    let mut buf = Vec::new();
    bundle.write(&mut buf).expect("write");
    Bundle::<ProofStamp>::read(&*buf).expect("canonical bundle reads");

    // Permuting the stored actions and re-serializing produces a non-canonical
    // encoding, which read must reject.
    let mut permuted = bundle;
    permuted.actions.swap(0, 1);
    let mut permuted_buf = Vec::new();
    permuted.write(&mut permuted_buf).expect("write permuted");

    let err = Bundle::<ProofStamp>::read(&*permuted_buf)
        .expect_err("non-canonical actions must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(err.to_string(), "actions are not canonically sorted");
}

/// A stamp whose tachygrams are not in canonical order is rejected on read,
/// matching the order the stamp digest commits to.
#[test]
fn read_rejects_noncanonical_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);
    let n = bundle.stamp.tachygrams.len();
    assert!(n >= 2, "need at least two tachygrams to permute");

    let mut permuted = bundle;
    permuted.stamp.tachygrams.swap(0, n - 1);
    let mut buf = Vec::new();
    permuted.write(&mut buf).expect("write");

    let err =
        Bundle::<ProofStamp>::read(&*buf).expect_err("non-canonical tachygrams must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(err.to_string(), "tachygrams are not canonically sorted");
}

/// Build a spend action plan without a pool/anchor: `Plan::spend`'s
/// `derive_rk` closure recomputes alpha internally, so only `ask` is needed
/// to derive a matching `rk`.
fn spend_plan_at(
    rng: &mut StdRng,
    wallet: &WalletSim,
    ask: &private::SpendAuthorizingKey,
    value: u64,
) -> action::Plan<effect::Spend> {
    let note = wallet.random_note(value);
    let (rcv, theta, _alpha) = spend_witness(rng, &note);
    action::Plan::spend(note, theta, rcv, |alpha| {
        ask.derive_action_private(&alpha).derive_action_public()
    })
}

#[test]
fn plan_value_balance_accepts_boundary_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let spend = spend_plan_at(rng, &wallet, &ask, MAX_MONEY);
    let bundle_plan = Plan::new(alloc::vec![spend], alloc::vec![]);

    assert_eq!(
        bundle_plan.value_balance(),
        Ok(value::Balance::try_from(i64::try_from(MAX_MONEY).unwrap()).unwrap())
    );
}

#[test]
fn plan_value_balance_accepts_boundary_negative_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let note = wallet.random_note(MAX_MONEY);
    let (_rcv, _alpha, output) = build_output_plan(rng, note);
    let bundle_plan = Plan::new(alloc::vec![], alloc::vec![output]);

    assert_eq!(
        bundle_plan.value_balance(),
        Ok(value::Balance::try_from(-i64::try_from(MAX_MONEY).unwrap()).unwrap())
    );
}

#[test]
fn plan_value_balance_rejects_overflow_above_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let spend_a = spend_plan_at(rng, &wallet, &ask, MAX_MONEY);
    let spend_b = spend_plan_at(rng, &wallet, &ask, MAX_MONEY);
    let bundle_plan = Plan::new(alloc::vec![spend_a, spend_b], alloc::vec![]);

    assert_eq!(bundle_plan.value_balance(), Err(value::OutOfRange));
    {
        let err = bundle_plan.commitment().unwrap_err();
        let CommitError::BalanceOverflow(_) = err else {
            panic!("expected CommitError::BalanceOverflow, got {err:?}");
        };
    }
    let sighash = [0u8; 32];
    {
        let err = bundle_plan.sign(&sighash, &ask, rng).unwrap_err();
        let SignError::BalanceOverflow = err else {
            panic!("expected SignError::BalanceOverflow, got {err:?}");
        };
    }
}

#[test]
fn plan_value_balance_rejects_overflow_below_negative_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let note_a = wallet.random_note(MAX_MONEY);
    let note_b = wallet.random_note(MAX_MONEY);
    let (_, _, output_a) = build_output_plan(rng, note_a);
    let (_, _, output_b) = build_output_plan(rng, note_b);
    let bundle_plan = Plan::new(alloc::vec![], alloc::vec![output_a, output_b]);

    assert_eq!(bundle_plan.value_balance(), Err(value::OutOfRange));
    {
        let err = bundle_plan.commitment().unwrap_err();
        let CommitError::BalanceOverflow(_) = err else {
            panic!("expected CommitError::BalanceOverflow, got {err:?}");
        };
    }
    let sighash = [0u8; 32];
    {
        let err = bundle_plan.sign(&sighash, &ask, rng).unwrap_err();
        let SignError::BalanceOverflow = err else {
            panic!("expected SignError::BalanceOverflow, got {err:?}");
        };
    }
}

#[test]
fn read_accepts_value_balance_at_max_money_boundaries() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_money = i64::try_from(MAX_MONEY).unwrap();

    for value_balance in [max_money, -max_money] {
        let vb = value::Balance::try_from(value_balance).unwrap();
        let mut bundle = build_autonome(rng, &wallet, 1000, 700);
        bundle.value_balance = vb;

        let mut buf = Vec::new();
        bundle.write(&mut buf).expect("write");
        let decoded = Bundle::<ProofStamp>::read(&*buf).expect("read must accept boundary balance");
        assert_eq!(decoded.value_balance, vb);
    }
}

/// `value::Balance::try_from` cannot construct an out-of-range value at all, so
/// this forges the invalid shape directly on the wire: `valueBalanceTachyon` is
/// the 8 bytes right after the 1-byte state tag (see the module-level wire
/// format documentation), mirroring `read_rejects_zero_wtxid`'s approach of
/// overwriting valid-encoding bytes to build an otherwise-unconstructible
/// input.
#[test]
fn read_rejects_value_balance_out_of_range() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_money = i64::try_from(MAX_MONEY).unwrap();

    for value_balance in [max_money + 1, -max_money - 1] {
        let bundle = build_autonome(rng, &wallet, 1000, 700);

        let mut buf = Vec::new();
        bundle.write(&mut buf).expect("write");
        buf[1..9].copy_from_slice(&value_balance.to_le_bytes());

        let stamp_err = Bundle::<ProofStamp>::read(&*buf)
            .expect_err("Bundle::<ProofStamp>::read must reject out-of-range value balance");
        assert_eq!(stamp_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(stamp_err.to_string(), "value balance out of range");

        let enum_err = TachyonBundle::read(&*buf)
            .expect_err("TachyonBundle::read must reject out-of-range value balance");
        assert_eq!(enum_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(enum_err.to_string(), "value balance out of range");
    }
}

#[test]
fn read_rejects_zero_actions_with_nonzero_balance() {
    let rng = &mut StdRng::seed_from_u64(0);
    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let bundle = Bundle {
        actions: alloc::vec![],
        value_balance: value::Balance::try_from(1).unwrap(),
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        stamp: PointerStamp::try_from([0x42u8; 64]).expect("nonzero id"),
    };

    let mut buf = Vec::new();
    bundle.write(&mut buf).expect("write");

    let adjunct_err = Bundle::<PointerStamp>::read(&*buf)
        .expect_err("Adjunct::read must reject zero actions with nonzero balance");
    assert_eq!(adjunct_err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        adjunct_err.to_string(),
        "bundle with no actions must have zero value balance"
    );

    let enum_err = TachyonBundle::read(&*buf)
        .expect_err("TachyonBundle::read must reject zero actions with nonzero balance");
    assert_eq!(enum_err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        enum_err.to_string(),
        "bundle with no actions must have zero value balance"
    );
}

/// Every construction path guarantees "no actions implies zero value
/// balance", so a violation here can only come from a hand-constructed
/// `Bundle` that bypasses `Plan`/`read`. `verify_signatures` has no special
/// case for it: the binding signature was produced for the real (zero)
/// balance, so it simply fails to validate against the `bvk` recomputed from
/// the forged nonzero balance.
#[test]
fn zero_action_bundle_rejects_nonzero_balance() {
    let rng = &mut StdRng::seed_from_u64(0);
    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let bundle = Bundle {
        actions: alloc::vec![],
        value_balance: value::Balance::try_from(1).unwrap(),
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        stamp: PointerStamp::try_from([1u8; 64]).expect("nonzero id"),
    };

    let err = bundle.verify_signatures(&sighash).unwrap_err();
    let SignatureError::Binding(_) = err else {
        panic!("expected SignatureError::Binding, got {err:?}");
    };
}
