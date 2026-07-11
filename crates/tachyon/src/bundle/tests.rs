#![allow(clippy::panic, reason = "test code")]

use alloc::{string::ToString as _, vec, vec::Vec};
use core::slice::from_ref;

use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    constants::EPOCH_SIZE,
    digest::blake2b::COMMIT_NO_BUNDLE,
    entropy::ActionEntropy,
    fixtures::{
        PoolSim, WalletSim, action_digests, build_autonome, build_output_stamp, mock_sighash,
        random_action, random_block, random_block_with, shared_sk,
    },
    primitives::{ActionDigest, BlockHeight},
    stamp::VerificationError,
};

#[test]
fn value_sum_checked_arithmetic() {
    let va = note::Value::try_from(100u64).unwrap();
    let vb = note::Value::try_from(200u64).unwrap();

    let sum = (ValueBalance::ZERO + va).unwrap();
    let total = (sum + vb).unwrap();
    assert_eq!(i64::try_from(total).unwrap(), 300);

    let diff = (ValueBalance::ZERO - va).unwrap();
    assert_eq!(i64::try_from(diff).unwrap(), -100);
}

#[test]
fn wrong_value_balance_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment().unwrap());

    bundle.value_balance = 999;
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
    let sighash = mock_sighash(bundle.commitment().unwrap());

    let (unassigned, _stamp) = bundle.strip();
    unassigned.verify_signatures(&sighash).unwrap();
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

    assert_eq!(
        bundle_plan.commitment().unwrap(),
        bundle.commitment().unwrap()
    );
}

#[test]
fn sign_reports_global_action_index_on_rk_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();

    // A valid spend at global index 0 — derive its rk exactly as `sign` does,
    // so it passes the spend check and signing reaches the outputs.
    let spend = action::Plan::spend(
        wallet.random_note(rng, 200),
        ActionEntropy::random(rng),
        value::CommitmentTrapdoor::random(rng),
        |alpha| ask.derive_action_private(&alpha).derive_action_public(),
    );

    // An output at global index 1 whose rk is corrupted to a foreign key.
    let mut output = action::Plan::output(
        wallet.random_note(rng, 100),
        ActionEntropy::random(rng),
        value::CommitmentTrapdoor::random(rng),
    );
    let wrong_rk = action::Plan::output(
        wallet.random_note(rng, 50),
        ActionEntropy::random(rng),
        value::CommitmentTrapdoor::random(rng),
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
    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let bundle = Bundle {
        actions: alloc::vec![],
        value_balance: 0,
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        stamp: AggregateId::try_from([1u8; 64]).expect("nonzero id"),
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
    let sighash = mock_sighash(stamped.commitment().unwrap());
    stamped
        .verify_signatures(&sighash)
        .expect("payment bundle must verify");
}

#[test]
fn stamp_verify_action_multiset_invariants() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let stamped = build_autonome(rng, &wallet, 1000, 700);

    // Permutation accepts.
    {
        let action_a = stamped.actions[0];
        let action_b = stamped.actions[1];
        stamped
            .stamp
            .verify(rng, &[action_b, action_a])
            .expect("permuted actions must verify");
    }

    // Drop rejects.
    {
        let mut actions = stamped.actions.clone();
        actions.pop();
        let err = stamped.stamp.verify(rng, &actions).unwrap_err();
        let VerificationError::ActionSetMismatch = err else {
            panic!("drop: expected ActionSetMismatch, got {err:?}");
        };
    }

    // Duplicate rejects.
    {
        let mut actions = stamped.actions.clone();
        actions.push(actions[0]);
        let err = stamped.stamp.verify(rng, &actions).unwrap_err();
        let VerificationError::ActionSetMismatch = err else {
            panic!("duplicate: expected ActionSetMismatch, got {err:?}");
        };
    }

    // Foreign-extra rejects.
    {
        let mut actions = stamped.actions.clone();
        actions.push(random_action(rng));
        let err = stamped.stamp.verify(rng, &actions).unwrap_err();
        let VerificationError::ActionSetMismatch = err else {
            panic!("extra: expected ActionSetMismatch, got {err:?}");
        };
    }

    // Replace-with-foreign rejects.
    {
        let mut actions = stamped.actions.clone();
        actions[0] = random_action(rng);
        let err = stamped.stamp.verify(rng, &actions).unwrap_err();
        let VerificationError::ActionSetMismatch = err else {
            panic!("replaced: expected ActionSetMismatch, got {err:?}");
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

    let digests_a = action_digests(&autonome_a.actions);
    let digests_b = action_digests(&autonome_b.actions);
    let (adjunct_a, stamp_a) = autonome_a.strip();
    let (adjunct_b, stamp_b) = autonome_b.strip();

    let innocent = {
        let innocent_plan = Plan::new(alloc::vec![], alloc::vec![]);
        let innocent_sighash = mock_sighash(innocent_plan.commitment().unwrap());

        let stamp = Stamp::prove_merge(rng, (stamp_a, &digests_a), (stamp_b, &digests_b))
            .expect("prove_merge");

        Bundle {
            actions: alloc::vec![],
            value_balance: 0,
            binding_sig: innocent_plan
                .derive_bsk_private()
                .sign(rng, &innocent_sighash),
            stamp,
        }
    };

    innocent
        .verify_signatures(&mock_sighash(innocent.commitment().unwrap()))
        .expect("innocent binding sig should verify");

    let adjunct_actions: Vec<Action> = [adjunct_a.actions, adjunct_b.actions].concat();
    innocent
        .stamp
        .verify(rng, &adjunct_actions)
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

    let sighash = mock_sighash(becomes_based.commitment().unwrap());

    let based_digests = action_digests(&becomes_based.actions);
    let digests_a = action_digests(&autonome_a.actions);
    let digests_b = action_digests(&autonome_b.actions);

    let (adjunct_a, stamp_a) = autonome_a.strip();
    let (adjunct_b, stamp_b) = autonome_b.strip();

    let mut innocent_digests = digests_a.clone();
    innocent_digests.extend_from_slice(&digests_b);
    let innocent_stamp = Stamp::prove_merge(rng, (stamp_a, &digests_a), (stamp_b, &digests_b))
        .expect("innocent merge");

    let based_stamp = Stamp::prove_merge(
        rng,
        (becomes_based.stamp, &based_digests),
        (innocent_stamp, &innocent_digests),
    )
    .expect("based merge");

    becomes_based.stamp = based_stamp;

    becomes_based
        .verify_signatures(&sighash)
        .expect("based aggregate binding sig should verify");

    let all_actions: Vec<Action> = [
        becomes_based.actions.clone(),
        adjunct_a.actions,
        adjunct_b.actions,
    ]
    .concat();

    becomes_based
        .stamp
        .verify(rng, &all_actions)
        .expect("based aggregate stamp should verify against all actions");
}

#[test]
fn invalid_action_sig_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment().unwrap());

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
    let deserialized = Bundle::<Stamp>::read(&*buf).expect("read");

    assert_eq!(original.actions, deserialized.actions);
    assert_eq!(original.value_balance, deserialized.value_balance);
    assert_eq!(original.stamp.tachygrams, deserialized.stamp.tachygrams);
    assert_eq!(original.stamp.anchor, deserialized.stamp.anchor);

    let sighash = mock_sighash(deserialized.commitment().unwrap());
    deserialized
        .verify_signatures(&sighash)
        .expect("deserialized bundle must verify");
}

#[test]
fn stripped_read_write_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (unassigned, _stamp) = build_autonome(rng, &wallet, 1000, 700).strip();
    let stripped =
        unassigned.assign_wtxid(AggregateId::try_from([0x42u8; 64]).expect("nonzero id"));

    let mut buf = Vec::new();
    stripped.write(&mut buf).expect("write");
    let deserialized = Bundle::<AggregateId>::read(&*buf).expect("read");

    assert_eq!(stripped, deserialized);
    assert_eq!(
        deserialized.stamp,
        AggregateId::try_from([0x42u8; 64]).expect("nonzero id")
    );
}

#[test]
fn tachyon_bundle_conversions() {
    // Stamped Ok: actions, value_balance, tachygrams, anchor preserved.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let original = build_autonome(rng, &wallet, 1000, 700);
        let erased: TachyonBundle = original.clone().into();
        let back = Bundle::<Stamp>::try_from(erased).expect("stamped variant");

        assert_eq!(original.actions, back.actions);
        assert_eq!(original.value_balance, back.value_balance);
        assert_eq!(original.stamp.tachygrams, back.stamp.tachygrams);
        assert_eq!(original.stamp.anchor, back.stamp.anchor);
    }

    // Stripped Ok: wtxid preserved.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let (unassigned, _stamp) = build_autonome(rng, &wallet, 1000, 700).strip();
        let stripped =
            unassigned.assign_wtxid(AggregateId::try_from([0xABu8; 64]).expect("nonzero id"));

        let erased: TachyonBundle = stripped.clone().into();
        let back = Bundle::<AggregateId>::try_from(erased).expect("stripped variant");

        assert_eq!(stripped, back);
        assert_eq!(
            back.stamp,
            AggregateId::try_from([0xABu8; 64]).expect("nonzero id")
        );
    }

    // Err: TryFrom rejects the wrong variant in both directions.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let (unassigned, _stamp) = build_autonome(rng, &wallet, 1000, 700).strip();
        let adjunct =
            unassigned.assign_wtxid(AggregateId::try_from([0x55u8; 64]).expect("nonzero id"));

        let stamped_erased: TachyonBundle = stamped.into();
        Bundle::<AggregateId>::try_from(stamped_erased).expect_err("stamped is not an adjunct");

        let adjunct_erased: TachyonBundle = adjunct.into();
        Bundle::<Stamp>::try_from(adjunct_erased).expect_err("adjunct is not stamped");
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
        let decoded = TachyonBundle::read(&*buf)
            .expect("read")
            .expect("some bundle");
        let back = Bundle::<Stamp>::try_from(decoded).expect("stamped variant");

        // Stamp carries a proof and is not PartialEq, so compare fields.
        assert_eq!(stamped.actions, back.actions);
        assert_eq!(stamped.value_balance, back.value_balance);
        assert_eq!(stamped.stamp.tachygrams, back.stamp.tachygrams);
        assert_eq!(stamped.stamp.anchor, back.stamp.anchor);
    }

    // Stripped variant (0x02).
    {
        let (unassigned, _stamp) = build_autonome(rng, &wallet, 1000, 700).strip();
        let stripped =
            unassigned.assign_wtxid(AggregateId::try_from([0xCDu8; 64]).expect("nonzero id"));
        let erased: TachyonBundle = stripped.clone().into();
        let mut buf = Vec::new();
        erased.write(&mut buf).expect("write");
        let decoded = TachyonBundle::read(&*buf)
            .expect("read")
            .expect("some bundle");
        let back = Bundle::<AggregateId>::try_from(decoded).expect("stripped variant");

        assert_eq!(stripped, back);
    }
}

#[test]
fn aggregate_id_try_from_rejects_zero() {
    AggregateId::try_from([0u8; 64]).unwrap_err();
}

#[test]
fn wire_state_byte_dispatch() {
    // Garbage state byte: rejected by every reader.
    {
        let buf: &[u8] = &[0x03];
        for err in [
            Bundle::<Stamp>::read(buf).expect_err("invalid state byte must be rejected"),
            Bundle::<AggregateId>::read(buf).expect_err("invalid state byte must be rejected"),
            TachyonBundle::read(buf).expect_err("invalid state byte must be rejected"),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "invalid bundle state");
        }
    }

    // No-bundle (0x00): the enum reader decodes to None, not an error.
    {
        let buf: &[u8] = &[0x00];
        let decoded = TachyonBundle::read(buf).expect("read");
        assert!(decoded.is_none(), "0x00 must decode to None");
    }

    // Valid-but-mismatched state byte: each definite reader rejects the other's.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());

        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let mut stamped_buf = Vec::new();
        stamped.write(&mut stamped_buf).expect("write stamped");

        let (unassigned, _stamp) = build_autonome(rng, &wallet, 1000, 700).strip();
        let adjunct =
            unassigned.assign_wtxid(AggregateId::try_from([0x66u8; 64]).expect("nonzero id"));
        let mut adjunct_buf = Vec::new();
        adjunct.write(&mut adjunct_buf).expect("write adjunct");

        let adjunct_on_stamped = Bundle::<AggregateId>::read(&*stamped_buf)
            .expect_err("Adjunct::read must reject a stamped (0x01) buffer");
        assert_eq!(
            adjunct_on_stamped.to_string(),
            "stripped bundle requires tachyonBundleState 0x02"
        );
        let stamped_on_adjunct = Bundle::<Stamp>::read(&*adjunct_buf)
            .expect_err("Stamped::read must reject a stripped (0x02) buffer");
        assert_eq!(
            stamped_on_adjunct.to_string(),
            "stamped bundle requires tachyonBundleState 0x01"
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

    // Adjunct (non-empty actions) and innocent (empty actions) both reject.
    let adjunct = {
        let (unassigned, _stamp) = build_autonome(rng, &wallet, 1000, 700).strip();
        assert!(!unassigned.actions.is_empty());
        unassigned.assign_wtxid(AggregateId::try_from([0x42u8; 64]).expect("nonzero id"))
    };

    let innocent = {
        let plan = Plan::new(alloc::vec![], alloc::vec![]);
        let sighash = mock_sighash(plan.commitment().unwrap());
        let bundle = Bundle {
            actions: alloc::vec![],
            value_balance: 0,
            binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
            stamp: AggregateId::try_from([0x42u8; 64]).expect("nonzero id"),
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
            Bundle::<AggregateId>::read(&*buf).expect_err("Adjunct::read must reject zero wtxid");
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
    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let innocent = Bundle {
        actions: alloc::vec![],
        value_balance: 0,
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        stamp: AggregateId::try_from([0x42u8; 64]).expect("nonzero id"),
    };

    let mut buf = Vec::new();
    innocent.write(&mut buf).expect("write innocent");

    let via_adjunct = Bundle::<AggregateId>::read(&*buf).expect("Adjunct::read innocent");
    assert_eq!(innocent, via_adjunct);

    let decoded = TachyonBundle::read(&*buf)
        .expect("TachyonBundle::read")
        .expect("some bundle");
    let via_enum = Bundle::<AggregateId>::try_from(decoded).expect("adjunct variant");
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

        let (unassigned, _stamp) = stamped.strip();
        let stripped =
            unassigned.assign_wtxid(AggregateId::try_from([0x11u8; 64]).expect("nonzero id"));
        assert_ne!(stamped_digest, stripped.auth_digest());
    }

    // wtxid binds: distinct wtxids on otherwise-identical stripped bundles
    // produce distinct digests.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let (unassigned, _stamp) = build_autonome(rng, &wallet, 1000, 700).strip();

        let stripped_aa = unassigned
            .clone()
            .assign_wtxid(AggregateId::try_from([0xAAu8; 64]).expect("nonzero id"));
        let digest_aa = stripped_aa.auth_digest();
        let stripped_bb =
            unassigned.assign_wtxid(AggregateId::try_from([0xBBu8; 64]).expect("nonzero id"));
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
        let erased: TachyonBundle = stamped.into();
        assert_eq!(erased.auth_digest(), stamped_direct);

        let wallet2 = WalletSim::new(shared_sk());
        let (unassigned, _stamp) = build_autonome(rng, &wallet2, 1000, 700).strip();
        let stripped =
            unassigned.assign_wtxid(AggregateId::try_from([0x33u8; 64]).expect("nonzero id"));
        let stripped_direct = stripped.auth_digest();
        let erased_stripped: TachyonBundle = stripped.into();
        assert_eq!(erased_stripped.auth_digest(), stripped_direct);
    }
}

/// Coverage-check protocol: an observer reconstructs the merged action-digest
/// set commitment from a based aggregate's own actions plus all covered
/// adjuncts' visible actions, and checks it against the stamped aggregate's
/// serialized `cActionsTachyon`.
#[test]
fn coverage_check_matches_stamped_action_set() {
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

    let based_digests = action_digests(&becomes_based.actions);
    let digests_a = action_digests(&autonome_a.actions);
    let digests_b = action_digests(&autonome_b.actions);

    let (adjunct_a, stamp_a) = autonome_a.strip();
    let (adjunct_b, stamp_b) = autonome_b.strip();

    let innocent_digests: Vec<ActionDigest> =
        digests_a.iter().chain(digests_b.iter()).copied().collect();
    let innocent_stamp = Stamp::prove_merge(rng, (stamp_a, &digests_a), (stamp_b, &digests_b))
        .expect("innocent merge");

    let based_stamp = Stamp::prove_merge(
        rng,
        (becomes_based.stamp, &based_digests),
        (innocent_stamp, &innocent_digests),
    )
    .expect("based merge");
    becomes_based.stamp = based_stamp;

    // Coverage confirmation: the based aggregate's carried commitment matches
    // its own actions plus both covered adjuncts'.
    assert!(
        becomes_based
            .covers(&[adjunct_a.clone(), adjunct_b.clone()])
            .expect("valid digests"),
        "full covered set matches cActionsTachyon"
    );

    // Missing an adjunct: fewer roots, no match.
    assert!(
        !becomes_based
            .covers(from_ref(&adjunct_a))
            .expect("valid digests"),
        "missing adjunct must mismatch"
    );

    // Extra (duplicated) adjunct: more roots, no match.
    assert!(
        !becomes_based
            .covers(&[adjunct_a.clone(), adjunct_b, adjunct_a])
            .expect("valid digests"),
        "extra adjunct must mismatch"
    );
}
