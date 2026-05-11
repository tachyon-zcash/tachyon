use alloc::{vec, vec::Vec};

use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::fixtures::{
    PoolSim, WalletSim, action_digests, build_autonome, build_output_stamp, mock_sighash,
    random_action, random_block_with,
};

#[test]
fn wrong_value_balance_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment().unwrap());

    bundle.value_balance = 999;
    assert!(bundle.verify_signatures(&sighash).is_err());
}

#[test]
fn stripped_bundle_retains_signatures() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment().unwrap());

    let (stripped, _stamp) = bundle.strip();
    stripped.verify_signatures(&sighash).unwrap();
}

#[test]
fn plan_commitment_matches_bundle_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(rng, 200);
    let pool = PoolSim::genesis(rng);
    let (stamp, output_plan) = build_output_stamp(rng, pool.anchor(), note);

    let bundle_plan = Plan::new(alloc::vec![], alloc::vec![output_plan]);
    let sighash = mock_sighash(bundle_plan.commitment());

    let bundle: Stamped = bundle_plan
        .sign(&sighash, &ask, rng)
        .expect("sign output bundle")
        .stamp(stamp);

    assert_eq!(bundle_plan.commitment(), bundle.commitment().unwrap());
}

#[test]
fn no_bundle_commitment_differs_from_empty_bundle() {
    let empty_plan = Plan::new(alloc::vec![], alloc::vec![]);
    assert_ne!(
        empty_commitment(),
        empty_plan.commitment(),
        "absent bundle must differ from empty bundle"
    );
}

#[test]
fn zero_action_bundle_is_valid() {
    let rng = &mut StdRng::seed_from_u64(0);
    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment());

    let bundle: Stripped = Bundle {
        actions: alloc::vec![],
        value_balance: 0,
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        stamp: Adjunct::default(),
    };

    bundle.verify_signatures(&sighash).unwrap();
}

#[test]
fn payment_bundle_verifies() {
    let rng = &mut StdRng::seed_from_u64(0);
    let sender = WalletSim::random(rng);
    let recipient = WalletSim::random(rng);
    let input_note = sender.random_note(rng, 500);
    let output_note = recipient.random_note(rng, 200);
    let change_note = sender.random_note(rng, 300);

    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(rng, &[vec![input_note.commitment()]], 50));
    let height = pool.height();
    let anchor = pool.anchor_at(height);
    let spend = sender.fresh_spend(rng, &pool, height, input_note);
    let stamped = sender.autonome(
        rng,
        anchor,
        alloc::vec![spend],
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
    let wallet = WalletSim::random(rng);
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
        assert!(stamped.stamp.verify(rng, &actions).is_err(), "drop");
    }

    // Duplicate rejects.
    {
        let mut actions = stamped.actions.clone();
        actions.push(actions[0]);
        assert!(stamped.stamp.verify(rng, &actions).is_err(), "duplicate");
    }

    // Foreign-extra rejects.
    {
        let mut actions = stamped.actions.clone();
        actions.push(random_action(rng));
        assert!(stamped.stamp.verify(rng, &actions).is_err(), "extra");
    }

    // Replace-with-foreign rejects.
    {
        let mut actions = stamped.actions.clone();
        actions[0] = random_action(rng);
        assert!(stamped.stamp.verify(rng, &actions).is_err(), "replaced");
    }
}

#[test]
fn innocent_aggregate_from_two_autonomes() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);

    let spend_a = wallet.random_note(rng, 1000);
    let output_a = wallet.random_note(rng, 700);
    let spend_b = wallet.random_note(rng, 500);
    let output_b = wallet.random_note(rng, 200);

    // Mine both spend cms into the same block so both autonomes share anchor.
    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(
        rng,
        &[vec![spend_a.commitment()], vec![spend_b.commitment()]],
        50,
    ));
    let height = pool.height();
    let anchor = pool.anchor_at(height);

    let tuple_a = wallet.fresh_spend(rng, &pool, height, spend_a);
    let tuple_b = wallet.fresh_spend(rng, &pool, height, spend_b);
    let autonome_a = wallet.autonome(rng, anchor, alloc::vec![tuple_a], alloc::vec![output_a]);
    let autonome_b = wallet.autonome(rng, anchor, alloc::vec![tuple_b], alloc::vec![output_b]);

    let digests_a = action_digests(&autonome_a.actions);
    let digests_b = action_digests(&autonome_b.actions);
    let (adjunct_a, stamp_a) = autonome_a.strip();
    let (adjunct_b, stamp_b) = autonome_b.strip();

    let innocent: Stamped = {
        let innocent_plan = Plan::new(alloc::vec![], alloc::vec![]);
        let innocent_sighash = mock_sighash(innocent_plan.commitment());

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
    let wallet = WalletSim::random(rng);

    let based_spend = wallet.random_note(rng, 800);
    let based_output = wallet.random_note(rng, 400);
    let a_spend = wallet.random_note(rng, 1000);
    let a_output = wallet.random_note(rng, 700);
    let b_spend = wallet.random_note(rng, 500);
    let b_output = wallet.random_note(rng, 200);

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
    let height = pool.height();
    let anchor = pool.anchor_at(height);

    let based_tuple = wallet.fresh_spend(rng, &pool, height, based_spend);
    let a_tuple = wallet.fresh_spend(rng, &pool, height, a_spend);
    let b_tuple = wallet.fresh_spend(rng, &pool, height, b_spend);
    let mut becomes_based = wallet.autonome(
        rng,
        anchor,
        alloc::vec![based_tuple],
        alloc::vec![based_output],
    );
    let autonome_a = wallet.autonome(rng, anchor, alloc::vec![a_tuple], alloc::vec![a_output]);
    let autonome_b = wallet.autonome(rng, anchor, alloc::vec![b_tuple], alloc::vec![b_output]);

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
    let wallet = WalletSim::random(rng);
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment().unwrap());

    let mut sig_bytes: [u8; 64] = bundle.actions[0].sig.into();
    sig_bytes[0] ^= 0xFF;
    bundle.actions[0].sig = action::Signature::from(sig_bytes);

    assert!(bundle.verify_signatures(&sighash).is_err());
}

#[test]
fn stamped_read_write_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let original = build_autonome(rng, &wallet, 1000, 700);
    let mut buf = Vec::new();
    original.write(&mut buf).expect("write");
    let deserialized = Stamped::read(&*buf).expect("read");

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
    // Adjunct shape: wtxid preserved.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::random(rng);
        let (mut stripped, _stamp) = build_autonome(rng, &wallet, 1000, 700).strip();
        stripped.stamp.wtxid = [0x42u8; 64];

        let mut buf = Vec::new();
        stripped.write(&mut buf).expect("write");
        let deserialized = Stripped::read(&*buf).expect("read");

        assert_eq!(stripped, deserialized);
        assert_eq!(deserialized.stamp.wtxid, [0x42u8; 64]);
    }

    // Innocent shape: empty actions, zero wtxid.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let plan = Plan::new(alloc::vec![], alloc::vec![]);
        let sighash = mock_sighash(plan.commitment());

        let stripped: Stripped = Bundle {
            actions: alloc::vec![],
            value_balance: 0,
            binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
            stamp: Adjunct::default(),
        };

        let mut buf = Vec::new();
        stripped.write(&mut buf).expect("write");
        let deserialized = Stripped::read(&*buf).expect("read");

        assert_eq!(stripped, deserialized);
        assert_eq!(deserialized.stamp.wtxid, [0; 64]);
    }
}

#[test]
fn tachyon_bundle_in_memory_round_trip() {
    // Stamped: actions, value_balance, tachygrams, anchor.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::random(rng);
        let original = build_autonome(rng, &wallet, 1000, 700);
        let erased: TachyonBundle = original.clone().into();
        let back = Stamped::try_from(erased).expect("stamped variant");

        assert_eq!(original.actions, back.actions);
        assert_eq!(original.value_balance, back.value_balance);
        assert_eq!(original.stamp.tachygrams, back.stamp.tachygrams);
        assert_eq!(original.stamp.anchor, back.stamp.anchor);
    }

    // Stripped: wtxid preserved.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::random(rng);
        let (mut stripped, _stamp) = build_autonome(rng, &wallet, 1000, 700).strip();
        stripped.stamp.wtxid = [0xABu8; 64];

        let erased: TachyonBundle = stripped.clone().into();
        let back = Stripped::try_from(erased).expect("stripped variant");

        assert_eq!(stripped, back);
        assert_eq!(back.stamp.wtxid, [0xABu8; 64]);
    }
}

#[test]
fn bundle_wire_round_trip_via_tachyon_bundle() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let (mut stripped, _stamp) = build_autonome(rng, &wallet, 1000, 700).strip();
    stripped.stamp.wtxid = [0xCDu8; 64];

    let erased: TachyonBundle = stripped.clone().into();
    let mut buf = Vec::new();
    erased.write(&mut buf).expect("write");
    let decoded = TachyonBundle::read(&*buf)
        .expect("read")
        .expect("some bundle");
    let back = Stripped::try_from(decoded).expect("stripped variant");

    assert_eq!(stripped, back);
}

#[test]
fn wire_rejects_invalid_state_byte() {
    let buf: &[u8] = &[0x03];
    Stamped::read(buf).expect_err("invalid state byte must be rejected");
    Stripped::read(buf).expect_err("invalid state byte must be rejected");
    TachyonBundle::read(buf).expect_err("invalid state byte must be rejected");
}

#[test]
fn auth_digest_invariants() {
    // Stamped vs stripped: distinct auth_digests — the property that makes
    // wtxid discriminate across aggregation forms.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::random(rng);
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let stamped_digest = stamped.auth_digest();

        let (mut stripped, _stamp) = stamped.strip();
        stripped.stamp.wtxid = [0x11u8; 64];
        assert_ne!(stamped_digest, stripped.auth_digest());
    }

    // wtxid binds: distinct wtxids on otherwise-identical stripped bundles
    // produce distinct digests.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::random(rng);
        let (mut stripped, _stamp) = build_autonome(rng, &wallet, 1000, 700).strip();

        stripped.stamp.wtxid = [0xAAu8; 64];
        let digest_aa = stripped.auth_digest();
        stripped.stamp.wtxid = [0xBBu8; 64];
        let digest_bb = stripped.auth_digest();
        assert_ne!(digest_aa, digest_bb);
    }

    // TachyonBundle dispatch matches the concrete-variant methods, for both
    // stamped and stripped.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::random(rng);
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let stamped_direct = stamped.auth_digest();
        let erased: TachyonBundle = stamped.into();
        assert_eq!(erased.auth_digest(), stamped_direct);

        let wallet2 = WalletSim::random(rng);
        let (mut stripped, _stamp) = build_autonome(rng, &wallet2, 1000, 700).strip();
        stripped.stamp.wtxid = [0x33u8; 64];
        let stripped_direct = stripped.auth_digest();
        let erased_stripped: TachyonBundle = stripped.into();
        assert_eq!(erased_stripped.auth_digest(), stripped_direct);
    }
}
