use ff::Field as _;
use mock_ragu::Polynomial;
use pasta_curves::Fp;
use rand::{CryptoRng, RngCore, SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    action,
    entropy::ActionEntropy,
    keys::private,
    primitives::{BlockHeight, PoolCommit},
    stamp::Stamp,
    test_support::{
        PoolSim, WalletSim, action_digests, build_output_action, mock_sighash, random_block_with,
    },
    value,
};

fn make_output_stamp(
    rng: &mut (impl RngCore + CryptoRng),
    wallet: &WalletSim,
    value_amount: u64,
) -> (Stamp, Action, action::Plan<effect::Output>) {
    let note = wallet.random_note(rng, value_amount);
    let rcv = value::CommitmentTrapdoor::random(&mut *rng);
    let theta = ActionEntropy::random(&mut *rng);
    let plan = action::Plan::output(note, theta, rcv);
    let alpha = theta.randomizer::<effect::Output>(&note.commitment());

    let stamp = Stamp::prove_output(
        &mut *rng,
        rcv,
        alpha,
        note,
        Anchor(
            BlockHeight(0),
            PoolCommit(Polynomial::default().commit(Fp::ZERO)),
        ),
    )
    .expect("prove_output");
    let action = Action {
        cv: plan.cv(),
        rk: plan.rk,
        sig: action::Signature::from([0u8; 64]),
    };
    (stamp, action, plan)
}

/// Convenience wrapper: fresh wallet + pool, mine the spend note's cm,
/// then prove a non-balancing autonome (`value_balance = spend_value -
/// output_value`).
fn build_autonome(
    rng: &mut (impl RngCore + CryptoRng),
    spend_value: u64,
    output_value: u64,
) -> Stamped {
    let wallet = WalletSim::new(private::SpendingKey::from([0x42u8; 32]));
    let spend_note = wallet.random_note(rng, spend_value);
    let output_note = wallet.random_note(rng, output_value);
    let mut pool = PoolSim::new();
    pool.mine(random_block_with(rng, spend_note.commitment(), 50));
    let anchor = pool.anchor();
    let spend = wallet.fresh_spend(rng, anchor, pool.state().clone(), spend_note);
    wallet.autonome(rng, anchor, alloc::vec![spend], alloc::vec![output_note])
}

#[test]
fn wrong_value_balance_fails_verification() {
    let mut rng = StdRng::seed_from_u64(0);
    let mut bundle = build_autonome(&mut rng, 1000, 700);
    let sighash = mock_sighash(bundle.commitment().unwrap());

    bundle.value_balance = 999;
    assert!(bundle.verify_signatures(&sighash).is_err());
}

/// Stripping preserves the binding signature and action signatures.
#[test]
fn stripped_bundle_retains_signatures() {
    let mut rng = StdRng::seed_from_u64(0);
    let bundle = build_autonome(&mut rng, 1000, 700);
    let sighash = mock_sighash(bundle.commitment().unwrap());

    let (stripped, _stamp) = bundle.strip();
    stripped.verify_signatures(&sighash).unwrap();
}

/// The plan commitment and the built bundle commitment must agree.
/// Signatures don't feed the commitment, so the zero-sig action from
/// `make_output_stamp` is sufficient.
#[test]
fn plan_commitment_matches_bundle_commitment() {
    let mut rng = StdRng::seed_from_u64(42);
    let wallet = WalletSim::new(private::SpendingKey::from([0x42u8; 32]));
    let (stamp, output_action, output_plan) = make_output_stamp(&mut rng, &wallet, 200);

    let bundle_plan = Plan::new(alloc::vec![], alloc::vec![output_plan]);
    let sighash = mock_sighash(bundle_plan.commitment());

    let bundle: Stamped = Bundle {
        actions: alloc::vec![output_action],
        value_balance: bundle_plan.value_balance(),
        binding_sig: bundle_plan.derive_bsk_private().sign(&mut rng, &sighash),
        stamp,
    };

    assert_eq!(bundle_plan.commitment(), bundle.commitment().unwrap());
}

/// The "no bundle" commitment must differ from an empty bundle's
/// commitment (identity accumulator + zero balance).
#[test]
fn no_bundle_commitment_differs_from_empty_bundle() {
    let empty_plan = Plan::new(alloc::vec![], alloc::vec![]);
    assert_ne!(
        *COMMIT_NO_BUNDLE,
        empty_plan.commitment(),
        "absent bundle must differ from empty bundle"
    );
}

/// A zero-action bundle with zero balance must verify correctly.
///
/// This exercises the edge case where `BindingVerificationKey::derive`
/// receives an empty action slice and value_balance = 0, producing the
/// identity point as `bvk`.
#[test]
fn zero_action_bundle_is_valid() {
    let mut rng = StdRng::seed_from_u64(0xdead);
    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment());

    let bundle: Stripped = Bundle {
        actions: alloc::vec![],
        value_balance: 0,
        binding_sig: plan.derive_bsk_private().sign(&mut rng, &sighash),
        stamp: Adjunct::default(),
    };

    bundle.verify_signatures(&sighash).unwrap();
}

/// Payment bundle: sender spends an input note, recipient receives an
/// output at the payment value, sender gets the change. Covers the
/// 1-spend-plus-multiple-outputs shape (distinct from the single-output
/// `build_autonome` flow) and exercises a deeper merge tree (3 stamps →
/// 2 merges) at the bundle layer.
#[test]
fn payment_bundle_verifies() {
    let mut rng = StdRng::seed_from_u64(0x9AB6);
    let sender = WalletSim::new(private::SpendingKey::random(&mut rng));
    let recipient = WalletSim::new(private::SpendingKey::random(&mut rng));
    let input_note = sender.random_note(&mut rng, 500);
    let output_note = recipient.random_note(&mut rng, 200);
    let change_note = sender.random_note(&mut rng, 300);

    let mut pool = PoolSim::new();
    pool.mine(random_block_with(&mut rng, input_note.commitment(), 50));
    let anchor = pool.anchor();
    let spend = sender.fresh_spend(&mut rng, anchor, pool.state().clone(), input_note);
    let stamped = sender.autonome(
        &mut rng,
        anchor,
        alloc::vec![spend],
        alloc::vec![output_note, change_note],
    );
    let sighash = mock_sighash(stamped.commitment().unwrap());
    stamped
        .verify_signatures(&sighash)
        .expect("payment bundle must verify");
}

/// `stamp.verify` binds the *action multiset*: order-agnostic, but every
/// other deviation (missing, extra, duplicated, substituted) rejects.
/// Exercises the cv-sign / ActionDigest binding inside the stamp proof —
/// if an attacker tampers with any action's (cv, rk), the reconstructed
/// multiset no longer matches what the circuit committed to.
#[test]
fn stamp_binds_action_multiset() {
    let mut rng = StdRng::seed_from_u64(0x1157);
    let stamped = build_autonome(&mut rng, 1000, 700);
    let action_a = stamped.actions[0];
    let action_b = stamped.actions[1];

    // Unrelated third action (different wallet, new output) for
    // "extra" and "substituted" cases.
    let other_wallet = WalletSim::new(private::SpendingKey::from([0x17u8; 32]));
    let unrelated_note = other_wallet.random_note(&mut rng, 400);
    let (_, _, action_c) = build_output_action(&mut rng, unrelated_note);

    // Permutation must verify — multiset is order-invariant.
    stamped
        .stamp
        .verify(&[action_b, action_a], &mut rng)
        .expect("permuted actions must verify");

    // Every other deviation must reject.
    assert!(
        stamped.stamp.verify(&[action_a], &mut rng).is_err(),
        "missing action must reject"
    );
    assert!(
        stamped
            .stamp
            .verify(&[action_a, action_b, action_c], &mut rng)
            .is_err(),
        "extra action must reject"
    );
    assert!(
        stamped
            .stamp
            .verify(&[action_a, action_a], &mut rng)
            .is_err(),
        "duplicated action must reject"
    );
    assert!(
        stamped
            .stamp
            .verify(&[action_a, action_c], &mut rng)
            .is_err(),
        "substituted action must reject"
    );
}

/// Zero `value_balance` is common (fully-shielded transaction) and must
/// continue to verify. Individual-note nonzero doesn't imply bundle-level
/// nonzero: this test spends V, outputs V, leaves zero transparent flow.
#[test]
fn bundle_with_zero_value_balance_verifies() {
    let mut rng = StdRng::seed_from_u64(0xBA1A);
    let stamped = build_autonome(&mut rng, 500, 500);
    assert_eq!(
        stamped.value_balance, 0,
        "spend value equals output value -> balance is zero"
    );
    let sighash = mock_sighash(stamped.commitment().unwrap());
    stamped
        .verify_signatures(&sighash)
        .expect("zero-balance bundle must verify");
}

#[test]
fn innocent_aggregate_from_two_autonomes() {
    let mut rng = StdRng::seed_from_u64(0xCAFE);
    let wallet = WalletSim::new(private::SpendingKey::from([0x42u8; 32]));

    let spend_a = wallet.random_note(&mut rng, 1000);
    let output_a = wallet.random_note(&mut rng, 700);
    let spend_b = wallet.random_note(&mut rng, 500);
    let output_b = wallet.random_note(&mut rng, 200);

    // Mine both spend cms into the same pool so both autonomes share anchor.
    let mut pool = PoolSim::new();
    pool.mine(random_block_with(&mut rng, spend_a.commitment(), 50));
    pool.mine(random_block_with(&mut rng, spend_b.commitment(), 50));
    let anchor = pool.anchor();
    let pool_state = pool.state().clone();

    let tuple_a = wallet.fresh_spend(&mut rng, anchor, pool_state.clone(), spend_a);
    let tuple_b = wallet.fresh_spend(&mut rng, anchor, pool_state, spend_b);
    let autonome_a = wallet.autonome(
        &mut rng,
        anchor,
        alloc::vec![tuple_a],
        alloc::vec![output_a],
    );
    let autonome_b = wallet.autonome(
        &mut rng,
        anchor,
        alloc::vec![tuple_b],
        alloc::vec![output_b],
    );

    let digests_a = action_digests(&autonome_a.actions);
    let digests_b = action_digests(&autonome_b.actions);
    let (adjunct_a, stamp_a) = autonome_a.strip();
    let (adjunct_b, stamp_b) = autonome_b.strip();

    let innocent: Stamped = {
        let innocent_plan = Plan::new(alloc::vec![], alloc::vec![]);
        let innocent_sighash = mock_sighash(innocent_plan.commitment());

        let stamp = Stamp::prove_merge(&mut rng, (stamp_a, &digests_a), (stamp_b, &digests_b))
            .expect("prove_merge");

        Bundle {
            actions: alloc::vec![],
            value_balance: 0,
            binding_sig: innocent_plan
                .derive_bsk_private()
                .sign(&mut rng, &innocent_sighash),
            stamp,
        }
    };

    innocent
        .verify_signatures(&mock_sighash(innocent.commitment().unwrap()))
        .expect("innocent binding sig should verify");

    let adjunct_actions: Vec<Action> = [adjunct_a.actions, adjunct_b.actions].concat();
    innocent
        .stamp
        .verify(&adjunct_actions, &mut rng)
        .expect("innocent stamp should verify against adjunct actions");
}

#[test]
fn based_aggregate_with_two_adjuncts() {
    let mut rng = StdRng::seed_from_u64(0xBEEF);
    let wallet = WalletSim::new(private::SpendingKey::from([0x42u8; 32]));

    let based_spend = wallet.random_note(&mut rng, 800);
    let based_output = wallet.random_note(&mut rng, 400);
    let a_spend = wallet.random_note(&mut rng, 1000);
    let a_output = wallet.random_note(&mut rng, 700);
    let b_spend = wallet.random_note(&mut rng, 500);
    let b_output = wallet.random_note(&mut rng, 200);

    let mut pool = PoolSim::new();
    pool.mine(random_block_with(&mut rng, based_spend.commitment(), 50));
    pool.mine(random_block_with(&mut rng, a_spend.commitment(), 50));
    pool.mine(random_block_with(&mut rng, b_spend.commitment(), 50));
    let anchor = pool.anchor();
    let pool_state = pool.state().clone();

    let based_tuple = wallet.fresh_spend(&mut rng, anchor, pool_state.clone(), based_spend);
    let a_tuple = wallet.fresh_spend(&mut rng, anchor, pool_state.clone(), a_spend);
    let b_tuple = wallet.fresh_spend(&mut rng, anchor, pool_state, b_spend);
    let mut becomes_based = wallet.autonome(
        &mut rng,
        anchor,
        alloc::vec![based_tuple],
        alloc::vec![based_output],
    );
    let autonome_a = wallet.autonome(
        &mut rng,
        anchor,
        alloc::vec![a_tuple],
        alloc::vec![a_output],
    );
    let autonome_b = wallet.autonome(
        &mut rng,
        anchor,
        alloc::vec![b_tuple],
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
    let innocent_stamp = Stamp::prove_merge(&mut rng, (stamp_a, &digests_a), (stamp_b, &digests_b))
        .expect("innocent merge");

    let based_stamp = Stamp::prove_merge(
        &mut rng,
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
        .verify(&all_actions, &mut rng)
        .expect("based aggregate stamp should verify against all actions");
}

#[test]
fn invalid_action_sig_fails_verification() {
    let mut rng = StdRng::seed_from_u64(11);
    let mut bundle = build_autonome(&mut rng, 1000, 700);
    let sighash = mock_sighash(bundle.commitment().unwrap());

    let mut sig_bytes: [u8; 64] = bundle.actions[0].sig.into();
    sig_bytes[0] ^= 0xFF;
    bundle.actions[0].sig = action::Signature::from(sig_bytes);

    assert!(bundle.verify_signatures(&sighash).is_err());
}

/// Plan::sign produces a verifiable bundle.
#[test]
fn plan_sign_and_verify() {
    let mut rng = StdRng::seed_from_u64(700);
    let wallet = WalletSim::new(private::SpendingKey::from([0x42u8; 32]));
    let ask = wallet.sk.derive_auth_private();

    let (stamp, _action, plan) = make_output_stamp(&mut rng, &wallet, 200);
    let bundle_plan = Plan::new(alloc::vec![], alloc::vec![plan]);
    let sighash = mock_sighash(bundle_plan.commitment());

    let stamped = bundle_plan
        .sign(&sighash, &ask, &mut rng)
        .expect("sign should succeed")
        .stamp(stamp);

    stamped
        .verify_signatures(&sighash)
        .expect("signed bundle should verify");
}

/// Stamped::write → Stamped::read preserves all fields and the
/// deserialized bundle remains verifiable.
#[test]
fn stamped_read_write_round_trip() {
    let mut rng = StdRng::seed_from_u64(800);
    let original = build_autonome(&mut rng, 1000, 700);
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

/// Stripped adjunct round-trips preserving its assigned wtxid.
#[test]
fn stripped_adjunct_read_write_round_trip() {
    let mut rng = StdRng::seed_from_u64(801);
    let (mut stripped, _stamp) = build_autonome(&mut rng, 1000, 700).strip();
    stripped.stamp.wtxid = [0x42u8; 64];

    let mut buf = Vec::new();
    stripped.write(&mut buf).expect("write");
    let deserialized = Stripped::read(&*buf).expect("read");

    assert_eq!(stripped, deserialized);
    assert_eq!(deserialized.stamp.wtxid, [0x42u8; 64]);
}

/// Stripped innocent (empty actions) round-trips with a zero wtxid.
#[test]
fn stripped_innocent_read_write_round_trip() {
    let mut rng = StdRng::seed_from_u64(802);
    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment());

    let stripped: Stripped = Bundle {
        actions: alloc::vec![],
        value_balance: 0,
        binding_sig: plan.derive_bsk_private().sign(&mut rng, &sighash),
        stamp: Adjunct::default(),
    };

    let mut buf = Vec::new();
    stripped.write(&mut buf).expect("write");
    let deserialized = Stripped::read(&*buf).expect("read");

    assert_eq!(stripped, deserialized);
    assert_eq!(deserialized.stamp.wtxid, [0; 64]);
}

/// TachyonBundle round-trips a stamped bundle through the erased form
/// without losing any fields.
#[test]
fn tachyon_bundle_round_trip_stamped() {
    let mut rng = StdRng::seed_from_u64(810);
    let original = build_autonome(&mut rng, 1000, 700);
    let erased: TachyonBundle = original.clone().into();
    let back = Stamped::try_from(erased).expect("stamped variant");

    assert_eq!(original.actions, back.actions);
    assert_eq!(original.value_balance, back.value_balance);
    assert_eq!(original.stamp.tachygrams, back.stamp.tachygrams);
    assert_eq!(original.stamp.anchor, back.stamp.anchor);
}

/// TachyonBundle round-trips a stripped bundle's wtxid losslessly.
#[test]
fn tachyon_bundle_round_trip_stripped() {
    let mut rng = StdRng::seed_from_u64(811);
    let (mut stripped, _stamp) = build_autonome(&mut rng, 1000, 700).strip();
    stripped.stamp.wtxid = [0xABu8; 64];

    let erased: TachyonBundle = stripped.clone().into();
    let back = Stripped::try_from(erased).expect("stripped variant");

    assert_eq!(stripped, back);
    assert_eq!(back.stamp.wtxid, [0xABu8; 64]);
}

/// TachyonBundle::write → TachyonBundle::read round-trips the
/// variant and the wtxid (for stripped).
#[test]
fn bundle_wire_round_trip_via_tachyon_bundle() {
    let mut rng = StdRng::seed_from_u64(812);
    let (mut stripped, _stamp) = build_autonome(&mut rng, 1000, 700).strip();
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

/// Wire bytes with an invalid state byte are rejected.
#[test]
fn wire_rejects_invalid_state_byte() {
    let buf: &[u8] = &[0x03];
    Stamped::read(buf).expect_err("invalid state byte must be rejected");
    Stripped::read(buf).expect_err("invalid state byte must be rejected");
    TachyonBundle::read(buf).expect_err("invalid state byte must be rejected");
}

/// empty_commitment() matches the canonical COMMIT_NO_BUNDLE static.
#[test]
fn empty_commitment_matches_static() {
    assert_eq!(empty_commitment(), *COMMIT_NO_BUNDLE);
}

/// empty_auth_digest() matches the canonical AUTH_DIGEST_NO_BUNDLE static.
#[test]
fn empty_auth_digest_matches_static() {
    assert_eq!(empty_auth_digest(), *AUTH_DIGEST_NO_BUNDLE);
}

/// A stamped bundle and its stripped sibling produce distinct
/// auth_digests — the defining property that makes wtxid discriminate
/// across aggregation forms.
#[test]
fn stamped_and_stripped_auth_digests_differ() {
    let mut rng = StdRng::seed_from_u64(820);
    let stamped = build_autonome(&mut rng, 1000, 700);
    let stamped_digest = stamped.auth_digest();

    let (mut stripped, _stamp) = stamped.strip();
    stripped.stamp.wtxid = [0x11u8; 64];
    let stripped_digest = stripped.auth_digest();

    assert_ne!(stamped_digest, stripped_digest);
}

/// Different covering-aggregate wtxids on an otherwise-identical stripped
/// bundle produce distinct auth_digests — confirms the ref enters the
/// hash.
#[test]
fn stripped_auth_digest_binds_wtxid() {
    let mut rng = StdRng::seed_from_u64(821);
    let (mut stripped, _stamp) = build_autonome(&mut rng, 1000, 700).strip();

    stripped.stamp.wtxid = [0xAAu8; 64];
    let a_digest = stripped.auth_digest();

    stripped.stamp.wtxid = [0xBBu8; 64];
    let b_digest = stripped.auth_digest();

    assert_ne!(a_digest, b_digest);
}

/// TachyonBundle's dispatching auth_digest matches the concrete-variant
/// methods.
#[test]
fn tachyon_bundle_auth_digest_matches_variants() {
    let mut rng = StdRng::seed_from_u64(822);
    let stamped = build_autonome(&mut rng, 1000, 700);
    let stamped_direct = stamped.auth_digest();
    let erased: TachyonBundle = stamped.into();
    assert_eq!(erased.auth_digest(), stamped_direct);

    let mut rng2 = StdRng::seed_from_u64(823);
    let (mut stripped, _stamp) = build_autonome(&mut rng2, 1000, 700).strip();
    stripped.stamp.wtxid = [0x33u8; 64];
    let stripped_direct = stripped.auth_digest();
    let erased_stripped: TachyonBundle = stripped.into();
    assert_eq!(erased_stripped.auth_digest(), stripped_direct);
}
