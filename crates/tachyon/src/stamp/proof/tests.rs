//! Proof-step tests: `StampLift`, `SpendBind`, and the Spendable*
//! steps. Grouped in one module so all step-level behavior lives together
//! next to the step definitions.

extern crate alloc;

use ff::Field as _;
use mock_ragu::{Polynomial, Proof};
use pasta_curves::Fp;
use rand::{SeedableRng as _, rngs::StdRng};

use super::{PROOF_SYSTEM, compute_action_acc, delegation, spend, spendable, stamp as stamp_proof};
use crate::{
    constants::EPOCH_SIZE,
    entropy::ActionEntropy,
    keys::private,
    note,
    primitives::{
        ActionCommit, Anchor, BlockAcc, BlockHeight, DelegationTrapdoor, EpochIndex, PoolCommit,
        PoolDelta, PoolSet, Tachygram, TachygramAcc, TachygramCommit, effect,
    },
    stamp::Stamp,
    test_support::{
        PoolSim, SyncSim, WalletSim, build_output_action,
        ggm_tools::{delegate_range, nullifier_from_master, nullifier_pair_from_master},
        random_block, random_block_with,
    },
    value,
};

// ── StampLift ──────────────────────────────────────────────────────────────

/// StampLift: advances stamp anchor across same-epoch blocks that carry
/// tachygrams. The delta is the real product of those intervening blocks.
#[test]
fn stamp_lift_within_epoch() {
    let mut rng = StdRng::seed_from_u64(400);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();

    pool.advance(1, |_| random_block(&mut rng, 50));
    let anchor_5 = pool.anchor();
    let left_pool_acc = pool.state_at(anchor_5.0);

    let note = user.random_note(&mut rng, 200);
    let (rcv, alpha, action) = build_output_action(&mut rng, note);
    let stamp = Stamp::prove_output(&mut rng, rcv, alpha, note, anchor_5).expect("prove_output");

    let action_acc = compute_action_acc(&[action]).unwrap();
    let tachygram_acc = TachygramAcc::from(&*stamp.tachygrams);
    let action_commit = ActionCommit(action_acc.0.commit(Fp::ZERO));
    let tachygram_commit = TachygramCommit(tachygram_acc.0.commit(Fp::ZERO));

    pool.advance(2, |_| random_block(&mut rng, 50));
    let anchor_10 = pool.anchor();
    let delta = pool.delta(anchor_5.0, anchor_10.0);

    let stamp_hdr = (action_commit, tachygram_commit, anchor_5);
    let stamp_pcd = stamp.proof.carry(stamp_hdr);

    let (lifted_proof, ()) = PROOF_SYSTEM
        .fuse(
            &mut rng,
            &stamp_proof::StampLift,
            (
                action_acc.into(),
                tachygram_acc.into(),
                left_pool_acc.into(),
                delta.into(),
                anchor_10,
            ),
            stamp_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("stamp lift");

    let lifted_hdr = (action_commit, tachygram_commit, anchor_10);
    let lifted_pcd = lifted_proof.carry::<stamp_proof::StampHeader>(lifted_hdr);
    PROOF_SYSTEM
        .rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted stamp");
}

/// StampLift rejects target in a different epoch.
#[test]
fn stamp_lift_rejects_cross_epoch() {
    let mut rng = StdRng::seed_from_u64(604);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();

    pool.advance(1, |_| random_block(&mut rng, 50));
    let anchor_5 = pool.anchor();

    let note = user.random_note(&mut rng, 200);
    let (rcv, alpha, action) = build_output_action(&mut rng, note);
    let stamp = Stamp::prove_output(&mut rng, rcv, alpha, note, anchor_5).expect("prove_output");

    let action_acc = compute_action_acc(&[action]).unwrap();
    let tachygram_acc = TachygramAcc::from(&*stamp.tachygrams);

    let remaining = usize::try_from(EPOCH_SIZE - u32::from(pool.anchor().0)).expect("fits usize");
    pool.advance(remaining, |_| random_block(&mut rng, 10));
    assert_eq!(pool.anchor().0.epoch().0, 1);

    let delta = PoolDelta(Polynomial::from_roots(&[]));
    let action_commit = ActionCommit(action_acc.0.commit(Fp::ZERO));
    let tachygram_commit = TachygramCommit(tachygram_acc.0.commit(Fp::ZERO));
    let stamp_hdr = (action_commit, tachygram_commit, anchor_5);
    let stamp_pcd = stamp.proof.carry(stamp_hdr);
    let to_anchor = pool.anchor();

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &stamp_proof::StampLift,
        (
            action_acc.into(),
            tachygram_acc.into(),
            PoolSet::<Polynomial>(Polynomial::default()).into(),
            delta.into(),
            to_anchor,
        ),
        stamp_pcd,
        Proof::trivial().carry::<()>(()),
    );
    assert!(
        result.is_err(),
        "stamp lift across epoch boundary must fail"
    );
}

// ── SpendBind non-adjacent epochs ─────────────────────────────────────────

/// `SpendBind` must reject two delegation-derived nullifier PCDs whose epochs
/// are not adjacent (`right_epoch != left_epoch + 1`).
#[test]
fn spend_bind_rejects_non_adjacent_epochs() {
    let mut rng = StdRng::seed_from_u64(200);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);

    let epoch_e = EpochIndex(0);
    let epoch_far = EpochIndex(5);
    let delegation_id = user.pak.nk.derive_delegation_id(&note, trap);
    // Wallet delegates range covering both epochs.
    let master = user.delegate_master(&mut rng, note, trap);
    let sync = SyncSim::new(delegate_range(&mut rng, &master, epoch_e.0..=epoch_far.0));

    let nf_pcd_e = sync.nullifier(&mut rng, delegation_id, epoch_e);
    let nf_pcd_far = sync.nullifier(&mut rng, delegation_id, epoch_far);

    let rcv = value::CommitmentTrapdoor::random(&mut rng);
    let theta = ActionEntropy::random(&mut rng);
    let alpha = theta.randomizer::<effect::Spend>(&note.commitment());

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spend::SpendBind,
        (rcv, alpha, user.pak, note, trap),
        nf_pcd_e,
        nf_pcd_far,
    );
    assert!(result.is_err(), "SpendBind must reject non-adjacent epochs");
}

// ── Zero-value witness rejection ──────────────────────────────────────────

/// Every step that witnesses a `Note` must independently constrain `value ==
/// 0`. The `Value` newtype's `From<u64>` panics on zero, but the tuple field is
/// `pub(crate)` so a test can bypass the API check; the circuit check is the
/// actual soundness guarantee and must fire on the zero witness.
#[test]
fn step_rejects_zero_value_note() {
    let mut rng = StdRng::seed_from_u64(800);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let trap = DelegationTrapdoor::random(&mut rng);
    let target_epoch = EpochIndex(0);

    let zero_note = note::Note {
        pk: user.pak.derive_payment_key(),
        value: note::Value(0),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };

    // DelegationSeed: no PCD inputs needed.
    assert!(
        PROOF_SYSTEM
            .seed(
                &mut rng,
                &delegation::DelegationSeed,
                (zero_note, user.pak, trap),
            )
            .is_err(),
        "DelegationSeed must reject zero-value note"
    );

    // OutputStamp: no PCD inputs needed.
    let out_rcv = value::CommitmentTrapdoor::random(&mut rng);
    let out_theta = ActionEntropy::random(&mut rng);
    let out_alpha = out_theta.randomizer::<effect::Output>(&zero_note.commitment());
    let out_anchor = PoolSim::new().anchor();
    assert!(
        PROOF_SYSTEM
            .seed(
                &mut rng,
                &stamp_proof::OutputStamp,
                (out_rcv, out_alpha, zero_note, out_anchor),
            )
            .is_err(),
        "OutputStamp must reject zero-value note"
    );

    // SpendBind: left/right nf PCDs built from a *valid* note; witness uses zero
    // note.
    let valid_note = user.random_note(&mut rng, 500);
    let valid_master = user.delegate_master(&mut rng, valid_note, trap);
    let (nf_now_pcd, nf_next_pcd) =
        nullifier_pair_from_master(&mut rng, valid_master, target_epoch);
    let spend_rcv = value::CommitmentTrapdoor::random(&mut rng);
    let spend_theta = ActionEntropy::random(&mut rng);
    let spend_alpha = spend_theta.randomizer::<effect::Spend>(&zero_note.commitment());
    assert!(
        PROOF_SYSTEM
            .fuse(
                &mut rng,
                &spend::SpendBind,
                (spend_rcv, spend_alpha, user.pak, zero_note, trap),
                nf_now_pcd,
                nf_next_pcd,
            )
            .is_err(),
        "SpendBind must reject zero-value note"
    );

    // SpendableInit: pool must contain cm; witness uses zero-value note.
    let mut pool = PoolSim::new();
    pool.mine(random_block_with(&mut rng, zero_note.commitment(), 50));
    let init_anchor = pool.anchor();
    let delegation_id = user.pak.nk.derive_delegation_id(&zero_note, trap);
    let nf = zero_note.nullifier(&user.pak.nk, target_epoch);
    let nf_pcd =
        Proof::trivial().carry::<delegation::NullifierHeader>((nf, target_epoch, delegation_id));
    assert!(
        PROOF_SYSTEM
            .fuse(
                &mut rng,
                &spendable::SpendableInit,
                (
                    zero_note,
                    user.pak,
                    trap,
                    pool.state().clone().into(),
                    init_anchor,
                ),
                nf_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .is_err(),
        "SpendableInit must reject zero-value note"
    );
}

// ── SpendBind ─────────────────────────────────────────────────────────────

/// `SpendBind` must reject when the witness's `(note, trap)` recomputes a
/// `delegation_id` that differs from the one carried on the nullifier PCDs.
/// Same note, different trapdoor — isolates the delegation_id equality check
/// from the note/pak binding.
#[test]
fn spend_bind_rejects_delegation_id_mismatch() {
    let mut rng = StdRng::seed_from_u64(705);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let note = user.random_note(&mut rng, 500);
    let trap_nf = DelegationTrapdoor::random(&mut rng);
    let trap_bind = DelegationTrapdoor::random(&mut rng);
    let target_epoch = EpochIndex(0);

    let nf_master = user.delegate_master(&mut rng, note, trap_nf);
    let (nf_now_pcd, nf_next_pcd) = nullifier_pair_from_master(&mut rng, nf_master, target_epoch);
    let rcv = value::CommitmentTrapdoor::random(&mut rng);
    let theta = ActionEntropy::random(&mut rng);
    let alpha = theta.randomizer::<effect::Spend>(&note.commitment());

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spend::SpendBind,
        (rcv, alpha, user.pak, note, trap_bind),
        nf_now_pcd,
        nf_next_pcd,
    );
    assert!(
        result.is_err(),
        "SpendBind must reject when recomputed delegation_id doesn't match nf header"
    );
}

// ── Spendable{Init, Lift, Rollover, EpochLift} ────────────────────────────

/// SpendableEpochLift: sync's cross-epoch `lift_spendable` internally chains
/// `SpendableLift` → `SpendableRollover` → `SpendableEpochLift`, so a
/// successful cross-epoch lift binds all three steps.
#[test]
fn spendable_epoch_lift_across_boundary() {
    let mut rng = StdRng::seed_from_u64(300);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    let delegation_id = user.pak.nk.derive_delegation_id(&note, trap);

    let epoch_0 = EpochIndex(0);
    let master = user.delegate_master(&mut rng, note, trap);
    let mut sync = SyncSim::new(delegate_range(&mut rng, &master, epoch_0.0..=epoch_0.0 + 1));

    pool.mine(random_block_with(&mut rng, note.commitment(), 50));
    let nf_pcd = sync.nullifier(&mut rng, delegation_id, epoch_0);
    let spendable_pcd = user.spendable_init(
        &mut rng,
        note,
        trap,
        pool.anchor(),
        pool.state().clone(),
        nf_pcd,
    );
    sync.accept_spendable(spendable_pcd);

    // Advance into epoch 1, then lift; sync chooses the cross-epoch path.
    let remaining = usize::try_from(EPOCH_SIZE + 1 - u32::from(pool.anchor().0)).expect("fits");
    pool.advance(remaining, |_| random_block(&mut rng, 10));
    assert_eq!(pool.anchor().0.epoch().0, 1);
    sync.lift(&mut rng, &pool);

    PROOF_SYSTEM
        .rerandomize(sync.spendable(delegation_id), &mut rng)
        .expect("rerandomize lifted spendable");
}

/// SpendableLift: advances spendable anchor within the same epoch across
/// blocks that carry tachygrams unrelated to this note's `nf`. The delta is
/// the real product of those intervening block polynomials.
#[test]
fn spendable_lift_within_epoch() {
    let mut rng = StdRng::seed_from_u64(350);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    let delegation_id = user.pak.nk.derive_delegation_id(&note, trap);
    let epoch_0 = EpochIndex(0);

    let master = user.delegate_master(&mut rng, note, trap);
    let mut sync = SyncSim::new(delegate_range(&mut rng, &master, epoch_0.0..=epoch_0.0));

    pool.mine(random_block_with(&mut rng, note.commitment(), 50));
    let nf_pcd = sync.nullifier(&mut rng, delegation_id, epoch_0);
    let spendable_pcd = user.spendable_init(
        &mut rng,
        note,
        trap,
        pool.anchor(),
        pool.state().clone(),
        nf_pcd,
    );
    sync.accept_spendable(spendable_pcd);

    pool.advance(2, |_| random_block(&mut rng, 50));

    sync.lift(&mut rng, &pool);
    let lifted_pcd = sync.spendable(delegation_id);

    PROOF_SYSTEM
        .rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted spendable");
}

/// SpendableLift rejects target in a different epoch.
#[test]
fn spendable_lift_rejects_cross_epoch() {
    let mut rng = StdRng::seed_from_u64(351);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    pool.mine(random_block_with(&mut rng, note.commitment(), 50));
    let init_anchor = pool.anchor();
    let left_pool_acc = pool.state().clone();
    let master_pcd = user.delegate_master(&mut rng, note, trap);
    let nf_pcd = nullifier_from_master(&mut rng, master_pcd, init_anchor.0.epoch());
    let spendable_pcd = user.spendable_init(
        &mut rng,
        note,
        trap,
        init_anchor,
        left_pool_acc.clone(),
        nf_pcd,
    );

    // Advance to epoch-final of epoch 0, then across the boundary.
    let epoch_final = BlockHeight(EPOCH_SIZE - 1);
    let to_epoch_final = usize::try_from(epoch_final.0 - init_anchor.0.0).expect("fits usize");
    pool.advance(to_epoch_final, |_| random_block(&mut rng, 10));
    // Accurate delta for the same-epoch span; the lift should still reject
    // because `to_anchor` below crosses the boundary.
    let delta = pool.delta(init_anchor.0, epoch_final);
    pool.advance(1, |_| random_block(&mut rng, 10));
    assert_eq!(pool.anchor().0.epoch().0, 1);

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableLift,
        (left_pool_acc.into(), delta.into(), pool.anchor()),
        spendable_pcd,
        Proof::trivial().carry::<()>(()),
    );
    assert!(
        result.is_err(),
        "spendable lift across epoch boundary must fail"
    );
}

/// SpendableInit rejects when the note's cm is not in the pool.
#[test]
fn spendable_init_rejects_cm_absent() {
    let mut rng = StdRng::seed_from_u64(700);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    let epoch_0 = EpochIndex(0);

    // Advance with an UNRELATED tachygram — cm is NOT in the pool.
    let unrelated = Fp::from(0xDEAD_BEEFu64);
    pool.mine(BlockAcc::from(&[Tachygram::from(&unrelated)][..]));
    let anchor = pool.anchor();

    let master_pcd = user.delegate_master(&mut rng, note, trap);
    let nf_pcd = nullifier_from_master(&mut rng, master_pcd, epoch_0);
    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableInit,
        (note, user.pak, trap, pool.state().clone().into(), anchor),
        nf_pcd,
        Proof::trivial().carry::<()>(()),
    );
    assert!(
        result.is_err(),
        "SpendableInit must reject when cm is absent from pool"
    );
}

/// SpendableInit rejects when the note's `nf` for this epoch is already
/// present in the pool (i.e., the note has been spent).
///
/// TODO: is this a valid thing to test? presently, SpendableInit just checks
/// the total pool state, so it can do this. But, it should probably just check
/// a single block state.
#[test]
fn spendable_init_rejects_nf_present() {
    let mut rng = StdRng::seed_from_u64(701);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    let epoch_0 = EpochIndex(0);

    let nf = note.nullifier(&user.pak.nk, epoch_0);
    // Mine a block containing BOTH cm and nf — cm-in-pool passes, nf-in-pool
    // is the intended failure.
    pool.mine(BlockAcc::from(
        &[Tachygram::from(&note.commitment()), Tachygram::from(&nf)][..],
    ));
    let anchor = pool.anchor();

    let master_pcd = user.delegate_master(&mut rng, note, trap);
    let nf_pcd = nullifier_from_master(&mut rng, master_pcd, epoch_0);
    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableInit,
        (note, user.pak, trap, pool.state().clone().into(), anchor),
        nf_pcd,
        Proof::trivial().carry::<()>(()),
    );
    assert!(
        result.is_err(),
        "SpendableInit must reject when nf is present in the pool"
    );
}

/// SpendableEpochLift rejects when the E+1 pool lacks the epoch-boundary
/// seed. This state isn't reachable via `PoolSim`, so the inputs are
/// fabricated — the test is exclusively about the proof step's constraint.
#[test]
fn spendable_epoch_lift_rejects_missing_seed() {
    let mut rng = StdRng::seed_from_u64(702);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    let delegation_id = user.pak.nk.derive_delegation_id(&note, trap);

    // Left: SpendableHeader at epoch-final with a fabricated pool (cm only).
    let cm_fp = Fp::from(&note.commitment());
    let epoch_final_height = BlockHeight(EPOCH_SIZE - 1);
    let left_pool = PoolSet(Polynomial::from_roots(&[cm_fp]));
    let left_anchor = Anchor(epoch_final_height, PoolCommit(left_pool.0.commit(Fp::ZERO)));
    let nf_e0 = note.nullifier(&user.pak.nk, EpochIndex(0));

    // Right: SpendableRolloverHeader at first block of epoch 1 with a pool
    // whose single root is unrelated to both the epoch seed and this note.
    let right_pool = PoolSet(Polynomial::from_roots(&[Fp::ONE]));
    let right_anchor = Anchor(
        BlockHeight(EPOCH_SIZE),
        PoolCommit(right_pool.0.commit(Fp::ZERO)),
    );
    let nf_e1 = note.nullifier(&user.pak.nk, EpochIndex(1));

    let left_pcd =
        Proof::trivial().carry::<spendable::SpendableHeader>((delegation_id, nf_e0, left_anchor));
    let right_pcd = Proof::trivial().carry::<spendable::SpendableRolloverHeader>((
        delegation_id,
        nf_e0,
        nf_e1,
        right_anchor,
    ));

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableEpochLift,
        (right_pool.into(),),
        left_pcd,
        right_pcd,
    );
    assert!(
        result.is_err(),
        "SpendableEpochLift must reject when E+1 pool lacks the seed root"
    );
}

/// SpendableLift rejects when the delta does not actually connect the two
/// pool states.
#[test]
fn spendable_lift_rejects_non_superset_delta() {
    let mut rng = StdRng::seed_from_u64(703);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    pool.mine(random_block_with(&mut rng, note.commitment(), 50));
    let left_pool_acc = pool.state().clone();
    let anchor = pool.anchor();
    let master_pcd = user.delegate_master(&mut rng, note, trap);
    let nf_pcd = nullifier_from_master(&mut rng, master_pcd, anchor.0.epoch());
    let spendable_pcd =
        user.spendable_init(&mut rng, note, trap, anchor, left_pool_acc.clone(), nf_pcd);

    pool.advance(2, |_| random_block(&mut rng, 50));
    let bogus_delta = PoolDelta(Polynomial::from_roots(&[Fp::from(0x1234u64)]));

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableLift,
        (left_pool_acc.into(), bogus_delta.into(), pool.anchor()),
        spendable_pcd,
        Proof::trivial().carry::<()>(()),
    );
    assert!(
        result.is_err(),
        "SpendableLift must reject a non-superset delta"
    );
}

// ── SpendableRollover ─────────────────────────────────────────────────────

/// `SpendableRollover` must reject when `new_nf` is already present as a
/// root of the E+1 pool — the nullifier has been mined, so a spendable-
/// status attestation for E+1 is meaningless.
#[test]
fn spendable_rollover_rejects_new_nf_in_pool() {
    let mut rng = StdRng::seed_from_u64(735);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    let delegation_id = user.pak.nk.derive_delegation_id(&note, trap);

    let epoch_0 = EpochIndex(0);
    let epoch_1 = EpochIndex(1);
    let master = user.delegate_master(&mut rng, note, trap);
    let sync = SyncSim::new(delegate_range(&mut rng, &master, epoch_0.0..=epoch_1.0));
    let old_nf_pcd = sync.nullifier(&mut rng, delegation_id, epoch_0);
    let new_nf_pcd = sync.nullifier(&mut rng, delegation_id, epoch_1);
    let new_nf = new_nf_pcd.data.0;

    // Pool rooted at new_nf → query(new_nf) == 0 → step rejects.
    let new_pool = PoolSet(Polynomial::from_roots(&[Fp::from(&new_nf)]));
    let new_anchor = Anchor(
        BlockHeight(EPOCH_SIZE),
        PoolCommit(new_pool.0.commit(Fp::ZERO)),
    );

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableRollover,
        (new_pool.into(), new_anchor),
        old_nf_pcd,
        new_nf_pcd,
    );
    assert!(
        result.is_err(),
        "SpendableRollover must reject when new_nf is already in the E+1 pool"
    );
}

/// `SpendableRollover` must reject when the two `NullifierHeader` PCDs carry
/// different `delegation_id`s.
#[test]
fn spendable_rollover_rejects_delegation_id_mismatch() {
    let mut rng = StdRng::seed_from_u64(736);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let note = user.random_note(&mut rng, 500);
    let trap_a = DelegationTrapdoor::random(&mut rng);
    let trap_b = DelegationTrapdoor::random(&mut rng);
    let id_a = user.pak.nk.derive_delegation_id(&note, trap_a);
    let id_b = user.pak.nk.derive_delegation_id(&note, trap_b);
    assert_ne!(id_a, id_b);

    let epoch_0 = EpochIndex(0);
    let epoch_1 = EpochIndex(1);
    let master_a = user.delegate_master(&mut rng, note, trap_a);
    let master_b = user.delegate_master(&mut rng, note, trap_b);
    let sync_a = SyncSim::new(delegate_range(&mut rng, &master_a, epoch_0.0..=epoch_1.0));
    let sync_b = SyncSim::new(delegate_range(&mut rng, &master_b, epoch_0.0..=epoch_1.0));
    let old_nf_pcd = sync_a.nullifier(&mut rng, id_a, epoch_0);
    let new_nf_pcd = sync_b.nullifier(&mut rng, id_b, epoch_1);

    // Unrelated root so the non-membership check would pass; delegation_id
    // check should fire first.
    let new_pool = PoolSet(Polynomial::from_roots(&[Fp::random(&mut rng)]));
    let new_anchor = Anchor(
        BlockHeight(EPOCH_SIZE),
        PoolCommit(new_pool.0.commit(Fp::ZERO)),
    );

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableRollover,
        (new_pool.into(), new_anchor),
        old_nf_pcd,
        new_nf_pcd,
    );
    assert!(
        result.is_err(),
        "SpendableRollover must reject delegation_id mismatch"
    );
}

/// `SpendableRollover` must reject when `new_epoch != old_epoch + 1`.
#[test]
fn spendable_rollover_rejects_non_adjacent_epochs() {
    let mut rng = StdRng::seed_from_u64(737);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    let delegation_id = user.pak.nk.derive_delegation_id(&note, trap);

    let epoch_0 = EpochIndex(0);
    let epoch_2 = EpochIndex(2);
    let master = user.delegate_master(&mut rng, note, trap);
    let sync = SyncSim::new(delegate_range(&mut rng, &master, epoch_0.0..=epoch_2.0));
    let old_nf_pcd = sync.nullifier(&mut rng, delegation_id, epoch_0);
    let new_nf_pcd = sync.nullifier(&mut rng, delegation_id, epoch_2);

    let new_pool = PoolSet(Polynomial::from_roots(&[Fp::random(&mut rng)]));
    let new_anchor = Anchor(
        BlockHeight(2 * EPOCH_SIZE),
        PoolCommit(new_pool.0.commit(Fp::ZERO)),
    );

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableRollover,
        (new_pool.into(), new_anchor),
        old_nf_pcd,
        new_nf_pcd,
    );
    assert!(
        result.is_err(),
        "SpendableRollover must reject non-adjacent epochs"
    );
}
