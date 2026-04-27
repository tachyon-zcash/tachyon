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
    BlockSet,
    constants::EPOCH_SIZE,
    entropy::ActionEntropy,
    keys::private,
    note,
    primitives::{
        ActionCommit, Anchor, BlockAcc, BlockCommit, BlockHeight, DelegationTrapdoor, EpochIndex,
        PoolChain, Tachygram, TachygramAcc, TachygramCommit, effect,
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

/// StampLift: advances stamp anchor one block within the same epoch via a
/// single chain step.
#[test]
fn stamp_lift_within_epoch() {
    let mut rng = StdRng::seed_from_u64(400);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();

    pool.advance(1, |_| random_block(&mut rng, 50));
    let old_height = pool.tip();
    let old_anchor = pool.anchor_at(old_height);
    let old_block = pool.block_at(old_height);
    let old_prev_chain = pool.prev_chain_at(old_height);

    let note = user.random_note(&mut rng, 200);
    let (rcv, alpha, action) = build_output_action(&mut rng, note);
    let stamp = Stamp::prove_output(&mut rng, rcv, alpha, note, old_anchor).expect("prove_output");

    let action_acc = compute_action_acc(&[action]).unwrap();
    let tachygram_acc = TachygramAcc::from(&*stamp.tachygrams);
    let action_commit = ActionCommit(action_acc.0.commit(Fp::ZERO));
    let tachygram_commit = TachygramCommit(tachygram_acc.0.commit(Fp::ZERO));

    pool.advance(1, |_| random_block(&mut rng, 50));
    let new_height = pool.tip();
    let new_anchor = pool.anchor_at(new_height);
    let new_block = pool.block_at(new_height);

    let stamp_hdr = (action_commit, tachygram_commit, old_anchor);
    let stamp_pcd = stamp.proof.carry(stamp_hdr);

    let (lifted_proof, ()) = PROOF_SYSTEM
        .fuse(
            &mut rng,
            &stamp_proof::StampLift,
            (
                action_acc.into(),
                tachygram_acc.into(),
                old_prev_chain,
                old_block.into(),
                old_height,
                new_block.into(),
                new_height,
                new_anchor,
            ),
            stamp_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("stamp lift");

    let lifted_hdr = (action_commit, tachygram_commit, new_anchor);
    let lifted_pcd = lifted_proof.carry::<stamp_proof::StampHeader>(lifted_hdr);
    PROOF_SYSTEM
        .rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted stamp");
}

/// StampLift rejects a target across the epoch boundary.
#[test]
fn stamp_lift_rejects_cross_epoch() {
    let mut rng = StdRng::seed_from_u64(604);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();

    // Advance to the epoch-final block of epoch 0.
    let epoch_final = BlockHeight(EPOCH_SIZE - 1);
    let to_final = usize::try_from(epoch_final.0 - pool.tip().0).expect("fits");
    pool.advance(to_final, |_| random_block(&mut rng, 10));
    let old_height = pool.tip();
    assert!(old_height.is_epoch_final());
    let old_anchor = pool.anchor_at(old_height);
    let old_block = pool.block_at(old_height);
    let old_prev_chain = pool.prev_chain_at(old_height);

    let note = user.random_note(&mut rng, 200);
    let (rcv, alpha, action) = build_output_action(&mut rng, note);
    let stamp = Stamp::prove_output(&mut rng, rcv, alpha, note, old_anchor).expect("prove_output");

    let action_acc = compute_action_acc(&[action]).unwrap();
    let tachygram_acc = TachygramAcc::from(&*stamp.tachygrams);

    // Advance one block — that step crosses into epoch 1.
    pool.advance(1, |_| random_block(&mut rng, 10));
    let new_height = pool.tip();
    let new_anchor = pool.anchor_at(new_height);
    let new_block = pool.block_at(new_height);
    assert_ne!(old_height.epoch(), new_height.epoch());

    let action_commit = ActionCommit(action_acc.0.commit(Fp::ZERO));
    let tachygram_commit = TachygramCommit(tachygram_acc.0.commit(Fp::ZERO));
    let stamp_hdr = (action_commit, tachygram_commit, old_anchor);
    let stamp_pcd = stamp.proof.carry(stamp_hdr);

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &stamp_proof::StampLift,
        (
            action_acc.into(),
            tachygram_acc.into(),
            old_prev_chain,
            old_block.into(),
            old_height,
            new_block.into(),
            new_height,
            new_anchor,
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
    let master = user.note_master(&mut rng, note);
    let sync = SyncSim::new(delegate_range(
        &mut rng,
        &master,
        trap,
        epoch_e.0..=epoch_far.0,
    ));

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

    // NoteSeedStep: no PCD inputs needed.
    assert!(
        PROOF_SYSTEM
            .seed(&mut rng, &delegation::NoteSeedStep, (zero_note, user.pak),)
            .is_err(),
        "NoteSeedStep must reject zero-value note"
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
    let valid_master = user.note_master(&mut rng, valid_note);
    let (nf_now_pcd, nf_next_pcd) =
        nullifier_pair_from_master(&mut rng, valid_master, trap, target_epoch);
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
    pool.mine(&random_block_with(&mut rng, &[zero_note.commitment()], 50));
    let init_height = pool.tip();
    let init_anchor = pool.anchor_at(init_height);
    let init_prev_chain = pool.prev_chain_at(init_height);
    let init_block = pool.block_at(init_height);
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
                    init_prev_chain,
                    init_block.into(),
                    init_height,
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

    let nf_master = user.note_master(&mut rng, note);
    let (nf_now_pcd, nf_next_pcd) =
        nullifier_pair_from_master(&mut rng, nf_master, trap_nf, target_epoch);
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

/// SpendableEpochLift: sync's cross-epoch `lift` internally chains
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
    let master = user.note_master(&mut rng, note);
    let mut sync = SyncSim::new(delegate_range(
        &mut rng,
        &master,
        trap,
        epoch_0.0..=epoch_0.0 + 1,
    ));

    pool.mine(&random_block_with(&mut rng, &[note.commitment()], 50));
    let init_height = pool.tip();
    let nf_pcd = sync.nullifier(&mut rng, delegation_id, epoch_0);
    let spendable_pcd = user.spendable_init(&mut rng, note, trap, &pool, init_height, nf_pcd);
    sync.accept_spendable(spendable_pcd, init_height);

    // Advance into epoch 1, then lift; sync chooses the cross-epoch path.
    let remaining = usize::try_from(EPOCH_SIZE + 1 - pool.tip().0).expect("fits");
    pool.advance(remaining, |_| random_block(&mut rng, 10));
    assert_eq!(pool.tip().epoch().0, 1);
    sync.lift(&mut rng, &pool);

    PROOF_SYSTEM
        .rerandomize(sync.spendable(delegation_id), &mut rng)
        .expect("rerandomize lifted spendable");
}

/// SpendableLift: advances spendable anchor one block within the same epoch.
#[test]
fn spendable_lift_within_epoch() {
    let mut rng = StdRng::seed_from_u64(350);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    let delegation_id = user.pak.nk.derive_delegation_id(&note, trap);
    let epoch_0 = EpochIndex(0);

    let master = user.note_master(&mut rng, note);
    let mut sync = SyncSim::new(delegate_range(
        &mut rng,
        &master,
        trap,
        epoch_0.0..=epoch_0.0,
    ));

    pool.mine(&random_block_with(&mut rng, &[note.commitment()], 50));
    let init_height = pool.tip();
    let nf_pcd = sync.nullifier(&mut rng, delegation_id, epoch_0);
    let spendable_pcd = user.spendable_init(&mut rng, note, trap, &pool, init_height, nf_pcd);
    sync.accept_spendable(spendable_pcd, init_height);

    pool.advance(2, |_| random_block(&mut rng, 50));

    sync.lift(&mut rng, &pool);
    let lifted_pcd = sync.spendable(delegation_id);

    PROOF_SYSTEM
        .rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted spendable");
}

/// SpendableLift rejects a target step that crosses an epoch boundary.
#[test]
fn spendable_lift_rejects_cross_epoch() {
    let mut rng = StdRng::seed_from_u64(351);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);

    // Mine cm into the epoch-final block of epoch 0.
    let epoch_final = BlockHeight(EPOCH_SIZE - 1);
    let to_final_minus_one = usize::try_from(epoch_final.0 - pool.tip().0 - 1).expect("fits");
    pool.advance(to_final_minus_one, |_| random_block(&mut rng, 10));
    pool.mine(&random_block_with(&mut rng, &[note.commitment()], 50));
    assert_eq!(pool.tip(), epoch_final);

    let old_height = pool.tip();
    let old_block = pool.block_at(old_height);
    let old_prev_chain = pool.prev_chain_at(old_height);
    let master_pcd = user.note_master(&mut rng, note);
    let nf_pcd = nullifier_from_master(&mut rng, master_pcd, trap, old_height.epoch());
    let spendable_pcd = user.spendable_init(&mut rng, note, trap, &pool, old_height, nf_pcd);

    // Advance one block — crosses into epoch 1.
    pool.advance(1, |_| random_block(&mut rng, 10));
    let new_height = pool.tip();
    let new_anchor = pool.anchor_at(new_height);
    let new_block = pool.block_at(new_height);
    assert_ne!(old_height.epoch(), new_height.epoch());

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableLift,
        (
            old_prev_chain,
            old_block.into(),
            old_height,
            new_block.into(),
            new_height,
            new_anchor,
        ),
        spendable_pcd,
        Proof::trivial().carry::<()>(()),
    );
    assert!(
        result.is_err(),
        "spendable lift across epoch boundary must fail"
    );
}

/// SpendableInit rejects when the note's cm is not in the block.
#[test]
fn spendable_init_rejects_cm_absent() {
    let mut rng = StdRng::seed_from_u64(700);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    let epoch_0 = EpochIndex(0);

    // Mine an UNRELATED tachygram — cm is NOT in the latest block.
    let unrelated = Fp::from(0xDEAD_BEEFu64);
    pool.mine(&BlockAcc::from(&[Tachygram::from(&unrelated)][..]));
    let height = pool.tip();
    let anchor = pool.anchor_at(height);
    let prev_chain = pool.prev_chain_at(height);
    let block = pool.block_at(height);

    let master_pcd = user.note_master(&mut rng, note);
    let nf_pcd = nullifier_from_master(&mut rng, master_pcd, trap, epoch_0);
    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableInit,
        (
            note,
            user.pak,
            trap,
            prev_chain,
            block.into(),
            height,
            anchor,
        ),
        nf_pcd,
        Proof::trivial().carry::<()>(()),
    );
    assert!(
        result.is_err(),
        "SpendableInit must reject when cm is absent from the block"
    );
}

/// SpendableInit rejects when the note's `nf` for this epoch is already
/// present in the latest block (i.e., the note has been spent).
#[test]
fn spendable_init_rejects_nf_present() {
    let mut rng = StdRng::seed_from_u64(701);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    let epoch_0 = EpochIndex(0);

    let nf = note.nullifier(&user.pak.nk, epoch_0);
    // Mine a block containing BOTH cm and nf — cm-in-block passes, nf-in-block
    // is the intended failure.
    pool.mine(&BlockAcc::from(
        &[Tachygram::from(&note.commitment()), Tachygram::from(&nf)][..],
    ));
    let height = pool.tip();
    let anchor = pool.anchor_at(height);
    let prev_chain = pool.prev_chain_at(height);
    let block = pool.block_at(height);

    let master_pcd = user.note_master(&mut rng, note);
    let nf_pcd = nullifier_from_master(&mut rng, master_pcd, trap, epoch_0);
    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableInit,
        (
            note,
            user.pak,
            trap,
            prev_chain,
            block.into(),
            height,
            anchor,
        ),
        nf_pcd,
        Proof::trivial().carry::<()>(()),
    );
    assert!(
        result.is_err(),
        "SpendableInit must reject when nf is present in the block"
    );
}

/// SpendableLift rejects when the witnessed `new_anchor` chain doesn't
/// actually advance from `old_anchor.1` via `new_block`'s commitment.
#[test]
fn spendable_lift_rejects_chain_mismatch() {
    let mut rng = StdRng::seed_from_u64(703);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let mut pool = PoolSim::new();
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);

    pool.mine(&random_block_with(&mut rng, &[note.commitment()], 50));
    let old_height = pool.tip();
    let old_block = pool.block_at(old_height);
    let old_prev_chain = pool.prev_chain_at(old_height);
    let master_pcd = user.note_master(&mut rng, note);
    let nf_pcd = nullifier_from_master(&mut rng, master_pcd, trap, old_height.epoch());
    let spendable_pcd = user.spendable_init(&mut rng, note, trap, &pool, old_height, nf_pcd);

    pool.advance(1, |_| random_block(&mut rng, 50));
    let new_height = pool.tip();
    let new_block = pool.block_at(new_height);
    let real_new_anchor = pool.anchor_at(new_height);

    // Forge a new_anchor with the right block_commit but a bogus chain
    // hash — `check_anchor` must reject because `old_anchor.1.advance` ≠ chain.
    let bogus_anchor = Anchor(real_new_anchor.0, PoolChain::genesis());

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableLift,
        (
            old_prev_chain,
            old_block.into(),
            old_height,
            new_block.into(),
            new_height,
            bogus_anchor,
        ),
        spendable_pcd,
        Proof::trivial().carry::<()>(()),
    );
    assert!(
        result.is_err(),
        "SpendableLift must reject a forged new_anchor chain"
    );

    // Also reject a forged new_anchor with the wrong block_commit.
    let other_block_commit =
        BlockCommit(Polynomial::from_roots(&[Fp::from(0x00C0_FFEEu64)]).commit(Fp::ZERO));
    let bogus_block_commit_anchor = Anchor(other_block_commit, real_new_anchor.1);

    // Re-init the spendable so we have a fresh PCD to feed the second
    // attempt — the prior `fuse` consumed `spendable_pcd`.
    let master_pcd_two = user.note_master(&mut rng, note);
    let nf_pcd_two = nullifier_from_master(&mut rng, master_pcd_two, trap, old_height.epoch());
    let spendable_pcd_two =
        user.spendable_init(&mut rng, note, trap, &pool, old_height, nf_pcd_two);

    let result_two = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableLift,
        (
            old_prev_chain,
            pool.block_at(old_height).into(),
            old_height,
            pool.block_at(new_height).into(),
            new_height,
            bogus_block_commit_anchor,
        ),
        spendable_pcd_two,
        Proof::trivial().carry::<()>(()),
    );
    assert!(
        result_two.is_err(),
        "SpendableLift must reject a forged new_anchor block_commit"
    );
}

// ── SpendableRollover ─────────────────────────────────────────────────────

/// `SpendableRollover` must reject when `new_nf` is already present as a
/// root of the new block — the nullifier has been mined, so a spendable-
/// status attestation for E+1 is meaningless.
#[test]
fn spendable_rollover_rejects_new_nf_in_block() {
    let mut rng = StdRng::seed_from_u64(735);
    let user = WalletSim::new(private::SpendingKey::random(&mut rng));
    let note = user.random_note(&mut rng, 500);
    let trap = DelegationTrapdoor::random(&mut rng);
    let delegation_id = user.pak.nk.derive_delegation_id(&note, trap);

    let epoch_0 = EpochIndex(0);
    let epoch_1 = EpochIndex(1);
    let master = user.note_master(&mut rng, note);
    let sync = SyncSim::new(delegate_range(
        &mut rng,
        &master,
        trap,
        epoch_0.0..=epoch_1.0,
    ));
    let old_nf_pcd = sync.nullifier(&mut rng, delegation_id, epoch_0);
    let new_nf_pcd = sync.nullifier(&mut rng, delegation_id, epoch_1);
    let new_nf = new_nf_pcd.data.0;

    // Construct a block at first-of-epoch-1 height containing the new_nf as
    // a root — the rollover step queries new_nf in the block and must fail.
    let new_height = BlockHeight(EPOCH_SIZE);
    let prev_chain = PoolChain::genesis();
    let new_block = BlockSet(Polynomial::from_roots(&[
        Fp::from(&new_nf),
        Fp::from(&new_height.tachygram(prev_chain)),
    ]));
    let block_commit = BlockCommit(new_block.0.commit(Fp::ZERO));
    let new_anchor = Anchor(block_commit, prev_chain.advance(&block_commit));

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableRollover,
        (prev_chain, new_block.into(), new_height, new_anchor),
        old_nf_pcd,
        new_nf_pcd,
    );
    assert!(
        result.is_err(),
        "SpendableRollover must reject when new_nf is already in the block"
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
    let master_a = user.note_master(&mut rng, note);
    let master_b = user.note_master(&mut rng, note);
    let sync_a = SyncSim::new(delegate_range(
        &mut rng,
        &master_a,
        trap_a,
        epoch_0.0..=epoch_1.0,
    ));
    let sync_b = SyncSim::new(delegate_range(
        &mut rng,
        &master_b,
        trap_b,
        epoch_0.0..=epoch_1.0,
    ));
    let old_nf_pcd = sync_a.nullifier(&mut rng, id_a, epoch_0);
    let new_nf_pcd = sync_b.nullifier(&mut rng, id_b, epoch_1);

    // Unrelated root + canonical height tachygram so non-membership and
    // height checks pass; delegation_id check should fire first.
    let new_height = BlockHeight(EPOCH_SIZE);
    let prev_chain = PoolChain::genesis();
    let new_block = BlockSet(Polynomial::from_roots(&[
        Fp::random(&mut rng),
        Fp::from(&new_height.tachygram(prev_chain)),
    ]));
    let block_commit = BlockCommit(new_block.0.commit(Fp::ZERO));
    let new_anchor = Anchor(block_commit, prev_chain.advance(&block_commit));

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableRollover,
        (prev_chain, new_block.into(), new_height, new_anchor),
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
    let master = user.note_master(&mut rng, note);
    let sync = SyncSim::new(delegate_range(
        &mut rng,
        &master,
        trap,
        epoch_0.0..=epoch_2.0,
    ));
    let old_nf_pcd = sync.nullifier(&mut rng, delegation_id, epoch_0);
    let new_nf_pcd = sync.nullifier(&mut rng, delegation_id, epoch_2);

    let new_height = BlockHeight(2 * EPOCH_SIZE);
    let prev_chain = PoolChain::genesis();
    let new_block = BlockSet(Polynomial::from_roots(&[
        Fp::random(&mut rng),
        Fp::from(&new_height.tachygram(prev_chain)),
    ]));
    let block_commit = BlockCommit(new_block.0.commit(Fp::ZERO));
    let new_anchor = Anchor(block_commit, prev_chain.advance(&block_commit));

    let result = PROOF_SYSTEM.fuse(
        &mut rng,
        &spendable::SpendableRollover,
        (prev_chain, new_block.into(), new_height, new_anchor),
        old_nf_pcd,
        new_nf_pcd,
    );
    assert!(
        result.is_err(),
        "SpendableRollover must reject non-adjacent epochs"
    );
}
