use core::iter;

use ff::Field as _;
use mock_ragu::Polynomial;
use pasta_curves::Fp;
use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    action,
    constants::EPOCH_SIZE,
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{GGM_TREE_DEPTH, ProofAuthorizingKey, private, public},
    note::{self, Note, Nullifier},
    primitives::{
        ActionCommit, BlockAcc, BlockHeight, EpochIndex, NoteId, PoolAcc, PoolCommit, PoolDelta,
        PoolSet, Tachygram, TachygramCommit, epoch_seed_hash,
    },
    stamp::proof::{delegation, header, spend, spendable},
    value,
};

/// Simulates the sync service's evolving pool state.
///
/// Tracks the cumulative pool polynomial and current block height. No PCD —
/// the pool chain is public, so downstream steps take the anchor as witness
/// data and the verifier cross-checks the anchor against the real chain.
struct PoolSim {
    height: BlockHeight,
    pool: PoolAcc,
}

impl PoolSim {
    fn new() -> Self {
        Self {
            height: BlockHeight(0),
            pool: PoolSet(Polynomial::default()),
        }
    }

    fn anchor(&self) -> Anchor {
        Anchor(self.height, PoolCommit(self.pool.0.commit(Fp::ZERO)))
    }

    /// Advance pool 1 block of `block_size` fresh random tachygrams. Returns
    /// the block's tachygrams to the caller.
    fn advance_by(&mut self, rng: &mut StdRng, block_size: usize) -> Vec<Tachygram> {
        let block_tgs: Vec<Tachygram> =
            iter::repeat_with(|| Tachygram::from(Fp::random(&mut *rng)))
                .take(block_size)
                .collect();
        self.advance_with(&BlockAcc::from(&*block_tgs));
        block_tgs
    }

    /// Advance pool 1 block containing `block` tachygrams.
    fn advance_with(&mut self, block: &BlockAcc) {
        let prior_pool: Polynomial = if self.height.is_epoch_final() {
            Polynomial::from_roots(&[epoch_seed_hash(&PoolCommit(self.pool.0.commit(Fp::ZERO)))])
        } else {
            self.pool.0.clone()
        };
        self.pool = PoolSet(prior_pool.multiply(&block.0));
        self.height = self.height.next();
    }
}

fn make_output_stamp(
    rng: &mut StdRng,
    sk: &private::SpendingKey,
    anchor: Anchor,
) -> (Stamp, Action) {
    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(200u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut *rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut *rng)),
    };
    let rcv = value::CommitmentTrapdoor::random(&mut *rng);
    let theta = ActionEntropy::random(&mut *rng);
    let plan = action::Plan::output(note, theta, rcv);
    let alpha = theta.randomizer::<effect::Output>(&note.commitment());

    let action = Action {
        cv: plan.cv(),
        rk: plan.rk,
        sig: action::Signature::from([0u8; 64]),
    };

    let stamp = Stamp::prove_output(&mut *rng, rcv, alpha, note, anchor).expect("prove_output");
    (stamp, action)
}

fn build_delegation_to_nullifier(
    rng: &mut StdRng,
    app: mock_ragu::Application,
    note: Note,
    pak: ProofAuthorizingKey,
    note_id: NoteId,
    target_epoch: EpochIndex,
) -> (mock_ragu::Proof, (Nullifier, EpochIndex, NoteId), Fp) {
    let first_bit = (target_epoch.0 >> (GGM_TREE_DEPTH - 1)) & 1 != 0;
    let (mut proof, ()) = app
        .seed(rng, &delegation::DelegationSeed, (note, pak, first_bit))
        .expect("delegation seed");

    let mk = pak.nk().derive_note_private(&note.psi);
    let mut nk_node = mk.step(first_bit);
    let mut hdr = (nk_node, note_id);

    for level in 1..u32::from(GGM_TREE_DEPTH) {
        let bit_pos = GGM_TREE_DEPTH - 1 - u8::try_from(level).unwrap();
        let direction = (target_epoch.0 >> bit_pos) & 1 != 0;
        let pcd = proof.carry::<delegation::DelegationHeader>(hdr);
        let trivial = mock_ragu::Proof::trivial().carry::<()>(());
        let (next_proof, ()) = app
            .fuse(rng, &delegation::DelegationStep, (direction,), pcd, trivial)
            .expect("delegation step");
        nk_node = nk_node.step(direction);
        hdr = (nk_node, note_id);
        proof = next_proof;
    }

    let pcd = proof.carry::<delegation::DelegationHeader>(hdr);
    let trivial = mock_ragu::Proof::trivial().carry::<()>(());
    let (nf_proof, ()) = app
        .fuse(rng, &delegation::NullifierStep, (), pcd, trivial)
        .expect("nullifier step");

    let nf_hdr = (Nullifier::from(nk_node.inner), target_epoch, note_id);
    (nf_proof, nf_hdr, nk_node.inner)
}

/// Build a spendable by first creating a pool chain that includes the note's
/// commitment in block 1.
fn build_spendable(
    rng: &mut StdRng,
    app: mock_ragu::Application,
    note: Note,
    pak: ProofAuthorizingKey,
    nf_proof: mock_ragu::Proof,
    nf_hdr: &(Nullifier, EpochIndex, NoteId),
) -> (mock_ragu::Proof, (NoteId, Nullifier, Anchor), PoolSim) {
    let cm_fp = Fp::from(note.commitment());
    let block_acc = &BlockAcc::from(&[Tachygram::from(cm_fp)][..]);
    let mut pool = PoolSim::new();
    pool.advance_with(block_acc);
    let anchor = pool.anchor();

    let nf_pcd = nf_proof.carry::<delegation::NullifierHeader>(*nf_hdr);
    let trivial = mock_ragu::Proof::trivial().carry::<()>(());

    let (spendable_proof, ()) = app
        .fuse(
            rng,
            &spendable::SpendableInit,
            (note, pak, pool.pool.clone().into(), anchor),
            nf_pcd,
            trivial,
        )
        .expect("spendable init");

    let spendable_hdr = (nf_hdr.2, nf_hdr.0, anchor);
    (spendable_proof, spendable_hdr, pool)
}

fn build_spend_pcd(
    rng: &mut StdRng,
    app: mock_ragu::Application,
    note: Note,
    pak: ProofAuthorizingKey,
    target_epoch: EpochIndex,
) -> (
    mock_ragu::Proof,
    (Fp, [Nullifier; 2], EpochIndex, NoteId),
    Action,
) {
    let note_id = note.id(pak.nk());
    let nf0 = note.nullifier(pak.nk(), target_epoch);
    let nf1 = note.nullifier(pak.nk(), EpochIndex(target_epoch.0 + 1));
    let rcv = value::CommitmentTrapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let spend_alpha = theta.randomizer::<effect::Spend>(&note.commitment());
    let (snf_proof, ()) = app
        .seed(rng, &spend::SpendNullifier, (note, pak, target_epoch))
        .expect("spend nullifier");
    let snf_hdr = (nf0, nf1, target_epoch, note_id);
    let snf_pcd = snf_proof.carry(snf_hdr);
    let (sb_proof, ()) = app
        .fuse(
            rng,
            &spend::SpendBind,
            (rcv, spend_alpha, pak, note),
            snf_pcd,
            mock_ragu::Proof::trivial().carry::<()>(()),
        )
        .expect("spend bind");
    let plan = action::Plan::spend(note, theta, rcv, |alpha| {
        pak.ak().derive_action_public(&alpha)
    });
    let action = Action {
        cv: plan.cv(),
        rk: plan.rk,
        sig: action::Signature::from([0u8; 64]),
    };
    let ad = Fp::from(ActionDigest::try_from(&action).unwrap());
    let sp_hdr = (ad, [nf0, nf1], target_epoch, note_id);
    (sb_proof, sp_hdr, action)
}

#[test]
fn output_stamp_then_verify() {
    let mut rng = StdRng::seed_from_u64(0);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let mut pool = PoolSim::new();
    pool.advance_by(&mut rng, 50);
    let (stamp, action) = make_output_stamp(&mut rng, &sk, pool.anchor());

    stamp
        .verify(&[action], &mut rng)
        .expect("verify should succeed");
}

#[test]
fn verify_rejects_wrong_action() {
    let mut rng = StdRng::seed_from_u64(1);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let mut pool = PoolSim::new();
    pool.advance_by(&mut rng, 50);
    let anchor = pool.anchor();
    let (stamp, _action_a) = make_output_stamp(&mut rng, &sk, anchor);
    let (_stamp_b, action_b) = make_output_stamp(&mut rng, &sk, anchor);

    assert!(
        stamp.verify(&[action_b], &mut rng).is_err(),
        "verify with wrong action must fail"
    );
}

fn action_digest_fp(action: &Action) -> Fp {
    Fp::from(ActionDigest::try_from(action).unwrap())
}

#[test]
fn merge_two_outputs_then_verify() {
    let mut rng = StdRng::seed_from_u64(2);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let mut pool = PoolSim::new();
    pool.advance_by(&mut rng, 50);
    let anchor = pool.anchor();

    let (stamp_a, action_a) = make_output_stamp(&mut rng, &sk, anchor);
    let (stamp_b, action_b) = make_output_stamp(&mut rng, &sk, anchor);

    let digests_a = alloc::vec![action_digest_fp(&action_a)];
    let digests_b = alloc::vec![action_digest_fp(&action_b)];
    let merged = Stamp::prove_merge(&mut rng, stamp_a, &digests_a, stamp_b, &digests_b)
        .expect("prove_merge");

    merged
        .verify(&[action_a, action_b], &mut rng)
        .expect("merged stamp should verify");
}

#[test]
fn merged_stamp_rejects_partial_actions() {
    let mut rng = StdRng::seed_from_u64(3);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let mut pool = PoolSim::new();
    pool.advance_by(&mut rng, 50);
    let anchor = pool.anchor();

    let (stamp_a, action_a) = make_output_stamp(&mut rng, &sk, anchor);
    let (stamp_b, action_b) = make_output_stamp(&mut rng, &sk, anchor);

    let digests_a = alloc::vec![action_digest_fp(&action_a)];
    let digests_b = alloc::vec![action_digest_fp(&action_b)];
    let merged = Stamp::prove_merge(&mut rng, stamp_a, &digests_a, stamp_b, &digests_b)
        .expect("prove_merge");

    assert!(
        merged.verify(&[action_a], &mut rng).is_err(),
        "verify with partial actions must fail"
    );
}

/// Full spend pipeline: delegation -> nullifier -> spendable -> spend stamp.
#[test]
fn full_spend_pipeline() {
    let mut rng = StdRng::seed_from_u64(100);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let app = *PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let target_epoch = EpochIndex(0);
    let nf0 = note.nullifier(pak.nk(), target_epoch);
    let nf1 = note.nullifier(pak.nk(), EpochIndex(target_epoch.0 + 1));
    let note_id = note.id(pak.nk());

    let (nf_proof, nf_hdr, nf) =
        build_delegation_to_nullifier(&mut rng, app, note, pak, note_id, target_epoch);
    assert_eq!(Fp::from(nf0), nf, "GGM tree leaf should equal nf0");

    let (spendable_proof, spendable_hdr, _pool) =
        build_spendable(&mut rng, app, note, pak, nf_proof, &nf_hdr);
    let spendable_pcd = spendable_proof.carry(spendable_hdr);

    let (sb_proof, sp_hdr, spend_action) = build_spend_pcd(&mut rng, app, note, pak, target_epoch);
    let sp_pcd = sb_proof.carry::<spend::SpendHeader>(sp_hdr);

    let tachygram_nf0 = Tachygram::from(Fp::from(nf0));
    let tachygram_nf1 = Tachygram::from(Fp::from(nf1));
    let stamp = Stamp::prove_spend(
        &mut rng,
        sp_pcd,
        spendable_pcd,
        alloc::vec![tachygram_nf0, tachygram_nf1],
    )
    .expect("prove_spend");
    stamp
        .verify(&[spend_action], &mut rng)
        .expect("spend stamp should verify");
}

#[test]
fn spend_nullifier_fuse_from_two_delegation_chains() {
    let mut rng = StdRng::seed_from_u64(200);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let app = *PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let note_id = note.id(pak.nk());
    let epoch_e = EpochIndex(0);
    let epoch_e1 = EpochIndex(1);

    let (nf_proof_e, nf_hdr_e, nf_e) =
        build_delegation_to_nullifier(&mut rng, app, note, pak, note_id, epoch_e);
    let (nf_proof_e1, nf_hdr_e1, nf_e1) =
        build_delegation_to_nullifier(&mut rng, app, note, pak, note_id, epoch_e1);

    let nf_pcd_e = nf_proof_e.carry::<delegation::NullifierHeader>(nf_hdr_e);
    let nf_pcd_e1 = nf_proof_e1.carry::<delegation::NullifierHeader>(nf_hdr_e1);

    let (fused_proof, ()) = app
        .fuse(
            &mut rng,
            &spend::SpendNullifierFuse,
            (),
            nf_pcd_e,
            nf_pcd_e1,
        )
        .expect("spend nullifier fuse");

    let fused_hdr = (
        Nullifier::from(nf_e),
        Nullifier::from(nf_e1),
        epoch_e,
        note_id,
    );

    let expected_nf0 = note.nullifier(pak.nk(), epoch_e);
    let expected_nf1 = note.nullifier(pak.nk(), epoch_e1);
    assert_eq!(fused_hdr.0, expected_nf0);
    assert_eq!(fused_hdr.1, expected_nf1);

    let pcd = fused_proof.carry::<spend::SpendNullifierHeader>(fused_hdr);
    app.rerandomize(pcd, &mut rng)
        .expect("rerandomize fused spend nullifier");
}

/// SpendableEpochLift: epoch-final SpendableHeader x SpendableRolloverHeader.
#[test]
fn spendable_epoch_lift_across_boundary() {
    let mut rng = StdRng::seed_from_u64(300);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let app = *PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let note_id = note.id(pak.nk());

    let epoch_0 = EpochIndex(0);
    let (nf_proof_0, nf_hdr_0, _nf0) =
        build_delegation_to_nullifier(&mut rng, app, note, pak, note_id, epoch_0);

    // SpendableInit at block 1 (note's cm is added there).
    let (spendable_proof_0, spendable_hdr_0, mut pool) =
        build_spendable(&mut rng, app, note, pak, nf_proof_0, &nf_hdr_0);

    // Advance pool to epoch-final, carrying one random tachygram per block
    // so the SpendableLift delta is a real product.
    let initial_nf = spendable_hdr_0.1;
    let left_pool_acc = pool.pool.clone();
    let epoch_final = EPOCH_SIZE - 1;
    let mut intervening_roots: Vec<Fp> = Vec::new();
    for _ in (u32::from(pool.anchor().0))..epoch_final {
        let block_tgs = pool.advance_by(&mut rng, 10);
        intervening_roots.extend(block_tgs.iter().copied().map(Fp::from));
    }
    assert!(pool.anchor().0.is_epoch_final());

    let delta = PoolDelta(Polynomial::from_roots(&intervening_roots));
    let epoch_final_anchor = pool.anchor();
    let spendable_pcd_init = spendable_proof_0.carry(spendable_hdr_0);
    let trivial = mock_ragu::Proof::trivial().carry::<()>(());
    let (spendable_proof_final, ()) = app
        .fuse(
            &mut rng,
            &spendable::SpendableLift,
            (left_pool_acc.into(), delta.into(), epoch_final_anchor),
            spendable_pcd_init,
            trivial,
        )
        .expect("spendable lift to epoch-final");
    let spendable_hdr_final = (note_id, initial_nf, epoch_final_anchor);
    let spendable_pcd_final = spendable_proof_final.carry(spendable_hdr_final);

    // Cross the epoch boundary. PoolSim injects the epoch seed as a root
    // when advancing past an epoch-final height.
    pool.advance_by(&mut rng, 10);
    assert_eq!(pool.anchor().0.epoch().0, 1);
    let epoch_1_anchor = pool.anchor();

    // Build nullifier header for epoch 1.
    let epoch_1 = EpochIndex(1);
    let (nf_proof_1, nf_hdr_1, _) =
        build_delegation_to_nullifier(&mut rng, app, note, pak, note_id, epoch_1);
    let nf_pcd_1 = nf_proof_1.carry::<delegation::NullifierHeader>(nf_hdr_1);

    // SpendableRollover at epoch 1.
    let rollover_pool_acc = pool.pool.clone();
    let trivial_ro = mock_ragu::Proof::trivial().carry::<()>(());
    let (rollover_proof, ()) = app
        .fuse(
            &mut rng,
            &spendable::SpendableRollover,
            (rollover_pool_acc.clone().into(), epoch_1_anchor),
            nf_pcd_1,
            trivial_ro,
        )
        .expect("spendable rollover");
    let rollover_hdr = (note_id, nf_hdr_1.0, pool.anchor());
    let rollover_pcd = rollover_proof.carry(rollover_hdr);

    // SpendableEpochLift: epoch-final x rollover -> new spendable.
    let (lift_proof, ()) = app
        .fuse(
            &mut rng,
            &spendable::SpendableEpochLift,
            (rollover_pool_acc.into(),),
            spendable_pcd_final,
            rollover_pcd,
        )
        .expect("spendable epoch lift");

    let lifted_hdr = (note_id, nf_hdr_1.0, pool.anchor());
    let lifted_pcd = lift_proof.carry::<spendable::SpendableHeader>(lifted_hdr);
    app.rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted spendable");
}

/// SpendableLift: advances spendable anchor within the same epoch across
/// blocks that carry tachygrams unrelated to this note's `nf`. The delta is
/// the real product of those intervening block polynomials.
#[test]
fn spendable_lift_within_epoch() {
    let mut rng = StdRng::seed_from_u64(350);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let app = *PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let note_id = note.id(pak.nk());
    let epoch_0 = EpochIndex(0);

    let (nf_proof, nf_hdr, _) =
        build_delegation_to_nullifier(&mut rng, app, note, pak, note_id, epoch_0);

    let (spendable_proof, spendable_hdr, mut pool) =
        build_spendable(&mut rng, app, note, pak, nf_proof, &nf_hdr);

    let left_pool_acc = pool.pool.clone();

    let mut intervening_roots: Vec<Fp> = Vec::new();
    for _ in 0u32..2 {
        let block_tgs = pool.advance_by(&mut rng, 50);
        intervening_roots.extend(block_tgs.iter().copied().map(Fp::from));
    }

    let delta = PoolDelta(Polynomial::from_roots(&intervening_roots));
    let to_anchor = pool.anchor();

    let spendable_pcd = spendable_proof.carry(spendable_hdr);
    let trivial = mock_ragu::Proof::trivial().carry::<()>(());

    let (lifted_proof, ()) = app
        .fuse(
            &mut rng,
            &spendable::SpendableLift,
            (left_pool_acc.into(), delta.into(), to_anchor),
            spendable_pcd,
            trivial,
        )
        .expect("spendable lift");

    let lifted_hdr = (note_id, nf_hdr.0, to_anchor);
    let lifted_pcd = lifted_proof.carry::<spendable::SpendableHeader>(lifted_hdr);
    app.rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted spendable");
}

// TODO: spendable_lift_within_epoch_with_empty_delta

/// SpendableLift rejects target in a different epoch.
#[test]
fn spendable_lift_rejects_cross_epoch() {
    let mut rng = StdRng::seed_from_u64(351);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let app = *PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let note_id = note.id(pak.nk());
    let epoch_0 = EpochIndex(0);

    let (nf_proof, nf_hdr, _) =
        build_delegation_to_nullifier(&mut rng, app, note, pak, note_id, epoch_0);
    let (spendable_proof, spendable_hdr, mut pool) =
        build_spendable(&mut rng, app, note, pak, nf_proof, &nf_hdr);

    // Advance pool across the epoch boundary with one random tachygram per
    // block.
    for _ in (u32::from(pool.anchor().0))..EPOCH_SIZE {
        pool.advance_by(&mut rng, 10);
    }
    assert_eq!(pool.anchor().0.epoch().0, 1);

    // Any delta is fine — the epoch mismatch should reject first.
    let delta = PoolDelta(Polynomial::from_roots(&[]));
    let spendable_pcd = spendable_proof.carry(spendable_hdr);
    let trivial = mock_ragu::Proof::trivial().carry::<()>(());
    let left_pool_acc = PoolSet(Polynomial::default());
    let to_anchor = pool.anchor();

    let result = app.fuse(
        &mut rng,
        &spendable::SpendableLift,
        (left_pool_acc.into(), delta.into(), to_anchor),
        spendable_pcd,
        trivial,
    );
    assert!(
        result.is_err(),
        "spendable lift across epoch boundary must fail"
    );
}

/// StampLift: advances stamp anchor across same-epoch blocks that carry
/// tachygrams. The delta is the real product of those intervening blocks.
#[test]
fn stamp_lift_within_epoch() {
    let mut rng = StdRng::seed_from_u64(400);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let app = *PROOF_SYSTEM;

    let mut pool = PoolSim::new();
    pool.advance_by(&mut rng, 50);
    let anchor_5 = pool.anchor();
    let left_pool_acc = pool.pool.clone();

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(200u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let rcv = value::CommitmentTrapdoor::random(&mut rng);
    let theta = ActionEntropy::random(&mut rng);
    let alpha = theta.randomizer::<effect::Output>(&note.commitment());
    let plan = action::Plan::output(note, theta, rcv);
    let action = Action {
        cv: plan.cv(),
        rk: plan.rk,
        sig: action::Signature::from([0u8; 64]),
    };
    let stamp = Stamp::prove_output(&mut rng, rcv, alpha, note, anchor_5).expect("prove_output");

    let action_acc = compute_action_acc(&[action]).unwrap();
    let tachygram_acc = TachygramAcc::from(&*stamp.tachygrams);
    let action_commit = ActionCommit(action_acc.0.commit(Fp::ZERO));
    let tachygram_commit = TachygramCommit(tachygram_acc.0.commit(Fp::ZERO));

    let mut intervening_roots: Vec<Fp> = Vec::new();
    for _ in 0u32..2 {
        let block_tgs = pool.advance_by(&mut rng, 50);
        intervening_roots.extend(block_tgs.iter().copied().map(Fp::from));
    }
    let anchor_10 = pool.anchor();
    let delta = PoolDelta(Polynomial::from_roots(&intervening_roots));

    let stamp_hdr = (action_commit, tachygram_commit, anchor_5);
    let stamp_pcd = stamp.proof.carry(stamp_hdr);
    let trivial = mock_ragu::Proof::trivial().carry::<()>(());

    let (lifted_proof, ()) = app
        .fuse(
            &mut rng,
            &header::StampLift,
            (
                action_acc.into(),
                tachygram_acc.into(),
                left_pool_acc.into(),
                delta.into(),
                anchor_10,
            ),
            stamp_pcd,
            trivial,
        )
        .expect("stamp lift");

    let lifted_hdr = (action_commit, tachygram_commit, anchor_10);
    let lifted_pcd = lifted_proof.carry::<StampHeader>(lifted_hdr);
    app.rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted stamp");
}

// TODO: stamp_lift_within_epoch_with_empty_delta

/// MergeStamp rejects mismatched anchors.
#[test]
fn merge_stamp_rejects_mismatched_anchors() {
    let mut rng = StdRng::seed_from_u64(500);
    let sk = private::SpendingKey::from([0x42u8; 32]);

    let mut pool_a = PoolSim::new();
    pool_a.advance_by(&mut rng, 50);
    let (stamp_a, action_a) = make_output_stamp(&mut rng, &sk, pool_a.anchor());
    let digests_a = alloc::vec![action_digest_fp(&action_a)];

    let mut pool = PoolSim::new();
    pool.advance_by(&mut rng, 50);
    pool.advance_by(&mut rng, 50);

    let note_b = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(300u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let rcv_b = value::CommitmentTrapdoor::random(&mut rng);
    let theta_b = ActionEntropy::random(&mut rng);
    let plan_b = action::Plan::output(note_b, theta_b, rcv_b);
    let alpha_b = theta_b.randomizer::<effect::Output>(&note_b.commitment());
    let action_b = Action {
        cv: plan_b.cv(),
        rk: plan_b.rk,
        sig: action::Signature::from([0u8; 64]),
    };
    let digests_b = alloc::vec![action_digest_fp(&action_b)];
    let stamp_b = Stamp::prove_output(&mut rng, rcv_b, alpha_b, note_b, pool.anchor())
        .expect("prove_output at block 5");

    assert!(
        Stamp::prove_merge(&mut rng, stamp_a, &digests_a, stamp_b, &digests_b).is_err(),
        "merge with mismatched anchors must fail"
    );
}

fn build_spend_nullifier_pcd(
    rng: &mut StdRng,
    app: mock_ragu::Application,
    note: Note,
    pak: ProofAuthorizingKey,
    target_epoch: EpochIndex,
) -> (mock_ragu::Proof, (Nullifier, Nullifier, EpochIndex, NoteId)) {
    let note_id = note.id(pak.nk());
    let nf0 = note.nullifier(pak.nk(), target_epoch);
    let nf1 = note.nullifier(pak.nk(), EpochIndex(target_epoch.0 + 1));
    let (snf_proof, ()) = app
        .seed(rng, &spend::SpendNullifier, (note, pak, target_epoch))
        .expect("spend nullifier");
    let snf_hdr = (nf0, nf1, target_epoch, note_id);
    (snf_proof, snf_hdr)
}

fn make_output_plan_entry(
    rng: &mut StdRng,
    sk: &private::SpendingKey,
    value_amount: u64,
) -> (
    (value::Commitment, public::ActionVerificationKey),
    (
        ActionRandomizer<effect::Output>,
        Note,
        value::CommitmentTrapdoor,
    ),
    Action,
) {
    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(value_amount),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut *rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut *rng)),
    };
    let rcv = value::CommitmentTrapdoor::random(&mut *rng);
    let theta = ActionEntropy::random(&mut *rng);
    let plan = action::Plan::output(note, theta, rcv);
    let alpha = theta.randomizer::<effect::Output>(&note.commitment());

    let action = Action {
        cv: plan.cv(),
        rk: plan.rk,
        sig: action::Signature::from([0u8; 64]),
    };

    ((plan.cv(), plan.rk), (alpha, note, rcv), action)
}

/// Plan::prove with outputs only — the simplest path.
#[test]
fn plan_prove_outputs_only() {
    let mut rng = StdRng::seed_from_u64(600);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let mut pool = PoolSim::new();
    pool.advance_by(&mut rng, 50);
    let anchor = pool.anchor();

    let (desc_a, wit_a, action_a) = make_output_plan_entry(&mut rng, &sk, 200);
    let (desc_b, wit_b, action_b) = make_output_plan_entry(&mut rng, &sk, 300);

    let plan = Plan::new(
        alloc::vec![],
        alloc::vec![(desc_a, wit_a), (desc_b, wit_b)],
        anchor,
    );

    let stamp = plan
        .prove(&mut rng, &pak, alloc::vec![])
        .expect("plan prove outputs only");

    stamp
        .verify(&[action_a, action_b], &mut rng)
        .expect("plan-produced stamp should verify");
}

/// Plan::prove with one spend and one output.
#[test]
fn plan_prove_spend_and_output() {
    let mut rng = StdRng::seed_from_u64(601);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let app = *PROOF_SYSTEM;
    let target_epoch = EpochIndex(0);

    let spend_note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let spend_rcv = value::CommitmentTrapdoor::random(&mut rng);
    let spend_theta = ActionEntropy::random(&mut rng);
    let spend_alpha = spend_theta.randomizer::<effect::Spend>(&spend_note.commitment());
    let spend_plan = action::Plan::spend(spend_note, spend_theta, spend_rcv, |alpha| {
        pak.ak().derive_action_public(&alpha)
    });
    let spend_action = Action {
        cv: spend_plan.cv(),
        rk: spend_plan.rk,
        sig: action::Signature::from([0u8; 64]),
    };
    let spend_desc = (spend_plan.cv(), spend_plan.rk);
    let spend_wit = (spend_alpha, spend_note, spend_rcv);

    let (snf_proof, snf_hdr) =
        build_spend_nullifier_pcd(&mut rng, app, spend_note, pak, target_epoch);
    let snf_pcd = snf_proof.carry(snf_hdr);

    let note_id = spend_note.id(pak.nk());
    let (nf_proof, nf_hdr, _) =
        build_delegation_to_nullifier(&mut rng, app, spend_note, pak, note_id, target_epoch);
    let (spendable_proof, spendable_hdr, pool) =
        build_spendable(&mut rng, app, spend_note, pak, nf_proof, &nf_hdr);
    let spendable_pcd = spendable_proof.carry(spendable_hdr);

    let (output_desc, output_wit, output_action) = make_output_plan_entry(&mut rng, &sk, 200);

    // The plan anchor must match the spendable's anchor (block 1 where the
    // spend note's cm was added).
    let anchor = pool.anchor();

    let plan = Plan::new(
        alloc::vec![(spend_desc, spend_wit)],
        alloc::vec![(output_desc, output_wit)],
        anchor,
    );

    let stamp = plan
        .prove(&mut rng, &pak, alloc::vec![(snf_pcd, spendable_pcd)])
        .expect("plan prove spend+output");

    stamp
        .verify(&[spend_action, output_action], &mut rng)
        .expect("mixed spend+output stamp should verify");
}

#[test]
fn plan_prove_rejects_empty() {
    let mut rng = StdRng::seed_from_u64(602);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let mut pool = PoolSim::new();
    pool.advance_by(&mut rng, 50);
    let anchor = pool.anchor();

    let plan = Plan::new(alloc::vec![], alloc::vec![], anchor);

    let result = plan.prove(&mut rng, &pak, alloc::vec![]);
    assert!(
        matches!(result, Err(ProveError::NoActions)),
        "empty plan must return NoActions"
    );
}

#[test]
fn plan_prove_rejects_pcd_count_mismatch() {
    let mut rng = StdRng::seed_from_u64(603);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let mut pool = PoolSim::new();
    pool.advance_by(&mut rng, 50);
    let anchor = pool.anchor();

    let spend_note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let spend_rcv = value::CommitmentTrapdoor::random(&mut rng);
    let spend_theta = ActionEntropy::random(&mut rng);
    let spend_alpha = spend_theta.randomizer::<effect::Spend>(&spend_note.commitment());
    let spend_plan = action::Plan::spend(spend_note, spend_theta, spend_rcv, |alpha| {
        pak.ak().derive_action_public(&alpha)
    });
    let spend_desc = (spend_plan.cv(), spend_plan.rk);
    let spend_wit = (spend_alpha, spend_note, spend_rcv);

    let plan = Plan::new(alloc::vec![(spend_desc, spend_wit)], alloc::vec![], anchor);
    let result = plan.prove(&mut rng, &pak, alloc::vec![]);
    assert!(
        matches!(result, Err(ProveError::SpendableMismatch)),
        "1 spend with 0 PCDs must return SpendableMismatch"
    );
}

/// StampLift rejects target in a different epoch.
#[test]
fn stamp_lift_rejects_cross_epoch() {
    let mut rng = StdRng::seed_from_u64(604);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let app = *PROOF_SYSTEM;

    let mut pool = PoolSim::new();
    pool.advance_by(&mut rng, 50);
    let anchor_5 = pool.anchor();

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(200u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let rcv = value::CommitmentTrapdoor::random(&mut rng);
    let theta = ActionEntropy::random(&mut rng);
    let alpha = theta.randomizer::<effect::Output>(&note.commitment());
    let plan = action::Plan::output(note, theta, rcv);
    let action = Action {
        cv: plan.cv(),
        rk: plan.rk,
        sig: action::Signature::from([0u8; 64]),
    };
    let stamp = Stamp::prove_output(&mut rng, rcv, alpha, note, anchor_5).expect("prove_output");

    let action_acc = compute_action_acc(&[action]).unwrap();
    let tachygram_acc = TachygramAcc::from(&*stamp.tachygrams);

    // Advance into epoch 1 with one random tachygram per block.
    while pool.anchor().0.epoch().0 == 0 {
        pool.advance_by(&mut rng, 1);
    }
    assert_eq!(pool.anchor().0.epoch().0, 1);

    let delta = PoolDelta(Polynomial::from_roots(&[]));
    let action_commit = ActionCommit(action_acc.0.commit(Fp::ZERO));
    let tachygram_commit = TachygramCommit(tachygram_acc.0.commit(Fp::ZERO));
    let stamp_hdr = (action_commit, tachygram_commit, anchor_5);
    let stamp_pcd = stamp.proof.carry(stamp_hdr);
    let trivial = mock_ragu::Proof::trivial().carry::<()>(());
    let to_anchor = pool.anchor();

    let result = app.fuse(
        &mut rng,
        &header::StampLift,
        (
            action_acc.into(),
            tachygram_acc.into(),
            PoolSet::<Polynomial>(Polynomial::default()).into(),
            delta.into(),
            to_anchor,
        ),
        stamp_pcd,
        trivial,
    );
    assert!(
        result.is_err(),
        "stamp lift across epoch boundary must fail"
    );
}

/// SpendableInit rejects when the note's cm is not in the right pool header's
/// `block_commit`.
#[test]
fn spendable_init_rejects_cm_absent() {
    let mut rng = StdRng::seed_from_u64(700);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let app = *PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let note_id = note.id(pak.nk());
    let epoch_0 = EpochIndex(0);
    let (nf_proof, nf_hdr, _) =
        build_delegation_to_nullifier(&mut rng, app, note, pak, note_id, epoch_0);

    // Advance with an UNRELATED tachygram — cm is NOT in the pool.
    let mut pool = PoolSim::new();
    let unrelated = Fp::from(0xDEAD_BEEFu64);
    let block_acc = &BlockAcc::from(&[Tachygram::from(unrelated)][..]);
    pool.advance_with(block_acc);
    let anchor = pool.anchor();

    let nf_pcd = nf_proof.carry::<delegation::NullifierHeader>(nf_hdr);
    let trivial = mock_ragu::Proof::trivial().carry::<()>(());

    let result = app.fuse(
        &mut rng,
        &spendable::SpendableInit,
        (note, pak, pool.pool.clone().into(), anchor),
        nf_pcd,
        trivial,
    );
    assert!(
        result.is_err(),
        "SpendableInit must reject when cm is absent from pool"
    );
}

/// SpendableInit rejects when the note's nf is already in the right anchor's
/// pool.
#[test]
fn spendable_init_rejects_nf_present() {
    let mut rng = StdRng::seed_from_u64(701);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let app = *PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let note_id = note.id(pak.nk());
    let epoch_0 = EpochIndex(0);
    let nf0 = note.nullifier(pak.nk(), epoch_0);
    let (nf_proof, nf_hdr, _) =
        build_delegation_to_nullifier(&mut rng, app, note, pak, note_id, epoch_0);

    // Poison the pool: include BOTH cm and nf0 in the same block.
    let cm_fp = Fp::from(note.commitment());
    let nf_fp = Fp::from(nf0);
    let mut pool = PoolSim::new();
    let block_acc = &BlockAcc::from(&[Tachygram::from(cm_fp), Tachygram::from(nf_fp)][..]);
    pool.advance_with(block_acc);
    let anchor = pool.anchor();

    let nf_pcd = nf_proof.carry::<delegation::NullifierHeader>(nf_hdr);
    let trivial = mock_ragu::Proof::trivial().carry::<()>(());

    let result = app.fuse(
        &mut rng,
        &spendable::SpendableInit,
        (note, pak, pool.pool.clone().into(), anchor),
        nf_pcd,
        trivial,
    );
    assert!(
        result.is_err(),
        "SpendableInit must reject when nf is already in pool"
    );
}

/// SpendableEpochLift rejects when the E+1 pool lacks the epoch-boundary seed.
#[test]
fn spendable_epoch_lift_rejects_missing_seed() {
    let mut rng = StdRng::seed_from_u64(702);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let app = *PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let note_id = note.id(pak.nk());

    // Left: construct a SpendableHeader at epoch-final with a fabricated pool
    // (one that is legitimately derivable — note's cm only).
    let cm_fp = Fp::from(note.commitment());
    let epoch_final_height = BlockHeight(EPOCH_SIZE - 1);
    let left_pool = PoolSet(Polynomial::from_roots(&[cm_fp]));
    let left_anchor = Anchor(epoch_final_height, PoolCommit(left_pool.0.commit(Fp::ZERO)));
    let nf_e0 = note.nullifier(pak.nk(), EpochIndex(0));

    // Right: construct a SpendableRolloverHeader at first block of epoch 1
    // with a pool missing the epoch seed root.
    let right_pool = PoolSet(Polynomial::from_roots(&[cm_fp]));
    let right_anchor = Anchor(
        BlockHeight(EPOCH_SIZE),
        PoolCommit(right_pool.0.commit(Fp::ZERO)),
    );
    let nf_e1 = note.nullifier(pak.nk(), EpochIndex(1));

    // Fabricate input PCDs.
    let left_pcd = mock_ragu::Proof::trivial().carry::<spendable::SpendableHeader>((
        note_id,
        nf_e0,
        left_anchor,
    ));
    let right_pcd = mock_ragu::Proof::trivial().carry::<spendable::SpendableRolloverHeader>((
        note_id,
        nf_e1,
        right_anchor,
    ));

    let result = app.fuse(
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
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let app = *PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let note_id = note.id(pak.nk());
    let epoch_0 = EpochIndex(0);

    let (nf_proof, nf_hdr, _) =
        build_delegation_to_nullifier(&mut rng, app, note, pak, note_id, epoch_0);
    let (spendable_proof, spendable_hdr, mut pool) =
        build_spendable(&mut rng, app, note, pak, nf_proof, &nf_hdr);
    let left_pool_acc = pool.pool.clone();
    for _ in 0u32..2 {
        pool.advance_by(&mut rng, 50);
    }

    // Wrong delta: does not equal pool_R / pool_L.
    let bogus_delta = PoolDelta(Polynomial::from_roots(&[Fp::from(0x1234u64)]));
    let to_anchor = pool.anchor();
    let spendable_pcd = spendable_proof.carry(spendable_hdr);
    let trivial = mock_ragu::Proof::trivial().carry::<()>(());

    let result = app.fuse(
        &mut rng,
        &spendable::SpendableLift,
        (left_pool_acc.into(), bogus_delta.into(), to_anchor),
        spendable_pcd,
        trivial,
    );
    assert!(
        result.is_err(),
        "SpendableLift must reject a non-superset delta"
    );
}
