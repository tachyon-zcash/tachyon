use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::Fp;
use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    action,
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{GGM_TREE_DEPTH, NullifierKey, SpendValidatingKey, private, public},
    note::{self, Note, Nullifier},
    primitives::{
        BlockChainHash, BlockCommit, BlockHeight, Epoch, EpochChainHash, NoteId, PoolCommit,
        SetCommit, Tachygram, polynomial,
    },
    stamp::{
        exclusion::{
            ExclusionFuse, ExclusionHeader, ExclusionLeaf, ExclusionSetExtract, ExclusionSetFuse,
            ExclusionSetHeader, ExclusionSetLeaf, NullifierExclusionFuse, NullifierExclusionHeader,
            SpendableExclusionFuse, SpendableExclusionHeader,
        },
        spend::SpendHeader,
        spendable::{
            SpendableEpochLift, SpendableLift, SpendableRollover, SpendableRolloverHeader,
        },
    },
    value,
};

fn pad_tachygrams<const N: usize>(tgs: &[Tachygram]) -> [Tachygram; N] {
    assert!(tgs.len() <= N, "tachygrams must fit within {N} size");
    let mut arr = [Tachygram::from(Fp::ZERO); N];
    arr[..tgs.len()].copy_from_slice(tgs);
    arr
}

fn make_output_stamp(rng: &mut StdRng, sk: &private::SpendingKey) -> (Stamp, Action) {
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

    let stamp = Stamp::prove_output(&mut *rng, rcv, alpha, note, Anchor::genesis(BlockHeight(0)))
        .expect("prove_output");
    (stamp, action)
}

fn build_delegation_to_nullifier(
    rng: &mut StdRng,
    app: mock_ragu::Application,
    note: Note,
    nk: NullifierKey,
    note_id: NoteId,
    target_epoch: Epoch,
) -> (mock_ragu::Proof, (Nullifier, Epoch, NoteId), Fp) {
    let first_bit = (target_epoch.0 >> (GGM_TREE_DEPTH - 1)) & 1 != 0;
    let (mut proof, ()) = app
        .seed(rng, &delegation::DelegationSeed, (note, nk, first_bit))
        .expect("delegation seed");

    let mk = nk.derive_note_private(&note.psi);
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

/// Build an exclusion proof (single leaf) for a nullifier against a set of
/// tachygrams.
/// Small subset size for tests (real system uses up to 4095).
const TEST_N: usize = 8;

/// Batch size used by batch-path tests.
const TEST_M: usize = 4;

/// Pad an M-element nullifier vector from a list of real nullifiers.
fn pad_nullifiers<const M: usize>(nfs: &[Fp]) -> [Fp; M] {
    assert!(nfs.len() <= M, "nullifiers must fit within {M} size");
    let mut arr = [Fp::ZERO; M];
    arr[..nfs.len()].copy_from_slice(nfs);
    arr
}

/// Build a SpendableHeader at block 0 for a newly-created note.
///
/// The creation block is a synthetic block with the note's commitment as
/// its sole tachygram (padded to `TEST_N`). SpendableInit binds the
/// witness to the PoolHeader via the block polynomial commitment.
fn build_spendable(
    rng: &mut StdRng,
    app: mock_ragu::Application,
    note: Note,
    nk: NullifierKey,
    nf_proof: mock_ragu::Proof,
    nf_hdr: &(Nullifier, Epoch, NoteId),
) -> (mock_ragu::Proof, (NoteId, Nullifier, Anchor)) {
    let cm = note.commitment();
    let cm_tg = Tachygram::from(Fp::from(cm));
    let block_tachygrams = pad_tachygrams::<TEST_N>(&[cm_tg]);

    let roots: Vec<Fp> = block_tachygrams.iter().map(|tg| Fp::from(*tg)).collect();
    let block_commit = BlockCommit(SetCommit::from(polynomial::pedersen_commit(
        &polynomial::poly_from_roots(&roots),
    )));
    let pool_commit = PoolCommit(SetCommit::identity() + block_commit.0);

    let anchor = Anchor {
        block_height: BlockHeight(0),
        block_commit,
        pool_commit,
        block_chain: BlockChainHash::genesis(BlockHeight(0)),
        epoch_chain: EpochChainHash::genesis(BlockHeight(0)),
    };

    let (pool_proof, ()) = app
        .seed(rng, &pool::PoolSeed, BlockHeight(0))
        .expect("pool seed");
    let pool_pcd = pool_proof.carry::<pool::PoolHeader>(anchor);

    let nf_pcd = nf_proof.carry::<delegation::NullifierHeader>(*nf_hdr);

    let (spendable_proof, ()) = app
        .fuse(
            rng,
            &spendable::SpendableInit::<TEST_N>,
            (note, nk, &block_tachygrams, 0usize),
            nf_pcd,
            pool_pcd,
        )
        .expect("spendable init");

    let spendable_hdr = (nf_hdr.2, nf_hdr.0, anchor);

    (spendable_proof, spendable_hdr)
}

fn build_spend_pcd(
    rng: &mut StdRng,
    app: mock_ragu::Application,
    note: Note,
    nk: NullifierKey,
    ak: SpendValidatingKey,
    target_epoch: Epoch,
) -> (
    mock_ragu::Proof,
    (Fp, [Nullifier; 2], Epoch, NoteId),
    Action,
) {
    let note_id = note.id(&nk);
    let nf0 = note.nullifier(&nk, target_epoch);
    let nf1 = note.nullifier(&nk, Epoch(target_epoch.0 + 1));
    let rcv = value::CommitmentTrapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let spend_alpha = theta.randomizer::<effect::Spend>(&note.commitment());
    let (snf_proof, ()) = app
        .seed(rng, &spend::SpendNullifier, (note, nk, target_epoch))
        .expect("spend nullifier");
    let snf_hdr = (nf0, nf1, target_epoch, note_id);
    let snf_pcd = snf_proof.carry::<SpendNullifierHeader>(snf_hdr);
    let (sb_proof, ()) = app
        .fuse(
            rng,
            &SpendBind,
            (rcv, spend_alpha, ak, note, nk),
            snf_pcd,
            mock_ragu::Proof::trivial().carry::<()>(()),
        )
        .expect("spend bind");
    let plan = action::Plan::spend(note, theta, rcv, |alpha| ak.derive_action_public(&alpha));
    let action = Action {
        cv: plan.cv(),
        rk: plan.rk,
        sig: action::Signature::from([0u8; 64]),
    };
    let ad = Fp::from(ActionDigest::try_from(&action).unwrap());
    let sp_hdr = (ad, [nf0, nf1], target_epoch, note_id);
    (sb_proof, sp_hdr, action)
}

/// Builds a pool chain from genesis to a given height.
fn build_pool_chain(
    rng: &mut StdRng,
    app: mock_ragu::Application,
    num_blocks: u32,
) -> (mock_ragu::Proof, Anchor) {
    let h0 = BlockHeight(0);
    let genesis = Anchor::genesis(BlockHeight(0));
    let (mut proof, ()) = app.seed(rng, &pool::PoolSeed, h0).expect("pool seed");
    let mut anchor = genesis;

    for _ in 0..num_blocks {
        let new_height = anchor.block_height.next();
        // Synthetic block from a deterministic tachygram, padded to full subset.
        let tg = Tachygram::from(Fp::from(u64::from(u32::from(new_height)) * 1000 + 1));
        let block_arr = pad_tachygrams::<TEST_N>(&[tg]);
        let roots: Vec<Fp> = block_arr.iter().map(|elem| Fp::from(*elem)).collect();
        let block_cm = BlockCommit(SetCommit::from(polynomial::pedersen_commit(
            &polynomial::poly_from_roots(&roots),
        )));
        let pool_cm = if new_height.is_epoch_boundary() {
            PoolCommit(block_cm.0)
        } else {
            PoolCommit(anchor.pool_commit.0 + block_cm.0)
        };
        let new_block_chain = anchor.block_chain.chain(anchor.block_commit);
        let new_epoch_chain = if new_height.is_epoch_boundary() {
            anchor.epoch_chain.chain(anchor.pool_commit)
        } else {
            anchor.epoch_chain
        };

        let pcd = proof.carry::<pool::PoolHeader>(anchor);
        let trivial = mock_ragu::Proof::trivial().carry::<()>(());
        let (next_proof, ()) = app
            .fuse(rng, &pool::PoolStep, (block_cm, pool_cm), pcd, trivial)
            .expect("pool step");
        anchor = Anchor {
            block_height: new_height,
            block_commit: block_cm,
            pool_commit: pool_cm,
            block_chain: new_block_chain,
            epoch_chain: new_epoch_chain,
        };
        proof = next_proof;
    }

    (proof, anchor)
}

#[test]
fn output_stamp_then_verify() {
    let mut rng = StdRng::seed_from_u64(0);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let (stamp, action) = make_output_stamp(&mut rng, &sk);

    stamp
        .verify(&[action], &mut rng)
        .expect("verify should succeed");
}

#[test]
fn verify_rejects_wrong_action() {
    let mut rng = StdRng::seed_from_u64(1);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let (stamp, _action_a) = make_output_stamp(&mut rng, &sk);
    let (_stamp_b, action_b) = make_output_stamp(&mut rng, &sk);

    assert!(
        stamp.verify(&[action_b], &mut rng).is_err(),
        "verify with wrong action must fail"
    );
}

#[test]
fn merge_two_outputs_then_verify() {
    let mut rng = StdRng::seed_from_u64(2);
    let sk = private::SpendingKey::from([0x42u8; 32]);

    let (stamp_a, action_a) = make_output_stamp(&mut rng, &sk);
    let (stamp_b, action_b) = make_output_stamp(&mut rng, &sk);

    let acc_a = compute_action_acc(&[action_a]).unwrap();
    let acc_b = compute_action_acc(&[action_b]).unwrap();
    let merged = Stamp::prove_merge(&mut rng, stamp_a, acc_a, stamp_b, acc_b).expect("prove_merge");

    merged
        .verify(&[action_a, action_b], &mut rng)
        .expect("merged stamp should verify");
}

#[test]
fn merged_stamp_rejects_partial_actions() {
    let mut rng = StdRng::seed_from_u64(3);
    let sk = private::SpendingKey::from([0x42u8; 32]);

    let (stamp_a, action_a) = make_output_stamp(&mut rng, &sk);
    let (stamp_b, action_b) = make_output_stamp(&mut rng, &sk);

    let acc_a = compute_action_acc(&[action_a]).unwrap();
    let acc_b = compute_action_acc(&[action_b]).unwrap();
    let merged = Stamp::prove_merge(&mut rng, stamp_a, acc_a, stamp_b, acc_b).expect("prove_merge");

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
    let nk = *pak.nk();
    let ak = *pak.ak();
    let app = &*PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let target_epoch = Epoch(0);
    let nf0 = note.nullifier(&nk, target_epoch);
    let nf1 = note.nullifier(&nk, Epoch(target_epoch.0 + 1));
    let note_id = note.id(&nk);

    // Delegation -> NullifierStep
    let (nf_proof, nf_hdr, nf) =
        build_delegation_to_nullifier(&mut rng, *app, note, nk, note_id, target_epoch);
    assert_eq!(Fp::from(nf0), nf, "GGM tree leaf should equal nf0");

    // SpendableInit (NullifierHeader x PoolHeader -> SpendableHeader)
    let (spendable_proof, spendable_hdr) =
        build_spendable(&mut rng, *app, note, nk, nf_proof, &nf_hdr);
    let spendable_pcd = spendable_proof.carry::<SpendableHeader>(spendable_hdr);

    // SpendNullifier -> SpendBind
    let (sb_proof, sp_hdr, spend_action) =
        build_spend_pcd(&mut rng, *app, note, nk, ak, target_epoch);
    let sp_pcd = sb_proof.carry::<SpendHeader>(sp_hdr);

    // SpendStamp -> verify
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

/// SpendNullifierFuse: two NullifierHeaders (E, E+1) -> SpendNullifierHeader.
#[test]
fn spend_nullifier_fuse_from_two_delegation_chains() {
    let mut rng = StdRng::seed_from_u64(200);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let nk = *pak.nk();
    let app = &*PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let note_id = note.id(&nk);
    let epoch_e = Epoch(0);
    let epoch_e1 = Epoch(1);

    let (nf_proof_e, nf_hdr_e, nf_e) =
        build_delegation_to_nullifier(&mut rng, *app, note, nk, note_id, epoch_e);
    let (nf_proof_e1, nf_hdr_e1, nf_e1) =
        build_delegation_to_nullifier(&mut rng, *app, note, nk, note_id, epoch_e1);

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

    let expected_nf0 = note.nullifier(&nk, epoch_e);
    let expected_nf1 = note.nullifier(&nk, epoch_e1);
    assert_eq!(fused_hdr.0, expected_nf0);
    assert_eq!(fused_hdr.1, expected_nf1);

    let pcd = fused_proof.carry::<SpendNullifierHeader>(fused_hdr);
    app.rerandomize(pcd, &mut rng)
        .expect("rerandomize fused spend nullifier");
}

/// Helper: build an ExclusionHeader for a nullifier against a set of
/// tachygrams (single leaf, padded to TEST_N).
fn build_exclusion_proof(
    rng: &mut StdRng,
    app: mock_ragu::Application,
    nf: Nullifier,
    tachygrams: &[Tachygram],
) -> (mock_ragu::Proof, (Nullifier, SetCommit)) {
    let arr = pad_tachygrams::<TEST_N>(tachygrams);

    let roots: Vec<Fp> = arr.iter().map(|tg| Fp::from(*tg)).collect();
    let coeffs = polynomial::poly_from_roots(&roots);
    let scope = SetCommit::from(polynomial::pedersen_commit(&coeffs));

    let (proof, ()) = app
        .seed(rng, &ExclusionLeaf::<TEST_N>, (nf, &arr))
        .expect("exclusion leaf");

    (proof, (nf, scope))
}

/// Helper: build a partitioned exclusion proof from multiple subsets,
/// fused into one ExclusionHeader.
fn build_partitioned_exclusion(
    rng: &mut StdRng,
    app: mock_ragu::Application,
    nf: Nullifier,
    subsets: &[&[Tachygram]],
) -> (mock_ragu::Proof, (Nullifier, SetCommit)) {
    let mut proofs: Vec<(mock_ragu::Proof, (Nullifier, SetCommit))> = Vec::new();
    for tgs in subsets {
        let (proof, hdr) = build_exclusion_proof(rng, app, nf, tgs);
        proofs.push((proof, hdr));
    }

    while proofs.len() > 1 {
        let (right_proof, right_hdr) = proofs.pop().expect("non-empty");
        let (left_proof, left_hdr) = proofs.pop().expect("non-empty");
        let left_pcd = left_proof.carry::<ExclusionHeader>(left_hdr);
        let right_pcd = right_proof.carry::<ExclusionHeader>(right_hdr);
        let (fused_proof, ()) = app
            .fuse(rng, &ExclusionFuse, (), left_pcd, right_pcd)
            .expect("exclusion fuse");
        let fused_scope = left_hdr.1 + right_hdr.1;
        proofs.push((fused_proof, (nf, fused_scope)));
    }

    proofs.pop().expect("at least one subset")
}

/// SpendableEpochLift: epoch-final SpendableHeader x SpendableRolloverHeader.
///
/// Rollover built via ExclusionLeaf + NullifierExclusionFuse +
/// SpendableRollover. The new epoch's pool is a single synthetic block,
/// so one ExclusionLeaf covers the full epoch.
#[test]
fn spendable_epoch_lift_across_boundary() {
    let mut rng = StdRng::seed_from_u64(300);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let nk = *pak.nk();
    let app = &*PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let note_id = note.id(&nk);
    let epoch_size: u32 = 4096;

    // Build pool chain to epoch-final block (epoch_size - 1)
    let epoch_final_height = epoch_size - 1;
    let (_pool_proof_final, anchor_final) = build_pool_chain(&mut rng, *app, epoch_final_height);

    // Build nullifier for epoch 0
    let epoch_0 = Epoch(0);
    let (nf_proof_0, nf_hdr_0, _nf0) =
        build_delegation_to_nullifier(&mut rng, *app, note, nk, note_id, epoch_0);

    // SpendableInit at epoch 0 genesis
    let (spendable_proof_0, _) = build_spendable(&mut rng, *app, note, nk, nf_proof_0, &nf_hdr_0);

    // Construct spendable at epoch-final
    let spendable_hdr_final = (note_id, nf_hdr_0.0, anchor_final);
    let spendable_pcd_final = spendable_proof_0.carry::<SpendableHeader>(spendable_hdr_final);

    // Build pool at first block of epoch 1.
    let (pool_proof_e1, anchor_e1) = build_pool_chain(&mut rng, *app, epoch_size);

    // Build nullifier for epoch 1
    let epoch_1 = Epoch(1);
    let (nf_proof_1, nf_hdr_1, _) =
        build_delegation_to_nullifier(&mut rng, *app, note, nk, note_id, epoch_1);

    // Exclusion proof for epoch 1. Must cover the actual tachygrams
    // of block `epoch_size` (which build_pool_chain created) so that
    // scope == pool_commit. Pool resets at boundary, so pool_commit
    // is just this one block's polynomial commitment.
    let e1_tg = Tachygram::from(Fp::from(u64::from(epoch_size) * 1000 + 1));
    let (excl_proof_1, excl_hdr_1) = build_exclusion_proof(&mut rng, *app, nf_hdr_1.0, &[e1_tg]);

    // NullifierExclusionFuse: bind nullifier to exclusion.
    let nf_pcd_1 = nf_proof_1.carry::<delegation::NullifierHeader>(nf_hdr_1);
    let excl_pcd_1 = excl_proof_1.carry::<ExclusionHeader>(excl_hdr_1);
    let (nexcl_proof_1, ()) = app
        .fuse(&mut rng, &NullifierExclusionFuse, (), nf_pcd_1, excl_pcd_1)
        .expect("nullifier exclusion fuse e1");
    let nexcl_hdr_1 = (nf_hdr_1.0, nf_hdr_1.1, nf_hdr_1.2, excl_hdr_1.1);
    let nexcl_pcd_1 = nexcl_proof_1.carry::<NullifierExclusionHeader>(nexcl_hdr_1);

    // SpendableRollover
    let pool_pcd_e1 = pool_proof_e1.carry::<pool::PoolHeader>(anchor_e1);
    let (rollover_proof, ()) = app
        .fuse(&mut rng, &SpendableRollover, (), nexcl_pcd_1, pool_pcd_e1)
        .expect("spendable rollover");
    let rollover_hdr = (note_id, nf_hdr_1.0, anchor_e1);
    let rollover_pcd = rollover_proof.carry::<SpendableRolloverHeader>(rollover_hdr);

    // SpendableEpochLift: epoch-final x rollover -> new spendable
    let (lift_proof, ()) = app
        .fuse(
            &mut rng,
            &SpendableEpochLift,
            (),
            spendable_pcd_final,
            rollover_pcd,
        )
        .expect("spendable epoch lift");

    let lifted_hdr = (note_id, nf_hdr_1.0, anchor_e1);
    let lifted_pcd = lift_proof.carry::<SpendableHeader>(lifted_hdr);
    app.rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted spendable");
}

/// SpendableLift via ExclusionLeaf path: delta non-membership.
///
/// User builds SpendableInit at block 0, then an exclusion proof
/// covering blocks 1-3 (partitioned), binds via SpendableExclusionFuse,
/// and lifts to block 3.
#[test]
fn spendable_lift_within_epoch() {
    let mut rng = StdRng::seed_from_u64(350);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let nk = *pak.nk();
    let app = &*PROOF_SYSTEM;

    let note = Note {
        pk: sk.derive_payment_key(),
        value: note::Value::from(500u64),
        psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
        rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
    };
    let note_id = note.id(&nk);
    let epoch_0 = Epoch(0);

    let (nf_proof, nf_hdr, _) =
        build_delegation_to_nullifier(&mut rng, *app, note, nk, note_id, epoch_0);
    let (spendable_proof, spendable_hdr) =
        build_spendable(&mut rng, *app, note, nk, nf_proof, &nf_hdr);
    let start_anchor = spendable_hdr.2;

    // Build a pool chain from start_anchor to block 3.
    let mut anchor = start_anchor;
    let mut pool_proof = {
        let (proof, ()) = app
            .seed(&mut rng, &pool::PoolSeed, BlockHeight(0))
            .expect("pool seed");
        proof
    };
    for i in 1..=3u32 {
        let tg = Tachygram::from(Fp::from(u64::from(i) * 100));
        let block_arr = pad_tachygrams::<TEST_N>(&[tg]);
        let roots: Vec<Fp> = block_arr.iter().map(|elem| Fp::from(*elem)).collect();
        let bc = BlockCommit(SetCommit::from(polynomial::pedersen_commit(
            &polynomial::poly_from_roots(&roots),
        )));
        let pc = PoolCommit(anchor.pool_commit.0 + bc.0);
        let new_height = anchor.block_height.next();
        let new_block_chain = anchor.block_chain.chain(anchor.block_commit);
        let new_epoch_chain = if new_height.is_epoch_boundary() {
            anchor.epoch_chain.chain(anchor.pool_commit)
        } else {
            anchor.epoch_chain
        };

        let pcd = pool_proof.carry::<pool::PoolHeader>(anchor);
        let trivial = mock_ragu::Proof::trivial().carry::<()>(());
        let (next_proof, ()) = app
            .fuse(&mut rng, &pool::PoolStep, (bc, pc), pcd, trivial)
            .expect("pool step");

        anchor = Anchor {
            block_height: new_height,
            block_commit: bc,
            pool_commit: pc,
            block_chain: new_block_chain,
            epoch_chain: new_epoch_chain,
        };
        pool_proof = next_proof;
    }
    let target_anchor = anchor;

    // Partitioned exclusion proof covering the delta (blocks 1-3).
    let delta_tgs: [&[Tachygram]; 3] = [
        &[Tachygram::from(Fp::from(100u64))],
        &[Tachygram::from(Fp::from(200u64))],
        &[Tachygram::from(Fp::from(300u64))],
    ];
    let (excl_proof, excl_hdr) = build_partitioned_exclusion(&mut rng, *app, nf_hdr.0, &delta_tgs);
    let excl_pcd = excl_proof.carry::<ExclusionHeader>(excl_hdr);

    // SpendableExclusionFuse: bind spendable to exclusion.
    let spendable_pcd = spendable_proof.carry::<SpendableHeader>(spendable_hdr);
    let (sexcl_proof, ()) = app
        .fuse(
            &mut rng,
            &SpendableExclusionFuse,
            (),
            spendable_pcd,
            excl_pcd,
        )
        .expect("spendable exclusion fuse");
    let sexcl_hdr = (note_id, nf_hdr.0, start_anchor, excl_hdr.1);
    let sexcl_pcd = sexcl_proof.carry::<SpendableExclusionHeader>(sexcl_hdr);

    // SpendableLift
    let pool_pcd = pool_proof.carry::<pool::PoolHeader>(target_anchor);
    let (lifted_proof, ()) = app
        .fuse(&mut rng, &SpendableLift, (), sexcl_pcd, pool_pcd)
        .expect("spendable lift");

    let lifted_hdr = (
        note_id,
        nf_hdr.0,
        Anchor {
            epoch_chain: start_anchor.epoch_chain,
            ..target_anchor
        },
    );
    let lifted_pcd = lifted_proof.carry::<SpendableHeader>(lifted_hdr);
    app.rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted spendable");
}

/// SpendableLift rejects cross-epoch delta.
#[test]
fn spendable_lift_rejects_cross_epoch() {
    use mock_ragu::Step as _;

    let nf = Nullifier::from(Fp::from(42u64));
    let scope = SetCommit::identity(); // doesn't matter for this test

    let left_anchor = Anchor {
        block_height: BlockHeight(0), // epoch 0
        block_commit: BlockCommit(SetCommit::identity()),
        pool_commit: PoolCommit(SetCommit::identity()),
        block_chain: BlockChainHash::genesis(BlockHeight(0)),
        epoch_chain: EpochChainHash::genesis(BlockHeight(0)),
    };
    let right_anchor = Anchor {
        block_height: BlockHeight(4096), // epoch 1
        block_commit: BlockCommit(SetCommit::identity()),
        pool_commit: PoolCommit(SetCommit::identity()),
        block_chain: BlockChainHash::genesis(BlockHeight(0)),
        epoch_chain: EpochChainHash::genesis(BlockHeight(0)),
    };

    let left = (NoteId::from(Fp::ZERO), nf, left_anchor, scope);
    let right = right_anchor;

    let result = SpendableLift.witness((), left, right);
    assert!(
        result.is_err(),
        "spendable lift across epoch boundary must fail"
    );
}

/// StampLift: advances stamp anchor to a later block in the same epoch.
#[test]
fn stamp_lift_within_epoch() {
    let mut rng = StdRng::seed_from_u64(400);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let app = &*PROOF_SYSTEM;

    // Build pool to block 5
    let (_pool_proof_5, anchor_5) = build_pool_chain(&mut rng, *app, 5);

    // Make an output stamp anchored at block 5
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
    let tachygram_acc = compute_tachygram_acc(&stamp.tachygrams);

    // Build pool to block 10 (same epoch)
    let (pool_proof_10, anchor_10) = build_pool_chain(&mut rng, *app, 10);

    // StampLift from block 5 -> block 10
    let stamp_hdr = (action_acc, tachygram_acc, anchor_5);
    let stamp_pcd = stamp.proof.carry::<StampHeader>(stamp_hdr);
    let pool_pcd_10 = pool_proof_10.carry::<pool::PoolHeader>(anchor_10);

    let (lifted_proof, ()) = app
        .fuse(&mut rng, &header::StampLift, (), stamp_pcd, pool_pcd_10)
        .expect("stamp lift");

    let lifted_hdr = (action_acc, tachygram_acc, anchor_10);
    let lifted_pcd = lifted_proof.carry::<StampHeader>(lifted_hdr);
    app.rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted stamp");
}

/// MergeStamp rejects mismatched anchors.
#[test]
fn merge_stamp_rejects_mismatched_anchors() {
    let mut rng = StdRng::seed_from_u64(500);
    let sk = private::SpendingKey::from([0x42u8; 32]);

    // Stamp A at genesis anchor
    let (stamp_a, action_a) = make_output_stamp(&mut rng, &sk);
    let acc_a = compute_action_acc(&[action_a]).unwrap();

    // Stamp B at a different anchor (block 5)
    let app = &*PROOF_SYSTEM;
    let (_, anchor_5) = build_pool_chain(&mut rng, *app, 5);

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
    let acc_b = compute_action_acc(&[Action {
        cv: plan_b.cv(),
        rk: plan_b.rk,
        sig: action::Signature::from([0u8; 64]),
    }])
    .unwrap();
    let stamp_b = Stamp::prove_output(&mut rng, rcv_b, alpha_b, note_b, anchor_5)
        .expect("prove_output at block 5");

    // Merge should fail -- different anchors
    assert!(
        Stamp::prove_merge(&mut rng, stamp_a, acc_a, stamp_b, acc_b).is_err(),
        "merge with mismatched anchors must fail"
    );
}

/// Builds a SpendNullifierHeader PCD (stops before SpendBind).
///
/// Returns the PCD plus the action::Plan for the spend so the caller can
/// construct the stamp::Plan entry.
fn build_spend_nullifier_pcd(
    rng: &mut StdRng,
    app: mock_ragu::Application,
    note: Note,
    nk: NullifierKey,
    target_epoch: Epoch,
) -> (mock_ragu::Proof, (Nullifier, Nullifier, Epoch, NoteId)) {
    let note_id = note.id(&nk);
    let nf0 = note.nullifier(&nk, target_epoch);
    let nf1 = note.nullifier(&nk, Epoch(target_epoch.0 + 1));
    let (snf_proof, ()) = app
        .seed(rng, &spend::SpendNullifier, (note, nk, target_epoch))
        .expect("spend nullifier");
    let snf_hdr = (nf0, nf1, target_epoch, note_id);
    (snf_proof, snf_hdr)
}

/// Helper: create an output action descriptor + witness for stamp::Plan.
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
    let anchor = Anchor::genesis(BlockHeight(0));

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
    let nk = *pak.nk();
    let ak = *pak.ak();
    let app = &*PROOF_SYSTEM;
    let target_epoch = Epoch(0);

    // -- Spend side --
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
        ak.derive_action_public(&alpha)
    });
    let spend_action = Action {
        cv: spend_plan.cv(),
        rk: spend_plan.rk,
        sig: action::Signature::from([0u8; 64]),
    };
    let spend_desc = (spend_plan.cv(), spend_plan.rk);
    let spend_wit = (spend_alpha, spend_note, spend_rcv);

    // Build SpendNullifierHeader PCD (what sync service provides)
    let (snf_proof, snf_hdr) =
        build_spend_nullifier_pcd(&mut rng, *app, spend_note, nk, target_epoch);
    let snf_pcd = snf_proof.carry::<SpendNullifierHeader>(snf_hdr);

    // Build SpendableHeader PCD (what sync service provides)
    let note_id = spend_note.id(&nk);
    let (nf_proof, nf_hdr, _) =
        build_delegation_to_nullifier(&mut rng, *app, spend_note, nk, note_id, target_epoch);
    let (spendable_proof, spendable_hdr) =
        build_spendable(&mut rng, *app, spend_note, nk, nf_proof, &nf_hdr);
    let spendable_anchor = spendable_hdr.2;
    let spendable_pcd = spendable_proof.carry::<SpendableHeader>(spendable_hdr);

    // -- Output side --
    let (output_desc, output_wit, output_action) = make_output_plan_entry(&mut rng, &sk, 200);

    // -- Build and prove the plan --
    // Use the spendable anchor so output stamps match spend stamps.
    let plan = Plan::new(
        alloc::vec![(spend_desc, spend_wit)],
        alloc::vec![(output_desc, output_wit)],
        spendable_anchor,
    );

    let stamp = plan
        .prove(&mut rng, &pak, alloc::vec![(snf_pcd, spendable_pcd)])
        .expect("plan prove spend+output");

    stamp
        .verify(&[spend_action, output_action], &mut rng)
        .expect("mixed spend+output stamp should verify");
}

/// Plan::prove with no actions returns NoActions.
#[test]
fn plan_prove_rejects_empty() {
    let mut rng = StdRng::seed_from_u64(602);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let anchor = Anchor::genesis(BlockHeight(0));

    let plan = Plan::new(alloc::vec![], alloc::vec![], anchor);

    let result = plan.prove(&mut rng, &pak, alloc::vec![]);
    assert!(
        matches!(result, Err(ProveError::NoActions)),
        "empty plan must return NoActions"
    );
}

/// Plan::prove rejects mismatched spend PCD count.
#[test]
fn plan_prove_rejects_pcd_count_mismatch() {
    let mut rng = StdRng::seed_from_u64(603);
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let pak = sk.derive_proof_private();
    let ak = *pak.ak();
    let anchor = Anchor::genesis(BlockHeight(0));

    // Build a spend entry for the plan
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
        ak.derive_action_public(&alpha)
    });
    let spend_desc = (spend_plan.cv(), spend_plan.rk);
    let spend_wit = (spend_alpha, spend_note, spend_rcv);

    // Plan has 1 spend but 0 PCDs
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
    let app = &*PROOF_SYSTEM;

    // Build pool to block 5
    let (_pool_proof_5, anchor_5) = build_pool_chain(&mut rng, *app, 5);

    // Make an output stamp anchored at block 5
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
    let tachygram_acc = compute_tachygram_acc(&stamp.tachygrams);

    // Build pool into epoch 1 (block 4096)
    let (pool_proof_e1, anchor_e1) = build_pool_chain(&mut rng, *app, 4096);

    // StampLift from block 5 -> block 4096 should fail (cross-epoch)
    let stamp_hdr = (action_acc, tachygram_acc, anchor_5);
    let stamp_pcd = stamp.proof.carry::<StampHeader>(stamp_hdr);
    let pool_pcd_e1 = pool_proof_e1.carry::<pool::PoolHeader>(anchor_e1);

    let result = app.fuse(&mut rng, &header::StampLift, (), stamp_pcd, pool_pcd_e1);
    assert!(
        result.is_err(),
        "stamp lift across epoch boundary must fail"
    );
}

// ---- ExclusionSet (multi-nullifier batch) path ----

/// ExclusionSetLeaf + ExclusionSetFuse + ExclusionSetExtract roundtrip.
///
/// Two subsets, two nullifiers. Leaf each subset, fuse, extract each
/// nullifier into ExclusionHeader.
#[test]
fn exclusion_set_roundtrip() {
    let mut rng = StdRng::seed_from_u64(700);
    let app = &*PROOF_SYSTEM;
    let nf_a = Fp::from(555u64);
    let nf_b = Fp::from(777u64);
    let nullifiers = pad_nullifiers::<TEST_M>(&[nf_a, nf_b]);

    // Two distinct subsets of tachygrams.
    let tgs_1 = pad_tachygrams::<TEST_N>(&[
        Tachygram::from(Fp::from(10u64)),
        Tachygram::from(Fp::from(20u64)),
    ]);
    let tgs_2 = pad_tachygrams::<TEST_N>(&[
        Tachygram::from(Fp::from(30u64)),
        Tachygram::from(Fp::from(40u64)),
    ]);

    // Leaf 1
    let (leaf1_proof, ()) = app
        .seed(
            &mut rng,
            &ExclusionSetLeaf::<TEST_N, TEST_M>,
            (&tgs_1, &nullifiers),
        )
        .expect("exclusion set leaf 1");
    let roots1: Vec<Fp> = tgs_1.iter().map(|tg| Fp::from(*tg)).collect();
    let coeffs1 = polynomial::poly_from_roots(&roots1);
    let scope1 = SetCommit::from(polynomial::pedersen_commit(&coeffs1));
    let products1: Vec<Fp> = nullifiers
        .iter()
        .map(|&nf| polynomial::poly_eval(&coeffs1, nf))
        .collect();
    let nf_set = polynomial::pedersen_commit(nullifiers.as_slice());
    let prod_set1 = polynomial::pedersen_commit(&products1);
    let leaf1_pcd = leaf1_proof.carry::<ExclusionSetHeader<TEST_M>>((nf_set, prod_set1, scope1));

    // Leaf 2
    let (leaf2_proof, ()) = app
        .seed(
            &mut rng,
            &ExclusionSetLeaf::<TEST_N, TEST_M>,
            (&tgs_2, &nullifiers),
        )
        .expect("exclusion set leaf 2");
    let roots2: Vec<Fp> = tgs_2.iter().map(|tg| Fp::from(*tg)).collect();
    let coeffs2 = polynomial::poly_from_roots(&roots2);
    let scope2 = SetCommit::from(polynomial::pedersen_commit(&coeffs2));
    let products2: Vec<Fp> = nullifiers
        .iter()
        .map(|&nf| polynomial::poly_eval(&coeffs2, nf))
        .collect();
    let prod_set2 = polynomial::pedersen_commit(&products2);
    let leaf2_pcd = leaf2_proof.carry::<ExclusionSetHeader<TEST_M>>((nf_set, prod_set2, scope2));

    // Fuse
    let prods1_arr: [Fp; TEST_M] = products1.try_into().unwrap();
    let prods2_arr: [Fp; TEST_M] = products2.try_into().unwrap();
    let (fused_proof, ()) = app
        .fuse(
            &mut rng,
            &ExclusionSetFuse::<TEST_M>,
            (&prods1_arr, &prods2_arr),
            leaf1_pcd,
            leaf2_pcd,
        )
        .expect("exclusion set fuse");
    let merged_products: Vec<Fp> = prods1_arr
        .iter()
        .zip(prods2_arr.iter())
        .map(|(&lp, &rp)| lp * rp)
        .collect();
    let merged_scope = scope1 + scope2;
    let merged_prod_set = polynomial::pedersen_commit(&merged_products);

    // Extract nullifier A (index 0)
    let merged_products_arr: [Fp; TEST_M] = merged_products.try_into().unwrap();
    let fused_hdr = (nf_set, merged_prod_set, merged_scope);
    let fused_pcd_a = fused_proof.carry::<ExclusionSetHeader<TEST_M>>(fused_hdr);
    let (extract_a_proof, ()) = app
        .fuse(
            &mut rng,
            &ExclusionSetExtract::<TEST_M>,
            (&nullifiers, &merged_products_arr, 0usize),
            fused_pcd_a,
            mock_ragu::Proof::trivial().carry::<()>(()),
        )
        .expect("extract nullifier A");
    let excl_a_hdr = (Nullifier::from(nf_a), merged_scope);
    let excl_a_pcd = extract_a_proof.carry::<ExclusionHeader>(excl_a_hdr);
    app.rerandomize(excl_a_pcd, &mut rng)
        .expect("rerandomize exclusion A");
}

/// ExclusionSetExtract rejects when the product at the indexed slot is zero.
#[test]
fn exclusion_set_extract_rejects_zero_product() {
    use mock_ragu::Step as _;

    let nf_fp = Fp::from(42u64);
    let nullifiers = pad_nullifiers::<TEST_M>(&[nf_fp]);
    let mut products = [Fp::ONE; TEST_M];
    products[0] = Fp::ZERO; // nf is in the covered set

    let nf_set = polynomial::pedersen_commit(nullifiers.as_slice());
    let prod_set = polynomial::pedersen_commit(products.as_slice());
    let scope = SetCommit::identity();

    let left = (nf_set, prod_set, scope);
    let result = ExclusionSetExtract::<TEST_M>.witness((&nullifiers, &products, 0usize), left, ());
    assert!(
        result.is_err(),
        "extract must reject when product at indexed slot is zero"
    );
}

/// ExclusionLeaf rejects when nf IS a root (membership, not exclusion).
#[test]
fn exclusion_leaf_rejects_member() {
    use mock_ragu::Step as _;

    let member_tg = Tachygram::from(Fp::from(42u64));
    let nf = Nullifier::from(Fp::from(42u64)); // same value — is a root
    let tgs = pad_tachygrams::<TEST_N>(&[member_tg]);

    let result = ExclusionLeaf::<TEST_N>.witness((nf, &tgs), (), ());
    assert!(
        result.is_err(),
        "exclusion leaf must reject when nf is a root"
    );
}
