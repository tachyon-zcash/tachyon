use ff::Field as _;
use pasta_curves::Fp;
use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    action,
    entropy::ActionEntropy,
    keys::{GGM_TREE_DEPTH, NullifierKey, SpendValidatingKey, private},
    note::{self, Note, Nullifier},
    primitives::{BlockCommit, BlockHeight, Epoch, NoteId, PoolCommit},
    value,
};

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

fn build_spendable(
    rng: &mut StdRng,
    app: mock_ragu::Application,
    note: Note,
    nk: NullifierKey,
    nf_proof: mock_ragu::Proof,
    nf_hdr: &(Nullifier, Epoch, NoteId),
) -> (mock_ragu::Proof, (NoteId, Nullifier, Anchor)) {
    let anchor = Anchor::genesis(BlockHeight(0));

    let (pool_proof, ()) = app
        .seed(rng, &pool::PoolSeed, BlockHeight(0))
        .expect("pool seed");
    let pool_pcd = pool_proof.carry::<pool::PoolHeader>(anchor);

    let nf_pcd = nf_proof.carry::<delegation::NullifierHeader>(*nf_hdr);

    let (spendable_proof, ()) = app
        .fuse(rng, &spendable::SpendableInit, (note, nk), nf_pcd, pool_pcd)
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
    let snf_pcd = snf_proof.carry::<spend::SpendNullifierHeader>(snf_hdr);
    let (sb_proof, ()) = app
        .fuse(
            rng,
            &spend::SpendBind,
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
        let block_cm = BlockCommit::from(Fp::from(u64::from(u32::from(new_height))));
        let pool_cm = PoolCommit::from(Fp::from(u64::from(u32::from(new_height)) + 1000));
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

// ---- Output path tests ----

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

    let merged = Stamp::prove_merge(&mut rng, stamp_a, stamp_b).expect("prove_merge");

    merged
        .verify(&[action_a, action_b], &mut rng)
        .expect("merged stamp should verify");
}

#[test]
fn merged_stamp_rejects_partial_actions() {
    let mut rng = StdRng::seed_from_u64(3);
    let sk = private::SpendingKey::from([0x42u8; 32]);

    let (stamp_a, action_a) = make_output_stamp(&mut rng, &sk);
    let (stamp_b, _action_b) = make_output_stamp(&mut rng, &sk);

    let merged = Stamp::prove_merge(&mut rng, stamp_a, stamp_b).expect("prove_merge");

    assert!(
        merged.verify(&[action_a], &mut rng).is_err(),
        "verify with partial actions must fail"
    );
}

// ---- Spend path tests ----

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
    let spendable_pcd = spendable_proof.carry::<spendable::SpendableHeader>(spendable_hdr);

    // SpendNullifier -> SpendBind
    let (sb_proof, sp_hdr, spend_action) =
        build_spend_pcd(&mut rng, *app, note, nk, ak, target_epoch);
    let sp_pcd = sb_proof.carry::<spend::SpendHeader>(sp_hdr);

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

// ---- SpendNullifierFuse test ----

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

    let pcd = fused_proof.carry::<spend::SpendNullifierHeader>(fused_hdr);
    app.rerandomize(pcd, &mut rng)
        .expect("rerandomize fused spend nullifier");
}

// ---- Epoch transition tests ----

/// SpendableEpochLift: epoch-final SpendableHeader x SpendableRolloverHeader.
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

    // Construct spendable at epoch-final (SpendableLift has TODO stubs)
    let spendable_hdr_final = (note_id, nf_hdr_0.0, anchor_final);
    let spendable_pcd_final =
        spendable_proof_0.carry::<spendable::SpendableHeader>(spendable_hdr_final);

    // Build pool at first block of epoch 1
    let (pool_proof_e1, anchor_e1) = build_pool_chain(&mut rng, *app, epoch_size);

    // Build nullifier for epoch 1
    let epoch_1 = Epoch(1);
    let (nf_proof_1, nf_hdr_1, _) =
        build_delegation_to_nullifier(&mut rng, *app, note, nk, note_id, epoch_1);
    let nf_pcd_1 = nf_proof_1.carry::<delegation::NullifierHeader>(nf_hdr_1);

    // SpendableRollover at epoch 1
    let pool_pcd_e1 = pool_proof_e1.carry::<pool::PoolHeader>(anchor_e1);
    let (rollover_proof, ()) = app
        .fuse(
            &mut rng,
            &spendable::SpendableRollover,
            (),
            nf_pcd_1,
            pool_pcd_e1,
        )
        .expect("spendable rollover");
    let rollover_hdr = (note_id, nf_hdr_1.0, anchor_e1);
    let rollover_pcd = rollover_proof.carry::<spendable::SpendableRolloverHeader>(rollover_hdr);

    // SpendableEpochLift: epoch-final x rollover -> new spendable
    let (lift_proof, ()) = app
        .fuse(
            &mut rng,
            &spendable::SpendableEpochLift,
            (),
            spendable_pcd_final,
            rollover_pcd,
        )
        .expect("spendable epoch lift");

    let lifted_hdr = (note_id, nf_hdr_1.0, anchor_e1);
    let lifted_pcd = lift_proof.carry::<spendable::SpendableHeader>(lifted_hdr);
    app.rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted spendable");
}

// ---- SpendableLift test ----

/// SpendableLift: advances spendable anchor within the same epoch.
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

    // Build nullifier for epoch 0
    let (nf_proof, nf_hdr, _) =
        build_delegation_to_nullifier(&mut rng, *app, note, nk, note_id, epoch_0);

    // SpendableInit at genesis
    let (spendable_proof, spendable_hdr) =
        build_spendable(&mut rng, *app, note, nk, nf_proof, &nf_hdr);

    // Build pool to block 5 (same epoch)
    let (pool_proof_5, anchor_5) = build_pool_chain(&mut rng, *app, 5);

    // SpendableLift from genesis -> block 5
    let spendable_pcd = spendable_proof.carry::<spendable::SpendableHeader>(spendable_hdr);
    let pool_pcd_5 = pool_proof_5.carry::<pool::PoolHeader>(anchor_5);

    let (lifted_proof, ()) = app
        .fuse(
            &mut rng,
            &spendable::SpendableLift,
            (),
            spendable_pcd,
            pool_pcd_5,
        )
        .expect("spendable lift");

    let lifted_hdr = (
        note_id,
        nf_hdr.0,
        Anchor {
            epoch_chain: spendable_hdr.2.epoch_chain,
            ..anchor_5
        },
    );
    let lifted_pcd = lifted_proof.carry::<spendable::SpendableHeader>(lifted_hdr);
    app.rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted spendable");
}

/// SpendableLift rejects target in a different epoch.
#[test]
fn spendable_lift_rejects_cross_epoch() {
    let mut rng = StdRng::seed_from_u64(351);
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

    // Build pool into epoch 1 (block 4096)
    let (pool_proof_e1, anchor_e1) = build_pool_chain(&mut rng, *app, 4096);

    let spendable_pcd = spendable_proof.carry::<spendable::SpendableHeader>(spendable_hdr);
    let pool_pcd_e1 = pool_proof_e1.carry::<pool::PoolHeader>(anchor_e1);

    let result = app.fuse(
        &mut rng,
        &spendable::SpendableLift,
        (),
        spendable_pcd,
        pool_pcd_e1,
    );
    assert!(
        result.is_err(),
        "spendable lift across epoch boundary must fail"
    );
}

// ---- StampLift test ----

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
    let stamp = Stamp::prove_output(&mut rng, rcv, alpha, note, anchor_5).expect("prove_output");

    // Build pool to block 10 (same epoch)
    let (pool_proof_10, anchor_10) = build_pool_chain(&mut rng, *app, 10);

    // StampLift from block 5 -> block 10
    let stamp_hdr = (stamp.action_acc, stamp.tachygram_acc, anchor_5);
    let stamp_pcd = stamp.proof.carry::<StampHeader>(stamp_hdr);
    let pool_pcd_10 = pool_proof_10.carry::<pool::PoolHeader>(anchor_10);

    let (lifted_proof, ()) = app
        .fuse(&mut rng, &header::StampLift, (), stamp_pcd, pool_pcd_10)
        .expect("stamp lift");

    let lifted_hdr = (stamp.action_acc, stamp.tachygram_acc, anchor_10);
    let lifted_pcd = lifted_proof.carry::<StampHeader>(lifted_hdr);
    app.rerandomize(lifted_pcd, &mut rng)
        .expect("rerandomize lifted stamp");
}

// ---- Anchor enforcement test ----

/// MergeStamp rejects mismatched anchors.
#[test]
fn merge_stamp_rejects_mismatched_anchors() {
    let mut rng = StdRng::seed_from_u64(500);
    let sk = private::SpendingKey::from([0x42u8; 32]);

    // Stamp A at genesis anchor
    let (stamp_a, _action_a) = make_output_stamp(&mut rng, &sk);

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
    let alpha_b = theta_b.randomizer::<effect::Output>(&note_b.commitment());
    let stamp_b = Stamp::prove_output(&mut rng, rcv_b, alpha_b, note_b, anchor_5)
        .expect("prove_output at block 5");

    // Merge should fail -- different anchors
    assert!(
        Stamp::prove_merge(&mut rng, stamp_a, stamp_b).is_err(),
        "merge with mismatched anchors must fail"
    );
}
