//! Proof-step tests: `StampLift`, `SpendBind`, the `Spendable*` lineage,
//! and the per-tachygram exclusion / inclusion seeds.

extern crate alloc;

use alloc::vec;

use ff::Field as _;
use pasta_curves::Fp;
use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::{CryptoRng, RngCore};

use super::{PROOF_SYSTEM, delegation, pool, spend, spendable, stamp};
use crate::{
    ActionSetCommit, TachygramSetCommit, TachygramSetPoly,
    constants::EPOCH_SIZE,
    entropy::ActionEntropy,
    fixtures::{
        PoolSim, SyncSim, WalletSim, build_anchor_chain_pcd, build_nullifier_rollover_pcd,
        build_output_stamp, build_unspent_pcd, build_unspent_seed_pcd,
        ggm_tools::{delegate_nullifier_from_master, delegate_range},
        random_block, random_block_with, spend_witness,
    },
    note::{self, Nullifier},
    primitives::{Anchor, BlockHeight, DelegationTrapdoor, EpochIndex, Tachygram, effect},
    value,
};

const NON_ADJACENT_EPOCH_PAIRS: &[(EpochIndex, EpochIndex)] = &[
    (EpochIndex(3), EpochIndex(3)),
    (EpochIndex(1), EpochIndex(4)),
    (EpochIndex(3), EpochIndex(0)),
];

fn tg<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Tachygram {
    Tachygram::from(Fp::random(rng))
}

#[test]
fn stamp_lift_within_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(1, |_| random_block(rng, 1, 4));
    let stamp_anchor = pool.anchor_at(BlockHeight(1));

    let note = user.random_note(rng, 200);
    let (stamp, plan) = build_output_stamp(rng, stamp_anchor, note);

    let action_commit: ActionSetCommit =
        ActionSetCommit::from([plan.digest().expect("valid plan")].as_slice());
    let tachygram_commit: TachygramSetCommit =
        TachygramSetCommit::from(stamp.tachygrams.as_slice());

    pool.advance(usize::try_from(EPOCH_SIZE - 2).expect("fits"), |_| {
        random_block(rng, 1, 4)
    });
    let new_height = pool.height();

    let stamp_pcd = stamp
        .proof
        .carry((action_commit, tachygram_commit, stamp_anchor));
    let anchor_chain = build_anchor_chain_pcd(rng, &pool, BlockHeight(2)..=new_height);

    let (lifted_pcd, ()) = PROOF_SYSTEM
        .fuse(rng, stamp::StampLift, (), stamp_pcd, anchor_chain)
        .expect("stamp lift");
    PROOF_SYSTEM
        .rerandomize(lifted_pcd, rng)
        .expect("rerandomize lifted stamp");
}

#[test]
fn spend_bind_rejects_invalid_inputs() {
    // Non-adjacent epoch pairs.
    for &(epoch_l, epoch_r) in NON_ADJACENT_EPOCH_PAIRS {
        let rng = &mut StdRng::seed_from_u64(0);
        let user = WalletSim::random(rng);
        let note = user.random_note(rng, 500);

        let nf_pcd_l = user.nullifier_pcd(rng, note, epoch_l);
        let nf_pcd_r = user.nullifier_pcd(rng, note, epoch_r);
        let (rcv, _theta, alpha) = spend_witness(rng, &note);

        let err = PROOF_SYSTEM
            .fuse(
                rng,
                spend::SpendBind,
                (rcv, alpha, user.pak, note),
                nf_pcd_l,
                nf_pcd_r,
            )
            .err().unwrap();
        assert_eq!(
            err.0, "SpendBind: nullifiers not adjacent",
            "epochs {epoch_l:?} {epoch_r:?}"
        );
    }

    // cm mismatch: leaves derived from two distinct notes (different cm)
    // are rejected by the `left_cm_tg == right_cm_tg` check.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let user = WalletSim::random(rng);
        let note_a = user.random_note(rng, 500);
        let note_b = user.random_note(rng, 500);
        assert_ne!(note_a.commitment(), note_b.commitment());

        let nf_now = user.nullifier_pcd(rng, note_a, EpochIndex(0));
        let nf_next = user.nullifier_pcd(rng, note_b, EpochIndex(1));
        let (rcv, _theta, alpha) = spend_witness(rng, &note_a);

        let err = PROOF_SYSTEM
            .fuse(
                rng,
                spend::SpendBind,
                (rcv, alpha, user.pak, note_a),
                nf_now,
                nf_next,
            )
            .err().unwrap();
        assert_eq!(err.0, "SpendBind: nullifiers not related");
    }

    // note↔leaf mismatch: leaves built from `note_a` but witness carries
    // `note_b` — the `Tachygram::from(note.commitment()) == left_cm_tg`
    // check rejects.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let user = WalletSim::random(rng);
        let note_a = user.random_note(rng, 500);
        let note_b = user.random_note(rng, 500);
        assert_ne!(note_a.commitment(), note_b.commitment());

        let (nf_now, nf_next) = user.nullifier_pair_pcd(rng, note_a, EpochIndex(0));
        let (rcv, _theta, alpha) = spend_witness(rng, &note_b);

        let err = PROOF_SYSTEM
            .fuse(
                rng,
                spend::SpendBind,
                (rcv, alpha, user.pak, note_b),
                nf_now,
                nf_next,
            )
            .err().unwrap();
        assert_eq!(err.0, "SpendBind: nullifiers not related to note");
    }

    // pk substitution: witness `pak_b` against `note_a` whose pk was derived
    // from `pak_a`.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let user_a = WalletSim::random(rng);
        let user_b = WalletSim::random(rng);
        assert_ne!(
            user_a.pak.derive_payment_key().0,
            user_b.pak.derive_payment_key().0,
        );
        let note_a = user_a.random_note(rng, 500);

        let (nf_now, nf_next) = user_a.nullifier_pair_pcd(rng, note_a, EpochIndex(0));
        let (rcv, _theta, alpha) = spend_witness(rng, &note_a);

        let err = PROOF_SYSTEM
            .fuse(
                rng,
                spend::SpendBind,
                (rcv, alpha, user_b.pak, note_a),
                nf_now,
                nf_next,
            )
            .err().unwrap();
        assert_eq!(err.0, "SpendBind: pak not related to note");
    }
}

#[test]
fn step_rejects_zero_value_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let target_epoch = EpochIndex(0);

    let zero_note = note::Note {
        pk: user.pak.derive_payment_key(),
        value: note::Value(0),
        psi: note::NullifierTrapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    };

    {
        let err = PROOF_SYSTEM
            .seed(rng, delegation::NfMasterSeed, (zero_note, user.pak))
            .err().unwrap();
        assert_eq!(err.0, "NfMasterSeed: zero-value note");
    }

    {
        let out_rcv = value::CommitmentTrapdoor::random(rng);
        let out_theta = ActionEntropy::random(rng);
        let out_alpha = out_theta.randomizer::<effect::Output>(zero_note.commitment());
        let out_anchor = PoolSim::genesis(rng).anchor();
        let err = PROOF_SYSTEM
            .seed(
                rng,
                stamp::OutputStamp,
                (out_rcv, out_alpha, zero_note, out_anchor),
            )
            .err().unwrap();
        assert_eq!(err.0, "OutputStamp: zero-value note");
    }

    {
        let valid_note = note::Note {
            value: note::Value(500),
            ..zero_note
        };
        let (nf_now_pcd, nf_next_pcd) = user.nullifier_pair_pcd(rng, valid_note, target_epoch);
        let spend_rcv = value::CommitmentTrapdoor::random(rng);
        let spend_theta = ActionEntropy::random(rng);
        let spend_alpha = spend_theta.randomizer::<effect::Spend>(valid_note.commitment());

        let err = PROOF_SYSTEM
            .fuse(
                rng,
                spend::SpendBind,
                (spend_rcv, spend_alpha, user.pak, zero_note),
                nf_now_pcd,
                nf_next_pcd,
            )
            .err().unwrap();
        assert_eq!(err.0, "SpendBind: zero-value note");

        // this should also fail the commitment test
        assert_ne!(valid_note.commitment(), zero_note.commitment());
    }
}

#[test]
fn spend_stamp_rejects_identity_cv() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);

    pool.mine(random_block_with(rng, &[alloc::vec![note.commitment()]], 4));
    let init_height = pool.height();
    let nf_pcd = user.nullifier_pcd(rng, note, EpochIndex(0));
    let spendable = user.spendable_init(rng, note, &pool, init_height, nf_pcd);

    let (nf_now_pcd, nf_next_pcd) = user.nullifier_pair_pcd(rng, note, EpochIndex(0));
    let (rcv, _theta, alpha) = spend_witness(rng, &note);
    let (real_spend, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (rcv, alpha, user.pak, note),
            nf_now_pcd,
            nf_next_pcd,
        )
        .expect("SpendBind");

    let (_real_cv, real_rk, real_nfs) = *real_spend.data();
    let identity_cv = value::Commitment::balance(0);
    let forged_spend =
        real_spend
            .proof()
            .clone()
            .carry::<spend::SpendHeader>((identity_cv, real_rk, real_nfs));

    let err = PROOF_SYSTEM
        .fuse(rng, stamp::SpendStamp, (), forged_spend, spendable)
        .err().unwrap();
    assert_eq!(err.0, "SpendStamp: action digest construction failed");
}

#[test]
fn spendable_epoch_lift_across_boundary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let trap = DelegationTrapdoor::random(rng);
    let delegation_id = user.pak.nk.derive_delegation_id(&note, trap);

    let epoch_0 = EpochIndex(0);
    let master = user.note_master(rng, note);
    let delegates = delegate_range(rng, &master, trap, epoch_0.0..=epoch_0.0 + 1);
    let mut sync = SyncSim::new();

    pool.mine(random_block_with(rng, &[alloc::vec![note.commitment()]], 4));
    let init_height = pool.height();
    let nf_pcd = user.nullifier_pcd(rng, note, epoch_0);
    let spendable_pcd = user.spendable_init(rng, note, &pool, init_height, nf_pcd);
    sync.accept_spendable(delegates, spendable_pcd);

    let remaining = usize::try_from(EPOCH_SIZE + 1 - pool.height().0).expect("fits");
    pool.advance(remaining, |_| random_block(rng, 1, 4));
    assert_eq!(pool.height().epoch().0, 1);
    sync.lift(rng, &pool);

    PROOF_SYSTEM
        .rerandomize(sync.spendable(delegation_id), rng)
        .expect("rerandomize lifted spendable");
}

#[test]
fn spendable_lift_rejects_invalid_inputs() {
    // prev_anchor mismatch: forge a SpendableHeader carrying a bogus anchor
    // that doesn't match the Unspent's prev_anchor.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let user = WalletSim::random(rng);
        let mut pool = PoolSim::genesis(rng);
        let note = user.random_note(rng, 500);

        pool.mine(random_block_with(rng, &[alloc::vec![note.commitment()]], 4));
        let init_height = pool.height();
        let nf_pcd = user.nullifier_pcd(rng, note, EpochIndex(0));
        let real_spendable = user.spendable_init(rng, note, &pool, init_height, nf_pcd);

        pool.advance(2, |_| random_block(rng, 1, 4));
        let target_height = pool.height();
        let unspent = build_unspent_pcd(
            rng,
            &pool,
            real_spendable.data().0,
            BlockHeight(init_height.0 + 1)..=target_height,
        );

        let forged_anchor = Anchor(Fp::random(&mut *rng));
        let forged_spendable = real_spendable
            .proof()
            .clone()
            .carry::<spendable::SpendableHeader>((real_spendable.data().0, forged_anchor));

        let err = PROOF_SYSTEM
            .fuse(rng, spendable::SpendableLift, (), forged_spendable, unspent)
            .err().unwrap();
        assert_eq!(err.0, "SpendableLift: unspent not adjacent to spendable");
    }

    // nf mismatch: spendable for note_a, unspent for note_b's nf.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let user = WalletSim::random(rng);
        let mut pool = PoolSim::genesis(rng);
        let note_a = user.random_note(rng, 100);
        let note_b = user.random_note(rng, 200);

        pool.mine(random_block_with(
            rng,
            &[alloc::vec![note_a.commitment()]],
            4,
        ));
        let init_height = pool.height();
        let nf_pcd_a = user.nullifier_pcd(rng, note_a, EpochIndex(0));
        let spendable_a = user.spendable_init(rng, note_a, &pool, init_height, nf_pcd_a);

        pool.advance(2, |_| random_block(rng, 1, 4));
        let target_height = pool.height();
        let nf_b = note_b.nullifier(&user.pak.nk, EpochIndex(0));
        let unspent_b = build_unspent_pcd(
            rng,
            &pool,
            nf_b,
            BlockHeight(init_height.0 + 1)..=target_height,
        );

        let err = PROOF_SYSTEM
            .fuse(rng, spendable::SpendableLift, (), spendable_a, unspent_b)
            .err().unwrap();
        assert_eq!(err.0, "SpendableLift: unspent does not relate to spendable");
    }
}

#[test]
fn spendable_init_rejects_tg_absent() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let note = user.random_note(rng, 500);

    let absent_set = TachygramSetPoly::from([tg(rng)].as_slice());
    let pre_cm_anchor = Anchor::default();
    let nf_pcd_absent = user.nullifier_pcd(rng, note, EpochIndex(0));
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            (pre_cm_anchor, absent_set),
            nf_pcd_absent,
            Proof::trivial().carry::<()>(()),
        )
        .err().unwrap();
    assert_eq!(err.0, "SpendableInit: commitment not in set");
}

#[test]
fn unspent_seed_rejects_tg_present() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let note = user.random_note(rng, 500);
    let nf = note.nullifier(&user.pak.nk, EpochIndex(0));

    let containing_set = TachygramSetPoly::from([nf.into()].as_slice());
    let start = Anchor::default();

    let err = PROOF_SYSTEM
        .seed(rng, pool::UnspentSeed, (start, containing_set, nf))
        .err().unwrap();
    assert_eq!(err.0, "UnspentSeed: found nullifier in set");
}

#[test]
fn delegate_rollover_fuse_rejects_invalid_inputs() {
    // delegation_id mismatch (different traps yield different ids).
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let user = WalletSim::random(rng);
        let note = user.random_note(rng, 500);
        let trap_a = DelegationTrapdoor::random(rng);
        let trap_b = DelegationTrapdoor::random(rng);
        assert_ne!(
            user.pak.nk.derive_delegation_id(&note, trap_a),
            user.pak.nk.derive_delegation_id(&note, trap_b),
        );

        let master_a = user.note_master(rng, note);
        let master_b = user.note_master(rng, note);
        let nf_a = delegate_nullifier_from_master(rng, master_a, trap_a, EpochIndex(0));
        let nf_b = delegate_nullifier_from_master(rng, master_b, trap_b, EpochIndex(1));

        let err = PROOF_SYSTEM
            .fuse(rng, spendable::DelegateRolloverFuse, (), nf_a, nf_b)
            .err().unwrap();
        assert_eq!(err.0, "DelegateRolloverFuse: nullifiers not related");
    }

    // Non-adjacent epoch pairs.
    for &(epoch_l, epoch_r) in NON_ADJACENT_EPOCH_PAIRS {
        let rng = &mut StdRng::seed_from_u64(0);
        let user = WalletSim::random(rng);
        let note = user.random_note(rng, 500);
        let trap = DelegationTrapdoor::random(rng);

        let master_a = user.note_master(rng, note);
        let master_b = user.note_master(rng, note);
        let nf_l = delegate_nullifier_from_master(rng, master_a, trap, epoch_l);
        let nf_r = delegate_nullifier_from_master(rng, master_b, trap, epoch_r);

        let err = PROOF_SYSTEM
            .fuse(rng, spendable::DelegateRolloverFuse, (), nf_l, nf_r)
            .err().unwrap();
        assert_eq!(
            err.0, "DelegateRolloverFuse: nullifiers not adjacent",
            "epochs {epoch_l:?} {epoch_r:?}"
        );
    }
}

#[test]
fn spendable_rollover_rejects_nf_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note_a = user.random_note(rng, 100);
    let note_b = user.random_note(rng, 200);

    pool.mine(random_block_with(
        rng,
        &[alloc::vec![note_a.commitment()]],
        4,
    ));
    let init_height = pool.height();
    let nf_pcd_a = user.nullifier_pcd(rng, note_a, EpochIndex(0));
    let spendable_a = user.spendable_init(rng, note_a, &pool, init_height, nf_pcd_a);

    let rollover_b = build_nullifier_rollover_pcd(rng, &user, note_b, EpochIndex(0));

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableRollover,
            (),
            spendable_a,
            rollover_b,
        )
        .err().unwrap();
    assert_eq!(err.0, "SpendableRollover: nullifiers don't match");
}

#[test]
fn spendable_epoch_lift_rejects_invalid_inputs() {
    // nf mismatch: rolled spendable for note_a, unspent for note_b's nf.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let user = WalletSim::random(rng);
        let mut pool = PoolSim::genesis(rng);
        let note_a = user.random_note(rng, 100);
        let note_b = user.random_note(rng, 200);

        pool.mine(random_block_with(
            rng,
            &[alloc::vec![note_a.commitment()]],
            4,
        ));
        let init_height = pool.height();
        let nf_pcd_a = user.nullifier_pcd(rng, note_a, EpochIndex(0));
        let spendable_a = user.spendable_init(rng, note_a, &pool, init_height, nf_pcd_a);

        let rollover_a = build_nullifier_rollover_pcd(rng, &user, note_a, EpochIndex(0));
        let (rolled_a, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spendable::SpendableRollover,
                (),
                spendable_a,
                rollover_a,
            )
            .expect("SpendableRollover");

        let nf_b = note_b.nullifier(&user.pak.nk, EpochIndex(0));
        let unspent_b = build_unspent_pcd(rng, &pool, nf_b, BlockHeight(0)..=init_height);

        let err = PROOF_SYSTEM
            .fuse(rng, spendable::SpendableEpochLift, (), rolled_a, unspent_b)
            .err().unwrap();
        assert_eq!(err.0, "SpendableEpochLift: nullifiers not related");
    }

    // prev_anchor mismatch: last_old_anchor flows from the spendable at
    // init_height, but the unspent is rooted at epoch_0_final's anchor.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let user = WalletSim::random(rng);
        let mut pool = PoolSim::genesis(rng);
        let note_a = user.random_note(rng, 500);

        pool.mine(random_block_with(
            rng,
            &[alloc::vec![note_a.commitment()]],
            4,
        ));
        let init_height = pool.height();
        pool.advance(usize::try_from(EPOCH_SIZE).expect("fits"), |_| {
            random_block(rng, 1, 4)
        });
        let epoch_1_first = BlockHeight(EPOCH_SIZE);

        let nf_pcd_a = user.nullifier_pcd(rng, note_a, EpochIndex(0));
        let spendable_a = user.spendable_init(rng, note_a, &pool, init_height, nf_pcd_a);
        let rollover_a = build_nullifier_rollover_pcd(rng, &user, note_a, EpochIndex(0));
        let nf_a_e1 = note_a.nullifier(&user.pak.nk, EpochIndex(1));
        let (rolled_a, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spendable::SpendableRollover,
                (),
                spendable_a,
                rollover_a,
            )
            .expect("SpendableRollover");

        let unspent = build_unspent_pcd(rng, &pool, nf_a_e1, epoch_1_first..=epoch_1_first);

        let err = PROOF_SYSTEM
            .fuse(rng, spendable::SpendableEpochLift, (), rolled_a, unspent)
            .err().unwrap();
        assert_eq!(
            err.0,
            "SpendableEpochLift: unspent prev_anchor must equal rollover boundary_anchor"
        );
    }
}

#[test]
fn rollover_fuse_rejects_invalid_inputs() {
    // cm mismatch: nullifiers from two different notes.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let user = WalletSim::random(rng);
        let note_a = user.random_note(rng, 100);
        let note_b = user.random_note(rng, 200);

        let nf_a = user.nullifier_pcd(rng, note_a, EpochIndex(0));
        let nf_b = user.nullifier_pcd(rng, note_b, EpochIndex(1));

        let err = PROOF_SYSTEM
            .fuse(rng, spendable::RolloverFuse, (), nf_a, nf_b)
            .err().unwrap();
        assert_eq!(err.0, "RolloverFuse: nullifiers not related");
    }

    // Non-adjacent epoch pairs.
    for &(epoch_l, epoch_r) in NON_ADJACENT_EPOCH_PAIRS {
        let rng = &mut StdRng::seed_from_u64(0);
        let user = WalletSim::random(rng);
        let note = user.random_note(rng, 500);

        let nf_l = user.nullifier_pcd(rng, note, epoch_l);
        let nf_r = user.nullifier_pcd(rng, note, epoch_r);

        let err = PROOF_SYSTEM
            .fuse(rng, spendable::RolloverFuse, (), nf_l, nf_r)
            .err().unwrap();
        assert_eq!(
            err.0, "RolloverFuse: nullifiers not adjacent",
            "epochs {epoch_l:?} {epoch_r:?}"
        );
    }
}

#[test]
fn unspent_fuse_rejects_invalid_compositions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let stamps_left = vec![tg(rng)];
    let stamps_right = vec![tg(rng)];
    let start = Anchor::default();
    let mid = start.next_stamp(&TachygramSetCommit::from(stamps_left.as_slice()));

    // nf mismatch: contiguous states but different nfs.
    {
        let nf_a = Nullifier::from(Fp::random(&mut *rng));
        let nf_b = Nullifier::from(Fp::random(&mut *rng));
        let shard_a = build_unspent_seed_pcd(rng, start, &stamps_left, nf_a);
        let shard_b = build_unspent_seed_pcd(rng, mid, &stamps_right, nf_b);
        let err = PROOF_SYSTEM
            .fuse(rng, pool::UnspentFuse, (), shard_a, shard_b)
            .err().unwrap();
        assert_eq!(err.0, "UnspentFuse: left and right must share the same nf");
    }

    // state discontinuity: same nf, but right's start matches `start`
    // instead of `left.end`.
    {
        let nf = Nullifier::from(Fp::random(&mut *rng));
        let shard_a = build_unspent_seed_pcd(rng, start, &stamps_left, nf);
        let shard_b = build_unspent_seed_pcd(rng, start, &stamps_right, nf);
        let err = PROOF_SYSTEM
            .fuse(rng, pool::UnspentFuse, (), shard_a, shard_b)
            .err().unwrap();
        assert_eq!(err.0, "UnspentFuse: left.end must equal right.start");
    }
}

#[test]
fn anchor_chain_fuse_rejects_invalid_compositions() {
    // anchor break: synthetic right-segment seeded from a bogus start anchor.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let mut pool = PoolSim::genesis(rng);
        pool.advance(2, |_| random_block(rng, 1, 2));

        let left = build_anchor_chain_pcd(rng, &pool, BlockHeight(0)..=BlockHeight(0));

        let bogus_start = Anchor(Fp::random(&mut *rng));
        let commit = pool.stamp_commits_at(BlockHeight(1))[0];
        let (right, ()) = PROOF_SYSTEM
            .seed(rng, pool::AnchorSeed, (bogus_start, commit))
            .expect("AnchorSeed");

        let err = PROOF_SYSTEM
            .fuse(rng, pool::AnchorFuse, (), left, right)
            .err().unwrap();
        assert_eq!(err.0, "AnchorFuse: segments not adjacent");
    }

    // cross-epoch: left segment ends at epoch_0_final's anchor, right segment
    // over the first block of epoch_1 starts at the boundary anchor.
    // Adjacency fails because the boundary anchor (via Anchor::next_epoch)
    // sits between them, and no AnchorChain step ever emits it.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let mut pool = PoolSim::genesis(rng);
        pool.advance(usize::try_from(EPOCH_SIZE + 1).expect("fits"), |_| {
            random_block(rng, 1, 2)
        });

        let left = build_anchor_chain_pcd(rng, &pool, BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1));
        let right = build_anchor_chain_pcd(
            rng,
            &pool,
            BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
        );

        let err = PROOF_SYSTEM
            .fuse(rng, pool::AnchorFuse, (), left, right)
            .err().unwrap();
        assert_eq!(err.0, "AnchorFuse: segments not adjacent");
    }
}

#[test]
fn unspent_fuse_rejects_cross_pool_or_cross_epoch() {
    // anchor break: two pools share the first and last block but diverge at
    // the middle, so `left` from pool_a ends at a height-2 anchor that
    // differs from `right`'s start in pool_b at the same height.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let mut pool_a = PoolSim::genesis(rng);
        let mut pool_b = PoolSim::genesis(rng);

        let shared_first = random_block(rng, 1, 2);
        pool_a.mine(shared_first.clone());
        pool_b.mine(shared_first);
        pool_a.mine(random_block(rng, 1, 2));
        pool_b.mine(random_block(rng, 1, 2));
        let shared_last = random_block(rng, 1, 2);
        pool_a.mine(shared_last.clone());
        pool_b.mine(shared_last);

        let nf = Nullifier::from(Fp::random(&mut *rng));
        let left = build_unspent_pcd(rng, &pool_a, nf, BlockHeight(1)..=BlockHeight(2));
        let right = build_unspent_pcd(rng, &pool_b, nf, BlockHeight(3)..=BlockHeight(3));

        let err = PROOF_SYSTEM
            .fuse(rng, pool::UnspentFuse, (), left, right)
            .err().unwrap();
        assert_eq!(err.0, "UnspentFuse: left.end must equal right.start");
    }

    // cross-epoch: ranges straddling the epoch boundary cannot fuse because
    // the boundary anchor (output of `Anchor::next_epoch`) sits in the sequence
    // between `left.end` and `right.start` — adjacency fails.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let mut pool = PoolSim::genesis(rng);
        pool.advance(usize::try_from(EPOCH_SIZE + 1).expect("fits"), |_| {
            random_block(rng, 1, 2)
        });

        let nf = Nullifier::from(Fp::random(&mut *rng));
        let left = build_unspent_pcd(rng, &pool, nf, BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1));
        let right = build_unspent_pcd(
            rng,
            &pool,
            nf,
            BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
        );

        let err = PROOF_SYSTEM
            .fuse(rng, pool::UnspentFuse, (), left, right)
            .err().unwrap();
        assert_eq!(err.0, "UnspentFuse: left.end must equal right.start");
    }
}

#[test]
fn empty_block_anchor_unique_per_height() {
    // Two consecutive empty blocks publish distinct anchors.
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.mine(vec![]);
    pool.mine(vec![]);

    let h1 = BlockHeight(1);
    let h2 = BlockHeight(2);
    assert_ne!(pool.anchor_at(h1), pool.anchor_at(h2));
    // h2's anchor is h1's anchor advanced via next_empty.
    assert_eq!(pool.anchor_at(h2), pool.anchor_at(h1).next_empty());
}

#[test]
fn empty_block_unspent_lifts_spendable() {
    // Build a spendable, then lift it across an empty block via an
    // Unspent built solely from EmptyBlockUnspentSeed.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let note = user.random_note(rng, 100);
    let cm = note.commitment();

    let mut pool = PoolSim::genesis(rng);
    let mut stamps = random_block(rng, 1, 4);
    stamps[1] = vec![cm.into()];
    pool.mine(stamps);
    let cm_height = pool.height();

    // Bootstrap spendable at the cm-block's published anchor.
    let nf_pcd = user.nullifier_pcd(rng, note, cm_height.epoch());
    let spendable = user.spendable_init(rng, note, &pool, cm_height, nf_pcd);
    let spendable_anchor_before = spendable.data().1;

    // Mine one empty block.
    pool.mine(vec![]);
    let empty_height = pool.height();

    // Build an Unspent over the empty block via EmptyBlockUnspentSeed,
    // then lift the spendable.
    let nf = spendable.data().0;
    let unspent = build_unspent_pcd(rng, &pool, nf, empty_height..=empty_height);
    let (lifted, ()) = PROOF_SYSTEM
        .fuse(rng, spendable::SpendableLift, (), spendable, unspent)
        .expect("SpendableLift across empty block");

    assert_eq!(lifted.data().1, spendable_anchor_before.next_empty());
    assert_eq!(lifted.data().1, pool.anchor_at(empty_height));
}
