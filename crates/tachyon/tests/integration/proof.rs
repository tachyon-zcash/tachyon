//! Proof-step tests: `StampLift`, `SpendBind` / `SpendStamp`, the flat
//! nullifier-derivation chain, `ArbitraryUnspent` composition, and the
//! `Spendable*` lineage.

extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};
use core::{array, iter};

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Pcd, Proof};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use zcash_tachyon::{
    ActionSetPoly, Anchor, BlockHeight, EpochIndex, NfSeqPoly, Note, Tachygram, TachygramSetPoly,
    constants::{EPOCH_MAX, EPOCH_SIZE},
    digest::poseidon,
    effect,
    entropy::ActionEntropy,
    note,
    nullifier::{self, NF_DERIVATION_WIDTH, Nullifier},
    stamp::proof::{PROOF_SYSTEM, delegation, output, pool, spend, spendable, stamp},
    value, witness,
};

use crate::fixtures::{
    PoolSim, SyncSim, WalletSim, build_anchor_chain_pcd, build_output_plan, build_output_stamp,
    build_unspent_pcd_over_epochs, qr_bucket_segment, random_block, random_block_with,
    seal_qr_intake, seed_qr_empty_intake, shared_sk, spend_witness,
};

fn mine_cm_block(rng: &mut StdRng, pool: &mut PoolSim, cm: note::Commitment) -> BlockHeight {
    pool.mine(random_block_with(rng, &[alloc::vec![cm]], 4));
    pool.height()
}

/// Mine blocks of two stamps each until `height` exists.
fn mine_through(rng: &mut StdRng, pool: &mut PoolSim, height: BlockHeight) {
    while pool.height() < height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
}

/// A pool whose epoch zero publishes `note` and then closes, with the entry
/// block of epoch one mined.
fn pool_closing_epoch_zero(rng: &mut StdRng, note: &Note) -> PoolSim {
    let mut pool = PoolSim::genesis(rng);
    mine_cm_block(rng, &mut pool, note.commitment());
    mine_through(rng, &mut pool, EpochIndex::new(1).first_block());
    pool
}

/// The note's segment over the whole of epoch zero, with the members its
/// `elapsed` holds.
fn epoch_zero_unspent(
    rng: &mut StdRng,
    pool: &PoolSim,
    user: &WalletSim,
    note: &Note,
) -> (Pcd<pool::ArbitraryUnspent>, Vec<Nullifier>) {
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    let unspent =
        build_unspent_pcd_over_epochs(rng, pool, |epoch| user.nf_at(note, epoch), (epoch0, epoch1));
    (unspent, vec![user.nf_at(note, epoch0)])
}

/// The segment of an empty bucket for `epoch`, sealed on a random predecessor
/// no pool published: an [`ArbitraryUnspent`](pool::ArbitraryUnspent) at an
/// arbitrary epoch without building the epochs before it.
fn detached_segment(
    rng: &mut StdRng,
    epoch: EpochIndex,
    nf: impl Fn(EpochIndex) -> Nullifier,
) -> Pcd<pool::ArbitraryUnspent> {
    let anchor_final_prev = Anchor::from(Fp::random(&mut *rng));
    let discriminant = zcash_tachyon::QrDiscriminant::from(Fp::random(&mut *rng));
    let intake = seed_qr_empty_intake(
        rng,
        anchor_final_prev.next_epoch(epoch).unwrap(),
        epoch,
        discriminant,
    );
    let bucket = seal_qr_intake(rng, intake, anchor_final_prev);
    qr_bucket_segment(rng, &bucket, nf)
}

fn mine_cm_in_epoch_one<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &mut PoolSim,
    cm: note::Commitment,
) -> BlockHeight {
    // Height EPOCH_SIZE is epoch 1's first block, carrying the real B_1 fold.
    while pool.height().0 < EPOCH_SIZE {
        pool.mine(random_block(rng, 1, 3));
    }
    pool.mine(random_block_with(rng, &[alloc::vec![cm]], 4));
    let cm_height = pool.height();
    assert_eq!(
        cm_height.epoch(),
        EpochIndex::new(1),
        "cm-block is in epoch 1"
    );
    cm_height
}

fn honest_spend_bind(
    rng: &mut StdRng,
    user: &WalletSim,
    note: &Note,
    spendable: Pcd<spendable::NoteSpendable>,
) -> Pcd<spend::SpendHeader> {
    let secret_pcd = honest_secret(rng, user, *note);
    let rcv = value::Trapdoor::random(rng);
    let (bind_pcd, ()) = PROOF_SYSTEM
        .fuse(rng, spend::SpendBind, (rcv,), spendable, secret_pcd)
        .expect("SpendBind honest");
    bind_pcd
}

fn honest_spend_stamp(
    rng: &mut StdRng,
    user: &WalletSim,
    note: &Note,
    bind_pcd: Pcd<spend::SpendHeader>,
) -> Pcd<stamp::Stamp> {
    let (_rcv, _theta, alpha) = spend_witness(rng, note);
    let (stamp, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::SpendStamp,
            witness::spend_stamp((*bind_pcd.data(), ()), alpha, user.pak),
            bind_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("SpendStamp honest");
    stamp
}

#[test]
fn same_epoch_honest_spend_accepted() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let cm_height = mine_cm_in_epoch_one(rng, &mut pool, note.commitment());
    let epoch = cm_height.epoch();

    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable);
    let stamp = honest_spend_stamp(rng, &user, &note, bind_pcd);

    let expected = TachygramSetPoly::from_iter([
        user.nf_at(&note, epoch).into(),
        user.nf_at(&note, epoch.next().unwrap()).into(),
    ])
    .commit();
    assert_eq!(stamp.data().1, expected, "publishes {{N_E, N_E+1}}");
    PROOF_SYSTEM
        .rerandomize(stamp, rng)
        .expect("rerandomize honest same-epoch spend");
}

#[test]
fn stamp_lift_within_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);

    pool.advance(1, |_| random_block(rng, 1, 4));
    let stamp_anchor = pool.block(BlockHeight(1)).anchor();

    let note = user.random_note(200);
    let (stamp, plan) = build_output_stamp(rng, stamp_anchor, note);

    let action_commit = ActionSetPoly::from_iter([plan.digest().expect("valid plan")]).commit();
    let tachygram_commit = TachygramSetPoly::from_iter(stamp.tachygrams).commit();

    pool.advance(EPOCH_SIZE - 2, |_| random_block(rng, 1, 4));
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
fn spendable_init_rejects_tg_absent() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let nf_header = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(0));
    let absent_tg = Tachygram::from(Fp::random(&mut *rng));

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            witness::spendable_init(
                (*nf_header.data(), ()),
                Anchor::default(),
                &[absent_tg],
                EpochIndex::new(0),
            ),
            nf_header,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "SpendableInit: commitment not in set");
}

#[test]
fn unspent_fuse_rejects_invalid_compositions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    mine_through(rng, &mut pool, EpochIndex::new(2).last_block());
    let nf: [Nullifier; 3] = array::from_fn(|_| Nullifier::from(Fp::random(&mut *rng)));
    let at = |epoch: EpochIndex| nf[usize::try_from(u32::from(epoch)).unwrap()];

    // Anchor discontinuity: the right segment skips epoch one.
    let left =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(0), EpochIndex::new(1)));
    let right =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(2), EpochIndex::new(3)));
    let w = witness::unspent_fuse((*left.data(), *right.data()), &nf[0..1], &nf[2..3]);
    let err = PROOF_SYSTEM
        .fuse(rng, pool::UnspentFuse, w, left, right)
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentFuse: left.anchor_next must equal right.anchor_start"
    );
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
        let stamps = pool.block(BlockHeight(1)).tachygrams();
        let (right, ()) = PROOF_SYSTEM
            .seed(
                rng,
                pool::AnchorSeed,
                witness::anchor_seed(((), ()), bogus_start, BlockHeight(1).epoch(), &stamps[0]),
            )
            .expect("AnchorSeed");

        let err = PROOF_SYSTEM
            .fuse(rng, pool::AnchorFuse, (), left, right)
            .err()
            .unwrap();
        let ragu_core::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(inner.to_string(), "AnchorFuse: paths do not share a vertex");
    }

    // cross-epoch: left segment ends at epoch_0_final's anchor, right segment
    // over the first block of epoch_1 starts at the entry anchor.
    // Adjacency fails because the entry anchor (via Anchor::next_epoch)
    // sits between them, and no AnchorChain step ever emits it.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let mut pool = PoolSim::genesis(rng);
        pool.advance(EPOCH_SIZE + 1, |_| random_block(rng, 1, 2));

        let left = build_anchor_chain_pcd(rng, &pool, BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1));
        let right = build_anchor_chain_pcd(
            rng,
            &pool,
            BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
        );

        let err = PROOF_SYSTEM
            .fuse(rng, pool::AnchorFuse, (), left, right)
            .err()
            .unwrap();
        let ragu_core::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(inner.to_string(), "AnchorFuse: paths do not share a vertex");
    }
}

#[test]
fn empty_blocks_do_not_advance_the_anchor() {
    // A block that publishes no stamp contributes no anchor link, so a run of
    // empty blocks shares the anchor of the last block that did publish one.
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block(rng, 1, 2));
    pool.mine(vec![]);
    pool.mine(vec![]);

    let stamped = BlockHeight(1);
    assert_eq!(
        pool.block(BlockHeight(2)).anchor(),
        pool.block(stamped).anchor()
    );
    assert_eq!(
        pool.block(BlockHeight(3)).anchor(),
        pool.block(stamped).anchor()
    );
}

#[test]
fn spendable_stays_current_across_empty_blocks() {
    // A note idling over a stampless span needs no proof work at all: the pool
    // anchor never leaves the spendable's, so there is nothing to lift over.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(100);
    let cm = note.commitment();

    let mut pool = PoolSim::genesis(rng);
    pool.mine(vec![vec![cm.into()]]);
    let cm_height = pool.height();

    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let spendable_anchor = spendable.data().2;

    pool.mine(vec![]);
    pool.mine(vec![]);

    assert_eq!(pool.block(pool.height()).anchor(), spendable_anchor);
}

#[test]
fn spend_bind_honest() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let (_cm, nf_current, nf_next, _anchor, _pk, _cv) = *bind_pcd.data();
    assert_eq!(nf_current, user.nf_at(&note, spend_epoch));
    assert_eq!(nf_next, user.nf_at(&note, spend_epoch.next().unwrap()));
}

/// A forged note reaches `SpendBind` only as the secret of another
/// commitment, and `SpendStamp` requires `pak` to derive the bound note's
/// `pk`.
#[test]
fn spend_rejects_invalid_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let other = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();

    let phantom = Note {
        value: value::Positive::try_from(999_999u64).expect("test value in range"),
        rcm: note::CommitmentTrapdoor::random(rng),
        ..note
    };
    assert_eq!(Fp::from(note.psi), Fp::from(phantom.psi), "shared psi");
    assert_ne!(note.commitment(), phantom.commitment(), "distinct cm");

    let wrong_value = value::Positive::try_from(999_999u64).expect("test value in range");
    assert_ne!(u64::from(wrong_value), u64::from(note.value));

    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    // `SpendBind` reads the value off a certified `NoteSecret`, so forging it
    // means supplying a secret for a different note.
    let forgeries = [
        ("value inflation", phantom),
        (
            "wrong value",
            Note {
                value: wrong_value,
                ..note
            },
        ),
    ];
    for (label, forged) in forgeries {
        let secret_pcd = honest_secret(rng, &user, forged);
        let rcv = value::Trapdoor::random(rng);
        let err = PROOF_SYSTEM
            .fuse(
                rng,
                spend::SpendBind,
                (rcv,),
                spendable_pcd.clone(),
                secret_pcd,
            )
            .err()
            .unwrap();
        let ragu_core::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "SpendBind: secret does not match note",
            "{label}"
        );
    }

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let (_rcv, _theta, alpha) = spend_witness(rng, &note);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::SpendStamp,
            witness::spend_stamp((*bind_pcd.data(), ()), alpha, other.pak),
            bind_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "SpendStamp: pak not related to note");
}

/// Zero-value notes are valid, so both stamping steps accept them: an output
/// mints one, and a spend consumes one.
#[test]
fn step_accepts_zero_value_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());

    {
        let zero_note = Note {
            pk: user.pak.derive_payment_key(),
            value: value::Positive::try_from(0u64).expect("zero is in range"),
            psi: nullifier::Trapdoor::random(rng),
            rcm: note::CommitmentTrapdoor::random(rng),
        };
        let out_rcv = value::Trapdoor::random(rng);
        let out_theta = ActionEntropy::random(rng);
        let out_alpha = out_theta.randomizer::<effect::Output>(zero_note.commitment());
        let out_anchor = PoolSim::genesis(rng).anchor();

        let (bind_pcd, ()) = PROOF_SYSTEM
            .seed(rng, output::OutputBind, (zero_note, out_rcv))
            .expect("bind of a zero-value note");

        PROOF_SYSTEM
            .fuse(
                rng,
                stamp::OutputStamp,
                witness::output_stamp((*bind_pcd.data(), ()), out_alpha, out_anchor),
                bind_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("output of a zero-value note");
    }

    {
        let mut pool = PoolSim::genesis(rng);
        let note = user.random_note(0);
        pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
        let height = pool.height();
        let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
        let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);

        let (_rcv, _theta, alpha) = spend_witness(rng, &note);
        PROOF_SYSTEM
            .fuse(
                rng,
                stamp::SpendStamp,
                witness::spend_stamp((*bind_pcd.data(), ()), alpha, user.pak),
                bind_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("spend of a zero-value note");
    }
}

#[test]
fn spend_after_lift_publishes_anchor_epoch_nullifiers() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());
    let epoch1 = EpochIndex::new(1);
    let epoch2 = EpochIndex::new(2);
    mine_through(rng, &mut pool, epoch2.first_block());

    let spendable = user.spendable_at(rng, &pool, &note, epoch1);
    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![user.nf_at(&note, epoch1), user.nf_at(&note, epoch2)],
        epoch1,
    );
    let unspent = sync.build_next_unspent(rng, 0, &pool, epoch2);
    let lifted = user.lift(rng, spendable, unspent, &note);

    let bind_pcd = honest_spend_bind(rng, &user, &note, lifted);
    let (_cm, nf_current, _nf_next, _anchor, _pk, _cv) = *bind_pcd.data();
    assert_eq!(
        nf_current,
        user.nf_at(&note, epoch2),
        "publishes the epoch-2 nf"
    );
    assert_ne!(
        nf_current,
        user.nf_at(&note, epoch1),
        "nf_1 was consumed by the lift"
    );

    let stamp = honest_spend_stamp(rng, &user, &note, bind_pcd);
    let expected = TachygramSetPoly::from_iter([
        user.nf_at(&note, epoch2).into(),
        user.nf_at(&note, EpochIndex::new(3)).into(),
    ])
    .commit();
    assert_eq!(stamp.data().1, expected);
}

#[test]
fn spend_stamp_assembles_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let stamp_pcd = honest_spend_stamp(rng, &user, &note, bind_pcd);
    let (_actions, tg_commit, _anchor) = *stamp_pcd.data();
    let expected = TachygramSetPoly::from_iter([
        Tachygram::from(user.nf_at(&note, spend_epoch)),
        Tachygram::from(user.nf_at(&note, spend_epoch.next().unwrap())),
    ])
    .commit();
    assert_eq!(tg_commit, expected);
}

#[test]
fn sync_sim_builds_unspent_for_wallet_lift_across_epochs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());
    let epoch1 = EpochIndex::new(1);
    let epoch2 = EpochIndex::new(2);
    mine_through(rng, &mut pool, epoch2.first_block());

    let spendable = user.spendable_at(rng, &pool, &note, epoch1);
    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![user.nf_at(&note, epoch1), user.nf_at(&note, epoch2)],
        epoch1,
    );

    let unspent = sync.build_next_unspent(rng, 0, &pool, epoch2);
    assert_eq!(sync.consumed(0), 1);

    let lifted = user.lift(rng, spendable, unspent, &note);

    assert_eq!(lifted.data().1, epoch2, "lineage advanced to epoch 2");
    assert_eq!(
        lifted.data().2,
        pool.block(epoch2.first_block()).prev,
        "anchor advanced to epoch 2's entry anchor"
    );
    assert_eq!(lifted.data().0, note.commitment(), "cm threaded unchanged");
}

#[test]
fn unspent_lift_spans_several_whole_epochs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());
    let epoch1 = EpochIndex::new(1);
    let epoch4 = EpochIndex::new(4);

    // One interior empty block sits in epoch 1 and contributes nothing.
    let empty_height = BlockHeight(EPOCH_SIZE + 4);
    while pool.height() < epoch4.first_block() {
        if pool.height().0 + 1 == empty_height.0 {
            pool.advance(1, |_| Vec::new());
        } else {
            pool.advance(1, |_| random_block(rng, 1, 2));
        }
    }

    let spendable = user.spendable_at(rng, &pool, &note, epoch1);
    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        (1..=4)
            .map(|epoch| user.nf_at(&note, EpochIndex::new(epoch)))
            .collect(),
        epoch1,
    );

    let unspent = sync.build_next_unspent(rng, 0, &pool, epoch4);
    assert_eq!(sync.consumed(0), 3, "epochs 1, 2 and 3");

    let lifted = user.lift(rng, spendable, unspent, &note);
    assert_eq!(lifted.data().1, epoch4, "lineage advanced to epoch 4");
    assert_eq!(
        lifted.data().2,
        pool.block(epoch4.first_block()).prev,
        "anchor advanced to epoch 4's entry anchor"
    );
    assert_eq!(lifted.data().0, note.commitment(), "cm threaded unchanged");
}

/// Two [`pool::ArbitraryUnspent`] halves meeting at epoch 2's entry anchor:
/// the left over epochs 0 and 1, the right over epochs 2 and 3.
fn multi_epoch_fuse_setup(
    rng: &mut StdRng,
) -> (
    [Nullifier; 4],
    Pcd<pool::ArbitraryUnspent>,
    Pcd<pool::ArbitraryUnspent>,
) {
    let mut pool = PoolSim::genesis(rng);
    mine_through(rng, &mut pool, EpochIndex::new(3).last_block());
    let nf: [Nullifier; 4] = array::from_fn(|_| Nullifier::from(Fp::random(&mut *rng)));
    let at = |epoch: EpochIndex| nf[usize::try_from(u32::from(epoch)).unwrap()];
    let left =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(0), EpochIndex::new(2)));
    let right =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(2), EpochIndex::new(4)));
    assert_eq!(left.data().0, Anchor::default(), "left opens on genesis");
    assert_eq!(
        left.data().4,
        right.data().0,
        "the halves meet at epoch 2's entry anchor"
    );
    (nf, left, right)
}

#[test]
fn unspent_fuse_composes() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, nf2, nf3], left, right) = multi_epoch_fuse_setup(rng);
    let start = left.data().0;
    let end = right.data().4;

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            witness::unspent_fuse((*left.data(), *right.data()), &[nf0, nf1], &[nf2, nf3]),
            left,
            right,
        )
        .expect("UnspentFuse at an entry anchor");

    let (anchor_start, epoch_start, elapsed, epoch_next, anchor_next) = *fused.data();
    assert_eq!(anchor_start, start);
    assert_eq!(anchor_next, end);
    assert_eq!(
        elapsed,
        NfSeqPoly::new(EpochIndex::new(0), &[nf0, nf1, nf2, nf3]).commit(),
        "each covered epoch's member appears once"
    );
    assert_eq!(u32::from(epoch_start), 0);
    assert_eq!(u32::from(epoch_next), 4);
}

#[test]
fn unspent_fuse_rejects_wrong_left_seq() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, nf2, nf3], left, right) = multi_epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            (
                NfSeqPoly::new(EpochIndex::new(0), &[nf1, nf0]),
                NfSeqPoly::new(EpochIndex::new(0), &[nf0, nf1, nf2, nf3]),
                NfSeqPoly::new(EpochIndex::new(2), &[nf2, nf3]),
            ),
            left,
            right,
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentFuse: left polynomial does not match header"
    );
}

#[test]
fn unspent_fuse_rejects_wrong_right_seq() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, nf2, nf3], left, right) = multi_epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            (
                NfSeqPoly::new(EpochIndex::new(0), &[nf0, nf1]),
                NfSeqPoly::new(EpochIndex::new(0), &[nf0, nf1, nf2, nf3]),
                NfSeqPoly::new(EpochIndex::new(2), &[nf3, nf2]),
            ),
            left,
            right,
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentFuse: right polynomial does not match header"
    );
}

#[test]
fn unspent_fuse_rejects_wrong_combined() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, nf2, nf3], left, right) = multi_epoch_fuse_setup(rng);
    // Both halves honest; `combined` forged as the right half alone.
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            (
                NfSeqPoly::new(EpochIndex::new(0), &[nf0, nf1]),
                NfSeqPoly::new(EpochIndex::new(2), &[nf2, nf3]),
                NfSeqPoly::new(EpochIndex::new(2), &[nf2, nf3]),
            ),
            left,
            right,
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentFuse: combined is not the concatenation of the halves"
    );
}

/// A stampless epoch lifts through its empty bucket, and the span still
/// records its nullifier.
#[test]
fn lift_crosses_a_stampless_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(300);
    mine_cm_block(rng, &mut pool, note.commitment());
    let (epoch1, epoch2, epoch3) = (EpochIndex::new(1), EpochIndex::new(2), EpochIndex::new(3));

    // Epoch 1 publishes after the bootstrap; epoch 2 publishes nothing at
    // all; epoch 3 resumes.
    mine_through(rng, &mut pool, epoch1.last_block());
    while pool.height() < epoch2.last_block() {
        pool.advance(1, |_| Vec::new());
    }
    pool.advance(1, |_| random_block(rng, 1, 2));
    assert_eq!(pool.height(), epoch3.first_block());

    let spendable = user.spendable_at(rng, &pool, &note, epoch1);
    let arbitrary = build_unspent_pcd_over_epochs(
        rng,
        &pool,
        |epoch| user.nf_at(&note, epoch),
        (epoch1, epoch3),
    );
    let (_, epoch_start, elapsed, epoch_next, _) = *arbitrary.data();
    assert_eq!(epoch_start, epoch1);
    assert_eq!(epoch_next, epoch3);
    assert_eq!(
        elapsed,
        NfSeqPoly::new(
            epoch1,
            &[user.nf_at(&note, epoch1), user.nf_at(&note, epoch2)],
        )
        .commit(),
        "every covered epoch's member recorded, including the silent epoch's"
    );

    let lifted = user.lift(rng, spendable, arbitrary, &note);
    assert_eq!(lifted.data().1, epoch3);
    assert_eq!(lifted.data().2, pool.block(epoch3.first_block()).prev);
}

#[test]
fn unspent_bind_rejects_a_forged_member() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let pool = pool_closing_epoch_zero(rng, &note);

    let forged = Nullifier::from(Fp::random(&mut *rng));
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    let nf = |epoch: EpochIndex| {
        if epoch == epoch0 {
            forged
        } else {
            user.nf_at(&note, epoch)
        }
    };
    let unspent = build_unspent_pcd_over_epochs(rng, &pool, nf, (epoch0, epoch1));

    // The witnessed sequence matches the header, with the forged member in
    // it, so the poly bind passes; the divisibility read then finds no such
    // member in the genuine sequence and rejects it.
    let (_, _, _, unspent_end, _) = *unspent.data();
    let range = user.derivation_pcd(rng, note, epoch0, unspent_end);
    let witness = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &[forged],
    );

    let err = PROOF_SYSTEM
        .fuse(rng, pool::UnspentBind, witness, unspent, range)
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: sequence does not match the derivation"
    );
}

#[test]
fn unspent_bind_window_may_end_at_the_final_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    // The epoch space's last derivation window: the unspent span covers all
    // of it before the final epoch, `[epoch_start, EPOCH_MAX)`. No crossing
    // leaves the final epoch, so no segment covers it.
    let epoch_start = EpochIndex::new(EPOCH_MAX + 1 - NF_DERIVATION_WIDTH as u32);
    let epoch_end = EpochIndex::new(EPOCH_MAX);
    let range = user.derivation_pcd(rng, note, epoch_start, epoch_end);

    let elapsed: Vec<Nullifier> = (u32::from(epoch_start)..u32::from(epoch_end))
        .map(|epoch| user.nf_at(&note, EpochIndex::new(epoch)))
        .collect();
    let synthetic_unspent = (
        Anchor::from(Fp::ZERO),
        epoch_start,
        NfSeqPoly::new(epoch_start, &elapsed).commit(),
        epoch_end,
        Anchor::from(Fp::ZERO),
    );

    let (_elapsed_seq, _nf_seq, complement_seq) = witness::unspent_bind(
        (synthetic_unspent, *range.data()),
        &user.covering_window(&note, &range),
        &elapsed,
    );

    // The complement is the final epoch's member alone: nothing below the
    // span, and nothing past the final epoch.
    assert_eq!(
        complement_seq.commit(),
        NfSeqPoly::new(epoch_end, &[user.nf_at(&note, epoch_end)]).commit()
    );
}

#[test]
fn unspent_bind_rejects_elapsed_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let pool = pool_closing_epoch_zero(rng, &note);

    let (unspent, elapsed) = epoch_zero_unspent(rng, &pool, &user, &note);
    let range = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(0));
    let (_honest_elapsed_seq, nf_seq, complement_seq) = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &elapsed,
    );
    let bogus_elapsed = NfSeqPoly::new(
        EpochIndex::new(0),
        &[Nullifier::from(Fp::random(&mut *rng))],
    );

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentBind,
            (bogus_elapsed, nf_seq, complement_seq),
            unspent,
            range,
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: elapsed polynomial does not match header"
    );
}

#[test]
fn unspent_bind_rejects_uncovered_start() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let pool = pool_closing_epoch_zero(rng, &note);

    let (unspent, elapsed) = epoch_zero_unspent(rng, &pool, &user, &note);
    // A derivation whose coverage begins after the unspent's start epoch (a
    // later window) cannot cover it.
    // The builder would segment out of range, so the witness is assembled
    // by hand: the genuine covering sequence, an empty complement.
    let range = user.derivation_pcd(rng, note, EpochIndex::new(64), EpochIndex::new(64));
    let window = user.covering_window(&note, &range);
    let witness = (
        NfSeqPoly::new(EpochIndex::new(0), &elapsed),
        NfSeqPoly::new(EpochIndex::new(64), &window),
        NfSeqPoly::new(EpochIndex::new(64), &[]),
    );

    let err = PROOF_SYSTEM
        .fuse(rng, pool::UnspentBind, witness, unspent, range)
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: sequence does not match the derivation"
    );
}

/// A derivation stopping short of the unspent's last member does not cover
/// it.
#[test]
fn unspent_bind_rejects_uncovered_end() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    // A segment over the first epoch past the window: its member sits where
    // the derivation does not reach.
    let last = EpochIndex::new(NF_DERIVATION_WIDTH as u32);
    let unspent = detached_segment(rng, last, |epoch| user.nf_at(&note, epoch));

    let range = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(0));
    let window = user.covering_window(&note, &range);
    // The builder would segment out of range, so the witness is assembled
    // by hand: the genuine elapsed and covering sequence, an empty
    // complement.
    let witness = (
        NfSeqPoly::new(last, &[user.nf_at(&note, last)]),
        NfSeqPoly::new(EpochIndex::new(0), &window),
        NfSeqPoly::new(EpochIndex::new(0), &[]),
    );

    let err = PROOF_SYSTEM
        .fuse(rng, pool::UnspentBind, witness, unspent, range)
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: sequence does not match the derivation"
    );
}

#[test]
fn spendable_lift_rejects_wrong_cm() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let phantom = Note {
        value: value::Positive::try_from(700u64).expect("test value in range"),
        rcm: note::CommitmentTrapdoor::random(rng),
        ..note
    };
    mine_cm_block(rng, &mut pool, note.commitment());
    let (epoch1, epoch2) = (EpochIndex::new(1), EpochIndex::new(2));
    mine_through(rng, &mut pool, epoch2.first_block());
    let spendable = user.spendable_at(rng, &pool, &note, epoch1);

    let arbitrary = build_unspent_pcd_over_epochs(
        rng,
        &pool,
        |epoch| user.nf_at(&note, epoch),
        (epoch1, epoch2),
    );
    let unspent = user.unspent_bind(rng, arbitrary, &phantom);

    let err = PROOF_SYSTEM
        .fuse(rng, spendable::SpendableLift, (), spendable, unspent)
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendableLift: unspent cm does not match spendable"
    );
}

#[test]
fn spendable_lift_rejects_non_adjacent_unspent() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let pool = pool_closing_epoch_zero(rng, &note);
    let epoch1 = EpochIndex::new(1);
    let spendable = user.spendable_at(rng, &pool, &note, epoch1);

    // A segment of the lineage's epoch, opening on an entry anchor no pool
    // published.
    let arbitrary = detached_segment(rng, epoch1, |epoch| user.nf_at(&note, epoch));
    let unspent = user.unspent_bind(rng, arbitrary, &note);

    let err = PROOF_SYSTEM
        .fuse(rng, spendable::SpendableLift, (), spendable, unspent)
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendableLift: unspent not adjacent to spendable"
    );
}

/// Expect `PROOF_SYSTEM.fuse` to fail with the given `InvalidWitness` text.
fn expect_invalid<H: ragu::Header, S>(
    rng: &mut StdRng,
    step: S,
    witness: S::Witness<'_>,
    left: Pcd<S::Left>,
    right: Pcd<S::Right>,
    message: &str,
) where
    S: ragu::Step<Output = H>,
{
    let err = PROOF_SYSTEM
        .fuse(rng, step, witness, left, right)
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), message);
}

/// An honest `NoteSecret` for a note.
fn honest_secret(rng: &mut StdRng, user: &WalletSim, note: Note) -> Pcd<delegation::NoteSecret> {
    let (secret, ()) = PROOF_SYSTEM
        .seed(
            rng,
            delegation::NoteSeed,
            witness::note_seed(((), ()), note, user.pak),
        )
        .expect("NoteSeed");
    secret
}

/// `NoteSeed` certifies the note's opening alongside its commitment and
/// master key.
#[test]
fn note_seed_carries_the_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let secret = honest_secret(rng, &user, note);

    let (cm, opening, mk) = *secret.data();
    assert_eq!(cm, note.commitment());
    assert_eq!(mk, user.mk(&note));
    assert_eq!(
        (
            Fp::from(opening.rcm),
            Fp::from(opening.pk),
            u64::from(opening.value),
            Fp::from(opening.psi),
        ),
        (
            Fp::from(note.rcm),
            Fp::from(note.pk),
            u64::from(note.value),
            Fp::from(note.psi),
        ),
        "the seed emits the opening `cm` commits to"
    );
}

/// The seed derives the note's payment key from `pak`, so a note addressed to
/// another key yields the secret of a different note.
#[test]
fn note_seed_derives_the_payment_key_from_pak() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let stranger = WalletSim::random(rng);
    let note = user.random_note(500);

    let (secret, ()) = PROOF_SYSTEM
        .seed(
            rng,
            delegation::NoteSeed,
            witness::note_seed(((), ()), note, stranger.pak),
        )
        .expect("NoteSeed");

    let (cm, opening, _) = *secret.data();
    assert_eq!(
        Fp::from(opening.pk),
        Fp::from(stranger.pak.derive_payment_key()),
        "the opening carries the payment key of the witnessed pak"
    );
    assert_ne!(
        cm,
        note.commitment(),
        "the secret is not for the supplied note"
    );
}

/// A sequence built from a different note's nullifiers fails the accumulation
/// opening: `mk` is threaded off the seed header, so the step derives the
/// real note's nullifiers no matter what polynomial is offered.
#[test]
fn nullifier_derive_rejects_a_foreign_sequence() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note_a = user.random_note(500);
    let note_b = user.random_note(700);

    let secret_a = honest_secret(rng, &user, note_a);
    let (cm_a, ..) = *secret_a.data();
    let (epoch_start, foreign_seq) =
        witness::nullifier_derive(((cm_a, note_a, user.mk(&note_b)), ()), EpochIndex::new(16));
    expect_invalid(
        rng,
        delegation::NullifierDerive,
        (epoch_start, foreign_seq),
        secret_a,
        Proof::trivial().carry::<()>(()),
        "NullifierDerive: sequence does not match the derived window",
    );
}

/// A start epoch off the group alignment is rejected before any derivation.
#[test]
fn nullifier_derive_rejects_a_misaligned_epoch_start() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let secret = honest_secret(rng, &user, note);
    let (_, seq) = witness::nullifier_derive((*secret.data(), ()), EpochIndex::new(12));
    expect_invalid(
        rng,
        delegation::NullifierDerive,
        (EpochIndex::new(14), seq),
        secret,
        Proof::trivial().carry::<()>(()),
        "NullifierDerive: epoch_start is not group-aligned",
    );
}

/// A window has to land inside the epoch range: an index past `EPOCH_MAX`
/// maps to no block height, so it labels no reachable epoch.
///
/// The witness is assembled here rather than through
/// [`witness::nullifier_derive`], which derives the window prover-side and so
/// trips the same bound before the step runs. The sequence is empty for the
/// same reason: the range check precedes every use of it.
#[test]
fn nullifier_derive_rejects_a_window_past_the_final_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    // Group-aligned for any EPOCH_MAX of the form `2^k - 1`, and short of a
    // whole window by three epochs.
    let epoch_start = EpochIndex::new(EPOCH_MAX - 3);
    let secret = honest_secret(rng, &user, note);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            delegation::NullifierDerive,
            (epoch_start, NfSeqPoly::new(epoch_start, &[])),
            secret,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "NullifierDerive: window exceeds the epoch range"
    );
}

/// A leaf exports its whole window, labelled with the window's bounds, and
/// every window of the same note carries the same `cm`.
#[test]
fn derivation_exports_the_whole_window() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let epoch_start = EpochIndex::new(12);
    let epoch_end = EpochIndex::new(u32::from(epoch_start) + NF_DERIVATION_WIDTH as u32 - 1);
    let range = user.derivation_pcd(rng, note, epoch_start, epoch_end);
    let (cm, start, commit, range_end) = *range.data();

    assert_eq!(start, epoch_start, "starts at the witnessed epoch");
    assert_eq!(range_end, epoch_end, "spans the whole window");
    let members = user.covering_window(&note, &range);
    let seq = NfSeqPoly::new(epoch_start, &members);
    assert_eq!(commit, seq.commit(), "header commits the window sequence");

    let far = user.derivation_pcd(
        rng,
        note,
        EpochIndex::new(100_000),
        EpochIndex::new(100_000 + NF_DERIVATION_WIDTH as u32 - 1),
    );
    assert_eq!(cm, far.data().0, "same note cm");
}

/// The fixture's covering derivation spans whole windows around the request
/// and commits the covering sequence.
#[test]
fn derivation_covers_with_whole_windows() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    // Spans two windows: the fixture fuses whole-window leaves internally.
    let start = EpochIndex::new(NF_DERIVATION_WIDTH as u32 - 2);
    let last = EpochIndex::new(NF_DERIVATION_WIDTH as u32 + 2);
    let range = user.derivation_pcd(rng, note, start, last);
    let (cm, cover_start, commit, cover_end) = *range.data();

    assert_eq!(Tachygram::from(cm), note.commitment().into());
    assert!(
        cover_start <= start && last <= cover_end,
        "covers the requested range"
    );
    assert_eq!(
        (u32::from(cover_end) - u32::from(cover_start) + 1) % NF_DERIVATION_WIDTH as u32,
        0,
        "whole windows"
    );
    let members: Vec<Nullifier> = (u32::from(cover_start)..=u32::from(cover_end))
        .map(|epoch| user.nf_at(&note, EpochIndex::new(epoch)))
        .collect();
    let seq = NfSeqPoly::new(cover_start, &members);
    assert_eq!(commit, seq.commit(), "merged commit is the concat sequence");
}

#[test]
fn nullifier_fuse_rejects_non_contiguous() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    // Windows separated by a gap: the left window covers `[0, 16)`, the right
    // starts at 32, so the halves are not adjacent.
    let (left_start, right_start) = (EpochIndex::new(0), EpochIndex::new(32));
    let range_a = user.derivation_pcd(rng, note, left_start, EpochIndex::new(15));
    let range_b = user.derivation_pcd(rng, note, right_start, EpochIndex::new(47));
    let witness = witness::nullifier_fuse(
        (*range_a.data(), *range_b.data()),
        &user.covering_window(&note, &range_a),
        &user.covering_window(&note, &range_b),
    );

    let err = PROOF_SYSTEM
        .fuse(rng, delegation::NullifierFuse, witness, range_a, range_b)
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "NullifierFuse: ranges not contiguous");
}

#[test]
fn nullifier_fuse_rejects_wrong_cm() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note_a = user.random_note(500);
    let note_b = user.random_note(700);

    let (left_start, right_start) = (EpochIndex::new(0), EpochIndex::new(16));
    let range_a = user.derivation_pcd(rng, note_a, left_start, EpochIndex::new(15));
    let range_b = user.derivation_pcd(rng, note_b, right_start, EpochIndex::new(31));
    let witness = witness::nullifier_fuse(
        (*range_a.data(), *range_b.data()),
        &user.covering_window(&note_a, &range_a),
        &user.covering_window(&note_b, &range_b),
    );

    let err = PROOF_SYSTEM
        .fuse(rng, delegation::NullifierFuse, witness, range_a, range_b)
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "NullifierFuse: note commitments differ");
}

/// A secret for a different note does not match the lineage's `cm`.
#[test]
fn spend_bind_rejects_a_secret_for_another_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let other = user.random_note(700);

    let mut pool = PoolSim::genesis(rng);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let foreign = honest_secret(rng, &user, other);
    let rcv = value::Trapdoor::random(rng);

    let err = PROOF_SYSTEM
        .fuse(rng, spend::SpendBind, (rcv,), spendable, foreign)
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "SpendBind: secret does not match note");
}

/// At an epoch ending its sponge group, the pair's second half comes from the
/// next group's sponge.
#[test]
fn spend_bind_derives_a_pair_across_a_group_boundary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let mut pool = PoolSim::genesis(rng);
    while pool.height().0 < 3 * EPOCH_SIZE {
        pool.mine(random_block(rng, 1, 2));
    }
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let epoch = init_height.epoch();
    assert_eq!(
        epoch,
        EpochIndex::new(3),
        "the last epoch of the first group"
    );
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let anchor = spendable.data().2;

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable);

    let (cm, nf_current, nf_next, bind_anchor, _pk, _cv) = *bind_pcd.data();
    assert_eq!(
        (cm, nf_current, nf_next, bind_anchor),
        (
            note.commitment(),
            user.nf_at(&note, epoch),
            user.nf_at(&note, EpochIndex::new(4)),
            anchor,
        )
    );
}

/// `SpendStamp` rejects a tachygram set not committing to the bound nullifier
/// pair.
#[test]
fn spend_stamp_rejects_a_mismatched_stamp_accumulator() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);

    let (_rcv, _theta, alpha) = spend_witness(rng, &note);
    let (.., action_set, _pair) = witness::spend_stamp((*bind_pcd.data(), ()), alpha, user.pak);
    // A foreign tachygram in place of the confirmed pair.
    let forged = TachygramSetPoly::from_iter([Tachygram::from(Fp::random(&mut *rng))]);

    expect_invalid(
        rng,
        stamp::SpendStamp,
        (alpha, user.pak, action_set, forged),
        bind_pcd,
        Proof::trivial().carry::<()>(()),
        "SpendStamp: tachygram set does not commit to the nullifier pair",
    );
}

/// `SpendStamp` rejects an action set not committing to the action it derives.
#[test]
fn spend_stamp_rejects_a_foreign_action_set() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);

    let (_rcv, _theta, alpha) = spend_witness(rng, &note);
    // A different randomizer yields a different rk, so a different digest.
    // The tachygram set comes off the bind header, so it is honest either way.
    let (_, _, foreign_alpha) = spend_witness(rng, &note);
    let (.., foreign, tachygram_set) =
        witness::spend_stamp((*bind_pcd.data(), ()), foreign_alpha, user.pak);

    expect_invalid(
        rng,
        stamp::SpendStamp,
        (alpha, user.pak, foreign, tachygram_set),
        bind_pcd,
        Proof::trivial().carry::<()>(()),
        "SpendStamp: action set does not commit to the action",
    );
}

/// A covering sequence built from a different note does not match the
/// derivation header's commitment at `UnspentBind`.
#[test]
fn unspent_bind_rejects_a_foreign_sequence() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let other = user.random_note(700);
    let pool = pool_closing_epoch_zero(rng, &note);

    let (unspent, elapsed) = epoch_zero_unspent(rng, &pool, &user, &note);
    let range = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(0));
    let witness = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&other, &range),
        &elapsed,
    );
    expect_invalid(
        rng,
        pool::UnspentBind,
        witness,
        unspent,
        range,
        "UnspentBind: covering sequence does not match header",
    );
}

/// A span exceeding one window chunks through sequential bind+lift rounds,
/// each bound against its own single window based at its chunk's start.
#[test]
fn multi_chunk_lift_uses_per_chunk_windows() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());
    let (epoch1, epoch2, epoch3) = (EpochIndex::new(1), EpochIndex::new(2), EpochIndex::new(3));
    mine_through(rng, &mut pool, epoch2.first_block());

    let spendable = user.spendable_at(rng, &pool, &note, epoch1);
    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.nf_at(&note, epoch1),
            user.nf_at(&note, epoch2),
            user.nf_at(&note, epoch3),
        ],
        epoch1,
    );

    // First chunk: epoch 1, bound against the window based at epoch 0.
    let unspent_one = sync.build_next_unspent(rng, 0, &pool, epoch2);
    let lifted_one = user.lift(rng, spendable, unspent_one, &note);
    assert_eq!(lifted_one.data().1, epoch2);

    // Second chunk: epoch 2, bound against a fresh window (the chunk boundary
    // needs no alignment between windows).
    mine_through(rng, &mut pool, epoch3.first_block());
    let unspent_two = sync.build_next_unspent(rng, 0, &pool, epoch3);
    let lifted_two = user.lift(rng, lifted_one, unspent_two, &note);

    assert_eq!(
        lifted_two.data().1,
        epoch3,
        "lineage advanced across two chunks"
    );
    assert_eq!(
        lifted_two.data().2,
        pool.block(epoch3.first_block()).prev,
        "anchor advanced across two chunks"
    );
    assert_eq!(lifted_two.data().0, note.commitment(), "cm threaded");
}

/// The pad the step publishes is `pad_tachygram` over the note's own fields.
fn expected_pad(note: &Note) -> Tachygram {
    Tachygram::from(poseidon::pad_tachygram(
        Fp::from(note.rcm),
        Fp::from(note.pk),
        u64::from(note.value),
        Fp::from(note.psi),
    ))
}

/// `OutputBind` emits the note's commitment and pad, both derived natively,
/// and its negated value committed under `rcv`.
#[test]
fn output_bind_publishes_the_note_pair() {
    let rng = &mut StdRng::seed_from_u64(0);
    let note = WalletSim::new(shared_sk()).random_note(200);
    let rcv = value::Trapdoor::random(rng);

    let (pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .expect("OutputBind honest");

    assert_eq!(
        *pcd.data(),
        (
            Tachygram::from(note.commitment()),
            expected_pad(&note),
            rcv.commit(-note.value),
        )
    );
}

/// `OutputStamp` publishes the pair `OutputBind` derived, at the witnessed
/// anchor.
#[test]
fn output_stamp_publishes_the_note_pair() {
    let rng = &mut StdRng::seed_from_u64(0);
    let note = WalletSim::new(shared_sk()).random_note(200);
    let (rcv, alpha, _plan) = build_output_plan(rng, note);
    let anchor = PoolSim::genesis(rng).anchor();

    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .expect("OutputBind honest");
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::OutputStamp,
            witness::output_stamp((*bind_pcd.data(), ()), alpha, anchor),
            bind_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("OutputStamp honest");

    let (_action_commit, tachygram_commit, stamp_anchor) = *pcd.data();
    assert_eq!(
        tachygram_commit,
        TachygramSetPoly::from_iter([Tachygram::from(note.commitment()), expected_pad(&note)])
            .commit()
    );
    assert_eq!(stamp_anchor, anchor);
}

/// `OutputStamp` rejects a tachygram set not committing to the bound
/// `{cm, pad}` pair.
#[test]
fn output_stamp_rejects_a_mismatched_stamp_accumulator() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(200);

    let (rcv, alpha, _plan) = build_output_plan(rng, note);
    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .expect("OutputBind honest");

    let anchor = PoolSim::genesis(rng).anchor();
    let (.., action_set, _pair) = witness::output_stamp((*bind_pcd.data(), ()), alpha, anchor);
    // A foreign tachygram in place of the bound pair.
    let forged = TachygramSetPoly::from_iter([Tachygram::from(Fp::random(&mut *rng))]);

    expect_invalid(
        rng,
        stamp::OutputStamp,
        (alpha, anchor, action_set, forged),
        bind_pcd,
        Proof::trivial().carry::<()>(()),
        "OutputStamp: tachygram set does not commit to the bound pair",
    );
}

/// Domain separation is what the pad buys: the same note fields hashed under
/// two domains must not coincide.
#[test]
fn pad_differs_from_commitment() {
    let note = WalletSim::new(shared_sk()).random_note(200);

    assert_ne!(Tachygram::from(note.commitment()), expected_pad(&note));
}

/// `OutputStamp` rejects an action set not committing to the action it
/// derives.
#[test]
fn output_stamp_rejects_a_foreign_action_set() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(200);

    let (rcv, alpha, _plan) = build_output_plan(rng, note);
    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .expect("OutputBind honest");

    let anchor = PoolSim::genesis(rng).anchor();
    // A different randomizer yields a different rk, so a different digest.
    // The tachygram set comes off the bind header, so it is honest either way.
    let (.., foreign, tachygram_set) = witness::output_stamp(
        (*bind_pcd.data(), ()),
        ActionEntropy::random(rng).randomizer::<effect::Output>(note.commitment()),
        anchor,
    );

    expect_invalid(
        rng,
        stamp::OutputStamp,
        (alpha, anchor, foreign, tachygram_set),
        bind_pcd,
        Proof::trivial().carry::<()>(()),
        "OutputStamp: action set does not commit to the action",
    );
}

/// Adjacent ranges fuse into one: the merged sequence is the product of the
/// halves, with the range threaded from the halves.
#[test]
fn nullifier_fuse_composes() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let left = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(15));
    let right = user.derivation_pcd(rng, note, EpochIndex::new(16), EpochIndex::new(31));
    let left_nfs: Vec<Nullifier> = (0..16)
        .map(|epoch| user.nf_at(&note, EpochIndex::new(epoch)))
        .collect();
    let right_nfs: Vec<Nullifier> = (16..32)
        .map(|epoch| user.nf_at(&note, EpochIndex::new(epoch)))
        .collect();
    let fuse_witness =
        witness::nullifier_fuse((*left.data(), *right.data()), &left_nfs, &right_nfs);
    let (merged, ()) = PROOF_SYSTEM
        .fuse(rng, delegation::NullifierFuse, fuse_witness, left, right)
        .expect("NullifierFuse");

    let (cm, start, commit, last) = *merged.data();
    assert_eq!(cm, note.commitment());
    assert_eq!((start, last), (EpochIndex::new(0), EpochIndex::new(31)));
    let members: Vec<Nullifier> = (0..32)
        .map(|epoch| user.nf_at(&note, EpochIndex::new(epoch)))
        .collect();
    let expected = NfSeqPoly::new(EpochIndex::new(0), &members);
    assert_eq!(
        commit,
        expected.commit(),
        "merged commits the concatenation"
    );
}

/// A merged polynomial that is not the product of the halves fails the
/// fuse identity.
#[test]
fn nullifier_fuse_rejects_a_wrong_merged() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let left = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(15));
    let right = user.derivation_pcd(rng, note, EpochIndex::new(16), EpochIndex::new(31));
    let left_nfs: Vec<Nullifier> = (0..16)
        .map(|epoch| user.nf_at(&note, EpochIndex::new(epoch)))
        .collect();
    let right_nfs: Vec<Nullifier> = (16..32)
        .map(|epoch| user.nf_at(&note, EpochIndex::new(epoch)))
        .collect();
    let (left_seq, _merged, right_seq) =
        witness::nullifier_fuse((*left.data(), *right.data()), &left_nfs, &right_nfs);
    let wrong_members: Vec<Nullifier> =
        iter::repeat_with(|| Nullifier::from(Fp::random(&mut *rng)))
            .take(32)
            .collect();
    let wrong = NfSeqPoly::new(EpochIndex::new(0), &wrong_members);
    expect_invalid(
        rng,
        delegation::NullifierFuse,
        (left_seq, wrong, right_seq),
        left,
        right,
        "NullifierFuse: merged is not the concat of the halves",
    );
}

/// A segment beginning past the spendable's position does not lift it: it
/// starts in a later epoch than the lineage's.
#[test]
fn spendable_lift_rejects_a_wrong_start() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());
    let (epoch1, epoch2, epoch3) = (EpochIndex::new(1), EpochIndex::new(2), EpochIndex::new(3));
    mine_through(rng, &mut pool, epoch2.last_block());
    let spendable = user.spendable_at(rng, &pool, &note, epoch1);

    // A segment covering only epoch 2, one epoch past the spendable.
    let arbitrary = build_unspent_pcd_over_epochs(
        rng,
        &pool,
        |epoch| user.nf_at(&note, epoch),
        (epoch2, epoch3),
    );
    let unspent = user.unspent_bind(rng, arbitrary, &note);

    expect_invalid(
        rng,
        spendable::SpendableLift,
        (),
        spendable,
        unspent,
        "SpendableLift: segment does not start at the lineage epoch",
    );
}

/// A forged complement cannot compensate the identity: the divisibility
/// pins the whole factorization, so junk in the complement fails the bind.
#[test]
fn unspent_bind_rejects_a_forged_complement() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let pool = pool_closing_epoch_zero(rng, &note);

    let (unspent, elapsed) = epoch_zero_unspent(rng, &pool, &user, &note);
    let range = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(1));
    let (elapsed_seq, nf_seq, _complement_seq) = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &elapsed,
    );
    let forged = NfSeqPoly::new(
        EpochIndex::new(1),
        &[Nullifier::from(Fp::random(&mut *rng))],
    );
    expect_invalid(
        rng,
        pool::UnspentBind,
        (elapsed_seq, nf_seq, forged),
        unspent,
        range,
        "UnspentBind: sequence does not match the derivation",
    );
}

/// The right nullifier value at the wrong epoch is a different member: the
/// pair binding is positional through the epoch, not just the value.
#[test]
fn unspent_bind_rejects_a_wrong_epoch_member() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    mine_through(rng, &mut pool, epoch1.last_block());

    // A segment over epoch 1 testing epoch 0's genuine nullifier: the value
    // is genuine, the epoch is not.
    let nf = |epoch: EpochIndex| user.nf_at(&note, if epoch == epoch1 { epoch0 } else { epoch });
    let unspent = build_unspent_pcd_over_epochs(rng, &pool, nf, (epoch1, EpochIndex::new(2)));
    let range = user.derivation_pcd(rng, note, epoch0, epoch1);
    let elapsed_seq = NfSeqPoly::new(epoch1, &[nf(epoch1)]);
    let complement_seq =
        NfSeqPoly::new(EpochIndex::new(0), &[user.nf_at(&note, EpochIndex::new(0))]);
    let nf_seq = NfSeqPoly::new(EpochIndex::new(0), &user.covering_window(&note, &range));
    expect_invalid(
        rng,
        pool::UnspentBind,
        (elapsed_seq, nf_seq, complement_seq),
        unspent,
        range,
        "UnspentBind: sequence does not match the derivation",
    );
}

/// A complement duplicating the tested member cannot pass: the derivation
/// carries each member exactly once, so a duplicated member does not divide
/// it.
#[test]
fn unspent_bind_rejects_a_duplicating_complement() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let pool = pool_closing_epoch_zero(rng, &note);

    let (unspent, elapsed) = epoch_zero_unspent(rng, &pool, &user, &note);
    let range = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(0));
    let (elapsed_seq, nf_seq, _complement_seq) = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &elapsed,
    );
    // Duplicating the tested member squares its encoding, and the squarefree
    // derivation rejects it.
    let duplicating = NfSeqPoly::new(EpochIndex::new(0), &[user.nf_at(&note, EpochIndex::new(0))]);
    expect_invalid(
        rng,
        pool::UnspentBind,
        (elapsed_seq, nf_seq, duplicating),
        unspent,
        range,
        "UnspentBind: sequence does not match the derivation",
    );
}

/// A span exceeding one window binds once, against a fused chain of cached
/// whole windows; no bind-per-window rounds and no partial leaves.
#[test]
fn multi_window_span_binds_once() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());

    // Publish one block per epoch (each epoch's first block) through epoch
    // NF_DERIVATION_WIDTH + 1, so the span covers one epoch more than a
    // single window.
    let last_epoch = NF_DERIVATION_WIDTH as u32 + 1;
    let target_height = BlockHeight(last_epoch * EPOCH_SIZE);
    while pool.height() < target_height {
        let publish = pool.height().0 % EPOCH_SIZE == EPOCH_SIZE - 1;
        if publish {
            pool.advance(1, |_| random_block(rng, 1, 2));
        } else {
            pool.advance(1, |_| Vec::new());
        }
    }

    let arbitrary = build_unspent_pcd_over_epochs(
        rng,
        &pool,
        |epoch| user.nf_at(&note, epoch),
        (EpochIndex::new(0), EpochIndex::new(last_epoch)),
    );
    let unspent = user.unspent_bind(rng, arbitrary, &note);

    assert_eq!(
        (unspent.data().2, unspent.data().3),
        (EpochIndex::new(0), EpochIndex::new(last_epoch)),
        "one bind carries the whole multi-window span"
    );
}

/// One covering derivation serves every request inside it, and the pair the
/// spend's bind derives from `mk` is the window's pair.
#[test]
fn one_window_serves_init_and_matches_the_bind() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let epoch = init_height.epoch();

    let window = user.derivation_pcd(rng, note, epoch, EpochIndex::new(u32::from(epoch) + 1));
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let again = user.derivation_pcd(rng, note, epoch, epoch);
    assert_eq!(
        again.data(),
        window.data(),
        "the memoized covering window is one PCD for every request inside it"
    );

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable);
    assert_eq!(bind_pcd.data().1, user.nf_at(&note, epoch));
    assert_eq!(bind_pcd.data().2, user.nf_at(&note, epoch.next().unwrap()));
}

/// A bucket-started spendable lifts across an epoch and binds to a spend.
#[test]
fn bucket_spendable_syncs_to_a_spend() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    let epoch2 = EpochIndex::new(2);
    mine_through(rng, &mut pool, epoch2.first_block());

    let lifted = user.spendable_at(rng, &pool, &note, epoch2);
    let bind_pcd = honest_spend_bind(rng, &user, &note, lifted);

    assert_eq!(bind_pcd.data().1, user.nf_at(&note, epoch2));
    assert_eq!(bind_pcd.data().2, user.nf_at(&note, EpochIndex::new(3)));
}
