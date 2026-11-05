extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};
use core::{array, iter};

use ragu::{Pcd, Proof};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use udon::field::Field as _;
use zcash_tachyon::{
    ActionSetCommit, ActionSetPoly, Anchor, AnchorSetPoly, BlockHeight, EpochIndex, NfSeqPoly,
    Note, Tachygram, TachygramSetPoly, action,
    constants::{EPOCH_MAX, EPOCH_SIZE},
    digest::poseidon,
    entropy::ActionEntropy,
    note,
    nullifier::{self, NF_DERIVATION_WIDTH, Nullifier},
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, delegation, output, pool, spend, spendable, stamp},
    value, witness,
};

use crate::fixtures::{
    PoolSim, SyncSim, WalletSim, build_anchor_span_pcd, build_output_plan, build_output_stamp,
    build_unspent_pcd_over_epochs, qr_bucket_segment, random_block, random_block_with,
    seal_qr_intake, seed_qr_empty_intake, shared_sk, 
};

fn mine_cm_block(rng: &mut StdRng, pool: &mut PoolSim, cm: note::Commitment) -> BlockHeight {
    pool.mine(random_block_with(rng, &[alloc::vec![cm]], 4));
    pool.height()
}

fn mine_through(rng: &mut StdRng, pool: &mut PoolSim, height: BlockHeight) {
    while pool.height() < height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
}

fn pool_closing_epoch_zero(rng: &mut StdRng, note: &Note) -> PoolSim {
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    mine_cm_block(rng, &mut pool, note.commitment());
    mine_through(rng, &mut pool, EpochIndex::new(1).first_block());
    pool
}

fn epoch_zero_unspent(
    rng: &mut StdRng,
    pool: &PoolSim,
    user: &WalletSim,
    note: &Note,
) -> (Pcd<pool::ArbitraryUnspent>, Vec<Nullifier>) {
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    let unspent = build_unspent_pcd_over_epochs(
        rng,
        pool,
        |epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch)
        },
        (epoch0, epoch1),
    );
    (
        unspent,
        vec![
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch0),
        ],
    )
}

fn detached_segment(
    rng: &mut StdRng,
    epoch: EpochIndex,
    nf: impl Fn(EpochIndex) -> Nullifier,
) -> Pcd<pool::ArbitraryUnspent> {
    let anchor_final_prev = Anchor::random(rng);
    let discriminant = zcash_tachyon::QrDiscriminant::random(rng);
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
    while pool.height().0 < EPOCH_SIZE {
        pool.mine(random_block(rng, 1, 3));
    }
    pool.mine(random_block_with(rng, &[alloc::vec![cm]], 4));
    let cm_height = pool.height();
    assert_eq!(cm_height.epoch(), EpochIndex::new(1));
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
        .unwrap();
    bind_pcd
}

fn honest_spend_stamp(
    rng: &mut StdRng,
    user: &WalletSim,
    bind_pcd: Pcd<spend::SpendHeader>,
) -> Pcd<stamp::Actions> {
    let (_rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let (stamp, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::SpendAction,
            witness::spend_action((*bind_pcd.data(), ()), theta, user.pak),
            bind_pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    stamp
}

#[test]
fn same_epoch_honest_spend_accepted() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    let cm_height = mine_cm_in_epoch_one(rng, &mut pool, note.commitment());
    let epoch = cm_height.epoch();

    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable);
    let stamp = honest_spend_stamp(rng, &user, bind_pcd);

    let expected = TachygramSetPoly::from_iter([
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch)
            .into(),
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch.next().unwrap())
            .into(),
    ])
    .commit();
    assert_eq!(stamp.data().1, expected, "publishes {{N_E, N_E+1}}");
}

#[test]
fn stamp_lift_within_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));

    pool.advance(1, |_| random_block(rng, 1, 4));
    let stamp_anchor = pool.block(BlockHeight(1)).anchor();

    let note = user.random_note(200);
    let (stamp, plan, fee_descriptor) = build_output_stamp(rng, stamp_anchor, note);

    let action_commit =
        ActionSetPoly::from_iter([plan.digest().unwrap(), fee_descriptor.digest().unwrap()])
            .commit();
    let tachygram_commit = TachygramSetPoly::from_iter(stamp.tachygrams).commit();

    pool.advance(EPOCH_SIZE - 2, |_| random_block(rng, 1, 4));
    let new_height = pool.height();

    let stamp_pcd = stamp
        .proof
        .carry((action_commit, tachygram_commit, stamp_anchor));
    let (span, members) = build_anchor_span_pcd(rng, &pool, BlockHeight(2)..=new_height);

    let (lifted_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::StampLift,
            witness::stamp_lift((*stamp_pcd.data(), *span.data()), &members),
            stamp_pcd,
            span,
        )
        .unwrap();
    assert_eq!(lifted_pcd.data().2, pool.block(new_height).anchor());
}

#[test]
fn spendable_init_rejects_tg_absent() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let nf_header = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(0));
    let absent_tg = Tachygram::random(rng);

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        spendable::SpendableInit,
        witness::spendable_init(
            (*nf_header.data(), ()),
            Anchor::default(),
            &[absent_tg],
            EpochIndex::new(0),
        ),
        nf_header,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(err.to_string(), "SpendableInit: commitment not in set");
    } else {
        panic!();
    }
}

#[test]
fn unspent_fuse_rejects_invalid_compositions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    mine_through(rng, &mut pool, EpochIndex::new(2).last_block());
    let nf: [Nullifier; 3] =
        array::from_fn(|_| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))));
    let at = |epoch: EpochIndex| nf[usize::try_from(u32::from(epoch)).unwrap()];

    let left =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(0), EpochIndex::new(1)));
    let right =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(2), EpochIndex::new(3)));
    let w = witness::unspent_fuse((*left.data(), *right.data()), &nf[0..1], &nf[2..3]);
    if let Err(ragu_core::Error::InvalidWitness(err)) =
        PROOF_SYSTEM.fuse(rng, pool::UnspentFuse, w, left, right)
    {
        assert_eq!(
            err.to_string(),
            "UnspentFuse: left.anchor_next must equal right.anchor_start"
        );
    } else {
        panic!();
    }
}

fn fuse_spans(
    rng: &mut StdRng,
    (left, left_members): (Pcd<pool::AnchorSpan>, &[Anchor]),
    (right, right_members): (Pcd<pool::AnchorSpan>, &[Anchor]),
) -> ragu_core::Result<Pcd<pool::AnchorSpan>> {
    let fuse_witness =
        witness::anchor_span_fuse((*left.data(), *right.data()), left_members, right_members);
    PROOF_SYSTEM
        .fuse(rng, pool::AnchorSpanFuse, fuse_witness, left, right)
        .map(|(fused, ())| fused)
}

#[test]
fn anchor_span_fuse_rejects_unjoined_spans() {
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
        pool.advance(2, |_| random_block(rng, 1, 2));

        let (left, left_members) =
            build_anchor_span_pcd(rng, &pool, BlockHeight(0)..=BlockHeight(0));

        let bogus_start = Anchor::random(rng);
        let stamps = pool
            .block(BlockHeight(1))
            .stamps
            .iter()
            .map(|stamp| stamp.1.clone())
            .collect::<Vec<_>>();
        let seed_witness =
            witness::anchor_span_seed(((), ()), bogus_start, BlockHeight(1).epoch(), &stamps[0]);
        let right_members = [bogus_start
            .next_stamp(seed_witness.1, &seed_witness.2)
            .unwrap()];
        let (right, ()) = PROOF_SYSTEM
            .seed(rng, pool::AnchorSpanSeed, seed_witness)
            .unwrap();

        if let Err(ragu_core::Error::InvalidWitness(err)) =
            fuse_spans(rng, (left, &left_members), (right, &right_members))
        {
            assert_eq!(
                err.to_string(),
                "AnchorSpanFuse: spans do not share a vertex"
            );
        } else {
            panic!();
        }
    }

    {
        let rng = &mut StdRng::seed_from_u64(0);
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
        pool.advance(EPOCH_SIZE + 1, |_| random_block(rng, 1, 2));

        let (left, left_members) =
            build_anchor_span_pcd(rng, &pool, BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1));
        let (right, right_members) = build_anchor_span_pcd(
            rng,
            &pool,
            BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
        );

        if let Err(ragu_core::Error::InvalidWitness(err)) =
            fuse_spans(rng, (left, &left_members), (right, &right_members))
        {
            assert_eq!(
                err.to_string(),
                "AnchorSpanFuse: spans do not share a vertex"
            );
        } else {
            panic!();
        }
    }
}

fn output_stamp_pcd(rng: &mut StdRng, user: &WalletSim, stamp_anchor: Anchor) -> Pcd<stamp::Stamp> {
    let (stamp, plan, fee_descriptor) =
        build_output_stamp(rng, stamp_anchor, user.random_note(200));
    let action_commit =
        ActionSetPoly::from_iter([plan.digest().unwrap(), fee_descriptor.digest().unwrap()])
            .commit();
    let tachygram_commit = TachygramSetPoly::from_iter(stamp.tachygrams).commit();
    stamp
        .proof
        .carry((action_commit, tachygram_commit, stamp_anchor))
}

fn lift_output_stamp(
    rng: &mut StdRng,
    user: &WalletSim,
    stamp_anchor: Anchor,
    span: &Pcd<pool::AnchorSpan>,
    members: &[Anchor],
) -> ragu_core::Result<Pcd<stamp::Stamp>> {
    let stamp_pcd = output_stamp_pcd(rng, user, stamp_anchor);

    PROOF_SYSTEM
        .fuse(
            rng,
            stamp::StampLift,
            witness::stamp_lift((*stamp_pcd.data(), *span.data()), members),
            stamp_pcd,
            span.clone(),
        )
        .map(|(lifted, ())| lifted)
}

#[test]
fn anchor_span_holds_the_anchors_its_folds_produce() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(2, |_| random_block(rng, 1, 2));

    let (span, members) = build_anchor_span_pcd(rng, &pool, BlockHeight(1)..=BlockHeight(2));
    let (anchor_start, members_commit, anchor_end) = *span.data();

    assert_eq!(members.len(), 4);
    assert_eq!(anchor_start, pool.block(BlockHeight(1)).prev);
    assert_eq!(anchor_end, pool.block(BlockHeight(2)).anchor());
    assert_eq!(members.last(), Some(&anchor_end));
    assert!(!members.contains(&anchor_start));
    assert_eq!(members_commit, AnchorSetPoly::from_iter(members).commit());
}

#[test]
fn stamp_lifts_from_the_start_a_member_or_the_end() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(1, |_| random_block(rng, 1, 3));

    let (span, members) = build_anchor_span_pcd(rng, &pool, BlockHeight(1)..=BlockHeight(1));
    let (anchor_start, _, anchor_end) = *span.data();

    for (label, stamp_anchor) in [
        ("start", anchor_start),
        ("interior member", members[0]),
        ("end", anchor_end),
    ] {
        let lifted = lift_output_stamp(rng, &user, stamp_anchor, &span, &members).expect(label);
        assert_eq!(lifted.data().2, anchor_end, "{label}");
    }
}

#[test]
fn stamp_lift_rejects_invalid_lifts() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(1, |_| random_block(rng, 1, 3));

    let (span, members) = build_anchor_span_pcd(rng, &pool, BlockHeight(1)..=BlockHeight(1));
    let (anchor_start, ..) = *span.data();
    let fork_set = TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit();
    let fork = anchor_start
        .next_stamp(BlockHeight(1).epoch(), &fork_set)
        .unwrap();
    let foreign_members: Vec<Anchor> = members.iter().copied().chain([fork]).collect();

    let cases = [
        (
            "stamp anchored on a fork",
            fork,
            members.clone(),
            "StampLift: stamp anchor is neither the span's start nor a member",
        ),
        (
            "foreign members",
            members[0],
            foreign_members,
            "StampLift: members do not match header",
        ),
    ];

    for (label, stamp_anchor, witnessed, expected) in cases {
        if let Err(ragu_core::Error::InvalidWitness(err)) =
            lift_output_stamp(rng, &user, stamp_anchor, &span, &witnessed)
        {
            assert_eq!(err.to_string(), expected, "{label}");
        } else {
            panic!("{label}");
        }
    }
}

#[test]
fn anchor_span_fuse_rejects_invalid_compositions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(2, |_| random_block(rng, 1, 1));

    let (left, left_members) = build_anchor_span_pcd(rng, &pool, BlockHeight(1)..=BlockHeight(1));
    let (right, right_members) = build_anchor_span_pcd(rng, &pool, BlockHeight(2)..=BlockHeight(2));

    {
        let (left_poly, _combined, right_poly) =
            witness::anchor_span_fuse((*left.data(), *right.data()), &left_members, &right_members);
        let forged = AnchorSetPoly::from_iter(left_members.iter().copied());
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            pool::AnchorSpanFuse,
            (left_poly, forged, right_poly),
            left.clone(),
            right.clone(),
        ) {
            assert_eq!(
                err.to_string(),
                "AnchorSpanFuse: combined is not the union of the halves"
            );
        } else {
            panic!();
        }
    }

    {
        let (left_poly, _combined, right_poly) =
            witness::anchor_span_fuse((*left.data(), *right.data()), &left_members, &right_members);
        let fork_set = TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit();
        let fork = left
            .data()
            .2
            .next_stamp(BlockHeight(2).epoch(), &fork_set)
            .unwrap();
        let forged = AnchorSetPoly::from_iter(
            left_members
                .iter()
                .chain(&right_members)
                .copied()
                .chain([fork]),
        );
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            pool::AnchorSpanFuse,
            (left_poly, forged, right_poly),
            left.clone(),
            right.clone(),
        ) {
            assert_eq!(
                err.to_string(),
                "AnchorSpanFuse: combined is not the union of the halves"
            );
        } else {
            panic!();
        }
    }

    {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            pool::AnchorSpanFuse,
            witness::anchor_span_fuse((*right.data(), *left.data()), &right_members, &left_members),
            right,
            left,
        ) {
            assert_eq!(
                err.to_string(),
                "AnchorSpanFuse: spans do not share a vertex"
            );
        } else {
            panic!();
        }
    }
}

#[test]
fn empty_blocks_do_not_advance_the_anchor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
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
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(100);
    let cm = note.commitment();

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
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
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let (_cm, nf_current, nf_next, _anchor, _pk, _cv) = *bind_pcd.data();
    assert_eq!(
        nf_current,
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(spend_epoch)
    );
    assert_eq!(
        nf_next,
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(spend_epoch.next().unwrap())
    );
}

#[test]
fn spend_rejects_invalid_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let other = WalletSim::random(rng);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();

    let phantom = Note {
        value: value::Positive::try_from(999_999u64).unwrap(),
        rcm: note::CommitmentTrapdoor::random(rng),
        ..note
    };
    assert_eq!(Fp::from(note.psi), Fp::from(phantom.psi));
    assert_ne!(note.commitment(), phantom.commitment());

    let wrong_value = value::Positive::try_from(999_999u64).unwrap();
    assert_ne!(u64::from(wrong_value), u64::from(note.value));

    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

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
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            spend::SpendBind,
            (rcv,),
            spendable_pcd.clone(),
            secret_pcd,
        ) {
            assert_eq!(
                err.to_string(),
                "SpendBind: secret does not match note",
                "{label}"
            );
        } else {
            panic!("{label}");
        }
    }

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let (_rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        stamp::SpendAction,
        witness::spend_action((*bind_pcd.data(), ()), theta, other.pak),
        bind_pcd,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(err.to_string(), "SpendAction: pak not related to note");
    } else {
        panic!();
    }
}

#[test]
fn step_accepts_zero_value_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());

    {
        let zero_note = Note {
            pk: user.pak.derive_payment_key(),
            value: value::Positive::try_from(0u64).unwrap(),
            psi: nullifier::Trapdoor::random(rng),
            rcm: note::CommitmentTrapdoor::random(rng),
        };
        let out_rcv = value::Trapdoor::random(rng);
        let out_theta = ActionEntropy::random(rng);
        let out_anchor = PoolSim::genesis_with(random_block(rng, 1, 50)).anchor();

        let (bind_pcd, ()) = PROOF_SYSTEM
            .seed(rng, output::OutputBind, (zero_note, out_rcv))
            .unwrap();

        PROOF_SYSTEM
            .fuse(
                rng,
                stamp::OutputAction,
                witness::output_action((*bind_pcd.data(), ()), out_theta, out_anchor),
                bind_pcd,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
    }

    {
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
        let note = user.random_note(0);
        pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
        let height = pool.height();
        let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
        let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);

        let (_rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
        PROOF_SYSTEM
            .fuse(
                rng,
                stamp::SpendAction,
                witness::spend_action((*bind_pcd.data(), ()), theta, user.pak),
                bind_pcd,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
    }
}

#[test]
fn spend_after_lift_publishes_anchor_epoch_nullifiers() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());
    let epoch1 = EpochIndex::new(1);
    let epoch2 = EpochIndex::new(2);
    mine_through(rng, &mut pool, epoch2.first_block());

    let spendable = user.spendable_at(rng, &pool, &note, epoch1);
    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch1),
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch2)
        ],
        epoch1,
    );
    let unspent = sync.build_next_unspent(rng, 0, &pool, epoch2);
    let lifted = user.lift(rng, spendable, unspent, &note);

    let bind_pcd = honest_spend_bind(rng, &user, &note, lifted);
    let (_cm, nf_current, _nf_next, _anchor, _pk, _cv) = *bind_pcd.data();
    assert_eq!(
        nf_current,
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch2)
    );
    assert_ne!(
        nf_current,
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch1)
    );

    let stamp = honest_spend_stamp(rng, &user, bind_pcd);
    let expected = TachygramSetPoly::from_iter([
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch2)
            .into(),
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(EpochIndex::new(3))
            .into(),
    ])
    .commit();
    assert_eq!(stamp.data().1, expected);
}

#[test]
fn spend_stamp_assembles_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let stamp_pcd = honest_spend_stamp(rng, &user, bind_pcd);
    let (_actions, tg_commit, _anchor) = *stamp_pcd.data();
    let expected = TachygramSetPoly::from_iter([
        Tachygram::from(
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(spend_epoch),
        ),
        Tachygram::from(
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(spend_epoch.next().unwrap()),
        ),
    ])
    .commit();
    assert_eq!(tg_commit, expected);
}

#[test]
fn sync_sim_builds_unspent_for_wallet_lift_across_epochs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());
    let epoch1 = EpochIndex::new(1);
    let epoch2 = EpochIndex::new(2);
    mine_through(rng, &mut pool, epoch2.first_block());

    let spendable = user.spendable_at(rng, &pool, &note, epoch1);
    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch1),
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch2)
        ],
        epoch1,
    );

    let unspent = sync.build_next_unspent(rng, 0, &pool, epoch2);
    assert_eq!(sync.consumed(0), 1);

    let lifted = user.lift(rng, spendable, unspent, &note);

    assert_eq!(lifted.data().1, epoch2);
    assert_eq!(lifted.data().2, pool.block(epoch2.first_block()).prev);
    assert_eq!(lifted.data().0, note.commitment());
}

#[test]
fn unspent_lift_spans_several_whole_epochs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());
    let epoch1 = EpochIndex::new(1);
    let epoch4 = EpochIndex::new(4);

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
            .map(|epoch| {
                user.pak
                    .nk
                    .derive_note_private(note.psi)
                    .derive_nullifier(EpochIndex::new(epoch))
            })
            .collect(),
        epoch1,
    );

    let unspent = sync.build_next_unspent(rng, 0, &pool, epoch4);
    assert_eq!(sync.consumed(0), 3);

    let lifted = user.lift(rng, spendable, unspent, &note);
    assert_eq!(lifted.data().1, epoch4);
    assert_eq!(lifted.data().2, pool.block(epoch4.first_block()).prev);
    assert_eq!(lifted.data().0, note.commitment());
}

fn multi_epoch_fuse_setup(
    rng: &mut StdRng,
) -> (
    [Nullifier; 4],
    Pcd<pool::ArbitraryUnspent>,
    Pcd<pool::ArbitraryUnspent>,
) {
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    mine_through(rng, &mut pool, EpochIndex::new(3).last_block());
    let nf: [Nullifier; 4] =
        array::from_fn(|_| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))));
    let at = |epoch: EpochIndex| nf[usize::try_from(u32::from(epoch)).unwrap()];
    let left =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(0), EpochIndex::new(2)));
    let right =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(2), EpochIndex::new(4)));
    assert_eq!(left.data().0, Anchor::default());
    assert_eq!(left.data().4, right.data().0);
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
        .unwrap();

    let (anchor_start, epoch_start, elapsed, epoch_next, anchor_next) = *fused.data();
    assert_eq!(anchor_start, start);
    assert_eq!(anchor_next, end);
    assert_eq!(
        elapsed,
        NfSeqPoly::new(EpochIndex::new(0), &[nf0, nf1, nf2, nf3]).commit()
    );
    assert_eq!(u32::from(epoch_start), 0);
    assert_eq!(u32::from(epoch_next), 4);
}

#[test]
fn unspent_fuse_rejects_wrong_left_seq() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, nf2, nf3], left, right) = multi_epoch_fuse_setup(rng);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        pool::UnspentFuse,
        (
            NfSeqPoly::new(EpochIndex::new(0), &[nf1, nf0]),
            NfSeqPoly::new(EpochIndex::new(0), &[nf0, nf1, nf2, nf3]),
            NfSeqPoly::new(EpochIndex::new(2), &[nf2, nf3]),
        ),
        left,
        right,
    ) {
        assert_eq!(
            err.to_string(),
            "UnspentFuse: left polynomial does not match header"
        );
    } else {
        panic!();
    }
}

#[test]
fn unspent_fuse_rejects_wrong_right_seq() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, nf2, nf3], left, right) = multi_epoch_fuse_setup(rng);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        pool::UnspentFuse,
        (
            NfSeqPoly::new(EpochIndex::new(0), &[nf0, nf1]),
            NfSeqPoly::new(EpochIndex::new(0), &[nf0, nf1, nf2, nf3]),
            NfSeqPoly::new(EpochIndex::new(2), &[nf3, nf2]),
        ),
        left,
        right,
    ) {
        assert_eq!(
            err.to_string(),
            "UnspentFuse: right polynomial does not match header"
        );
    } else {
        panic!();
    }
}

#[test]
fn unspent_fuse_rejects_wrong_combined() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, nf2, nf3], left, right) = multi_epoch_fuse_setup(rng);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        pool::UnspentFuse,
        (
            NfSeqPoly::new(EpochIndex::new(0), &[nf0, nf1]),
            NfSeqPoly::new(EpochIndex::new(2), &[nf2, nf3]),
            NfSeqPoly::new(EpochIndex::new(2), &[nf2, nf3]),
        ),
        left,
        right,
    ) {
        assert_eq!(
            err.to_string(),
            "UnspentFuse: combined is not the concatenation of the halves"
        );
    } else {
        panic!();
    }
}

#[test]
fn lift_crosses_a_stampless_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(300);
    mine_cm_block(rng, &mut pool, note.commitment());
    let (epoch1, epoch2, epoch3) = (EpochIndex::new(1), EpochIndex::new(2), EpochIndex::new(3));

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
        |epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch)
        },
        (epoch1, epoch3),
    );
    let (_, epoch_start, elapsed, epoch_next, _) = *arbitrary.data();
    assert_eq!(epoch_start, epoch1);
    assert_eq!(epoch_next, epoch3);
    assert_eq!(
        elapsed,
        NfSeqPoly::new(
            epoch1,
            &[
                user.pak
                    .nk
                    .derive_note_private(note.psi)
                    .derive_nullifier(epoch1),
                user.pak
                    .nk
                    .derive_note_private(note.psi)
                    .derive_nullifier(epoch2)
            ],
        )
        .commit()
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

    let forged = Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    let nf = |epoch: EpochIndex| {
        if epoch == epoch0 {
            forged
        } else {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch)
        }
    };
    let unspent = build_unspent_pcd_over_epochs(rng, &pool, nf, (epoch0, epoch1));

    let (_, _, _, unspent_end, _) = *unspent.data();
    let range = user.derivation_pcd(rng, note, epoch0, unspent_end);
    let witness = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &[forged],
    );

    if let Err(ragu_core::Error::InvalidWitness(err)) =
        PROOF_SYSTEM.fuse(rng, pool::UnspentBind, witness, unspent, range)
    {
        assert_eq!(
            err.to_string(),
            "UnspentBind: sequence does not match the derivation"
        );
    } else {
        panic!();
    }
}

#[test]
fn unspent_bind_window_may_end_at_the_final_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let epoch_start = EpochIndex::new(EPOCH_MAX + 1 - NF_DERIVATION_WIDTH as u32);
    let epoch_end = EpochIndex::new(EPOCH_MAX);
    let range = user.derivation_pcd(rng, note, epoch_start, epoch_end);

    let elapsed: Vec<Nullifier> = (u32::from(epoch_start)..u32::from(epoch_end))
        .map(|epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(EpochIndex::new(epoch))
        })
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

    assert_eq!(
        complement_seq.commit(),
        NfSeqPoly::new(
            epoch_end,
            &[user
                .pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch_end)]
        )
        .commit()
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
        &[Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)))],
    );

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        pool::UnspentBind,
        (bogus_elapsed, nf_seq, complement_seq),
        unspent,
        range,
    ) {
        assert_eq!(
            err.to_string(),
            "UnspentBind: elapsed polynomial does not match header"
        );
    } else {
        panic!();
    }
}

#[test]
fn unspent_bind_rejects_uncovered_start() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let pool = pool_closing_epoch_zero(rng, &note);

    let (unspent, elapsed) = epoch_zero_unspent(rng, &pool, &user, &note);
    let range = user.derivation_pcd(rng, note, EpochIndex::new(64), EpochIndex::new(64));
    let window = user.covering_window(&note, &range);
    let witness = (
        NfSeqPoly::new(EpochIndex::new(0), &elapsed),
        NfSeqPoly::new(EpochIndex::new(64), &window),
        NfSeqPoly::new(EpochIndex::new(64), &[]),
    );

    if let Err(ragu_core::Error::InvalidWitness(err)) =
        PROOF_SYSTEM.fuse(rng, pool::UnspentBind, witness, unspent, range)
    {
        assert_eq!(
            err.to_string(),
            "UnspentBind: sequence does not match the derivation"
        );
    } else {
        panic!();
    }
}

#[test]
fn unspent_bind_rejects_uncovered_end() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let last = EpochIndex::new(NF_DERIVATION_WIDTH as u32);
    let unspent = detached_segment(rng, last, |epoch| {
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch)
    });

    let range = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(0));
    let window = user.covering_window(&note, &range);
    let witness = (
        NfSeqPoly::new(
            last,
            &[user
                .pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(last)],
        ),
        NfSeqPoly::new(EpochIndex::new(0), &window),
        NfSeqPoly::new(EpochIndex::new(0), &[]),
    );

    if let Err(ragu_core::Error::InvalidWitness(err)) =
        PROOF_SYSTEM.fuse(rng, pool::UnspentBind, witness, unspent, range)
    {
        assert_eq!(
            err.to_string(),
            "UnspentBind: sequence does not match the derivation"
        );
    } else {
        panic!();
    }
}

#[test]
fn spendable_lift_rejects_wrong_cm() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    let phantom = Note {
        value: value::Positive::try_from(700u64).unwrap(),
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
        |epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch)
        },
        (epoch1, epoch2),
    );
    let unspent = user.unspent_bind(rng, arbitrary, &phantom);

    if let Err(ragu_core::Error::InvalidWitness(err)) =
        PROOF_SYSTEM.fuse(rng, spendable::SpendableLift, (), spendable, unspent)
    {
        assert_eq!(
            err.to_string(),
            "SpendableLift: unspent cm does not match spendable"
        );
    } else {
        panic!();
    }
}

#[test]
fn spendable_lift_rejects_non_adjacent_unspent() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let pool = pool_closing_epoch_zero(rng, &note);
    let epoch1 = EpochIndex::new(1);
    let spendable = user.spendable_at(rng, &pool, &note, epoch1);

    let arbitrary = detached_segment(rng, epoch1, |epoch| {
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch)
    });
    let unspent = user.unspent_bind(rng, arbitrary, &note);

    if let Err(ragu_core::Error::InvalidWitness(err)) =
        PROOF_SYSTEM.fuse(rng, spendable::SpendableLift, (), spendable, unspent)
    {
        assert_eq!(
            err.to_string(),
            "SpendableLift: unspent not adjacent to spendable"
        );
    } else {
        panic!();
    }
}

fn honest_secret(rng: &mut StdRng, user: &WalletSim, note: Note) -> Pcd<delegation::NoteSecret> {
    let (secret, ()) = PROOF_SYSTEM
        .seed(
            rng,
            delegation::NoteSeed,
            witness::note_seed(((), ()), note, user.pak),
        )
        .unwrap();
    secret
}

#[test]
fn note_seed_carries_the_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let secret = honest_secret(rng, &user, note);

    let (cm, opening, mk) = *secret.data();
    assert_eq!(cm, note.commitment());
    assert_eq!(mk, user.pak.nk.derive_note_private(note.psi));
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
        )
    );
}

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
        .unwrap();

    let (cm, opening, _) = *secret.data();
    assert_eq!(
        Fp::from(opening.pk),
        Fp::from(stranger.pak.derive_payment_key())
    );
    assert_ne!(cm, note.commitment());
}

#[test]
fn nullifier_derive_rejects_a_foreign_sequence() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note_a = user.random_note(500);
    let note_b = user.random_note(700);

    let secret_a = honest_secret(rng, &user, note_a);
    let (cm_a, ..) = *secret_a.data();
    let (epoch_start, foreign_seq) = witness::nullifier_derive(
        (
            (cm_a, note_a, user.pak.nk.derive_note_private(note_b.psi)),
            (),
        ),
        EpochIndex::new(16),
    );
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        delegation::NullifierDerive,
        (epoch_start, foreign_seq),
        secret_a,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "NullifierDerive: sequence does not match the derived window"
        );
    } else {
        panic!();
    }
}

#[test]
fn nullifier_derive_rejects_a_misaligned_epoch_start() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let secret = honest_secret(rng, &user, note);
    let (_, seq) = witness::nullifier_derive((*secret.data(), ()), EpochIndex::new(12));
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        delegation::NullifierDerive,
        (EpochIndex::new(14), seq),
        secret,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "NullifierDerive: epoch_start is not group-aligned"
        );
    } else {
        panic!();
    }
}

#[test]
fn nullifier_derive_rejects_a_window_past_the_final_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let epoch_start = EpochIndex::new(EPOCH_MAX - 3);
    let secret = honest_secret(rng, &user, note);

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        delegation::NullifierDerive,
        (epoch_start, NfSeqPoly::new(epoch_start, &[])),
        secret,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "NullifierDerive: window exceeds the epoch range"
        );
    } else {
        panic!();
    }
}

#[test]
fn derivation_exports_the_whole_window() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let epoch_start = EpochIndex::new(12);
    let epoch_end = EpochIndex::new(u32::from(epoch_start) + NF_DERIVATION_WIDTH as u32 - 1);
    let range = user.derivation_pcd(rng, note, epoch_start, epoch_end);
    let (cm, start, commit, range_end) = *range.data();

    assert_eq!(start, epoch_start);
    assert_eq!(range_end, epoch_end);
    let members = user.covering_window(&note, &range);
    let seq = NfSeqPoly::new(epoch_start, &members);
    assert_eq!(commit, seq.commit());

    let far = user.derivation_pcd(
        rng,
        note,
        EpochIndex::new(100_000),
        EpochIndex::new(100_000 + NF_DERIVATION_WIDTH as u32 - 1),
    );
    assert_eq!(cm, far.data().0);
}

#[test]
fn derivation_covers_with_whole_windows() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let start = EpochIndex::new(NF_DERIVATION_WIDTH as u32 - 2);
    let last = EpochIndex::new(NF_DERIVATION_WIDTH as u32 + 2);
    let range = user.derivation_pcd(rng, note, start, last);
    let (cm, cover_start, commit, cover_end) = *range.data();

    assert_eq!(Tachygram::from(cm), note.commitment().into());
    assert!(cover_start <= start && last <= cover_end);
    assert_eq!(
        (u32::from(cover_end) - u32::from(cover_start) + 1) % NF_DERIVATION_WIDTH as u32,
        0
    );
    let members: Vec<Nullifier> = (u32::from(cover_start)..=u32::from(cover_end))
        .map(|epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(EpochIndex::new(epoch))
        })
        .collect();
    let seq = NfSeqPoly::new(cover_start, &members);
    assert_eq!(commit, seq.commit());
}

#[test]
fn nullifier_fuse_rejects_non_contiguous() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let (left_start, right_start) = (EpochIndex::new(0), EpochIndex::new(32));
    let range_a = user.derivation_pcd(rng, note, left_start, EpochIndex::new(15));
    let range_b = user.derivation_pcd(rng, note, right_start, EpochIndex::new(47));
    let witness = witness::nullifier_fuse(
        (*range_a.data(), *range_b.data()),
        &user.covering_window(&note, &range_a),
        &user.covering_window(&note, &range_b),
    );

    if let Err(ragu_core::Error::InvalidWitness(err)) =
        PROOF_SYSTEM.fuse(rng, delegation::NullifierFuse, witness, range_a, range_b)
    {
        assert_eq!(err.to_string(), "NullifierFuse: ranges not contiguous");
    } else {
        panic!();
    }
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

    if let Err(ragu_core::Error::InvalidWitness(err)) =
        PROOF_SYSTEM.fuse(rng, delegation::NullifierFuse, witness, range_a, range_b)
    {
        assert_eq!(err.to_string(), "NullifierFuse: note commitments differ");
    } else {
        panic!();
    }
}

#[test]
fn spend_bind_rejects_a_secret_for_another_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let other = user.random_note(700);

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let foreign = honest_secret(rng, &user, other);
    let rcv = value::Trapdoor::random(rng);

    if let Err(ragu_core::Error::InvalidWitness(err)) =
        PROOF_SYSTEM.fuse(rng, spend::SpendBind, (rcv,), spendable, foreign)
    {
        assert_eq!(err.to_string(), "SpendBind: secret does not match note");
    } else {
        panic!();
    }
}

#[test]
fn spend_bind_derives_a_pair_across_a_group_boundary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    while pool.height().0 < 3 * EPOCH_SIZE {
        pool.mine(random_block(rng, 1, 2));
    }
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let epoch = init_height.epoch();
    assert_eq!(epoch, EpochIndex::new(3));
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let anchor = spendable.data().2;

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable);

    let (cm, nf_current, nf_next, bind_anchor, _pk, _cv) = *bind_pcd.data();
    assert_eq!(
        (cm, nf_current, nf_next, bind_anchor),
        (
            note.commitment(),
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch),
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(EpochIndex::new(4)),
            anchor,
        )
    );
}

#[test]
fn spend_stamp_rejects_a_mismatched_stamp_accumulator() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);

    let (_rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let (.., action_set, _pair) = witness::spend_action((*bind_pcd.data(), ()), theta, user.pak);
    let forged = TachygramSetPoly::from_iter([Tachygram::random(rng)]);

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        stamp::SpendAction,
        (theta, user.pak, action_set, forged),
        bind_pcd,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "SpendAction: tachygram set does not commit to the nullifier pair"
        );
    } else {
        panic!();
    }
}

#[test]
fn spend_stamp_rejects_a_foreign_action_set() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);

    let (_rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let (_, foreign_theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let (.., foreign, tachygram_set) =
        witness::spend_action((*bind_pcd.data(), ()), foreign_theta, user.pak);

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        stamp::SpendAction,
        (theta, user.pak, foreign, tachygram_set),
        bind_pcd,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "SpendAction: action set does not commit to the action"
        );
    } else {
        panic!();
    }
}

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
    if let Err(ragu_core::Error::InvalidWitness(err)) =
        PROOF_SYSTEM.fuse(rng, pool::UnspentBind, witness, unspent, range)
    {
        assert_eq!(
            err.to_string(),
            "UnspentBind: covering sequence does not match header"
        );
    } else {
        panic!();
    }
}

#[test]
fn multi_chunk_lift_uses_per_chunk_windows() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());
    let (epoch1, epoch2, epoch3) = (EpochIndex::new(1), EpochIndex::new(2), EpochIndex::new(3));
    mine_through(rng, &mut pool, epoch2.first_block());

    let spendable = user.spendable_at(rng, &pool, &note, epoch1);
    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch1),
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch2),
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch3),
        ],
        epoch1,
    );

    let unspent_one = sync.build_next_unspent(rng, 0, &pool, epoch2);
    let lifted_one = user.lift(rng, spendable, unspent_one, &note);
    assert_eq!(lifted_one.data().1, epoch2);

    mine_through(rng, &mut pool, epoch3.first_block());
    let unspent_two = sync.build_next_unspent(rng, 0, &pool, epoch3);
    let lifted_two = user.lift(rng, lifted_one, unspent_two, &note);

    assert_eq!(lifted_two.data().1, epoch3);
    assert_eq!(lifted_two.data().2, pool.block(epoch3.first_block()).prev);
    assert_eq!(lifted_two.data().0, note.commitment());
}

fn expected_pad(note: &Note) -> Tachygram {
    Tachygram::from(poseidon::pad_tachygram(
        Fp::from(note.rcm),
        Fp::from(note.pk),
        u64::from(note.value),
        Fp::from(note.psi),
    ))
}

#[test]
fn output_bind_publishes_the_note_pair() {
    let rng = &mut StdRng::seed_from_u64(0);
    let note = WalletSim::new(shared_sk()).random_note(200);
    let rcv = value::Trapdoor::random(rng);

    let (pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .unwrap();

    assert_eq!(
        *pcd.data(),
        (
            Tachygram::from(note.commitment()),
            expected_pad(&note),
            rcv.commit(-note.value),
        )
    );
}

#[test]
fn output_stamp_publishes_the_note_pair() {
    let rng = &mut StdRng::seed_from_u64(0);
    let note = WalletSim::new(shared_sk()).random_note(200);
    let (rcv, theta, _plan) = build_output_plan(rng, note);
    let anchor = PoolSim::genesis_with(random_block(rng, 1, 50)).anchor();

    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .unwrap();
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::OutputAction,
            witness::output_action((*bind_pcd.data(), ()), theta, anchor),
            bind_pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

    let (_action_commit, tachygram_commit, stamp_anchor) = *pcd.data();
    assert_eq!(
        tachygram_commit,
        TachygramSetPoly::from_iter([Tachygram::from(note.commitment()), expected_pad(&note)])
            .commit()
    );
    assert_eq!(stamp_anchor, anchor);
}

#[test]
fn output_stamp_rejects_a_mismatched_stamp_accumulator() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(200);

    let (rcv, theta, _plan) = build_output_plan(rng, note);
    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .unwrap();

    let anchor = PoolSim::genesis_with(random_block(rng, 1, 50)).anchor();
    let (.., action_set, _pair) = witness::output_action((*bind_pcd.data(), ()), theta, anchor);
    let forged = TachygramSetPoly::from_iter([Tachygram::random(rng)]);

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        stamp::OutputAction,
        (theta, anchor, action_set, forged),
        bind_pcd,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "OutputAction: tachygram set does not commit to the bound pair"
        );
    } else {
        panic!();
    }
}

#[test]
fn pad_differs_from_commitment() {
    let note = WalletSim::new(shared_sk()).random_note(200);

    assert_ne!(Tachygram::from(note.commitment()), expected_pad(&note));
}

#[test]
fn output_stamp_rejects_a_foreign_action_set() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(200);

    let (rcv, theta, _plan) = build_output_plan(rng, note);
    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .unwrap();

    let anchor = PoolSim::genesis_with(random_block(rng, 1, 50)).anchor();
    let (.., foreign, tachygram_set) =
        witness::output_action((*bind_pcd.data(), ()), ActionEntropy::random(rng), anchor);

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        stamp::OutputAction,
        (theta, anchor, foreign, tachygram_set),
        bind_pcd,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "OutputAction: action set does not commit to the action"
        );
    } else {
        panic!();
    }
}

fn output_action_commit(
    rng: &mut StdRng,
    note: Note,
    theta: ActionEntropy,
    rcv: value::Trapdoor,
) -> ActionSetCommit {
    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .unwrap();
    let anchor = PoolSim::genesis_with(random_block(rng, 1, 50)).anchor();
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::OutputAction,
            witness::output_action((*bind_pcd.data(), ()), theta, anchor),
            bind_pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    pcd.data().0
}

#[test]
fn output_action_is_bound_to_its_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let note = WalletSim::new(shared_sk()).random_note(200);
    let diverted = WalletSim::random(rng).random_note(200);
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let plan = action::Plan::output(note, theta, rcv);
    let planned = ActionSetPoly::from_iter([plan.digest().unwrap()]).commit();

    assert_eq!(output_action_commit(rng, note, theta, rcv), planned);
    assert_ne!(output_action_commit(rng, diverted, theta, rcv), planned);
}

fn spend_action_commit(
    rng: &mut StdRng,
    user: &WalletSim,
    spendable: Pcd<spendable::NoteSpendable>,
    note: Note,
    theta: ActionEntropy,
    rcv: value::Trapdoor,
) -> ActionSetCommit {
    let secret_pcd = honest_secret(rng, user, note);
    let (bind_pcd, ()) = PROOF_SYSTEM
        .fuse(rng, spend::SpendBind, (rcv,), spendable, secret_pcd)
        .unwrap();
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::SpendAction,
            witness::spend_action((*bind_pcd.data(), ()), theta, user.pak),
            bind_pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    pcd.data().0
}

#[test]
fn spend_action_is_bound_to_its_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let swapped = user.random_note(500);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(
        rng,
        &[vec![note.commitment(), swapped.commitment()]],
        4,
    ));
    let height = pool.height();

    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let plan = action::Plan::spend(note, theta, rcv, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });
    let planned = ActionSetPoly::from_iter([plan.digest().unwrap()]).commit();

    let planned_spendable = user.fresh_spend(rng, &pool, height, &note);
    assert_eq!(
        spend_action_commit(rng, &user, planned_spendable, note, theta, rcv),
        planned
    );
    let swapped_spendable = user.fresh_spend(rng, &pool, height, &swapped);
    assert_ne!(
        spend_action_commit(rng, &user, swapped_spendable, swapped, theta, rcv),
        planned
    );
}

#[test]
fn nullifier_fuse_composes() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let left = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(15));
    let right = user.derivation_pcd(rng, note, EpochIndex::new(16), EpochIndex::new(31));
    let left_nfs: Vec<Nullifier> = (0..16)
        .map(|epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(EpochIndex::new(epoch))
        })
        .collect();
    let right_nfs: Vec<Nullifier> = (16..32)
        .map(|epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(EpochIndex::new(epoch))
        })
        .collect();
    let fuse_witness =
        witness::nullifier_fuse((*left.data(), *right.data()), &left_nfs, &right_nfs);
    let (merged, ()) = PROOF_SYSTEM
        .fuse(rng, delegation::NullifierFuse, fuse_witness, left, right)
        .unwrap();

    let (cm, start, commit, last) = *merged.data();
    assert_eq!(cm, note.commitment());
    assert_eq!((start, last), (EpochIndex::new(0), EpochIndex::new(31)));
    let members: Vec<Nullifier> = (0..32)
        .map(|epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(EpochIndex::new(epoch))
        })
        .collect();
    let expected = NfSeqPoly::new(EpochIndex::new(0), &members);
    assert_eq!(commit, expected.commit());
}

#[test]
fn nullifier_fuse_rejects_a_wrong_merged() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let left = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(15));
    let right = user.derivation_pcd(rng, note, EpochIndex::new(16), EpochIndex::new(31));
    let left_nfs: Vec<Nullifier> = (0..16)
        .map(|epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(EpochIndex::new(epoch))
        })
        .collect();
    let right_nfs: Vec<Nullifier> = (16..32)
        .map(|epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(EpochIndex::new(epoch))
        })
        .collect();
    let (left_seq, _merged, right_seq) =
        witness::nullifier_fuse((*left.data(), *right.data()), &left_nfs, &right_nfs);
    let wrong_members: Vec<Nullifier> =
        iter::repeat_with(|| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))))
            .take(32)
            .collect();
    let wrong = NfSeqPoly::new(EpochIndex::new(0), &wrong_members);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        delegation::NullifierFuse,
        (left_seq, wrong, right_seq),
        left,
        right,
    ) {
        assert_eq!(
            err.to_string(),
            "NullifierFuse: merged is not the concat of the halves"
        );
    } else {
        panic!();
    }
}

#[test]
fn spendable_lift_rejects_a_wrong_start() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());
    let (epoch1, epoch2, epoch3) = (EpochIndex::new(1), EpochIndex::new(2), EpochIndex::new(3));
    mine_through(rng, &mut pool, epoch2.last_block());
    let spendable = user.spendable_at(rng, &pool, &note, epoch1);

    let arbitrary = build_unspent_pcd_over_epochs(
        rng,
        &pool,
        |epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch)
        },
        (epoch2, epoch3),
    );
    let unspent = user.unspent_bind(rng, arbitrary, &note);

    if let Err(ragu_core::Error::InvalidWitness(err)) =
        PROOF_SYSTEM.fuse(rng, spendable::SpendableLift, (), spendable, unspent)
    {
        assert_eq!(
            err.to_string(),
            "SpendableLift: segment does not start at the lineage epoch"
        );
    } else {
        panic!();
    }
}

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
        &[Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)))],
    );
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        pool::UnspentBind,
        (elapsed_seq, nf_seq, forged),
        unspent,
        range,
    ) {
        assert_eq!(
            err.to_string(),
            "UnspentBind: sequence does not match the derivation"
        );
    } else {
        panic!();
    }
}

#[test]
fn unspent_bind_rejects_a_wrong_epoch_member() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    mine_through(rng, &mut pool, epoch1.last_block());

    let nf = |epoch: EpochIndex| {
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(if epoch == epoch1 { epoch0 } else { epoch })
    };
    let unspent = build_unspent_pcd_over_epochs(rng, &pool, nf, (epoch1, EpochIndex::new(2)));
    let range = user.derivation_pcd(rng, note, epoch0, epoch1);
    let elapsed_seq = NfSeqPoly::new(epoch1, &[nf(epoch1)]);
    let complement_seq = NfSeqPoly::new(
        EpochIndex::new(0),
        &[user
            .pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(EpochIndex::new(0))],
    );
    let nf_seq = NfSeqPoly::new(EpochIndex::new(0), &user.covering_window(&note, &range));
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        pool::UnspentBind,
        (elapsed_seq, nf_seq, complement_seq),
        unspent,
        range,
    ) {
        assert_eq!(
            err.to_string(),
            "UnspentBind: sequence does not match the derivation"
        );
    } else {
        panic!();
    }
}

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
    let duplicating = NfSeqPoly::new(
        EpochIndex::new(0),
        &[user
            .pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(EpochIndex::new(0))],
    );
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        pool::UnspentBind,
        (elapsed_seq, nf_seq, duplicating),
        unspent,
        range,
    ) {
        assert_eq!(
            err.to_string(),
            "UnspentBind: sequence does not match the derivation"
        );
    } else {
        panic!();
    }
}

#[test]
fn multi_window_span_binds_once() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    mine_cm_block(rng, &mut pool, note.commitment());

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
        |epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch)
        },
        (EpochIndex::new(0), EpochIndex::new(last_epoch)),
    );
    let unspent = user.unspent_bind(rng, arbitrary, &note);

    assert_eq!(
        (unspent.data().2, unspent.data().3),
        (EpochIndex::new(0), EpochIndex::new(last_epoch))
    );
}

#[test]
fn one_window_serves_init_and_matches_the_bind() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let epoch = init_height.epoch();

    let window = user.derivation_pcd(rng, note, epoch, EpochIndex::new(u32::from(epoch) + 1));
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let again = user.derivation_pcd(rng, note, epoch, epoch);
    assert_eq!(again.data(), window.data());

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable);
    assert_eq!(
        bind_pcd.data().1,
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch)
    );
    assert_eq!(
        bind_pcd.data().2,
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch.next().unwrap())
    );
}

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

    assert_eq!(
        bind_pcd.data().1,
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch2)
    );
    assert_eq!(
        bind_pcd.data().2,
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(EpochIndex::new(3))
    );
}
