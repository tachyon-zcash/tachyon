extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};
use core::{array, iter};

use ragu::{Pcd, Proof};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    ActionSetPoly, Anchor, AnchorSetPoly, BlockHeight, EpochIndex, NfSeqPoly, Note, Tachygram,
    TachygramSetPoly, action,
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
    PoolSim, WalletSim, build_anchor_span_pcd, build_output_stamp,
    build_unspent_pcd_over_epochs, qr_bucket_segment, random_block, random_block_with,
    seal_qr_intake, seed_qr_empty_intake, shared_sk,
};

fn mine_cm_block(rng: &mut StdRng, pool: &mut PoolSim, cm: note::Commitment) -> BlockHeight {
    pool.mine(random_block_with(rng, &[vec![cm]], 4));
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

fn honest_spend_bind(
    rng: &mut StdRng,
    user: &WalletSim,
    note: &Note,
    spendable: Pcd<spendable::NoteSpendable>,
) -> Pcd<spend::SpendHeader> {
    let secret_pcd = user.secret_pcd(rng, *note);
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
    let theta = ActionEntropy::random(rng);
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
fn unspent_fuse_joins_only_adjacent_matching_segments() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    mine_through(rng, &mut pool, EpochIndex::new(3).last_block());
    let nf: [Nullifier; 4] =
        array::from_fn(|_| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))));
    let at = |epoch: EpochIndex| nf[usize::try_from(u32::from(epoch)).unwrap()];
    let [nf0, nf1, nf2, nf3] = nf;

    let first =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(0), EpochIndex::new(1)));
    let third =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(2), EpochIndex::new(3)));
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        pool::UnspentFuse,
        witness::unspent_fuse((*first.data(), *third.data()), &[nf0], &[nf2]),
        first,
        third,
    ) {
        assert_eq!(
            err.to_string(),
            "UnspentFuse: left.anchor_next must equal right.anchor_start"
        );
    } else {
        panic!();
    }

    let left =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(0), EpochIndex::new(2)));
    let right =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(2), EpochIndex::new(4)));
    for (fuse_witness, expected) in [
        (
            (
                NfSeqPoly::new(EpochIndex::new(0), &[nf1, nf0]),
                NfSeqPoly::new(EpochIndex::new(0), &nf),
                NfSeqPoly::new(EpochIndex::new(2), &[nf2, nf3]),
            ),
            "UnspentFuse: left polynomial does not match header",
        ),
        (
            (
                NfSeqPoly::new(EpochIndex::new(0), &[nf0, nf1]),
                NfSeqPoly::new(EpochIndex::new(0), &nf),
                NfSeqPoly::new(EpochIndex::new(2), &[nf3, nf2]),
            ),
            "UnspentFuse: right polynomial does not match header",
        ),
        (
            (
                NfSeqPoly::new(EpochIndex::new(0), &[nf0, nf1]),
                NfSeqPoly::new(EpochIndex::new(2), &[nf2, nf3]),
                NfSeqPoly::new(EpochIndex::new(2), &[nf2, nf3]),
            ),
            "UnspentFuse: combined is not the concatenation of the halves",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            pool::UnspentFuse,
            fuse_witness,
            left.clone(),
            right.clone(),
        ) {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }

    let (start, end) = (left.data().0, right.data().4);
    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            witness::unspent_fuse((*left.data(), *right.data()), &[nf0, nf1], &[nf2, nf3]),
            left,
            right,
        )
        .unwrap();
    assert_eq!(
        *fused.data(),
        (
            start,
            EpochIndex::new(0),
            NfSeqPoly::new(EpochIndex::new(0), &nf).commit(),
            EpochIndex::new(4),
            end,
        )
    );
}

#[test]
fn anchor_span_holds_the_anchors_its_folds_produce() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(2, |_| random_block(rng, 1, 2));

    let (span, members) = build_anchor_span_pcd(rng, &pool, BlockHeight(1)..=BlockHeight(2));
    let (anchor_start, members_commit, anchor_end) = *span.data();

    assert_eq!(anchor_start, pool.block(BlockHeight(1)).prev);
    assert_eq!(anchor_end, pool.block(BlockHeight(2)).anchor());
    assert_eq!(members_commit, AnchorSetPoly::from_iter(members).commit());
}

#[test]
fn stamp_lift_accepts_only_anchors_the_span_holds() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(1, |_| random_block(rng, 1, 3));

    let (span, members) = build_anchor_span_pcd(rng, &pool, BlockHeight(1)..=BlockHeight(1));
    let (anchor_start, _, anchor_end) = *span.data();
    let fork = anchor_start
        .next_stamp(
            BlockHeight(1).epoch(),
            &TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit(),
        )
        .unwrap();

    for (stamp_anchor, witnessed, expected) in [
        (anchor_start, members.clone(), None),
        (members[0], members.clone(), None),
        (anchor_end, members.clone(), None),
        (
            fork,
            members.clone(),
            Some("StampLift: stamp anchor is neither the span's start nor a member"),
        ),
        (
            members[0],
            members.iter().copied().chain([fork]).collect(),
            Some("StampLift: members do not match header"),
        ),
    ] {
        let (stamp, plan, fee_descriptor) =
            build_output_stamp(rng, stamp_anchor, user.random_note(200));
        let stamp_pcd = stamp.proof.carry((
            ActionSetPoly::from_iter([plan.digest().unwrap(), fee_descriptor.digest().unwrap()])
                .commit(),
            TachygramSetPoly::from_iter(stamp.tachygrams).commit(),
            stamp_anchor,
        ));
        let lifted = PROOF_SYSTEM.fuse(
            rng,
            stamp::StampLift,
            witness::stamp_lift((*stamp_pcd.data(), *span.data()), &witnessed),
            stamp_pcd,
            span.clone(),
        );
        if let Some(expected) = expected {
            if let Err(ragu_core::Error::InvalidWitness(err)) = lifted {
                assert_eq!(err.to_string(), expected);
            } else {
                panic!("{expected}");
            }
        } else {
            assert_eq!(lifted.unwrap().0.data().2, anchor_end);
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

    let (left_poly, _combined, right_poly) =
        witness::anchor_span_fuse((*left.data(), *right.data()), &left_members, &right_members);
    let fork = left
        .data()
        .2
        .next_stamp(
            BlockHeight(2).epoch(),
            &TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit(),
        )
        .unwrap();
    for (fuse_witness, (first, second), expected) in [
        (
            (
                left_poly.clone(),
                AnchorSetPoly::from_iter(left_members.iter().copied()),
                right_poly.clone(),
            ),
            (left.clone(), right.clone()),
            "AnchorSpanFuse: combined is not the union of the halves",
        ),
        (
            (
                left_poly,
                AnchorSetPoly::from_iter(
                    left_members
                        .iter()
                        .chain(&right_members)
                        .copied()
                        .chain([fork]),
                ),
                right_poly,
            ),
            (left.clone(), right.clone()),
            "AnchorSpanFuse: combined is not the union of the halves",
        ),
        (
            witness::anchor_span_fuse((*right.data(), *left.data()), &right_members, &left_members),
            (right, left),
            "AnchorSpanFuse: spans do not share a vertex",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) =
            PROOF_SYSTEM.fuse(rng, pool::AnchorSpanFuse, fuse_witness, first, second)
        {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }
}

#[test]
fn spend_rejects_invalid_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let other = WalletSim::random(rng);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    let height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable_pcd = user.spendable_init(rng, &note, &pool, height);

    let phantom = Note {
        value: value::Positive::try_from(999_999u64).unwrap(),
        rcm: note::CommitmentTrapdoor::random(rng),
        ..note
    };
    let secret_pcd = user.secret_pcd(rng, phantom);
    let rcv = value::Trapdoor::random(rng);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        spend::SpendBind,
        (rcv,),
        spendable_pcd.clone(),
        secret_pcd,
    ) {
        assert_eq!(err.to_string(), "SpendBind: secret does not match note");
    } else {
        panic!();
    }

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let theta = ActionEntropy::random(rng);
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

    let zero_output = Note {
        pk: user.pak.derive_payment_key(),
        value: value::Positive::try_from(0u64).unwrap(),
        psi: nullifier::Trapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    };
    let rcv = value::Trapdoor::random(rng);
    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (zero_output, rcv))
        .unwrap();
    let theta = ActionEntropy::random(rng);
    let anchor = Anchor::random(rng);
    PROOF_SYSTEM
        .fuse(
            rng,
            stamp::OutputAction,
            witness::output_action((*bind_pcd.data(), ()), theta, anchor),
            bind_pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let zero_spend = user.random_note(0);
    let height = mine_cm_block(rng, &mut pool, zero_spend.commitment());
    let spendable_pcd = user.spendable_init(rng, &zero_spend, &pool, height);
    let spend_bind = honest_spend_bind(rng, &user, &zero_spend, spendable_pcd);
    honest_spend_stamp(rng, &user, spend_bind);
}

#[test]
fn spend_after_lift_publishes_anchor_epoch_nullifiers() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);
    mine_cm_block(rng, &mut pool, note.commitment());
    let epoch1 = EpochIndex::new(1);
    let epoch2 = EpochIndex::new(2);
    mine_through(rng, &mut pool, epoch2.first_block());

    let spendable = user.spendable_at(rng, &pool, &note, epoch1);
    let unspent = build_unspent_pcd_over_epochs(
        rng,
        &pool,
        |epoch| mk.derive_nullifier(epoch),
        (epoch1, epoch2),
    );
    let lifted = user.lift(rng, spendable, unspent, &note);

    let bind_pcd = honest_spend_bind(rng, &user, &note, lifted);
    let (_cm, nf_current, _nf_next, _anchor, _pk, _cv) = *bind_pcd.data();
    assert_eq!(nf_current, mk.derive_nullifier(epoch2));
    assert_ne!(nf_current, mk.derive_nullifier(epoch1));

    let stamp = honest_spend_stamp(rng, &user, bind_pcd);
    let expected = TachygramSetPoly::from_iter([
        mk.derive_nullifier(epoch2).into(),
        mk.derive_nullifier(EpochIndex::new(3)).into(),
    ])
    .commit();
    assert_eq!(stamp.data().1, expected);
}

#[test]
fn spend_action_commits_to_the_plan_and_the_nullifier_pair() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let height = mine_cm_block(rng, &mut pool, note.commitment());
    let spend_epoch = height.epoch();
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);

    let spendable = user.spendable_init(rng, &note, &pool, height);
    let secret_pcd = user.secret_pcd(rng, note);
    let (bind_pcd, ()) = PROOF_SYSTEM
        .fuse(rng, spend::SpendBind, (rcv,), spendable, secret_pcd)
        .unwrap();
    let (.., action_set, tachygram_set) =
        witness::spend_action((*bind_pcd.data(), ()), theta, user.pak);
    let (.., foreign_action_set, _) =
        witness::spend_action((*bind_pcd.data(), ()), ActionEntropy::random(rng), user.pak);

    for (action_witness, expected) in [
        (
            (
                theta,
                user.pak,
                action_set,
                TachygramSetPoly::from_iter([Tachygram::random(rng)]),
            ),
            "SpendAction: tachygram set does not commit to the nullifier pair",
        ),
        (
            (theta, user.pak, foreign_action_set, tachygram_set),
            "SpendAction: action set does not commit to the action",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            stamp::SpendAction,
            action_witness,
            bind_pcd.clone(),
            Proof::bootstrap().carry::<()>(()),
        ) {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }

    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::SpendAction,
            witness::spend_action((*bind_pcd.data(), ()), theta, user.pak),
            bind_pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let plan = action::Plan::spend(note, theta, rcv, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });
    let (action_commit, tachygram_commit, _) = *pcd.data();
    assert_eq!(
        action_commit,
        ActionSetPoly::from_iter([plan.digest().unwrap()]).commit()
    );
    assert_eq!(
        tachygram_commit,
        TachygramSetPoly::from_iter([
            Tachygram::from(mk.derive_nullifier(spend_epoch)),
            Tachygram::from(mk.derive_nullifier(spend_epoch.next().unwrap())),
        ])
        .commit()
    );
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
    let unspent = build_unspent_pcd_over_epochs(
        rng,
        &pool,
        |epoch| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch)
        },
        (epoch1, epoch4),
    );

    let lifted = user.lift(rng, spendable, unspent, &note);
    assert_eq!(lifted.data().1, epoch4);
    assert_eq!(lifted.data().2, pool.block(epoch4.first_block()).prev);
    assert_eq!(lifted.data().0, note.commitment());
}

#[test]
fn lift_crosses_a_stampless_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(300);
    let mk = user.pak.nk.derive_note_private(note.psi);
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
        |epoch| mk.derive_nullifier(epoch),
        (epoch1, epoch3),
    );
    let (_, epoch_start, elapsed, epoch_next, _) = *arbitrary.data();
    assert_eq!(epoch_start, epoch1);
    assert_eq!(epoch_next, epoch3);
    assert_eq!(
        elapsed,
        NfSeqPoly::new(
            epoch1,
            &[mk.derive_nullifier(epoch1), mk.derive_nullifier(epoch2)],
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
    let mk = user.pak.nk.derive_note_private(note.psi);

    let epoch_start = EpochIndex::new(EPOCH_MAX + 1 - NF_DERIVATION_WIDTH as u32);
    let epoch_end = EpochIndex::new(EPOCH_MAX);
    let range = user.derivation_pcd(rng, note, epoch_start, epoch_end);

    let elapsed: Vec<Nullifier> = (u32::from(epoch_start)..u32::from(epoch_end))
        .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
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
        NfSeqPoly::new(epoch_end, &[mk.derive_nullifier(epoch_end)]).commit()
    );
}

#[test]
fn unspent_bind_rejects_mismatched_sequences() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let other = user.random_note(700);
    let pool = pool_closing_epoch_zero(rng, &note);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let unspent = build_unspent_pcd_over_epochs(
        rng,
        &pool,
        |epoch| mk.derive_nullifier(epoch),
        (EpochIndex::new(0), EpochIndex::new(1)),
    );
    let elapsed = vec![mk.derive_nullifier(EpochIndex::new(0))];

    let range = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(0));
    let (elapsed_seq, nf_seq, complement_seq) = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &elapsed,
    );
    let wide = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(1));
    let (wide_elapsed_seq, wide_nf_seq, _) = witness::unspent_bind(
        (*unspent.data(), *wide.data()),
        &user.covering_window(&note, &wide),
        &elapsed,
    );
    let later = user.derivation_pcd(rng, note, EpochIndex::new(64), EpochIndex::new(64));

    for (bind_range, bind_witness, expected) in [
        (
            range.clone(),
            (
                NfSeqPoly::new(
                    EpochIndex::new(0),
                    &[Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)))],
                ),
                nf_seq.clone(),
                complement_seq,
            ),
            "UnspentBind: elapsed polynomial does not match header",
        ),
        (
            range.clone(),
            witness::unspent_bind(
                (*unspent.data(), *range.data()),
                &user.covering_window(&other, &range),
                &elapsed,
            ),
            "UnspentBind: covering sequence does not match header",
        ),
        (
            range,
            (
                elapsed_seq,
                nf_seq,
                NfSeqPoly::new(
                    EpochIndex::new(0),
                    &[mk.derive_nullifier(EpochIndex::new(0))],
                ),
            ),
            "UnspentBind: sequence does not match the derivation",
        ),
        (
            wide,
            (
                wide_elapsed_seq,
                wide_nf_seq,
                NfSeqPoly::new(
                    EpochIndex::new(1),
                    &[Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)))],
                ),
            ),
            "UnspentBind: sequence does not match the derivation",
        ),
        (
            later.clone(),
            (
                NfSeqPoly::new(EpochIndex::new(0), &elapsed),
                NfSeqPoly::new(EpochIndex::new(64), &user.covering_window(&note, &later)),
                NfSeqPoly::new(EpochIndex::new(64), &[]),
            ),
            "UnspentBind: sequence does not match the derivation",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            pool::UnspentBind,
            bind_witness,
            unspent.clone(),
            bind_range,
        ) {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }
}

#[test]
fn unspent_bind_rejects_uncovered_end() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let last = EpochIndex::new(NF_DERIVATION_WIDTH as u32);
    let unspent = detached_segment(rng, last, |epoch| mk.derive_nullifier(epoch));

    let range = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(0));
    let window = user.covering_window(&note, &range);
    let witness = (
        NfSeqPoly::new(last, &[mk.derive_nullifier(last)]),
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
fn spendable_lift_rejects_mismatched_segments() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let phantom = Note {
        value: value::Positive::try_from(700u64).unwrap(),
        rcm: note::CommitmentTrapdoor::random(rng),
        ..note
    };
    mine_cm_block(rng, &mut pool, note.commitment());
    let (epoch1, epoch2, epoch3) = (EpochIndex::new(1), EpochIndex::new(2), EpochIndex::new(3));
    mine_through(rng, &mut pool, epoch2.last_block());
    let spendable = user.spendable_at(rng, &pool, &note, epoch1);

    for (unspent, expected) in [
        (
            {
                let arbitrary = build_unspent_pcd_over_epochs(
                    rng,
                    &pool,
                    |epoch| mk.derive_nullifier(epoch),
                    (epoch1, epoch2),
                );
                user.unspent_bind(rng, arbitrary, &phantom)
            },
            "SpendableLift: unspent cm does not match spendable",
        ),
        (
            {
                let arbitrary = detached_segment(rng, epoch1, |epoch| mk.derive_nullifier(epoch));
                user.unspent_bind(rng, arbitrary, &note)
            },
            "SpendableLift: unspent not adjacent to spendable",
        ),
        (
            {
                let arbitrary = build_unspent_pcd_over_epochs(
                    rng,
                    &pool,
                    |epoch| mk.derive_nullifier(epoch),
                    (epoch2, epoch3),
                );
                user.unspent_bind(rng, arbitrary, &note)
            },
            "SpendableLift: segment does not start at the lineage epoch",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            spendable::SpendableLift,
            (),
            spendable.clone(),
            unspent,
        ) {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }
}

#[test]
fn note_seed_carries_the_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let secret = user.secret_pcd(rng, note);

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
fn nullifier_derive_rejects_invalid_windows() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let other = user.random_note(700);
    let secret = user.secret_pcd(rng, note);
    let (cm, ..) = *secret.data();
    let past_the_end = EpochIndex::new(EPOCH_MAX - 3);

    for (derive_witness, expected) in [
        (
            witness::nullifier_derive(
                ((cm, note, user.pak.nk.derive_note_private(other.psi)), ()),
                EpochIndex::new(16),
            ),
            "NullifierDerive: sequence does not match the derived window",
        ),
        (
            (
                EpochIndex::new(14),
                witness::nullifier_derive((*secret.data(), ()), EpochIndex::new(12)).1,
            ),
            "NullifierDerive: epoch_start is not group-aligned",
        ),
        (
            (past_the_end, NfSeqPoly::new(past_the_end, &[])),
            "NullifierDerive: window exceeds the epoch range",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            delegation::NullifierDerive,
            derive_witness,
            secret.clone(),
            Proof::bootstrap().carry::<()>(()),
        ) {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }
}

#[test]
fn nullifier_fuse_rejects_unjoinable_ranges() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let other = user.random_note(700);

    for (right_note, right_start, right_end, expected) in [
        (
            note,
            EpochIndex::new(32),
            EpochIndex::new(47),
            "NullifierFuse: ranges not contiguous",
        ),
        (
            other,
            EpochIndex::new(16),
            EpochIndex::new(31),
            "NullifierFuse: note commitments differ",
        ),
    ] {
        let left = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(15));
        let right = user.derivation_pcd(rng, right_note, right_start, right_end);
        let fuse_witness = witness::nullifier_fuse(
            (*left.data(), *right.data()),
            &user.covering_window(&note, &left),
            &user.covering_window(&right_note, &right),
        );
        if let Err(ragu_core::Error::InvalidWitness(err)) =
            PROOF_SYSTEM.fuse(rng, delegation::NullifierFuse, fuse_witness, left, right)
        {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
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
fn spend_bind_derives_a_pair_across_a_group_boundary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    mine_through(rng, &mut pool, EpochIndex::new(3).first_block());
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
            mk.derive_nullifier(epoch),
            mk.derive_nullifier(EpochIndex::new(4)),
            anchor,
        )
    );
}

#[test]
fn multi_chunk_lift_uses_per_chunk_windows() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);
    mine_cm_block(rng, &mut pool, note.commitment());
    let (epoch1, epoch2, epoch3) = (EpochIndex::new(1), EpochIndex::new(2), EpochIndex::new(3));
    mine_through(rng, &mut pool, epoch2.first_block());

    let spendable = user.spendable_at(rng, &pool, &note, epoch1);
    let unspent_one = build_unspent_pcd_over_epochs(
        rng,
        &pool,
        |epoch| mk.derive_nullifier(epoch),
        (epoch1, epoch2),
    );
    let lifted_one = user.lift(rng, spendable, unspent_one, &note);
    assert_eq!(lifted_one.data().1, epoch2);

    mine_through(rng, &mut pool, epoch3.first_block());
    let unspent_two = build_unspent_pcd_over_epochs(
        rng,
        &pool,
        |epoch| mk.derive_nullifier(epoch),
        (epoch2, epoch3),
    );
    let lifted_two = user.lift(rng, lifted_one, unspent_two, &note);

    assert_eq!(lifted_two.data().1, epoch3);
    assert_eq!(lifted_two.data().2, pool.block(epoch3.first_block()).prev);
    assert_eq!(lifted_two.data().0, note.commitment());
}

#[test]
fn output_action_commits_to_the_plan_and_the_note_pair() {
    let rng = &mut StdRng::seed_from_u64(0);
    let note = WalletSim::new(shared_sk()).random_note(200);
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let anchor = Anchor::random(rng);
    let pad = Tachygram::from(poseidon::pad_tachygram(
        Fp::from(note.rcm),
        Fp::from(note.pk),
        u64::from(note.value),
        Fp::from(note.psi),
    ));

    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .unwrap();
    assert_eq!(
        *bind_pcd.data(),
        (
            Tachygram::from(note.commitment()),
            pad,
            rcv.commit(-note.value),
        )
    );
    let (.., action_set, tachygram_set) =
        witness::output_action((*bind_pcd.data(), ()), theta, anchor);
    let (.., foreign_action_set, _) =
        witness::output_action((*bind_pcd.data(), ()), ActionEntropy::random(rng), anchor);

    for (action_witness, expected) in [
        (
            (
                theta,
                anchor,
                action_set,
                TachygramSetPoly::from_iter([Tachygram::random(rng)]),
            ),
            "OutputAction: tachygram set does not commit to the bound pair",
        ),
        (
            (theta, anchor, foreign_action_set, tachygram_set),
            "OutputAction: action set does not commit to the action",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            stamp::OutputAction,
            action_witness,
            bind_pcd.clone(),
            Proof::bootstrap().carry::<()>(()),
        ) {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }

    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::OutputAction,
            witness::output_action((*bind_pcd.data(), ()), theta, anchor),
            bind_pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    assert_eq!(
        *pcd.data(),
        (
            ActionSetPoly::from_iter([action::Plan::output(note, theta, rcv).digest().unwrap()])
                .commit(),
            TachygramSetPoly::from_iter([Tachygram::from(note.commitment()), pad]).commit(),
            anchor,
        )
    );
}

#[test]
fn nullifier_fuse_concatenates_adjacent_windows() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);

    let left = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(15));
    let right = user.derivation_pcd(rng, note, EpochIndex::new(16), EpochIndex::new(31));
    let members: Vec<Nullifier> = (0..32)
        .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
        .collect();
    let (left_seq, merged_seq, right_seq) = witness::nullifier_fuse(
        (*left.data(), *right.data()),
        &members[..16],
        &members[16..],
    );

    let wrong_members: Vec<Nullifier> =
        iter::repeat_with(|| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))))
            .take(32)
            .collect();
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        delegation::NullifierFuse,
        (
            left_seq.clone(),
            NfSeqPoly::new(EpochIndex::new(0), &wrong_members),
            right_seq.clone(),
        ),
        left.clone(),
        right.clone(),
    ) {
        assert_eq!(
            err.to_string(),
            "NullifierFuse: merged is not the concat of the halves"
        );
    } else {
        panic!();
    }

    let (merged, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            delegation::NullifierFuse,
            (left_seq, merged_seq, right_seq),
            left,
            right,
        )
        .unwrap();
    assert_eq!(
        *merged.data(),
        (
            note.commitment(),
            EpochIndex::new(0),
            NfSeqPoly::new(EpochIndex::new(0), &members).commit(),
            EpochIndex::new(31),
        )
    );
}

#[test]
fn unspent_bind_rejects_a_wrong_epoch_member() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = user.random_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);
    mine_cm_block(rng, &mut pool, note.commitment());
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    mine_through(rng, &mut pool, epoch1.last_block());

    let nf = |epoch: EpochIndex| mk.derive_nullifier(if epoch == epoch1 { epoch0 } else { epoch });
    let unspent = build_unspent_pcd_over_epochs(rng, &pool, nf, (epoch1, EpochIndex::new(2)));
    let range = user.derivation_pcd(rng, note, epoch0, epoch1);
    let elapsed_seq = NfSeqPoly::new(epoch1, &[nf(epoch1)]);
    let complement_seq = NfSeqPoly::new(
        EpochIndex::new(0),
        &[mk.derive_nullifier(EpochIndex::new(0))],
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
