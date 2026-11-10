extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};
use core::{array, assert_matches, iter};

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::pasta::Pasta;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::{curve::Projective as _, field::Field as _};
use zcash_tachyon::{
    ActionSetPoly, Anchor, AnchorSetPoly, BlockHeight, EpochIndex, NfSeqPoly, Note, Tachygram,
    TachygramSetPoly, action,
    constants::{EPOCH_MAX, EPOCH_SIZE},
    digest::poseidon,
    entropy::ActionEntropy,
    note,
    nullifier::{self, NF_DERIVATION_WIDTH, Nullifier},
    pasta::{Eq, Fp},
    stamp::proof::{PROOF_SYSTEM, delegation, output, pool, spend, spendable, stamp},
    value, witness,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_anchor_span_pcd, build_output_stamp, build_unspent_pcd_over_epochs,
    qr_bucket_segment, random_block, random_block_with, seal_qr_intake, seed_qr_empty_intake,
    shared_sk,
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
) -> ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent> {
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
    spendable: ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
) -> ragu::Pcd<Pasta, ProductionRank, spend::SpendHeader> {
    let secret_pcd = user.secret_pcd(rng, *note);
    let rcv = value::Trapdoor::random(rng);
    let (bind_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            witness::spend_bind((*spendable.data(), *secret_pcd.data()), rcv),
            spendable,
            secret_pcd,
        )
        .unwrap();
    bind_pcd
}

#[test]
fn spendable_init_rejects_tg_absent() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let nf_header = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(0));
    let absent_tg = Tachygram::random(rng);

    assert_matches!(
        PROOF_SYSTEM
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
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "SpendableInit: commitment not in set"
    );
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
    assert_matches!(
        PROOF_SYSTEM
            .fuse(
                rng,
                pool::UnspentFuse,
                witness::unspent_fuse((*first.data(), *third.data()), &[nf0], &[nf2]),
                first,
                third,
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "UnspentFuse: left.anchor_next must equal right.anchor_start"
    );

    let left =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(0), EpochIndex::new(2)));
    let right =
        build_unspent_pcd_over_epochs(rng, &pool, at, (EpochIndex::new(2), EpochIndex::new(4)));
    assert_matches!(
        PROOF_SYSTEM
            .fuse(
                rng,
                pool::UnspentFuse,
                {
                    let mut witness = witness::unspent_fuse((*left.data(), *right.data()), &[nf0, nf1], &[nf2, nf3]);
                    witness.0 = NfSeqPoly::new(EpochIndex::new(2), &[nf2, nf3]);
                    witness
                },
                left.clone(),
                right.clone(),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == "UnspentFuse: combined is not the concatenation of the halves"
    );

    let (start, end) = (left.data().0, right.data().3);
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
        (start, EpochIndex::new(0), EpochIndex::new(4), end)
    );
    assert_eq!(
        fused.commitments()[0],
        Eq::from(NfSeqPoly::new(EpochIndex::new(0), &nf).commit()).to_affine()
    );
}

#[test]
fn anchor_span_holds_the_anchors_its_folds_produce() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(2, |_| random_block(rng, 1, 2));

    let (span, members) = build_anchor_span_pcd(rng, &pool, BlockHeight(1)..=BlockHeight(2));
    let (anchor_start, anchor_end) = *span.data();

    assert_eq!(anchor_start, pool.block(BlockHeight(1)).prev);
    assert_eq!(anchor_end, pool.block(BlockHeight(2)).anchor());
    assert_eq!(
        span.commitments()[0],
        Eq::from(AnchorSetPoly::from_iter(members).commit()).to_affine()
    );
}

#[test]
fn stamp_lift_accepts_only_anchors_the_span_holds() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(1, |_| random_block(rng, 1, 3));

    let (span, members) = build_anchor_span_pcd(rng, &pool, BlockHeight(1)..=BlockHeight(1));
    let (anchor_start, anchor_end) = *span.data();
    let fork = anchor_start
        .next_stamp(
            BlockHeight(1).epoch(),
            &TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit(),
        )
        .unwrap();

    for (stamp_anchor, expected) in [
        (anchor_start, None),
        (members[0], None),
        (anchor_end, None),
        (
            fork,
            Some("StampLift: stamp anchor is neither the span's start nor a member"),
        ),
    ] {
        let (stamp, plan, fee_descriptor) =
            build_output_stamp(rng, stamp_anchor, user.random_note(200));
        let stamp_pcd = stamp
            .proof
            .carry(stamp::Stamp::header(stamp.tachygram_set, stamp_anchor).unwrap());
        let lifted = PROOF_SYSTEM.fuse(
            rng,
            stamp::StampLift,
            witness::stamp_lift(
                (*stamp_pcd.data(), *span.data()),
                ActionSetPoly::from_iter([
                    plan.digest().unwrap(),
                    fee_descriptor.digest().unwrap(),
                ]),
            ),
            stamp_pcd,
            span.clone(),
        );
        if let Some(message) = expected {
            assert_matches!(
                lifted.err(),
                Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == message
            );
        } else {
            assert_eq!(lifted.unwrap().0.data().1, anchor_end);
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

    let fork = left
        .data()
        .1
        .next_stamp(
            BlockHeight(2).epoch(),
            &TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit(),
        )
        .unwrap();
    for (fuse_witness, (first, second), expected) in [
        (
            witness::anchor_span_fuse((*left.data(), *right.data()), &left_members, &[]),
            (left.clone(), right.clone()),
            "AnchorSpanFuse: combined is not the union of the halves",
        ),
        (
            witness::anchor_span_fuse(
                (*left.data(), *right.data()),
                &left_members,
                &right_members
                    .iter()
                    .copied()
                    .chain([fork])
                    .collect::<Vec<_>>(),
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
        assert_matches!(
            PROOF_SYSTEM
                .fuse(rng, pool::AnchorSpanFuse, fuse_witness, first, second)
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
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
    assert_matches!(
        PROOF_SYSTEM
            .fuse(
                rng,
                spend::SpendBind,
                witness::spend_bind((*spendable_pcd.data(), *secret_pcd.data()), rcv),
                spendable_pcd.clone(),
                secret_pcd,
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "SpendBind: secret does not match note"
    );

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let theta = ActionEntropy::random(rng);
    assert_matches!(
        PROOF_SYSTEM
            .fuse(
                rng,
                stamp::SpendAction,
                witness::spend_action((*bind_pcd.data(), ()), theta, other.pak),
                bind_pcd,
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "SpendAction: pak not related to note"
    );
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
        .seed(
            rng,
            output::OutputBind,
            witness::output_bind(((), ()), zero_output, rcv),
        )
        .unwrap();
    let theta = ActionEntropy::random(rng);
    let anchor = Anchor::random(rng);
    PROOF_SYSTEM
        .fuse(
            rng,
            stamp::OutputAction,
            witness::output_action((*bind_pcd.data(), ()), theta, anchor),
            bind_pcd,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let zero_spend = user.random_note(0);
    let height = mine_cm_block(rng, &mut pool, zero_spend.commitment());
    let spendable_pcd = user.spendable_init(rng, &zero_spend, &pool, height);
    let spend_bind = honest_spend_bind(rng, &user, &zero_spend, spendable_pcd);
    PROOF_SYSTEM
        .fuse(
            rng,
            stamp::SpendAction,
            witness::spend_action((*spend_bind.data(), ()), theta, user.pak),
            spend_bind,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
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
        .fuse(
            rng,
            spend::SpendBind,
            witness::spend_bind((*spendable.data(), *secret_pcd.data()), rcv),
            spendable,
            secret_pcd,
        )
        .unwrap();
    let valid = witness::spend_action((*bind_pcd.data(), ()), theta, user.pak);
    let (.., foreign_action_set, _) =
        witness::spend_action((*bind_pcd.data(), ()), ActionEntropy::random(rng), user.pak);

    for (action_witness, expected) in [
        (
            {
                let mut witness = valid.clone();
                witness.3 = TachygramSetPoly::from_iter([Tachygram::random(rng)]);
                witness
            },
            "SpendAction: tachygram set does not commit to the nullifier pair",
        ),
        (
            {
                let mut witness = valid;
                witness.2 = foreign_action_set;
                witness
            },
            "SpendAction: action set does not commit to the action",
        ),
    ] {
        assert_matches!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    stamp::SpendAction,
                    action_witness,
                    bind_pcd.clone(),
                    PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
                )
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
    }

    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::SpendAction,
            witness::spend_action((*bind_pcd.data(), ()), theta, user.pak),
            bind_pcd,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    let plan = action::Plan::spend(note, theta, rcv, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });
    let [action_commit, tachygram_commit] = pcd.commitments();
    assert_eq!(
        action_commit,
        Eq::from(ActionSetPoly::from_iter([plan.digest().unwrap()]).commit()).to_affine()
    );
    assert_eq!(
        tachygram_commit,
        Eq::from(
            TachygramSetPoly::from_iter([
                Tachygram::from(mk.derive_nullifier(spend_epoch)),
                Tachygram::from(mk.derive_nullifier(spend_epoch.next().unwrap())),
            ])
            .commit()
        )
        .to_affine()
    );
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

    let (_, _, unspent_end, _) = *unspent.data();
    let range = user.derivation_pcd(rng, note, epoch0, unspent_end);
    let witness = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &[forged],
    );

    assert_matches!(
        PROOF_SYSTEM
            .fuse(rng, pool::UnspentBind, witness, unspent, range)
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "UnspentBind: sequence does not match the derivation"
    );
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
        epoch_end,
        Anchor::from(Fp::ZERO),
    );

    let (complement_seq,) = witness::unspent_bind(
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
    let wide = user.derivation_pcd(rng, note, EpochIndex::new(0), EpochIndex::new(1));
    let later = user.derivation_pcd(rng, note, EpochIndex::new(64), EpochIndex::new(64));
    let honest = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &elapsed,
    );

    for (bind_range, bind_witness, expected) in [
        (
            range.clone(),
            witness::unspent_bind(
                (*unspent.data(), *range.data()),
                &user.covering_window(&other, &range),
                &elapsed,
            ),
            "UnspentBind: sequence does not match the derivation",
        ),
        (
            range,
            {
                let mut witness = honest.clone();
                witness.0 = NfSeqPoly::new(
                    EpochIndex::new(0),
                    &[mk.derive_nullifier(EpochIndex::new(0))],
                );
                witness
            },
            "UnspentBind: sequence does not match the derivation",
        ),
        (
            wide,
            {
                let mut witness = honest.clone();
                witness.0 = NfSeqPoly::new(
                    EpochIndex::new(1),
                    &[Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)))],
                );
                witness
            },
            "UnspentBind: sequence does not match the derivation",
        ),
        (
            later,
            {
                let mut witness = honest;
                witness.0 = NfSeqPoly::new(EpochIndex::new(64), &[]);
                witness
            },
            "UnspentBind: sequence does not match the derivation",
        ),
    ] {
        assert_matches!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    pool::UnspentBind,
                    bind_witness,
                    unspent.clone(),
                    bind_range,
                )
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
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
    let mut witness = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &[],
    );
    witness.0 = NfSeqPoly::new(EpochIndex::new(0), &[]);

    assert_matches!(
        PROOF_SYSTEM
            .fuse(rng, pool::UnspentBind, witness, unspent, range)
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "UnspentBind: sequence does not match the derivation"
    );
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
        assert_matches!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    spendable::SpendableLift,
                    (),
                    spendable.clone(),
                    unspent,
                )
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
    }
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
            {
                let mut witness =
                    witness::nullifier_derive((*secret.data(), ()), EpochIndex::new(12));
                witness.0 = EpochIndex::new(14);
                witness
            },
            "NullifierDerive: epoch_start is not group-aligned",
        ),
        (
            {
                let mut witness =
                    witness::nullifier_derive((*secret.data(), ()), EpochIndex::new(0));
                witness.0 = past_the_end;
                witness.1 = NfSeqPoly::new(past_the_end, &[]);
                witness
            },
            "NullifierDerive: window exceeds the epoch range",
        ),
    ] {
        assert_matches!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    delegation::NullifierDerive,
                    derive_witness,
                    secret.clone(),
                    PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
                )
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
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
        assert_matches!(
            PROOF_SYSTEM
                .fuse(rng, delegation::NullifierFuse, fuse_witness, left, right)
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
    }
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
        .seed(
            rng,
            output::OutputBind,
            witness::output_bind(((), ()), note, rcv),
        )
        .unwrap();
    assert_eq!(
        *bind_pcd.data(),
        (
            Tachygram::from(note.commitment()),
            pad,
            rcv.commit(-note.value),
        )
    );
    let valid = witness::output_action((*bind_pcd.data(), ()), theta, anchor);
    let (.., foreign_action_set, _) =
        witness::output_action((*bind_pcd.data(), ()), ActionEntropy::random(rng), anchor);

    for (action_witness, expected) in [
        (
            {
                let mut witness = valid.clone();
                witness.3 = TachygramSetPoly::from_iter([Tachygram::random(rng)]);
                witness
            },
            "OutputAction: tachygram set does not commit to the bound pair",
        ),
        (
            {
                let mut witness = valid;
                witness.2 = foreign_action_set;
                witness
            },
            "OutputAction: action set does not commit to the action",
        ),
    ] {
        assert_matches!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    stamp::OutputAction,
                    action_witness,
                    bind_pcd.clone(),
                    PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
                )
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
    }

    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::OutputAction,
            witness::output_action((*bind_pcd.data(), ()), theta, anchor),
            bind_pcd,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert_eq!(*pcd.data(), anchor);
    assert_eq!(
        pcd.commitments()[..2],
        [
            Eq::from(
                ActionSetPoly::from_iter([action::Plan::output(note, theta, rcv)
                    .digest()
                    .unwrap()])
                .commit()
            )
            .to_affine(),
            Eq::from(
                TachygramSetPoly::from_iter([Tachygram::from(note.commitment()), pad]).commit()
            )
            .to_affine(),
        ]
    );
    assert_ne!(
        action::Plan::output(WalletSim::random(rng).random_note(200), theta, rcv)
            .digest()
            .unwrap(),
        action::Plan::output(note, theta, rcv).digest().unwrap()
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
    let merged_witness = witness::nullifier_fuse(
        (*left.data(), *right.data()),
        &members[..16],
        &members[16..],
    );

    let wrong_members: Vec<Nullifier> =
        iter::repeat_with(|| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))))
            .take(32)
            .collect();
    assert_matches!(
        PROOF_SYSTEM
            .fuse(
                rng,
                delegation::NullifierFuse,
                witness::nullifier_fuse((*left.data(), *right.data()), &wrong_members, &[]),
                left.clone(),
                right.clone(),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "NullifierFuse: merged is not the concat of the halves"
    );

    let (merged, ()) = PROOF_SYSTEM
        .fuse(rng, delegation::NullifierFuse, merged_witness, left, right)
        .unwrap();
    assert_eq!(
        *merged.data(),
        (note.commitment(), EpochIndex::new(0), EpochIndex::new(31))
    );
    assert_eq!(
        merged.commitments()[0],
        Eq::from(NfSeqPoly::new(EpochIndex::new(0), &members).commit()).to_affine()
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
    let complement_seq = NfSeqPoly::new(
        EpochIndex::new(0),
        &[mk.derive_nullifier(EpochIndex::new(0))],
    );
    let mut witness = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &[nf(epoch1)],
    );
    witness.0 = complement_seq;
    assert_matches!(
        PROOF_SYSTEM
            .fuse(
                rng,
                pool::UnspentBind,
                witness,
                unspent,
                range,
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "UnspentBind: sequence does not match the derivation"
    );
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
