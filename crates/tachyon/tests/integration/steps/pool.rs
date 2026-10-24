//! Pool history: `AnchorSpanSeed` and `AnchorSpanFuse`, and the unspent
//! segments `UnspentFuse`, `UnspentLift` and `UnspentBind`.
//!
//! Some corruptions recarry an honest proof under an altered header. Mock
//! ragu does not authenticate a header against its proof, so the step's own
//! constraint is what rejects them; a real proof would not carry the altered
//! header at all.

extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::Fp;
use proptest::{collection::vec, option, prelude::*, sample::Index};
use ragu::Pcd;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, AnchorSetPoly, BlockHeight, EpochIndex, NfSeqPoly, QrClassRoot, Tachygram,
    TachygramSetPoly,
    constants::{EPOCH_MAX, EPOCH_SIZE},
    nullifier::{NF_DERIVATION_WIDTH, Nullifier},
    stamp::proof::{PROOF_SYSTEM, delegation, pool, qr},
    witness,
};

use crate::{
    fixtures::{
        PoolSim, WalletSim, build_anchor_span_pcd, build_unspent_pcd_over_epochs, detached_segment,
        epoch_bucket, mine_sparse, random_block, recarry, shared_sk,
    },
    strategies::{assert_rejections, check, tachygrams},
};

/// A span over any run of blocks of one epoch starts at the run's entry
/// anchor, ends at its final anchor, and holds exactly the anchors its folds
/// produce: one per stamp, the end among them and the start not.
#[test]
fn anchor_spans_hold_their_folds() {
    let strategy = (any::<u64>(), vec(1usize..=3, 1..=4), any::<Index>());
    check(16, strategy, |(seed, stamps_per_block, first)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
        for &stamps in &stamps_per_block {
            pool.mine(random_block(rng, 2, stamps));
        }
        let start = BlockHeight(u32::try_from(first.index(stamps_per_block.len())).unwrap() + 1);
        let end = pool.height();

        let (span, members) = build_anchor_span_pcd(rng, &pool, start..=end);
        let (anchor_start, members_commit, anchor_end) = *span.data();
        let folds: usize = stamps_per_block
            .iter()
            .skip(usize::try_from(start.0).unwrap() - 1)
            .sum();
        prop_assert_eq!(members.len(), folds);
        prop_assert_eq!(anchor_start, pool.block(start).prev);
        prop_assert_eq!(anchor_end, pool.block(end).anchor());
        prop_assert_eq!(members.last(), Some(&anchor_end));
        prop_assert!(!members.contains(&anchor_start));
        prop_assert_eq!(members_commit, AnchorSetPoly::from_iter(members).commit());
        Ok(())
    });
}

/// A fuse refuses spans that share no vertex (an invented start, a
/// crossing between them, or the halves reversed), halves other than the
/// headers', and a combined set that drops or adds a member.
#[test]
fn anchor_span_fuse_rejects_corruptions() {
    check(8, any::<u64>(), |seed| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let epoch1 = EpochIndex::new(1);
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
        pool.mine(random_block(rng, 1, 2));
        pool.mine(random_block(rng, 1, 2));
        let (left, left_members) =
            build_anchor_span_pcd(rng, &pool, BlockHeight(1)..=BlockHeight(1));
        let (right, right_members) =
            build_anchor_span_pcd(rng, &pool, BlockHeight(2)..=BlockHeight(2));

        let bogus_start = Anchor::from(Fp::random(&mut *rng));
        let bogus_witness =
            witness::anchor_span_seed(((), ()), bogus_start, epoch1, &tachygrams(rng, 1));
        let bogus_members = [bogus_start
            .next_stamp(bogus_witness.1, &bogus_witness.2)
            .unwrap()];
        let (bogus, ()) = PROOF_SYSTEM
            .seed(rng, pool::AnchorSpanSeed, bogus_witness)
            .expect("AnchorSpanSeed");

        let mut crossing_pool = PoolSim::genesis_with(random_block(rng, 1, 1));
        mine_sparse(rng, &mut crossing_pool, epoch1, None);
        crossing_pool.mine(random_block(rng, 1, 1));
        let last0 = BlockHeight(EPOCH_SIZE - 1);
        let (before, before_members) =
            build_anchor_span_pcd(rng, &crossing_pool, BlockHeight(0)..=last0);
        let (after, after_members) = build_anchor_span_pcd(
            rng,
            &crossing_pool,
            epoch1.first_block()..=crossing_pool.height(),
        );

        let fork_set = TachygramSetPoly::from_iter(tachygrams(rng, 1)).commit();
        let fork = left.data().2.next_stamp(epoch1, &fork_set).unwrap();
        let (left_poly, _, right_poly) =
            witness::anchor_span_fuse((*left.data(), *right.data()), &left_members, &right_members);
        let union = |extra: &[Anchor]| {
            AnchorSetPoly::from_iter(
                left_members
                    .iter()
                    .chain(&right_members)
                    .chain(extra)
                    .copied(),
            )
        };
        let fuse = |fuse_rng: &mut StdRng,
                    fuse_witness,
                    halves: (&Pcd<pool::AnchorSpan>, &Pcd<pool::AnchorSpan>)| {
            PROOF_SYSTEM
                .fuse(
                    fuse_rng,
                    pool::AnchorSpanFuse,
                    fuse_witness,
                    halves.0.clone(),
                    halves.1.clone(),
                )
                .map(drop)
        };
        let honest_fuse =
            |members: (&[Anchor], &[Anchor]),
             halves: (&Pcd<pool::AnchorSpan>, &Pcd<pool::AnchorSpan>)| {
                witness::anchor_span_fuse(
                    (*halves.0.data(), *halves.1.data()),
                    members.0,
                    members.1,
                )
            };

        assert_rejections([
            (
                "a right span from an invented start",
                fuse(
                    rng,
                    honest_fuse((&left_members, &bogus_members), (&left, &bogus)),
                    (&left, &bogus),
                ),
                "AnchorSpanFuse: spans do not share a vertex",
            ),
            (
                "spans either side of an epoch crossing",
                fuse(
                    rng,
                    honest_fuse((&before_members, &after_members), (&before, &after)),
                    (&before, &after),
                ),
                "AnchorSpanFuse: spans do not share a vertex",
            ),
            (
                "the halves reversed",
                fuse(
                    rng,
                    honest_fuse((&right_members, &left_members), (&right, &left)),
                    (&right, &left),
                ),
                "AnchorSpanFuse: spans do not share a vertex",
            ),
            (
                "a left half other than the header's",
                fuse(
                    rng,
                    (right_poly.clone(), union(&[]), right_poly.clone()),
                    (&left, &right),
                ),
                "AnchorSpanFuse: left members do not match header",
            ),
            (
                "a right half other than the header's",
                fuse(
                    rng,
                    (left_poly.clone(), union(&[]), left_poly.clone()),
                    (&left, &right),
                ),
                "AnchorSpanFuse: right members do not match header",
            ),
            (
                "a combined set without the right half",
                fuse(
                    rng,
                    (
                        left_poly.clone(),
                        AnchorSetPoly::from_iter(left_members.iter().copied()),
                        right_poly.clone(),
                    ),
                    (&left, &right),
                ),
                "AnchorSpanFuse: combined is not the union of the halves",
            ),
            (
                "a combined set with a fork's anchor",
                fuse(
                    rng,
                    (left_poly, union(&[fork]), right_poly),
                    (&left, &right),
                ),
                "AnchorSpanFuse: combined is not the union of the halves",
            ),
        ]);
        Ok(())
    });
}

/// Segments of consecutive epochs, QR-born one epoch each, compose: fused at
/// the entry anchor they share, or extended one epoch by lifting the next
/// epoch's bucket, they run from the first epoch's entry anchor to the last's
/// crossing and hold one member per epoch, a silent epoch's included. A
/// segment bound to a note carries the note's commitment, and one at the
/// last epoch before the final binds against the epoch space's last window.
#[test]
fn unspent_segments_compose() {
    let strategy = (any::<u64>(), 1u32..=2, 1u32..=2, option::of(0u32..=3));
    check(
        6,
        strategy,
        |(seed, left_epochs, right_epochs, silent_index)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let wallet = WalletSim::new(shared_sk());
            let note = wallet.random_note(500);
            let nf = |epoch| wallet.nf_at(&note, epoch);
            let (start, middle) = (EpochIndex::new(0), EpochIndex::new(left_epochs));
            let end = EpochIndex::new(left_epochs + right_epochs);
            let silent = silent_index
                .map(EpochIndex::new)
                .filter(|&epoch| epoch < end);
            let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
            mine_sparse(rng, &mut pool, end.next().unwrap(), silent);

            let left = build_unspent_pcd_over_epochs(rng, &pool, nf, (start, middle));
            let right = build_unspent_pcd_over_epochs(rng, &pool, nf, (middle, end));
            let members = |from: EpochIndex, to: EpochIndex| -> Vec<Nullifier> {
                (u32::from(from)..u32::from(to))
                    .map(|epoch| nf(EpochIndex::new(epoch)))
                    .collect()
            };
            let fuse_witness = witness::unspent_fuse(
                (*left.data(), *right.data()),
                &members(start, middle),
                &members(middle, end),
            );
            let (fused, ()) = PROOF_SYSTEM
                .fuse(rng, pool::UnspentFuse, fuse_witness, left.clone(), right)
                .expect("UnspentFuse");
            let entry = |epoch: EpochIndex| pool.block(epoch.first_block()).prev;
            prop_assert_eq!(
                *fused.data(),
                (
                    entry(start),
                    start,
                    NfSeqPoly::new(start, &members(start, end)).commit(),
                    end,
                    entry(end)
                )
            );

            let bucket = epoch_bucket(rng, &pool, middle);
            let lift_witness = witness::unspent_lift(
                (*left.data(), *bucket.pcd.data()),
                Tachygram::from(nf(middle)),
                &members(start, middle),
                &bucket.members,
            );
            let (lifted, ()) = PROOF_SYSTEM
                .fuse(rng, pool::UnspentLift, lift_witness, left, bucket.pcd)
                .expect("UnspentLift");
            let after = middle.next().unwrap();
            prop_assert_eq!(
                *lifted.data(),
                (
                    entry(start),
                    start,
                    NfSeqPoly::new(start, &members(start, after)).commit(),
                    after,
                    entry(after)
                )
            );

            let bound = wallet.unspent_bind(rng, fused, &note);
            prop_assert_eq!(
                *bound.data(),
                (note.commitment(), entry(start), start, end, entry(end))
            );

            let penultimate = EpochIndex::new(EPOCH_MAX - 1);
            let last_segment = detached_segment(rng, penultimate, nf);
            let (anchor_start, _, _, _, anchor_next) = *last_segment.data();
            let last_window_start =
                EpochIndex::new(EPOCH_MAX + 1 - u32::try_from(NF_DERIVATION_WIDTH).unwrap());
            let last_window =
                wallet.derivation_pcd(rng, note, last_window_start, EpochIndex::new(EPOCH_MAX));
            let last_witness = witness::unspent_bind(
                (*last_segment.data(), *last_window.data()),
                &wallet.covering_window(&note, &last_window),
                &[nf(penultimate)],
            );
            let (last_bound, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    pool::UnspentBind,
                    last_witness,
                    last_segment,
                    last_window,
                )
                .expect("UnspentBind at the last window");
            prop_assert_eq!(
                *last_bound.data(),
                (
                    note.commitment(),
                    anchor_start,
                    penultimate,
                    EpochIndex::new(EPOCH_MAX),
                    anchor_next
                )
            );
            Ok(())
        },
    );
}

/// `UnspentFuse` refuses halves that do not meet, halves other than the
/// headers', and a combined sequence other than their concatenation.
/// `UnspentBind` refuses a segment covering no epoch, an elapsed or
/// covering sequence other than the headers', and any factorization that
/// is not a genuine split of the derivation: a forged member, a derivation
/// short of the segment at either end, the right value at the wrong epoch,
/// and a forged or duplicating complement. `UnspentLift` refuses a bucket
/// past the segment's end or of another epoch, contents other than the
/// bucket's, an elapsed sequence other than the header's, a zero value, a
/// value in the bucket, classes of another value, an extension other than
/// the tested pair, and a bucket with no next epoch.
#[test]
fn unspent_steps_reject_corruptions() {
    check(6, any::<u64>(), |seed| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::new(shared_sk());
        let note = wallet.random_note(500);
        let other = wallet.random_note(700);
        let nf = |epoch| wallet.nf_at(&note, epoch);
        let [epoch0, epoch1, epoch2, epoch3] = [0, 1, 2, 3].map(EpochIndex::new);
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
        mine_sparse(rng, &mut pool, EpochIndex::new(4), None);
        let forged_nf = Nullifier::from(Fp::random(&mut *rng));
        let junk: Vec<Nullifier> = tachygrams(rng, 2)
            .into_iter()
            .map(Nullifier::from)
            .collect();

        let segment0 = build_unspent_pcd_over_epochs(rng, &pool, nf, (epoch0, epoch1));
        let segment1 = build_unspent_pcd_over_epochs(rng, &pool, nf, (epoch1, epoch2));
        let segment2 = build_unspent_pcd_over_epochs(rng, &pool, nf, (epoch2, epoch3));
        let (nf0, nf1) = (nf(epoch0), nf(epoch1));
        let fuse = |fuse_rng: &mut StdRng, fuse_witness, right: &Pcd<pool::ArbitraryUnspent>| {
            PROOF_SYSTEM
                .fuse(
                    fuse_rng,
                    pool::UnspentFuse,
                    fuse_witness,
                    segment0.clone(),
                    right.clone(),
                )
                .map(drop)
        };
        let off_epoch = recarry(&segment1, |data| data.1 = epoch2);
        let off_epoch_witness = (
            NfSeqPoly::new(epoch0, &[nf0]),
            NfSeqPoly::new(epoch0, &[nf0, nf1]),
            NfSeqPoly::new(epoch1, &[nf1]),
        );

        let window = wallet.derivation_pcd(rng, note, epoch0, epoch1);
        let covering = wallet.covering_window(&note, &window);
        let bind = |bind_rng: &mut StdRng,
                    unspent: &Pcd<pool::ArbitraryUnspent>,
                    bind_witness,
                    range: &Pcd<delegation::NoteNullifiers>| {
            PROOF_SYSTEM
                .fuse(
                    bind_rng,
                    pool::UnspentBind,
                    bind_witness,
                    unspent.clone(),
                    range.clone(),
                )
                .map(drop)
        };
        let honest_bind =
            witness::unspent_bind((*segment0.data(), *window.data()), &covering, &[nf0]);
        let (elapsed_seq, nf_seq, complement_seq) = honest_bind.clone();
        let forged_segment =
            build_unspent_pcd_over_epochs(rng, &pool, |_| forged_nf, (epoch0, epoch1));
        let far_window = wallet.derivation_pcd(rng, note, EpochIndex::new(64), EpochIndex::new(64));
        let far_covering = wallet.covering_window(&note, &far_window);
        let width = u32::try_from(NF_DERIVATION_WIDTH).unwrap();
        let past_window = EpochIndex::new(width);
        let past_segment = detached_segment(rng, past_window, nf);
        let near_window = wallet.derivation_pcd(rng, note, epoch0, epoch0);
        let near_covering = wallet.covering_window(&note, &near_window);
        let misplaced = build_unspent_pcd_over_epochs(rng, &pool, |_| nf0, (epoch1, epoch2));
        let empty_segment = recarry(&segment0, |data| data.3 = data.1);
        let foreign_contents = TachygramSetPoly::from_iter(tachygrams(rng, 1));

        let bucket1 = epoch_bucket(rng, &pool, epoch1);
        let bucket2 = epoch_bucket(rng, &pool, epoch2);
        let lift = |lift_rng: &mut StdRng,
                    onto: &Pcd<pool::ArbitraryUnspent>,
                    bucket: &Pcd<qr::QrBucket>,
                    lift_witness| {
            PROOF_SYSTEM
                .fuse(
                    lift_rng,
                    pool::UnspentLift,
                    lift_witness,
                    onto.clone(),
                    bucket.clone(),
                )
                .map(drop)
        };
        let lift_witness = |value: Tachygram,
                            elapsed: &[Nullifier],
                            bucket: &Pcd<qr::QrBucket>,
                            members: &[Tachygram]| {
            witness::unspent_lift((*segment0.data(), *bucket.data()), value, elapsed, members)
        };
        let (value, classes, mask, lift_elapsed, extended, contents) =
            lift_witness(nf1.into(), &[nf0], &bucket1.pcd, &bucket1.members);
        let other_classes = QrClassRoot::along(Fp::random(&mut *rng), bucket1.pcd.data().3);
        let renumbered = recarry(&bucket1.pcd, |data| data.0 = epoch2);
        let final_segment = recarry(&segment0, |data| data.3 = EpochIndex::new(EPOCH_MAX));
        let final_bucket = recarry(&bucket1.pcd, |data| data.0 = EpochIndex::new(EPOCH_MAX));
        let final_witness = witness::unspent_lift(
            (*final_segment.data(), *final_bucket.data()),
            nf1.into(),
            &[nf0],
            &bucket1.members,
        );

        assert_rejections([
            (
                "halves with an epoch between them",
                fuse(
                    rng,
                    witness::unspent_fuse(
                        (*segment0.data(), *segment2.data()),
                        &[nf0],
                        &[nf(epoch2)],
                    ),
                    &segment2,
                ),
                "UnspentFuse: left.anchor_next must equal right.anchor_start",
            ),
            (
                "halves meeting at an anchor but not an epoch",
                fuse(rng, off_epoch_witness, &off_epoch),
                "UnspentFuse: halves do not meet at one epoch",
            ),
            (
                "a left half other than the header's",
                fuse(
                    rng,
                    (
                        NfSeqPoly::new(epoch0, &[nf1]),
                        NfSeqPoly::new(epoch0, &[nf0, nf1]),
                        NfSeqPoly::new(epoch1, &[nf1]),
                    ),
                    &segment1,
                ),
                "UnspentFuse: left polynomial does not match header",
            ),
            (
                "a right half other than the header's",
                fuse(
                    rng,
                    (
                        NfSeqPoly::new(epoch0, &[nf0]),
                        NfSeqPoly::new(epoch0, &[nf0, nf1]),
                        NfSeqPoly::new(epoch1, &[nf0]),
                    ),
                    &segment1,
                ),
                "UnspentFuse: right polynomial does not match header",
            ),
            (
                "a combined sequence of the right half alone",
                fuse(
                    rng,
                    (
                        NfSeqPoly::new(epoch0, &[nf0]),
                        NfSeqPoly::new(epoch1, &[nf1]),
                        NfSeqPoly::new(epoch1, &[nf1]),
                    ),
                    &segment1,
                ),
                "UnspentFuse: combined is not the concatenation of the halves",
            ),
            (
                "a segment covering no epoch",
                bind(rng, &empty_segment, honest_bind, &window),
                "UnspentBind: segment covers no epoch",
            ),
            (
                "an elapsed sequence other than the header's",
                bind(
                    rng,
                    &segment0,
                    (
                        NfSeqPoly::new(epoch0, &junk[..1]),
                        nf_seq.clone(),
                        complement_seq,
                    ),
                    &window,
                ),
                "UnspentBind: elapsed polynomial does not match header",
            ),
            (
                "another note's covering sequence",
                bind(
                    rng,
                    &segment0,
                    witness::unspent_bind(
                        (*segment0.data(), *window.data()),
                        &wallet.covering_window(&other, &window),
                        &[nf0],
                    ),
                    &window,
                ),
                "UnspentBind: covering sequence does not match header",
            ),
            (
                "a forged member",
                bind(
                    rng,
                    &forged_segment,
                    witness::unspent_bind(
                        (*forged_segment.data(), *window.data()),
                        &covering,
                        &[forged_nf],
                    ),
                    &window,
                ),
                "UnspentBind: sequence does not match the derivation",
            ),
            (
                "a derivation starting after the segment",
                bind(
                    rng,
                    &segment0,
                    (
                        NfSeqPoly::new(epoch0, &[nf0]),
                        NfSeqPoly::new(EpochIndex::new(64), &far_covering),
                        NfSeqPoly::new(EpochIndex::new(64), &[]),
                    ),
                    &far_window,
                ),
                "UnspentBind: sequence does not match the derivation",
            ),
            (
                "a derivation ending before the segment",
                bind(
                    rng,
                    &past_segment,
                    (
                        NfSeqPoly::new(past_window, &[nf(past_window)]),
                        NfSeqPoly::new(epoch0, &near_covering),
                        NfSeqPoly::new(epoch0, &[]),
                    ),
                    &near_window,
                ),
                "UnspentBind: sequence does not match the derivation",
            ),
            (
                "the right value at the wrong epoch",
                bind(
                    rng,
                    &misplaced,
                    (
                        NfSeqPoly::new(epoch1, &[nf0]),
                        nf_seq.clone(),
                        NfSeqPoly::new(epoch0, &[nf0]),
                    ),
                    &window,
                ),
                "UnspentBind: sequence does not match the derivation",
            ),
            (
                "a forged complement",
                bind(
                    rng,
                    &segment0,
                    (
                        elapsed_seq.clone(),
                        nf_seq.clone(),
                        NfSeqPoly::new(epoch1, &junk[..1]),
                    ),
                    &window,
                ),
                "UnspentBind: sequence does not match the derivation",
            ),
            (
                "a complement duplicating the tested member",
                bind(
                    rng,
                    &segment0,
                    (elapsed_seq, nf_seq, NfSeqPoly::new(epoch0, &[nf0])),
                    &window,
                ),
                "UnspentBind: sequence does not match the derivation",
            ),
            (
                "a bucket past the segment's end",
                lift(
                    rng,
                    &segment0,
                    &bucket2.pcd,
                    lift_witness(nf1.into(), &[nf0], &bucket2.pcd, &bucket2.members),
                ),
                "UnspentLift: the bucket does not start where the segment ends",
            ),
            (
                "a bucket of another epoch",
                lift(
                    rng,
                    &segment0,
                    &renumbered,
                    lift_witness(nf1.into(), &[nf0], &renumbered, &bucket1.members),
                ),
                "UnspentLift: the bucket is not the segment's next epoch",
            ),
            (
                "contents other than the bucket's",
                lift(
                    rng,
                    &segment0,
                    &bucket1.pcd,
                    (
                        value,
                        classes,
                        mask,
                        lift_elapsed.clone(),
                        extended.clone(),
                        foreign_contents,
                    ),
                ),
                "UnspentLift: contents do not match the bucket",
            ),
            (
                "an elapsed sequence off the header",
                lift(
                    rng,
                    &segment0,
                    &bucket1.pcd,
                    lift_witness(nf1.into(), &[nf1], &bucket1.pcd, &bucket1.members),
                ),
                "UnspentLift: elapsed does not match header",
            ),
            (
                "a zero value",
                lift(
                    rng,
                    &segment0,
                    &bucket1.pcd,
                    lift_witness(
                        Tachygram::from(Fp::ZERO),
                        &[nf0],
                        &bucket1.pcd,
                        &bucket1.members,
                    ),
                ),
                "UnspentLift: tested value is zero",
            ),
            (
                "classes of another value",
                lift(
                    rng,
                    &segment0,
                    &bucket1.pcd,
                    (
                        value,
                        other_classes,
                        mask,
                        lift_elapsed.clone(),
                        extended,
                        contents.clone(),
                    ),
                ),
                "QR profile: root does not square to the claimed class",
            ),
            (
                "an extension other than the tested pair",
                lift(
                    rng,
                    &segment0,
                    &bucket1.pcd,
                    (
                        value,
                        classes,
                        mask,
                        lift_elapsed,
                        NfSeqPoly::new(epoch0, &[nf0, forged_nf]),
                        contents,
                    ),
                ),
                "UnspentLift: extended is not elapsed with the tested pair",
            ),
            (
                "a value in the bucket",
                lift(
                    rng,
                    &segment0,
                    &bucket1.pcd,
                    lift_witness(bucket1.members[0], &[nf0], &bucket1.pcd, &bucket1.members),
                ),
                "UnspentLift: found nullifier in the bucket",
            ),
            (
                "a bucket in the final epoch",
                lift(rng, &final_segment, &final_bucket, final_witness),
                "UnspentLift: bucket has no next epoch",
            ),
        ]);
        Ok(())
    });
}
