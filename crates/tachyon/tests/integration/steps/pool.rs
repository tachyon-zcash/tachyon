extern crate alloc;

use alloc::{vec, vec::Vec};
use core::iter;

use ragu::Pcd;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, AnchorSetPoly, BlockHeight, EpochIndex, NfSeqPoly, Note, QrClassRoot, Tachygram,
    TachygramSetPoly,
    constants::{EPOCH_MAX, EPOCH_SIZE},
    nullifier::{NF_DERIVATION_WIDTH, Nullifier},
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, delegation, pool, qr},
    witness,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_anchor_span_pcd, build_unspent_pcd_over_epochs, detached_segment,
    epoch_bucket, mine_sparse,
};

#[test]
fn anchor_spans_hold_their_folds() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (stamps_per_block, first) in [
        (&[1][..], 0),
        (&[3][..], 0),
        (&[1, 3, 2, 1][..], 0),
        (&[3, 1, 2, 3][..], 3),
        (&[2, 3, 1][..], 1),
    ] {
        let case = format!("blocks of {stamps_per_block:?} from block {first}");
        let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::random(rng)]]);
        for &stamps in stamps_per_block {
            pool.mine(
                iter::repeat_with(|| vec![Tachygram::random(rng), Tachygram::random(rng)])
                    .take(stamps)
                    .collect(),
            );
        }
        let start = BlockHeight(u32::try_from(first).unwrap() + 1);
        let end = pool.height();

        let (span, members) = build_anchor_span_pcd(rng, &pool, start..=end);
        let (anchor_start, members_commit, anchor_end) = *span.data();
        let folds: usize = stamps_per_block.iter().skip(first).sum();
        assert_eq!(members.len(), folds, "{case}: the member count");
        assert_eq!(anchor_start, pool.block(start).prev, "{case}: the start");
        assert_eq!(anchor_end, pool.block(end).anchor(), "{case}: the end");
        assert_eq!(members.last(), Some(&anchor_end), "{case}: the last member");
        assert!(
            !members.contains(&anchor_start),
            "{case}: the start is not a member"
        );
        assert_eq!(
            members_commit,
            AnchorSetPoly::from_iter(members).commit(),
            "{case}: the member set"
        );
    }
}

#[test]
fn anchor_span_fuse_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch1 = EpochIndex::new(1);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::random(rng)]]);
    pool.mine(vec![
        vec![Tachygram::random(rng)],
        vec![Tachygram::random(rng)],
    ]);
    pool.mine(vec![
        vec![Tachygram::random(rng)],
        vec![Tachygram::random(rng)],
    ]);
    let (left, left_members) = build_anchor_span_pcd(rng, &pool, BlockHeight(1)..=BlockHeight(1));
    let (right, right_members) = build_anchor_span_pcd(rng, &pool, BlockHeight(2)..=BlockHeight(2));

    let bogus_start = Anchor::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let bogus_witness =
        witness::anchor_span_seed(((), ()), bogus_start, epoch1, &[Tachygram::random(rng)]);
    let bogus_members = [bogus_start
        .next_stamp(bogus_witness.1, &bogus_witness.2)
        .unwrap()];
    let (bogus, ()) = PROOF_SYSTEM
        .seed(rng, pool::AnchorSpanSeed, bogus_witness)
        .expect("AnchorSpanSeed");
    assert_eq!(
        PROOF_SYSTEM
            .seed(
                rng,
                pool::AnchorSpanSeed,
                witness::anchor_span_seed(((), ()), bogus_start, epoch1, &[]),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: invalid anchor step",
    );

    let mut crossing_pool = PoolSim::genesis_with(vec![vec![Tachygram::random(rng)]]);
    mine_sparse(rng, &mut crossing_pool, epoch1, None);
    crossing_pool.mine(vec![vec![Tachygram::random(rng)]]);
    let last0 = BlockHeight(EPOCH_SIZE - 1);
    let (before, before_members) =
        build_anchor_span_pcd(rng, &crossing_pool, BlockHeight(0)..=last0);
    let (after, after_members) = build_anchor_span_pcd(
        rng,
        &crossing_pool,
        epoch1.first_block()..=crossing_pool.height(),
    );

    let fork_set = TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit();
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
            witness::anchor_span_fuse((*halves.0.data(), *halves.1.data()), members.0, members.1)
        };

    assert_eq!(
        fuse(
            rng,
            honest_fuse((&left_members, &bogus_members), (&left, &bogus)),
            (&left, &bogus),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: AnchorSpanFuse: spans do not share a vertex",
    );
    assert_eq!(
        fuse(
            rng,
            honest_fuse((&before_members, &after_members), (&before, &after)),
            (&before, &after),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: AnchorSpanFuse: spans do not share a vertex",
    );
    assert_eq!(
        fuse(
            rng,
            honest_fuse((&right_members, &left_members), (&right, &left)),
            (&right, &left),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: AnchorSpanFuse: spans do not share a vertex",
    );
    assert_eq!(
        fuse(
            rng,
            (right_poly.clone(), union(&[]), right_poly.clone()),
            (&left, &right),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: AnchorSpanFuse: left members do not match header",
    );
    assert_eq!(
        fuse(
            rng,
            (left_poly.clone(), union(&[]), left_poly.clone()),
            (&left, &right),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: AnchorSpanFuse: right members do not match header",
    );
    assert_eq!(
        fuse(
            rng,
            (
                left_poly.clone(),
                AnchorSetPoly::from_iter(left_members.iter().copied()),
                right_poly.clone(),
            ),
            (&left, &right),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: AnchorSpanFuse: combined is not the union of the halves",
    );
    assert_eq!(
        fuse(
            rng,
            (left_poly, union(&[fork]), right_poly),
            (&left, &right),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: AnchorSpanFuse: combined is not the union of the halves",
    );
}

#[test]
fn unspent_segments_compose() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let note = wallet.random_note(500);
    let nf = |epoch| {
        wallet
            .pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch)
    };
    let members = |from: EpochIndex, to: EpochIndex| -> Vec<Nullifier> {
        (u32::from(from)..u32::from(to))
            .map(|epoch| nf(EpochIndex::new(epoch)))
            .collect()
    };

    for (left_epochs, right_epochs, silent_index) in
        [(1, 1, 0), (1, 1, 1), (1, 2, 2), (2, 1, 1), (2, 2, 3)]
    {
        let case = format!("{left_epochs} epochs then {right_epochs}, epoch {silent_index} silent");
        let (start, middle) = (EpochIndex::new(0), EpochIndex::new(left_epochs));
        let end = EpochIndex::new(left_epochs + right_epochs);
        let silent = EpochIndex::new(silent_index);
        let mut pool = PoolSim::genesis_with(Vec::new());
        mine_sparse(rng, &mut pool, end.next().unwrap(), Some(silent));
        assert_eq!(
            pool.block(silent.last_block()).anchor(),
            pool.block(silent.first_block()).prev,
            "{case}: the silent epoch"
        );

        let left = build_unspent_pcd_over_epochs(rng, &pool, nf, (start, middle));
        let right = build_unspent_pcd_over_epochs(rng, &pool, nf, (middle, end));
        let fuse_witness = witness::unspent_fuse(
            (*left.data(), *right.data()),
            &members(start, middle),
            &members(middle, end),
        );
        let (fused, ()) = PROOF_SYSTEM
            .fuse(rng, pool::UnspentFuse, fuse_witness, left.clone(), right)
            .expect("UnspentFuse");
        let entry = |epoch: EpochIndex| pool.block(epoch.first_block()).prev;
        assert_eq!(
            *fused.data(),
            (
                entry(start),
                start,
                NfSeqPoly::new(start, &members(start, end)).commit(),
                end,
                entry(end)
            ),
            "{case}: the fused segment"
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
            .unwrap();
        let after = middle.next().unwrap();
        assert_eq!(
            *lifted.data(),
            (
                entry(start),
                start,
                NfSeqPoly::new(start, &members(start, after)).commit(),
                after,
                entry(after)
            ),
            "{case}: the lifted segment"
        );

        let bound = wallet.unspent_bind(rng, fused, &note);
        assert_eq!(
            *bound.data(),
            (note.commitment(), entry(start), start, end, entry(end)),
            "{case}: the bound segment"
        );
    }

    let penultimate = EpochIndex::new(EPOCH_MAX - 1);
    let last_segment = detached_segment(rng, penultimate, nf);
    let (anchor_start, _, _, _, anchor_next) = *last_segment.data();
    let last_window_start =
        EpochIndex::new(EPOCH_MAX + 1 - u32::try_from(NF_DERIVATION_WIDTH).unwrap());
    let last_window =
        wallet.derivation_pcd(rng, note, last_window_start, EpochIndex::new(EPOCH_MAX));
    let (_, covering_start, _, covering_last) = *last_window.data();
    let last_covering: Vec<Nullifier> = (u32::from(covering_start)..=u32::from(covering_last))
        .map(|epoch| nf(EpochIndex::new(epoch)))
        .collect();
    let last_witness = witness::unspent_bind(
        (*last_segment.data(), *last_window.data()),
        &last_covering,
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
        .unwrap();
    assert_eq!(
        *last_bound.data(),
        (
            note.commitment(),
            anchor_start,
            penultimate,
            EpochIndex::new(EPOCH_MAX),
            anchor_next
        )
    );
}

fn segments(rng: &mut StdRng) -> (WalletSim, Note, PoolSim, [Pcd<pool::ArbitraryUnspent>; 3]) {
    let wallet = WalletSim::random(rng);
    let note = wallet.random_note(500);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::random(rng)]]);
    mine_sparse(rng, &mut pool, EpochIndex::new(4), None);
    let segments = [0, 1, 2].map(|from| {
        build_unspent_pcd_over_epochs(
            rng,
            &pool,
            |epoch| {
                wallet
                    .pak
                    .nk
                    .derive_note_private(note.psi)
                    .derive_nullifier(epoch)
            },
            (EpochIndex::new(from), EpochIndex::new(from + 1)),
        )
    });
    (wallet, note, pool, segments)
}

#[test]
fn unspent_fuse_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, note, _, [segment0, segment1, segment2]) = segments(rng);
    let nf = |epoch| {
        wallet
            .pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch)
    };
    let [epoch0, epoch1, epoch2] = [0, 1, 2].map(EpochIndex::new);
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

    assert_eq!(
        fuse(
            rng,
            witness::unspent_fuse((*segment0.data(), *segment2.data()), &[nf0], &[nf(epoch2)]),
            &segment2,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentFuse: left.anchor_next must equal right.anchor_start",
    );
    assert_eq!(
        fuse(
            rng,
            (
                NfSeqPoly::new(epoch0, &[nf0]),
                NfSeqPoly::new(epoch0, &[nf0, nf1]),
                NfSeqPoly::new(epoch1, &[nf1]),
            ),
            &{
                let mut data = *segment1.data();
                data.1 = epoch2;
                segment1
                    .proof()
                    .clone()
                    .carry::<pool::ArbitraryUnspent>(data)
            },
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentFuse: halves do not meet at one epoch",
    );
    assert_eq!(
        fuse(
            rng,
            (
                NfSeqPoly::new(epoch0, &[nf1]),
                NfSeqPoly::new(epoch0, &[nf0, nf1]),
                NfSeqPoly::new(epoch1, &[nf1]),
            ),
            &segment1,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentFuse: left polynomial does not match header",
    );
    assert_eq!(
        fuse(
            rng,
            (
                NfSeqPoly::new(epoch0, &[nf0]),
                NfSeqPoly::new(epoch0, &[nf0, nf1]),
                NfSeqPoly::new(epoch1, &[nf0]),
            ),
            &segment1,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentFuse: right polynomial does not match header",
    );
    assert_eq!(
        fuse(
            rng,
            (
                NfSeqPoly::new(epoch0, &[nf0]),
                NfSeqPoly::new(epoch1, &[nf1]),
                NfSeqPoly::new(epoch1, &[nf1]),
            ),
            &segment1,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentFuse: combined is not the concatenation of the halves",
    );
}

#[test]
fn unspent_bind_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, note, pool, [segment0, ..]) = segments(rng);
    let other = wallet.random_note(700);
    let nf = |epoch| {
        wallet
            .pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch)
    };
    let [epoch0, epoch1, epoch2] = [0, 1, 2].map(EpochIndex::new);
    let nf0 = nf(epoch0);
    let forged_nf = Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let junk = Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)));

    let window = wallet.derivation_pcd(rng, note, epoch0, epoch1);
    let (_, window_start, _, window_last) = *window.data();
    let covering: Vec<Nullifier> = (u32::from(window_start)..=u32::from(window_last))
        .map(|epoch| nf(EpochIndex::new(epoch)))
        .collect();
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
    let honest_bind = witness::unspent_bind((*segment0.data(), *window.data()), &covering, &[nf0]);
    let (elapsed_seq, nf_seq, complement_seq) = honest_bind.clone();

    assert_eq!(
        bind(
            rng,
            &{
                let mut data = *segment0.data();
                data.3 = data.1;
                segment0
                    .proof()
                    .clone()
                    .carry::<pool::ArbitraryUnspent>(data)
            },
            honest_bind,
            &window,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentBind: segment covers no epoch",
    );
    assert_eq!(
        bind(
            rng,
            &segment0,
            (
                NfSeqPoly::new(epoch0, &[junk]),
                nf_seq.clone(),
                complement_seq.clone(),
            ),
            &window,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentBind: elapsed polynomial does not match header",
    );
    assert_eq!(
        bind(
            rng,
            &segment0,
            witness::unspent_bind(
                (*segment0.data(), *window.data()),
                &(u32::from(window_start)..=u32::from(window_last))
                    .map(|epoch| {
                        wallet
                            .pak
                            .nk
                            .derive_note_private(other.psi)
                            .derive_nullifier(EpochIndex::new(epoch))
                    })
                    .collect::<Vec<Nullifier>>(),
                &[nf0],
            ),
            &window,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentBind: covering sequence does not match header",
    );
    let forged_segment = build_unspent_pcd_over_epochs(rng, &pool, |_| forged_nf, (epoch0, epoch1));
    assert_eq!(
        bind(
            rng,
            &forged_segment,
            witness::unspent_bind(
                (*forged_segment.data(), *window.data()),
                &covering,
                &[forged_nf],
            ),
            &window,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentBind: sequence does not match the derivation",
    );
    let far = EpochIndex::new(64);
    let far_window = wallet.derivation_pcd(rng, note, far, far);
    let (_, far_start, _, far_last) = *far_window.data();
    let far_covering: Vec<Nullifier> = (u32::from(far_start)..=u32::from(far_last))
        .map(|epoch| nf(EpochIndex::new(epoch)))
        .collect();
    assert_eq!(
        bind(
            rng,
            &segment0,
            (
                NfSeqPoly::new(epoch0, &[nf0]),
                NfSeqPoly::new(far, &far_covering),
                NfSeqPoly::new(EpochIndex::new(65), &far_covering[1..]),
            ),
            &far_window,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentBind: sequence does not match the derivation",
    );
    let past_window = EpochIndex::new(u32::try_from(NF_DERIVATION_WIDTH).unwrap());
    let past_segment = detached_segment(rng, past_window, nf);
    let near_window = wallet.derivation_pcd(rng, note, epoch0, epoch0);
    let (_, near_start, _, near_last) = *near_window.data();
    let near_covering: Vec<Nullifier> = (u32::from(near_start)..=u32::from(near_last))
        .map(|epoch| nf(EpochIndex::new(epoch)))
        .collect();
    assert_eq!(
        bind(
            rng,
            &past_segment,
            (
                NfSeqPoly::new(past_window, &[nf(past_window)]),
                NfSeqPoly::new(epoch0, &near_covering),
                NfSeqPoly::new(epoch1, &near_covering[1..]),
            ),
            &near_window,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentBind: sequence does not match the derivation",
    );
    let misplaced = build_unspent_pcd_over_epochs(rng, &pool, |_| nf0, (epoch1, epoch2));
    assert_eq!(
        bind(
            rng,
            &misplaced,
            (
                NfSeqPoly::new(epoch1, &[nf0]),
                nf_seq.clone(),
                complement_seq,
            ),
            &window,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentBind: sequence does not match the derivation",
    );
    let mut forged_complement = covering[1..].to_vec();
    forged_complement[0] = junk;
    assert_eq!(
        bind(
            rng,
            &segment0,
            (
                elapsed_seq.clone(),
                nf_seq.clone(),
                NfSeqPoly::new(epoch1, &forged_complement),
            ),
            &window,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentBind: sequence does not match the derivation",
    );
    let duplicating_complement =
        NfSeqPoly::new(epoch0, &[nf0]) * NfSeqPoly::new(epoch2, &covering[2..]);
    assert_eq!(
        bind(
            rng,
            &segment0,
            (elapsed_seq, nf_seq, duplicating_complement),
            &window,
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentBind: sequence does not match the derivation",
    );
}

#[test]
fn unspent_lift_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, note, pool, [segment0, ..]) = segments(rng);
    let nf = |epoch| {
        wallet
            .pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch)
    };
    let [epoch0, epoch1, epoch2] = [0, 1, 2].map(EpochIndex::new);
    let (nf0, nf1) = (nf(epoch0), nf(epoch1));
    let forged_nf = Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)));

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

    assert_eq!(
        lift(
            rng,
            &segment0,
            &bucket2.pcd,
            lift_witness(nf1.into(), &[nf0], &bucket2.pcd, &bucket2.members),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentLift: the bucket does not start where the segment ends",
    );
    let mut renumbered_data = *bucket1.pcd.data();
    renumbered_data.0 = epoch2;
    let renumbered = bucket1
        .pcd
        .proof()
        .clone()
        .carry::<qr::QrBucket>(renumbered_data);
    assert_eq!(
        lift(
            rng,
            &segment0,
            &renumbered,
            lift_witness(nf1.into(), &[nf0], &renumbered, &bucket1.members),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentLift: the bucket is not the segment's next epoch",
    );
    let foreign_contents = TachygramSetPoly::from_iter([Tachygram::random(rng)]);
    assert_eq!(
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
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentLift: contents do not match the bucket",
    );
    assert_eq!(
        lift(
            rng,
            &segment0,
            &bucket1.pcd,
            lift_witness(nf1.into(), &[nf1], &bucket1.pcd, &bucket1.members),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentLift: elapsed does not match header",
    );
    assert_eq!(
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
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentLift: tested value is zero",
    );
    let other_classes = QrClassRoot::along(
        Fp::random(|bytes| rng.fill_bytes(bytes)),
        bucket1.pcd.data().3,
    );
    assert_eq!(
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
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: QR profile: root does not square to the claimed class",
    );
    assert_eq!(
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
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentLift: extended is not elapsed with the tested pair",
    );
    assert_eq!(
        lift(
            rng,
            &segment0,
            &bucket1.pcd,
            lift_witness(bucket1.members[0], &[nf0], &bucket1.pcd, &bucket1.members),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: UnspentLift: found nullifier in the bucket",
    );
    let mut final_segment_data = *segment0.data();
    final_segment_data.3 = EpochIndex::new(EPOCH_MAX);
    let final_segment = segment0
        .proof()
        .clone()
        .carry::<pool::ArbitraryUnspent>(final_segment_data);
    let mut final_bucket_data = *bucket1.pcd.data();
    final_bucket_data.0 = EpochIndex::new(EPOCH_MAX);
    let final_bucket = bucket1
        .pcd
        .proof()
        .clone()
        .carry::<qr::QrBucket>(final_bucket_data);
    let final_witness = witness::unspent_lift(
        (*final_segment.data(), *final_bucket.data()),
        nf1.into(),
        &[nf0],
        &bucket1.members,
    );
    assert_eq!(
        lift(rng, &final_segment, &final_bucket, final_witness)
            .unwrap_err()
            .to_string(),
        "invalid witness: UnspentLift: bucket has no next epoch",
    );
}
