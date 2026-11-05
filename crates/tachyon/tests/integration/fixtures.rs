extern crate alloc;

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{cell::RefCell, mem, ops::RangeInclusive};

use ragu::{Pcd, Proof};
use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use ragu_core::{PoseidonPermutation as _, pasta::PoseidonFp};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};
use zcash_tachyon::{
    Anchor, AnchorSetPoly, BlockHeight, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile,
    Tachygram, TachygramSetCommit, TachygramSetPoly, action,
    bundle::{self, Bundle},
    constants::EVIDENCE_TREE_ARITY,
    effect,
    entropy::ActionEntropy,
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    nullifier::{self, NF_DERIVATION_WIDTH, Nullifier},
    pasta::{Eq, Fp},
    stamp::{
        AggregateId, ProofStamp, StampState, Unproven,
        proof::{PROOF_SYSTEM, delegation, evidence, pool, qr, spendable, summary},
    },
    value, witness,
};

pub fn mock_sighash(bundle_digest: [u8; 32]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend sighash")
        .to_state()
        .update(&bundle_digest)
        .finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub fn mock_wtxid<S: StampState + 'static>(bundle: &Bundle<S>) -> AggregateId {
    let txid = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend txid")
        .to_state()
        .update(&bundle.commitment())
        .finalize();
    let auth = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend auth")
        .to_state()
        .update(&bundle.auth_digest())
        .finalize();

    let mut wtxid = [0u8; 64];
    wtxid[..32].copy_from_slice(txid.as_bytes());
    wtxid[32..].copy_from_slice(auth.as_bytes());

    AggregateId::try_from(wtxid).unwrap()
}

pub type StampEntry = (Anchor, Vec<Tachygram>, TachygramSetCommit, Anchor);

#[derive(Clone, Debug)]
pub struct PoolSimBlock {
    pub prev: Anchor,
    pub stamps: Vec<StampEntry>,
}

impl PoolSimBlock {
    pub fn anchor(&self) -> Anchor {
        match self.stamps.last() {
            Some(&(_, _, _, anchor)) => anchor,
            None => self.prev,
        }
    }
}

pub struct PoolSim {
    history: Vec<PoolSimBlock>,
    anchor_index: BTreeMap<Anchor, (BlockHeight, usize)>,
}

impl PoolSim {
    pub fn genesis_with(stamps: Vec<Vec<Tachygram>>) -> Self {
        let mut pool = Self {
            history: Vec::new(),
            anchor_index: BTreeMap::new(),
        };
        pool.push_block(Anchor::default(), stamps);
        pool
    }

    pub fn block(&self, height: BlockHeight) -> &PoolSimBlock {
        &self.history[usize::try_from(height).unwrap()]
    }

    /// Only an epoch-first block enters at an anchor not yet indexed.
    fn push_block(&mut self, prev: Anchor, stamps: Vec<Vec<Tachygram>>) {
        let height = BlockHeight::from(self.history.len());
        let epoch = height.epoch();
        let mut anchor = prev;
        let entries = stamps
            .into_iter()
            .map(|tgs| {
                let stamp_prev = anchor;
                let commit = tgs.iter().copied().collect::<TachygramSetPoly>().commit();
                let stamp_after = anchor.next_stamp(epoch, &commit).unwrap();
                anchor = stamp_after;
                (stamp_prev, tgs, commit, stamp_after)
            })
            .collect();
        let block = PoolSimBlock {
            prev,
            stamps: entries,
        };
        if height.is_first_in_epoch() {
            self.anchor_index.insert(prev, (height, 0));
        }
        for (position, &(_, _, _, stamp_after)) in block.stamps.iter().enumerate() {
            self.anchor_index
                .insert(stamp_after, (height, position + 1));
        }
        self.history.push(block);
    }

    #[must_use]
    pub fn height(&self) -> BlockHeight {
        BlockHeight::from(self.history.len() - 1)
    }

    pub fn stamps_between(&self, start: Anchor, end: Anchor) -> Vec<&StampEntry> {
        // An anchor indexes the first stamp slot it does not cover.
        let (start_height, start_inner) = self.anchor_index[&start];
        let (end_height, end_inner) = self.anchor_index[&end];
        let span = (start_height, start_inner)..(end_height, end_inner);

        (start_height.0..=end_height.0)
            .map(BlockHeight)
            .flat_map(|height| {
                self.block(height)
                    .stamps
                    .iter()
                    .enumerate()
                    .map(move |(position, entry)| ((height, position), entry))
            })
            .filter(|&(slot, _)| span.contains(&slot))
            .map(|(_, entry)| entry)
            .collect()
    }

    pub fn mine(&mut self, stamps: Vec<Vec<Tachygram>>) {
        let new_height = BlockHeight::from(self.history.len());
        let old_tip = self.block(self.height()).anchor();
        let prev = if new_height.is_first_in_epoch() {
            old_tip.next_epoch(new_height.epoch()).unwrap()
        } else {
            old_tip
        };
        self.push_block(prev, stamps);
    }
}

pub(crate) fn build_anchor_span_pcd<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    range: RangeInclusive<BlockHeight>,
) -> (Pcd<pool::AnchorSpan>, Vec<Anchor>) {
    let start = *range.start();
    let end = *range.end();
    assert_eq!(start.epoch(), end.epoch(), "AnchorSpan single-epoch range");
    assert!(start <= end);

    let mut state = pool.block(start).prev;
    let mut span: Option<Pcd<pool::AnchorSpan>> = None;
    let mut members = Vec::new();
    let mut height = start;
    loop {
        for tgs in pool.block(height).stamps.iter().map(|stamp| &stamp.1) {
            let witness = witness::anchor_span_seed(((), ()), state, height.epoch(), tgs);
            let next_state = state.next_stamp(witness.1, &witness.2).unwrap();
            let (seed, ()) = PROOF_SYSTEM
                .seed(rng, pool::AnchorSpanSeed, witness)
                .unwrap();
            span = Some(match span.take() {
                None => seed,
                Some(left) => {
                    let fuse_witness = witness::anchor_span_fuse(
                        (*left.data(), *seed.data()),
                        &members,
                        &[next_state],
                    );
                    let (fused, ()) = PROOF_SYSTEM
                        .fuse(rng, pool::AnchorSpanFuse, fuse_witness, left, seed)
                        .unwrap();
                    fused
                },
            });
            members.push(next_state);
            state = next_state;
        }
        if height >= end {
            break;
        }
        height = height.next().unwrap();
    }

    (span.unwrap(), members)
}

pub(crate) struct QrIntakeEntry {
    pub pcd: Pcd<qr::QrIntake>,
    pub members: Vec<Tachygram>,
}

pub(crate) struct QrBucketEntry {
    pub pcd: Pcd<qr::QrBucket>,
    pub members: Vec<Tachygram>,
}

fn build_qr_roots<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    (start, end): (Anchor, Anchor),
    discriminant: QrDiscriminant,
    capacity: usize,
) -> Vec<QrIntakeEntry> {
    let mut runs: Vec<Vec<&StampEntry>> = Vec::new();
    let mut open: Vec<&StampEntry> = Vec::new();
    let mut held = 0;
    for entry in pool.stamps_between(start, end) {
        let size = entry.1.len();
        if !open.is_empty() && (held + size) > capacity {
            runs.push(mem::take(&mut open));
            held = 0;
        }
        held += size;
        open.push(entry);
        if size > capacity {
            runs.push(mem::take(&mut open));
            held = 0;
        }
    }
    if !open.is_empty() {
        runs.push(open);
    }

    let mut roots = Vec::with_capacity(runs.len());
    for run in runs {
        let (first, last) = (run.first().unwrap(), run.last().unwrap());
        if run.len() == 1 && first.1.len() > capacity {
            let (entry, members) = (first.0, first.1.clone());
            let witness = witness::qr_stamp_intake_seed(
                ((), ()),
                entry,
                pool.anchor_index[&entry].0.epoch(),
                discriminant,
                &members,
            );
            let (pcd, ()) = PROOF_SYSTEM
                .seed(rng, qr::QrStampIntakeSeed, witness)
                .unwrap();
            roots.push(QrIntakeEntry { pcd, members });
            continue;
        }
        let (summary_start, summary_end) = (first.0, last.3);
        let entries = pool.stamps_between(summary_start, summary_end);
        let span_size: usize = entries.iter().map(|entry| entry.1.len()).sum();
        assert!(
            span_size < (1 << ProductionRank::RANK),
            "span exceeds one summary"
        );
        let epoch = pool.anchor_index[&summary_start].0.epoch();
        let (first_entry, rest) = entries.split_first().unwrap();
        let (mut summary, ()) = PROOF_SYSTEM
            .seed(
                rng,
                summary::SummarySeed,
                witness::summary_seed(((), ()), summary_start, epoch, &first_entry.1),
            )
            .unwrap();
        let mut members = first_entry.1.clone();
        for entry in rest {
            let (advanced, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    summary::SummaryAdvance,
                    witness::summary_advance((*summary.data(), ()), &members, &entry.1),
                    summary,
                    Proof::bootstrap().carry::<()>(()),
                )
                .unwrap();
            members.extend(entry.1.iter().copied());
            summary = advanced;
        }
        assert_eq!(
            summary.data().2,
            summary_end,
            "the summary closes at the span's end"
        );
        let witness = witness::qr_summary_intake((*summary.data(), ()), discriminant);
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSummaryIntake,
                witness,
                summary,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        roots.push(QrIntakeEntry { pcd, members });
    }
    roots
}

fn merge_qr_run<RNG: CryptoRng>(
    rng: &mut RNG,
    intakes: Vec<QrIntakeEntry>,
    capacity: usize,
) -> Vec<QrIntakeEntry> {
    let joins = |left: &QrIntakeEntry, right: &QrIntakeEntry| {
        let (_, _, _, _, left_profile, _) = *left.pcd.data();
        let (_, _, _, _, right_profile, _) = *right.pcd.data();
        left_profile == right_profile && (left.members.len() + right.members.len()) <= capacity
    };

    let mut merged: Vec<QrIntakeEntry> = Vec::new();
    let mut acc: Option<QrIntakeEntry> = None;
    for right in intakes {
        acc = match acc {
            None => Some(right),
            Some(left) if !joins(&left, &right) => {
                merged.push(left);
                Some(right)
            },
            Some(left) => {
                let witness = witness::qr_intake_merge(
                    (*left.pcd.data(), *right.pcd.data()),
                    &left.members,
                    &right.members,
                );
                let members = left
                    .members
                    .iter()
                    .chain(&right.members)
                    .copied()
                    .collect::<Vec<_>>();
                let (pcd, ()) = PROOF_SYSTEM
                    .fuse(rng, qr::QrIntakeMerge, witness, left.pcd, right.pcd)
                    .unwrap();
                Some(QrIntakeEntry { pcd, members })
            },
        };
    }
    merged.extend(acc);
    merged
}

pub(crate) fn split_qr_intake<RNG: CryptoRng>(
    rng: &mut RNG,
    intake: QrIntakeEntry,
) -> (QrIntakeEntry, QrIntakeEntry) {
    let (_epoch, _anchor_prev, _anchor_end, discriminant, profile, _contents) = *intake.pcd.data();
    let split_witness = witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members);
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            split_witness,
            intake.pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

    let mut descend = |side: bool| {
        let descend_witness = witness::qr_side_descend((*sides.data(), ()), &intake.members, side);
        let members = intake
            .members
            .iter()
            .copied()
            .filter(|&member| {
                qr::classify(Fp::from(member), discriminant.at(profile.depth)).0 == side
            })
            .collect::<Vec<_>>();
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                descend_witness,
                sides.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        QrIntakeEntry { pcd, members }
    };
    let non_residue = descend(false);
    let residue = descend(true);
    (non_residue, residue)
}

pub(crate) fn build_qr_partition<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    (start, end): (Anchor, Anchor),
    discriminant: QrDiscriminant,
    capacity: usize,
    depth: u32,
) -> Vec<QrIntakeEntry> {
    let mut layer = build_qr_roots(rng, pool, (start, end), discriminant, capacity);
    for _ in 0..depth {
        let mut residue = Vec::new();
        let mut non_residue = Vec::new();
        for intake in layer {
            let (nqr_side, qr_side) = split_qr_intake(rng, intake);
            non_residue.push(nqr_side);
            residue.push(qr_side);
        }
        layer = merge_qr_run(rng, residue, capacity);
        layer.extend(merge_qr_run(rng, non_residue, capacity));
    }
    layer
}

pub(crate) struct EvidenceLeaf {
    pub profile: QrProfile,
    pub contents: TachygramSetCommit,
    pub members: Vec<Tachygram>,
    pub path: Vec<([bool; 2], [EvidenceTreeRoot; EVIDENCE_TREE_ARITY])>,
}

pub(crate) struct EvidenceTreeEntry {
    pub pcd: Pcd<evidence::EvidenceTree>,
    pub leaves: Vec<EvidenceLeaf>,
}

/// Pads with copies of the last bucket; no step forbids a duplicate leaf.
pub(crate) fn build_evidence_tree<RNG: CryptoRng>(
    rng: &mut RNG,
    mut buckets: Vec<QrBucketEntry>,
) -> EvidenceTreeEntry {
    assert!(!buckets.is_empty(), "a tree holds at least one bucket");

    let mut width = EVIDENCE_TREE_ARITY;
    let mut depth = 1;
    while width < buckets.len() {
        width *= EVIDENCE_TREE_ARITY;
        depth += 1;
    }
    while buckets.len() < width {
        let last = buckets.last().unwrap();
        let padding = QrBucketEntry {
            pcd: last.pcd.clone(),
            members: last.members.clone(),
        };
        buckets.push(padding);
    }

    let (proofs, held): (Vec<_>, Vec<_>) = buckets
        .into_iter()
        .map(|bucket| {
            let (_epoch, _anchor_start, _anchor_next, _discriminant, profile, contents) =
                *bucket.pcd.data();
            (bucket.pcd, (profile, contents, bucket.members))
        })
        .unzip();

    let mut pairs = Vec::with_capacity(width / 2);
    let mut admitted = proofs.into_iter();
    while let (Some(first), Some(second)) = (admitted.next(), admitted.next()) {
        let (pair, ()) = PROOF_SYSTEM
            .fuse(rng, evidence::EvidenceTreeLeafPair, (), first, second)
            .unwrap();
        pairs.push(pair);
    }

    let mut levels = vec![
        pairs
            .iter()
            .flat_map(|pair| [pair.data().4, pair.data().5])
            .collect::<Vec<_>>(),
    ];
    let mut layer = Vec::with_capacity(pairs.len() / 2);
    let mut halves = pairs.into_iter();
    while let (Some(left), Some(right)) = (halves.next(), halves.next()) {
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(rng, evidence::EvidenceTreeFuse, (), left, right)
            .unwrap();
        layer.push(pcd);
    }
    levels.push(layer.iter().map(|pcd| pcd.data().4).collect());

    while layer.len() > 1 {
        let mut parents = Vec::with_capacity(layer.len() / EVIDENCE_TREE_ARITY);
        let mut children = layer.into_iter();
        while let (Some(first), Some(second), Some(third), Some(fourth)) = (
            children.next(),
            children.next(),
            children.next(),
            children.next(),
        ) {
            let (left, ()) = PROOF_SYSTEM
                .fuse(rng, evidence::EvidenceTreePairFuse, (), first, second)
                .unwrap();
            let (right, ()) = PROOF_SYSTEM
                .fuse(rng, evidence::EvidenceTreePairFuse, (), third, fourth)
                .unwrap();
            let (pcd, ()) = PROOF_SYSTEM
                .fuse(rng, evidence::EvidenceTreeFuse, (), left, right)
                .unwrap();
            parents.push(pcd);
        }
        levels.push(parents.iter().map(|pcd| pcd.data().4).collect());
        layer = parents;
    }

    let mut root = layer.pop().unwrap();
    let mut caps = Vec::new();
    while (depth + caps.len()) % evidence::EvidenceTreeDescend::LEVELS != 0 {
        caps.push(root.data().4);
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                evidence::EvidenceTreeCap,
                (),
                root,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        root = pcd;
    }

    let leaves = held
        .into_iter()
        .enumerate()
        .map(|(index, (profile, contents, members))| {
            let mut path: Vec<_> = caps
                .iter()
                .rev()
                .map(|child| ([false, false], [*child; EVIDENCE_TREE_ARITY]))
                .collect();
            path.extend((0..depth).rev().map(|level| {
                let base = EVIDENCE_TREE_ARITY * (index >> (2 * (level + 1)));
                let digit = (index >> (2 * level)) & 3;
                (
                    [digit & 2 != 0, digit & 1 != 0],
                    [
                        levels[level][base],
                        levels[level][base + 1],
                        levels[level][base + 2],
                        levels[level][base + 3],
                    ],
                )
            }));
            EvidenceLeaf {
                profile,
                contents,
                members,
                path,
            }
        })
        .collect();

    EvidenceTreeEntry { pcd: root, leaves }
}

pub fn descend_evidence_tree<RNG: CryptoRng>(
    rng: &mut RNG,
    tree: Pcd<evidence::EvidenceTree>,
    leaf: &EvidenceLeaf,
) -> Pcd<evidence::EvidenceTree> {
    let mut node = tree;
    for chunk in leaf.path.chunks(evidence::EvidenceTreeDescend::LEVELS) {
        let path = <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(chunk).unwrap();
        let witness = witness::evidence_tree_descend((*node.data(), ()), path);
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                evidence::EvidenceTreeDescend,
                witness,
                node,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        node = pcd;
    }
    node
}

pub fn qr_bucket_at<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    (start, final_anchor): (Anchor, Anchor),
    (discriminant, capacity, depth): (QrDiscriminant, usize, u32),
    value: Fp,
    anchor_final_prev: Anchor,
) -> QrBucketEntry {
    let mut branch = build_qr_roots(rng, pool, (start, final_anchor), discriminant, capacity);
    for level in 0..depth {
        let side = qr::classify(value, discriminant.at(level)).0;
        let mut kept = Vec::with_capacity(branch.len());
        for intake in branch {
            let (non_residue, residue) = split_qr_intake(rng, intake);
            kept.push(if side { residue } else { non_residue });
        }
        branch = merge_qr_run(rng, kept, capacity);
    }
    assert_eq!(branch.len(), 1, "the value's profile fits one intake");
    let intake = branch.pop().unwrap();
    assert_eq!(
        intake.pcd.data().4,
        (0..depth).fold(QrProfile::ROOT, |profile, level| {
            profile.descend(qr::classify(value, discriminant.at(level)).0)
        })
    );
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness::qr_bucket_seal((*intake.pcd.data(), ()), anchor_final_prev),
            intake.pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    QrBucketEntry {
        pcd,
        members: intake.members,
    }
}

pub fn detached_segment<RNG: CryptoRng>(
    rng: &mut RNG,
    epoch: EpochIndex,
    nf: impl Fn(EpochIndex) -> Nullifier,
) -> Pcd<pool::ArbitraryUnspent> {
    let anchor_final_prev = Anchor::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let discriminant = QrDiscriminant::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let entry = anchor_final_prev.next_epoch(epoch).unwrap();
    let (intake, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrEmptyIntakeSeed,
            witness::qr_empty_intake_seed(((), ()), entry, epoch, discriminant),
        )
        .unwrap();
    let (bucket, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness::qr_bucket_seal((*intake.data(), ()), anchor_final_prev),
            intake,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (bucket_epoch, ..) = *bucket.data();
    let (segment, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrUnspentInit,
            witness::qr_unspent_init((*bucket.data(), ()), nf(bucket_epoch).into(), &[]),
            bucket,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    segment
}

pub fn mine_sparse<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &mut PoolSim,
    through: EpochIndex,
    silent: Option<EpochIndex>,
) {
    while pool.height() < through.first_block() {
        let next = BlockHeight(pool.height().0 + 1);
        if next.is_last_in_epoch() && silent != Some(next.epoch()) {
            pool.mine(vec![vec![Tachygram::random(rng)]]);
        } else {
            pool.mine(Vec::new());
        }
    }
}

pub(crate) fn epoch_bucket<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    epoch: EpochIndex,
) -> QrBucketEntry {
    let entry = pool.block(epoch.first_block()).prev;
    let final_anchor = pool.block(epoch.last_block()).anchor();
    let anchor_final_prev = u32::from(epoch).checked_sub(1).map_or_else(
        || Anchor::from(Fp::ZERO),
        |prev| pool.block(EpochIndex::new(prev).last_block()).anchor(),
    );
    let discriminant = QrDiscriminant::random(rng);
    let intake = if entry == final_anchor {
        let (pcd, ()) = PROOF_SYSTEM
            .seed(
                rng,
                qr::QrEmptyIntakeSeed,
                witness::qr_empty_intake_seed(((), ()), entry, epoch, discriminant),
            )
            .unwrap();
        QrIntakeEntry {
            pcd,
            members: Vec::new(),
        }
    } else {
        let mut roots = build_qr_partition(
            rng,
            pool,
            (entry, final_anchor),
            discriminant,
            (1 << ProductionRank::RANK) - 1,
            0,
        );
        assert_eq!(roots.len(), 1, "the epoch fits one polynomial");
        roots.pop().unwrap()
    };
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness::qr_bucket_seal((*intake.pcd.data(), ()), anchor_final_prev),
            intake.pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    QrBucketEntry {
        pcd,
        members: intake.members,
    }
}

pub(crate) fn build_unspent_pcd_over_epochs<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    nf: impl Fn(EpochIndex) -> Nullifier,
    (epoch_start, epoch_next): (EpochIndex, EpochIndex),
) -> Pcd<pool::ArbitraryUnspent> {
    assert!(
        u32::from(epoch_start) < u32::from(epoch_next),
        "a segment covers at least one epoch"
    );
    let mut segments = Vec::new();
    for epoch in (u32::from(epoch_start)..u32::from(epoch_next)).map(EpochIndex::new) {
        let bucket = epoch_bucket(rng, pool, epoch);
        let (bucket_epoch, ..) = *bucket.pcd.data();
        let (segment, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                witness::qr_unspent_init(
                    (*bucket.pcd.data(), ()),
                    nf(bucket_epoch).into(),
                    &bucket.members,
                ),
                bucket.pcd,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        segments.push(segment);
    }
    let members: Vec<Nullifier> = (u32::from(epoch_start)..u32::from(epoch_next))
        .map(|epoch| nf(EpochIndex::new(epoch)))
        .collect();
    fuse_unspent_tree(rng, &members, epoch_start, segments)
}

fn fuse_unspent_tree<RNG: CryptoRng>(
    rng: &mut RNG,
    nf: &[Nullifier],
    base: EpochIndex,
    mut chains: Vec<Pcd<pool::ArbitraryUnspent>>,
) -> Pcd<pool::ArbitraryUnspent> {
    assert!(!chains.is_empty(), "tree fuses at least one chain");
    if chains.len() == 1 {
        return chains.pop().unwrap();
    }
    let right_chains = chains.split_off(chains.len() / 2);
    let left = fuse_unspent_tree(rng, nf, base, chains);
    let right = fuse_unspent_tree(rng, nf, base, right_chains);

    let elapsed_slice = |lo: EpochIndex, hi: EpochIndex| -> &[Nullifier] {
        let from = usize::try_from(u64::from(lo - base)).unwrap();
        let to = usize::try_from(u64::from(hi - base)).unwrap();
        &nf[from..to]
    };
    let (_, left_epoch_start, _, left_epoch_next, _) = *left.data();
    let (_, right_epoch_start, _, right_epoch_next, _) = *right.data();
    let left_el = elapsed_slice(left_epoch_start, left_epoch_next);
    let right_el = elapsed_slice(right_epoch_start, right_epoch_next);
    assert_eq!(
        u32::from(right_epoch_start),
        u32::from(left_epoch_next),
        "fused chains must meet at one epoch"
    );
    let witness = witness::unspent_fuse((*left.data(), *right.data()), left_el, right_el);
    let (fused, ()) = PROOF_SYSTEM
        .fuse(rng, pool::UnspentFuse, witness, left, right)
        .unwrap();
    fused
}

pub struct WalletSim {
    pub sk: private::SpendingKey,
    pub pak: ProofAuthorizingKey,
    pub notes: RefCell<StdRng>,
    pub secrets: RefCell<BTreeMap<Tachygram, Pcd<delegation::NoteSecret>>>,
    pub derivations: RefCell<BTreeMap<(Tachygram, u32, u32), Pcd<delegation::NoteNullifiers>>>,
}

impl WalletSim {
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        let sk = private::SpendingKey::random(rng);
        Self {
            sk,
            pak: sk.derive_proof_private(),
            notes: RefCell::new(StdRng::from_rng(rng)),
            secrets: RefCell::new(BTreeMap::new()),
            derivations: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn random_note(&self, value_amount: u64) -> Note {
        let notes = &mut *self.notes.borrow_mut();
        Note {
            pk: self.sk.derive_payment_key(),
            value: value::Positive::try_from(value_amount).unwrap(),
            psi: nullifier::Trapdoor::random(notes),
            rcm: note::CommitmentTrapdoor::random(notes),
        }
    }

    pub fn secret_pcd<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        note: Note,
    ) -> Pcd<delegation::NoteSecret> {
        let cm = Tachygram::from(note.commitment());
        if let Some(pcd) = self.secrets.borrow().get(&cm) {
            return pcd.clone();
        }
        let (pcd, ()) = PROOF_SYSTEM
            .seed(
                rng,
                delegation::NoteSeed,
                witness::note_seed(((), ()), note, self.pak),
            )
            .unwrap();

        self.secrets.borrow_mut().insert(cm, pcd.clone());
        pcd
    }

    pub fn derivation_pcd<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        note: Note,
        epoch_start: EpochIndex,
        epoch_end: EpochIndex,
    ) -> Pcd<delegation::NoteNullifiers> {
        let base = u32::from(epoch_start) - u32::from(epoch_start) % PoseidonFp::RATE as u32;
        let windows = (u32::from(epoch_end) - base + 1).div_ceil(NF_DERIVATION_WIDTH as u32);
        let cover_end = base + windows * NF_DERIVATION_WIDTH as u32 - 1;
        let key = (Tachygram::from(note.commitment()), base, cover_end);
        if let Some(pcd) = self.derivations.borrow().get(&key) {
            return pcd.clone();
        }
        let secret = self.secret_pcd(rng, note);
        let note_key = self.pak.nk.derive_note_private(note.psi);

        let mut merged: Option<Pcd<delegation::NoteNullifiers>> = None;
        for window in 0..windows {
            let chunk_start = EpochIndex::new(base + window * NF_DERIVATION_WIDTH as u32);
            let chunk_end =
                EpochIndex::new(u32::from(chunk_start) + NF_DERIVATION_WIDTH as u32 - 1);
            let (leaf, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    delegation::NullifierDerive,
                    witness::nullifier_derive((*secret.data(), ()), chunk_start),
                    secret.clone(),
                    Proof::bootstrap().carry::<()>(()),
                )
                .unwrap();
            merged = Some(match merged {
                None => leaf,
                Some(left) => {
                    let left_nfs: Vec<Nullifier> = (base..u32::from(chunk_start))
                        .map(|epoch| note_key.derive_nullifier(EpochIndex::new(epoch)))
                        .collect();
                    let right_nfs: Vec<Nullifier> = (u32::from(chunk_start)..=u32::from(chunk_end))
                        .map(|epoch| note_key.derive_nullifier(EpochIndex::new(epoch)))
                        .collect();
                    let (fused, ()) = PROOF_SYSTEM
                        .fuse(
                            rng,
                            delegation::NullifierFuse,
                            witness::nullifier_fuse(
                                (*left.data(), *leaf.data()),
                                &left_nfs,
                                &right_nfs,
                            ),
                            left,
                            leaf,
                        )
                        .unwrap();
                    fused
                },
            });
        }
        let pcd = merged.unwrap();

        self.derivations.borrow_mut().insert(key, pcd.clone());
        pcd
    }

    pub fn spendable_init<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        note: &Note,
        pool: &PoolSim,
        init_height: BlockHeight,
    ) -> Pcd<spendable::NoteSpendable> {
        let cm = note.commitment();
        let epoch = init_height.epoch();
        let (anchor_prev, creation_tgs) = {
            let block = pool.block(init_height);
            let cm_idx = block
                .stamps
                .iter()
                .position(|stamp| stamp.1.contains(&cm.into()))
                .unwrap();

            let anchor_prev = block.stamps[..cm_idx]
                .iter()
                .fold(block.prev, |anchor, stamp| {
                    anchor.next_stamp(init_height.epoch(), &stamp.2).unwrap()
                });

            (anchor_prev, block.stamps[cm_idx].1.clone())
        };
        let deriv = self.derivation_pcd(rng, *note, epoch, epoch);

        let (spendable, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spendable::SpendableInit,
                witness::spendable_init((*deriv.data(), ()), anchor_prev, &creation_tgs, epoch),
                deriv,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        spendable
    }

    pub fn unspent_bind<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        arbitrary: Pcd<pool::ArbitraryUnspent>,
        note: &Note,
    ) -> Pcd<pool::NoteUnspent> {
        let (_, epoch_start, _, epoch_next, _) = *arbitrary.data();
        let range = self.derivation_pcd(rng, *note, epoch_start, epoch_next);
        let note_key = self.pak.nk.derive_note_private(note.psi);
        let elapsed: Vec<Nullifier> = (u32::from(epoch_start)..u32::from(epoch_next))
            .map(|epoch| note_key.derive_nullifier(EpochIndex::new(epoch)))
            .collect();
        let (_, covering_start, _, covering_last) = *range.data();
        let covering: Vec<Nullifier> = (u32::from(covering_start)..=u32::from(covering_last))
            .map(|epoch| note_key.derive_nullifier(EpochIndex::new(epoch)))
            .collect();
        let (unspent, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                pool::UnspentBind,
                witness::unspent_bind((*arbitrary.data(), *range.data()), &covering, &elapsed),
                arbitrary,
                range,
            )
            .unwrap();
        unspent
    }

    pub fn lift_to_epoch<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        pool: &PoolSim,
        note: &Note,
        spendable: Pcd<spendable::NoteSpendable>,
        target: EpochIndex,
    ) -> Pcd<spendable::NoteSpendable> {
        let (_, epoch, _) = *spendable.data();
        if epoch == target {
            return spendable;
        }
        let note_key = self.pak.nk.derive_note_private(note.psi);
        let arbitrary = build_unspent_pcd_over_epochs(
            rng,
            pool,
            |covered| note_key.derive_nullifier(covered),
            (epoch, target),
        );
        let unspent = self.unspent_bind(rng, arbitrary, note);
        let (lifted, ()) = PROOF_SYSTEM
            .fuse(rng, spendable::SpendableLift, (), spendable, unspent)
            .unwrap();
        lifted
    }

    pub fn spendable_at<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        pool: &PoolSim,
        note: &Note,
        target: EpochIndex,
    ) -> Pcd<spendable::NoteSpendable> {
        let cm = Tachygram::from(note.commitment());
        let creation_height = pool
            .history
            .iter()
            .position(|block| block.stamps.iter().any(|stamp| stamp.1.contains(&cm)))
            .unwrap();
        let creation = BlockHeight::from(creation_height).epoch();
        let bucket = epoch_bucket(rng, pool, creation);
        let (bucket_epoch, ..) = *bucket.pcd.data();
        let (arbitrary, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                witness::qr_unspent_init(
                    (*bucket.pcd.data(), ()),
                    self.pak
                        .nk
                        .derive_note_private(note.psi)
                        .derive_nullifier(bucket_epoch)
                        .into(),
                    &bucket.members,
                ),
                bucket.pcd.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        let unspent = self.unspent_bind(rng, arbitrary, note);
        let witness =
            witness::qr_spendable_init((*unspent.data(), *bucket.pcd.data()), &bucket.members);
        let (spendable, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spendable::QrSpendableInit,
                witness,
                unspent,
                bucket.pcd,
            )
            .unwrap();
        self.lift_to_epoch(rng, pool, note, spendable, target)
    }

    pub fn autonome<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        anchor: Anchor,
        spends: Vec<(Note, Pcd<spendable::NoteSpendable>)>,
        output_notes: Vec<Note>,
    ) -> Bundle<ProofStamp> {
        let (bundle_plan, unproven, spend_pcds) =
            self.signed(rng, spends, output_notes, self.random_note(0));
        let stamp_plan = bundle_plan.stamp_plan(anchor, value::Positive::ZERO);
        let stamp = stamp_plan.prove(rng, &self.pak, spend_pcds).unwrap();

        unproven.stamp(stamp)
    }

    pub fn signed<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        spends: Vec<(Note, Pcd<spendable::NoteSpendable>)>,
        output_notes: Vec<Note>,
        max_fee_note: Note,
    ) -> (
        bundle::Plan,
        Bundle<Unproven>,
        Vec<(
            Pcd<delegation::NoteSecret>,
            Pcd<spendable::NoteSpendable>,
            Vec<(Pcd<pool::AnchorSpan>, AnchorSetPoly)>,
        )>,
    ) {
        let ask = self.sk.derive_auth_private();

        let mut spend_plans = Vec::with_capacity(spends.len());
        let mut spend_pcds = Vec::with_capacity(spends.len());
        for (note, spendable_pcd) in spends {
            let rcv = value::Trapdoor::random(rng);
            let theta = ActionEntropy::random(rng);
            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                self.pak.ak.derive_action_public(&alpha)
            });
            spend_plans.push(plan);
            spend_pcds.push((self.secret_pcd(rng, note), spendable_pcd, vec![]));
        }

        let output_plans: Vec<action::Plan<effect::Output>> = output_notes
            .into_iter()
            .map(|note| {
                let rcv = value::Trapdoor::random(rng);
                let theta = ActionEntropy::random(rng);
                action::Plan::output(note, theta, rcv)
            })
            .collect();

        let bundle_plan = bundle::Plan::new(spend_plans, output_plans, max_fee_note);
        let sighash = mock_sighash(bundle_plan.commitment().unwrap());
        let unproven = bundle_plan.sign(rng, &sighash, &ask).unwrap();

        (bundle_plan, unproven, spend_pcds)
    }
}

/// The mock's challenge `z`, known before choosing a scalar it doesn't absorb.
pub fn unpinned_challenge(commitments: &[Eq]) -> Fp {
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"MkRagu_Challng_\0")
        .to_state();
    for com in commitments {
        state.update(com.to_affine().to_bytes().as_ref());
    }
    let mut wide = [0u8; 64];
    wide.copy_from_slice(state.finalize().as_bytes());
    Fp::from_uniform_bytes(&wide)
}
