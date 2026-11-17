extern crate alloc;

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{array, iter, ops::RangeInclusive};
use std::sync::LazyLock;

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::pasta::Pasta;
use rand_core::CryptoRng;
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, Note, QrDiscriminant, QrProfile, Tachygram,
    TachygramSetCommit, TachygramSetPoly, note,
    nullifier::{self, Nullifier},
    pasta::Fp,
    stamp::proof::{App, pool, qr, summary},
    value, witness,
};

use super::{
    Proved, keyed_rng,
    qr::{
        EvidenceTreeEntry, QR_DEPTHS, QrBucketEntry, QrIntakeEntry, qr_profile_of,
        qr_profile_triplet, shared_discriminant,
    },
    wallet::shared_sk,
};

pub fn random_block<RNG: CryptoRng>(
    rng: &mut RNG,
    stamp_size: usize,
    n_stamps: usize,
) -> Vec<Vec<Tachygram>> {
    iter::repeat_with(|| {
        iter::repeat_with(|| Tachygram::random(rng))
            .take(stamp_size)
            .collect()
    })
    .take(n_stamps)
    .collect()
}

pub fn random_block_with<RNG: CryptoRng>(
    rng: &mut RNG,
    stamps_cms: &[Vec<note::Commitment>],
    n_stamps: usize,
) -> Vec<Vec<Tachygram>> {
    assert!(n_stamps >= stamps_cms.len());
    let mut stamps: Vec<Vec<Tachygram>> = stamps_cms
        .iter()
        .map(|cms| cms.iter().map(|&cm| Tachygram::from(cm)).collect())
        .collect();
    stamps.extend(
        iter::repeat_with(|| vec![Tachygram::random(rng)]).take(n_stamps - stamps_cms.len()),
    );
    stamps
}

pub type StampEntry = (Anchor, Vec<Tachygram>, TachygramSetCommit, Anchor);

#[derive(Clone, Debug)]
pub struct PoolSimBlock {
    pub prev: Anchor,
    pub stamps: Vec<StampEntry>,
}

impl PoolSimBlock {
    pub fn new(prev: Anchor, height: BlockHeight, stamps: Vec<Vec<Tachygram>>) -> Self {
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
        Self {
            prev,
            stamps: entries,
        }
    }

    pub fn anchor(&self) -> Anchor {
        match self.stamps.last() {
            Some(&(_, _, _, anchor)) => anchor,
            None => self.prev,
        }
    }
}

pub struct PoolSim {
    pub(super) history: Vec<PoolSimBlock>,
    pub(super) anchor_index: BTreeMap<Anchor, (BlockHeight, usize)>,
}

impl PoolSim {
    pub fn shared_note(value: u64) -> Note {
        assert!([500, 700, 800, 900, 1000].contains(&value));
        let mut rng = keyed_rng("shared note", &value.to_le_bytes());
        Note {
            pk: shared_sk().derive_payment_key(),
            value: value::Positive::try_from(value).unwrap(),
            psi: nullifier::Trapdoor::random(&mut rng),
            rcm: note::CommitmentTrapdoor::random(&mut rng),
        }
    }

    /// Epoch zero's QR tree must have at least 17 leaves at depth five so its
    /// evidence tree has three levels. The stamp after the mint stamp puts
    /// the mint anchor inside its block. Epoch three has no stamps because
    /// the lift tests cross a stampless epoch.
    /// The evidence tree needs padding beside a real leaf, in an all-padding
    /// quad beside real quads, and in an all-padding group of sixteen because a
    /// test opens each.
    pub fn shared() -> &'static Self {
        static SHARED: LazyLock<PoolSim> = LazyLock::new(|| {
            let mut rng = keyed_rng("shared chain", &[]);
            let [_, exceptional, companion] = qr_profile_triplet();
            let genesis = vec![Tachygram::from(exceptional), Tachygram::from(companion)];
            let mint = [500, 700, 800, 900, 1000]
                .into_iter()
                .map(|value| Tachygram::from(PoolSim::shared_note(value).commitment()))
                .collect::<Vec<_>>();
            let fillers: [Tachygram; 3] = array::from_fn(|_| Tachygram::random(&mut rng));
            let candidates: [Tachygram; 8] = array::from_fn(|_| Tachygram::random(&mut rng));
            let discriminant = shared_discriminant();
            let len = (1..=8)
                .find(|&len| {
                    let members = genesis
                        .iter()
                        .chain(&mint)
                        .chain(&fillers)
                        .chain(&candidates[..len])
                        .copied()
                        .collect::<Vec<_>>();
                    let leaf_count = PoolSim::leaves(&members, discriminant, 0);
                    leaf_count >= 17
                        && !leaf_count.is_multiple_of(4)
                        && !leaf_count.next_multiple_of(4).is_multiple_of(16)
                })
                .unwrap();
            let closing_stamp = candidates[..len].to_vec();
            let members = genesis
                .iter()
                .chain(&mint)
                .chain(&fillers)
                .chain(&closing_stamp)
                .copied()
                .collect::<Vec<_>>();
            let count = PoolSim::leaves(&members, discriminant, 0);
            assert!(
                count >= 17
                    && !count.is_multiple_of(4)
                    && !count.next_multiple_of(4).is_multiple_of(16)
            );
            let mut pool = PoolSim::genesis_with(vec![genesis]);
            pool.mine(vec![mint, vec![fillers[0]]]);
            pool.mine(vec![vec![fillers[1]], vec![fillers[2]]]);
            pool.mine(vec![closing_stamp]);
            pool.advance(EpochIndex::new(0).last_block().0 - pool.height().0, |_| {
                Vec::new()
            });
            for epoch in 1..=16 {
                let stamp_count = match epoch {
                    1 => 2,
                    3 => 0,
                    _ => 1,
                };
                pool.mine(random_block(&mut rng, 1, stamp_count));
                pool.advance(
                    EpochIndex::new(epoch).last_block().0 - pool.height().0,
                    |_| Vec::new(),
                );
            }
            pool.mine(Vec::new());
            pool
        });

        &SHARED
    }

    fn leaves(members: &[Tachygram], discriminant: QrDiscriminant, level: u32) -> usize {
        if level == 5 || members.is_empty() {
            return 1;
        }
        let (residue, non_residue): (Vec<_>, Vec<_>) = members
            .iter()
            .copied()
            .partition(|&member| qr::classify(Fp::from(member), discriminant.at(level)).0);
        Self::leaves(&residue, discriminant, level + 1)
            + Self::leaves(&non_residue, discriminant, level + 1)
    }

    fn qr_key((start, end): (Anchor, Anchor), discriminant: QrDiscriminant) -> Vec<u8> {
        [
            Fp::from(start).to_bytes(),
            Fp::from(end).to_bytes(),
            Fp::from(discriminant).to_bytes(),
        ]
        .concat()
    }

    fn qr_profile_key(
        span: (Anchor, Anchor),
        discriminant: QrDiscriminant,
        profile: QrProfile,
    ) -> Vec<u8> {
        let mut key = Self::qr_key(span, discriminant);
        key.extend_from_slice(&profile.depth.to_le_bytes());
        key.extend_from_slice(&profile.bits.to_le_bytes());
        key
    }

    pub(crate) fn qr_root(
        &self,
        app: &App<'_>,
        span: (Anchor, Anchor),
        discriminant: QrDiscriminant,
    ) -> QrIntakeEntry {
        static ROOTS: Proved<QrIntakeEntry> = Proved::new("qr_root");

        ROOTS.get(&Self::qr_key(span, discriminant), |rng| {
            let summary = self.summary(app, span);
            let members = self
                .stamps_between(span.0, span.1)
                .iter()
                .flat_map(|stamp| stamp.1.iter().copied())
                .collect();
            let witness = witness::qr_summary_intake((*summary.data(), ()), discriminant);
            let (pcd, ()) = app
                .fuse(
                    rng,
                    qr::QrSummaryIntake,
                    witness,
                    summary,
                    app.bootstrap_proof().clone().carry::<()>(()),
                )
                .unwrap();
            QrIntakeEntry { pcd, members }
        })
    }

    fn prove_qr_sides<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &App<'_>,
        parent: &QrIntakeEntry,
    ) -> ragu::Pcd<Pasta, ProductionRank, qr::QrIntakeSides> {
        let witness = witness::qr_intake_split((*parent.pcd.data(), ()), &parent.members);
        let (pcd, ()) = app
            .fuse(
                rng,
                qr::QrIntakeSplit,
                witness,
                parent.pcd.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        pcd
    }

    fn qr_sides(
        app: &App<'_>,
        span: (Anchor, Anchor),
        discriminant: QrDiscriminant,
        parent: &QrIntakeEntry,
    ) -> ragu::Pcd<Pasta, ProductionRank, qr::QrIntakeSides> {
        static SIDES: Proved<ragu::Pcd<Pasta, ProductionRank, qr::QrIntakeSides>> =
            Proved::new("qr_sides");

        let key = Self::qr_profile_key(span, discriminant, parent.pcd.data().4);
        SIDES.get(&key, |rng| Self::prove_qr_sides(rng, app, parent))
    }

    fn prove_qr_child<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &App<'_>,
        parent: &QrIntakeEntry,
        side: bool,
        sides: ragu::Pcd<Pasta, ProductionRank, qr::QrIntakeSides>,
    ) -> QrIntakeEntry {
        let witness = witness::qr_side_select((*sides.data(), ()), &parent.members, side);
        let (selection, ()) = app
            .fuse(
                rng,
                qr::QrSideSelect,
                witness,
                sides.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        let (pcd, ()) = app
            .fuse(
                rng,
                qr::QrSideDescend,
                witness::qr_side_descend((*sides.data(), *selection.data()), side),
                sides,
                selection,
            )
            .unwrap();
        let (_, _, _, discriminant, profile) = *parent.pcd.data();
        let members = parent
            .members
            .iter()
            .copied()
            .filter(|member| {
                qr::classify(Fp::from(*member), discriminant.at(profile.depth)).0 == side
            })
            .collect();
        QrIntakeEntry { pcd, members }
    }

    fn qr_child(
        app: &App<'_>,
        span: (Anchor, Anchor),
        discriminant: QrDiscriminant,
        parent: &QrIntakeEntry,
        side: bool,
    ) -> QrIntakeEntry {
        static CHILDREN: Proved<QrIntakeEntry> = Proved::new("qr_child");

        let profile = parent.pcd.data().4;
        let key = Self::qr_profile_key(span, discriminant, profile.descend(side));
        CHILDREN.get(&key, |rng| {
            let sides = Self::qr_sides(app, span, discriminant, parent);
            Self::prove_qr_child(rng, app, parent, side, sides)
        })
    }

    pub(crate) fn qr_intake(
        &self,
        app: &App<'_>,
        span: (Anchor, Anchor),
        discriminant: QrDiscriminant,
        value: Fp,
        depth: u32,
    ) -> QrIntakeEntry {
        let mut intake = self.qr_root(app, span, discriminant);
        for level in 0..depth {
            let side = qr::classify(value, discriminant.at(level)).0;
            intake = Self::qr_child(app, span, discriminant, &intake, side);
        }
        intake
    }

    /// Only four depths are kept because nothing reads the levels between them.
    pub fn qr_descent(
        &self,
        app: &App<'_>,
        span: (Anchor, Anchor),
        discriminant: QrDiscriminant,
        value: Fp,
    ) -> [QrIntakeEntry; 4] {
        static DESCENTS: Proved<[QrIntakeEntry; 4]> = Proved::new("qr_descent");

        let key = Self::qr_profile_key(
            span,
            discriminant,
            qr_profile_of(value, discriminant, u32::BITS),
        );
        DESCENTS.get(&key, |rng| {
            let root = self.qr_intake(app, span, discriminant, value, QR_DEPTHS[0]);
            let first = self.qr_intake(app, span, discriminant, value, QR_DEPTHS[1]);
            let mut intake = self.qr_intake(app, span, discriminant, value, 2);
            let mut penultimate = None;
            for level in 2..u32::BITS {
                let side = qr::classify(value, discriminant.at(level)).0;
                let sides = Self::prove_qr_sides(rng, app, &intake);
                intake = Self::prove_qr_child(rng, app, &intake, side, sides);
                if level + 1 == QR_DEPTHS[2] {
                    penultimate = Some(intake.clone());
                }
            }
            [root, first, penultimate.unwrap(), intake]
        })
    }

    pub fn qr_split(
        &self,
        app: &App<'_>,
        span: (Anchor, Anchor),
        discriminant: QrDiscriminant,
        value: Fp,
        depth: u32,
    ) -> ragu::Pcd<Pasta, ProductionRank, qr::QrIntakeSides> {
        let intake = self.qr_intake(app, span, discriminant, value, depth);
        Self::qr_sides(app, span, discriminant, &intake)
    }

    pub(crate) fn qr_intakes(
        &self,
        app: &App<'_>,
        span: (Anchor, Anchor),
        discriminant: QrDiscriminant,
        depth: u32,
    ) -> Vec<QrIntakeEntry> {
        let mut layer = vec![self.qr_root(app, span, discriminant)];
        for _ in 0..depth {
            let mut residue = Vec::new();
            let mut non_residue = Vec::new();
            let mut carried = Vec::new();
            for intake in layer {
                if intake.members.is_empty() {
                    carried.push(intake);
                    continue;
                }
                residue.push(Self::qr_child(app, span, discriminant, &intake, true));
                non_residue.push(Self::qr_child(app, span, discriminant, &intake, false));
            }
            layer = residue;
            layer.extend(non_residue);
            layer.extend(carried);
        }
        layer
    }

    pub fn evidence_tree(&self, app: &App<'_>) -> EvidenceTreeEntry {
        static TREES: Proved<EvidenceTreeEntry> = Proved::new("pool_evidence_tree");
        let epoch0 = EpochIndex::new(0);
        let span = self.epoch_span(epoch0);
        let discriminant = shared_discriminant();
        TREES.get(&Self::qr_key(span, discriminant), |rng| {
            let members = self
                .stamps_between(span.0, span.1)
                .iter()
                .flat_map(|stamp| stamp.1.iter().copied())
                .collect::<Vec<_>>();
            let count = Self::leaves(&members, discriminant, 0);
            let mut layer = self.qr_intakes(app, span, discriminant, 2);
            for _ in 2..5 {
                let mut residue = Vec::new();
                let mut non_residue = Vec::new();
                let mut carried = Vec::new();
                for intake in layer {
                    if intake.members.is_empty() {
                        carried.push(intake);
                        continue;
                    }
                    let sides = Self::prove_qr_sides(rng, app, &intake);
                    residue.push(Self::prove_qr_child(rng, app, &intake, true, sides.clone()));
                    non_residue.push(Self::prove_qr_child(rng, app, &intake, false, sides));
                }
                layer = residue;
                layer.extend(non_residue);
                layer.extend(carried);
            }
            assert_eq!(layer.len(), count);
            let (empty, occupied): (Vec<_>, Vec<_>) = layer
                .into_iter()
                .partition(|intake| intake.members.is_empty());
            let buckets = empty
                .into_iter()
                .chain(occupied)
                .map(|intake| intake.seal(rng, app, Anchor::from(Fp::ZERO)))
                .collect::<Vec<_>>();
            EvidenceTreeEntry::build(rng, app, &buckets)
        })
    }

    pub(crate) fn qr_bucket(
        &self,
        app: &App<'_>,
        span: (Anchor, Anchor),
        discriminant: QrDiscriminant,
        value: Fp,
        depth: u32,
        anchor_final_prev: Anchor,
    ) -> QrBucketEntry {
        let intake = self.qr_intake(app, span, discriminant, value, depth);
        intake.sealed(app, anchor_final_prev)
    }

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

    /// The anchor after the stamp that mints the shared notes.
    pub fn mint_anchor(&self) -> Anchor {
        self.block(BlockHeight(1)).stamps[0].3
    }

    fn push_block(&mut self, prev: Anchor, stamps: Vec<Vec<Tachygram>>) {
        let height = BlockHeight::from(self.history.len());
        let block = PoolSimBlock::new(prev, height, stamps);
        if height.is_first_in_epoch() {
            self.anchor_index.insert(prev, (height, 0));
        }
        for (position, &(_prev_anchor, _, _, anchor)) in block.stamps.iter().enumerate() {
            self.anchor_index.insert(anchor, (height, position + 1));
        }
        self.history.push(block);
    }

    #[must_use]
    pub fn height(&self) -> BlockHeight {
        BlockHeight::from(self.history.len() - 1)
    }

    #[must_use]
    pub fn anchor(&self) -> Anchor {
        self.block(self.height()).anchor()
    }

    pub fn stamps_between(&self, start: Anchor, end: Anchor) -> Vec<&StampEntry> {
        let (start_height, start_inner) = self.anchor_index[&start];
        let (end_height, end_inner) = self.anchor_index[&end];
        let span = (start_height, start_inner)..(end_height, end_inner);

        let entries: Vec<&StampEntry> = (start_height.0..=end_height.0)
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
            .collect();

        let (first, rest) = entries.split_first().unwrap();
        assert_eq!(first.0, start);
        let mut cursor = first.3;
        for entry in rest {
            assert_eq!(entry.0, cursor);
            cursor = entry.3;
        }
        assert_eq!(cursor, end);

        entries
    }

    pub fn advance(
        &mut self,
        count: u32,
        mut block_factory: impl FnMut(&Self) -> Vec<Vec<Tachygram>>,
    ) {
        for _ in 0..count {
            let block = block_factory(self);
            self.mine(block);
        }
    }

    pub fn mine(&mut self, stamps: Vec<Vec<Tachygram>>) {
        let new_height = BlockHeight::from(self.history.len());
        let old_tip = self.anchor();
        let prev = if new_height.is_first_in_epoch() {
            old_tip.next_epoch(new_height.epoch()).unwrap()
        } else {
            old_tip
        };
        self.push_block(prev, stamps);
    }

    pub(crate) fn anchors_in(&self, range: RangeInclusive<BlockHeight>) -> Vec<Anchor> {
        (range.start().0..=range.end().0)
            .flat_map(|height| {
                self.block(BlockHeight(height))
                    .stamps
                    .iter()
                    .map(|stamp| stamp.3)
            })
            .collect()
    }

    pub(crate) fn anchor_span(
        &self,
        app: &App<'_>,
        range: RangeInclusive<BlockHeight>,
    ) -> ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan> {
        static SEEDS: Proved<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>> =
            Proved::new("anchor_span_seed");
        static SPANS: Proved<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>> =
            Proved::new("anchor_span");

        fn prove(
            app: &App<'_>,
            epoch: EpochIndex,
            stamps: &[&StampEntry],
        ) -> ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan> {
            let (last, prefix) = stamps.split_last().unwrap();
            if prefix.is_empty() {
                let key = [Fp::from(last.0).to_bytes(), Fp::from(last.3).to_bytes()].concat();
                return SEEDS.get(&key, |rng| {
                    let witness = witness::anchor_span_seed(((), ()), last.0, epoch, &last.1);
                    let (seed, ()) = app.seed(rng, pool::AnchorSpanSeed, witness).unwrap();
                    seed
                });
            }
            let key = [
                Fp::from(prefix[0].0).to_bytes(),
                Fp::from(last.3).to_bytes(),
            ]
            .concat();
            SPANS.get(&key, |rng| {
                let left = prove(app, epoch, prefix);
                let right = prove(app, epoch, &stamps[stamps.len() - 1..]);
                let members = prefix.iter().map(|stamp| stamp.3).collect::<Vec<_>>();
                let witness =
                    witness::anchor_span_fuse((*left.data(), *right.data()), &members, &[last.3]);
                let (fused, ()) = app
                    .fuse(rng, pool::AnchorSpanFuse, witness, left, right)
                    .unwrap();
                fused
            })
        }

        let start = *range.start();
        let end = *range.end();
        assert_eq!(start.epoch(), end.epoch());
        assert!(start <= end);
        let stamps = (start.0..=end.0)
            .flat_map(|height| &self.block(BlockHeight(height)).stamps)
            .collect::<Vec<_>>();
        prove(app, start.epoch(), &stamps)
    }

    fn prove_summary<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &App<'_>,
        start: Anchor,
        epoch: EpochIndex,
        stamps: &[&StampEntry],
    ) -> ragu::Pcd<Pasta, ProductionRank, summary::Summary> {
        let (first, rest) = stamps.split_first().unwrap();
        let (mut pcd, ()) = app
            .seed(
                rng,
                summary::SummarySeed,
                witness::summary_seed(((), ()), start, epoch, &first.1),
            )
            .unwrap();
        let mut held = first.1.clone();
        for stamp in rest {
            let witness = witness::summary_advance((*pcd.data(), ()), &held, &stamp.1);
            let (advanced, ()) = app
                .fuse(
                    rng,
                    summary::SummaryAdvance,
                    witness,
                    pcd,
                    app.bootstrap_proof().clone().carry::<()>(()),
                )
                .unwrap();
            held.extend(stamp.1.iter().copied());
            pcd = advanced;
        }
        pcd
    }

    pub(crate) fn summary(
        &self,
        app: &App<'_>,
        (start, end): (Anchor, Anchor),
    ) -> ragu::Pcd<Pasta, ProductionRank, summary::Summary> {
        static SUMMARIES: Proved<ragu::Pcd<Pasta, ProductionRank, summary::Summary>> =
            Proved::new("summary");

        let stamps = self.stamps_between(start, end);
        let key = [Fp::from(start).to_bytes(), Fp::from(end).to_bytes()].concat();
        SUMMARIES.get(&key, |rng| {
            Self::prove_summary(
                rng,
                app,
                start,
                self.anchor_index[&start].0.epoch(),
                &stamps,
            )
        })
    }

    pub fn entry_anchor(&self, epoch: EpochIndex) -> Anchor {
        u32::from(epoch)
            .checked_sub(1)
            .map_or_else(Anchor::default, |previous| {
                self.block(EpochIndex::new(previous).last_block())
                    .anchor()
                    .next_epoch(epoch)
                    .unwrap()
            })
    }

    pub fn epoch_span(&self, epoch: EpochIndex) -> (Anchor, Anchor) {
        (
            self.entry_anchor(epoch),
            self.block(epoch.last_block()).anchor(),
        )
    }

    pub(crate) fn epoch_discriminant(&self, epoch: EpochIndex) -> QrDiscriminant {
        if u32::from(epoch) == 0 {
            return shared_discriminant();
        }
        let mut key = u32::from(epoch).to_le_bytes().to_vec();
        key.extend_from_slice(&Fp::from(self.entry_anchor(epoch)).to_bytes());
        QrDiscriminant::random(&mut keyed_rng("epoch discriminant", &key))
    }

    fn epoch_bucket_anchors(&self, epoch: EpochIndex) -> [Anchor; 3] {
        let (entry, final_anchor) = self.epoch_span(epoch);
        let anchor_final_prev = u32::from(epoch).checked_sub(1).map_or_else(
            || Anchor::from(Fp::ZERO),
            |prev| self.block(EpochIndex::new(prev).last_block()).anchor(),
        );
        [entry, final_anchor, anchor_final_prev]
    }

    fn epoch_bucket_key(epoch: EpochIndex, anchors: [Anchor; 3]) -> Vec<u8> {
        let mut key = u32::from(epoch).to_le_bytes().to_vec();
        for anchor in anchors {
            key.extend_from_slice(&Fp::from(anchor).to_bytes());
        }
        key
    }

    pub(crate) fn epoch_bucket(&self, app: &App<'_>, epoch: EpochIndex) -> QrBucketEntry {
        static BUCKETS: Proved<QrBucketEntry> = Proved::new("epoch_bucket");
        let [entry, final_anchor, anchor_final_prev] = self.epoch_bucket_anchors(epoch);
        let discriminant = self.epoch_discriminant(epoch);
        // Epoch zero shares its root and seal because tests read them directly.
        if u32::from(epoch) == 0 {
            let intake = if entry == final_anchor {
                QrIntakeEntry::empty(app, entry, epoch, discriminant)
            } else {
                self.qr_root(app, (entry, final_anchor), discriminant)
            };
            return intake.sealed(app, anchor_final_prev);
        }
        BUCKETS.get(
            &Self::epoch_bucket_key(epoch, [entry, final_anchor, anchor_final_prev]),
            |rng| {
                let intake = if entry == final_anchor {
                    QrIntakeEntry::empty(app, entry, epoch, discriminant)
                } else {
                    let stamps = self.stamps_between(entry, final_anchor);
                    let summary = Self::prove_summary(rng, app, entry, epoch, &stamps);
                    let members = stamps
                        .iter()
                        .flat_map(|stamp| stamp.1.iter().copied())
                        .collect();
                    let witness = witness::qr_summary_intake((*summary.data(), ()), discriminant);
                    let (pcd, ()) = app
                        .fuse(
                            rng,
                            qr::QrSummaryIntake,
                            witness,
                            summary,
                            app.bootstrap_proof().clone().carry::<()>(()),
                        )
                        .unwrap();
                    QrIntakeEntry { pcd, members }
                };
                intake.seal(rng, app, anchor_final_prev)
            },
        )
    }

    pub(crate) fn unspent(
        &self,
        app: &App<'_>,
        (epoch_start, epoch_next): (EpochIndex, EpochIndex),
        nf: impl Fn(EpochIndex) -> Nullifier,
    ) -> ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent> {
        static SEGMENTS: Proved<ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent>> =
            Proved::new("unspent_segment");
        static RANGES: Proved<ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent>> =
            Proved::new("unspent_range");

        fn prove(
            pool: &PoolSim,
            app: &App<'_>,
            (lo, hi): (EpochIndex, EpochIndex),
            members: &[Nullifier],
        ) -> ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent> {
            if let &[nf] = members {
                let mut key = PoolSim::epoch_bucket_key(lo, pool.epoch_bucket_anchors(lo));
                key.extend_from_slice(&Fp::from(nf).to_bytes());
                return SEGMENTS.get(&key, |rng| {
                    let bucket = pool.epoch_bucket(app, lo);
                    bucket.segment(rng, app, |_| nf)
                });
            }
            let first = pool.entry_anchor(lo);
            let last = EpochIndex::new(u32::from(hi) - 1);
            let final_anchor = pool.block(last.last_block()).anchor();
            let mut key = [
                Fp::from(first).to_bytes(),
                Fp::from(final_anchor).to_bytes(),
            ]
            .concat();
            key.extend_from_slice(&u32::from(lo).to_le_bytes());
            key.extend_from_slice(&u32::from(hi).to_le_bytes());
            key.extend_from_slice(&u32::try_from(members.len()).unwrap().to_le_bytes());
            for member in members {
                key.extend_from_slice(&Fp::from(*member).to_bytes());
            }
            RANGES.get(&key, |rng| {
                let split = members.len() / 2;
                let middle = EpochIndex::new(u32::from(lo) + u32::try_from(split).unwrap());
                let left = prove(pool, app, (lo, middle), &members[..split]);
                let right = prove(pool, app, (middle, hi), &members[split..]);
                let witness = witness::unspent_fuse(
                    (*left.data(), *right.data()),
                    &members[..split],
                    &members[split..],
                );
                let (fused, ()) = app
                    .fuse(rng, pool::UnspentFuse, witness, left, right)
                    .unwrap();
                fused
            })
        }

        assert!(u32::from(epoch_start) < u32::from(epoch_next));
        let members: Vec<Nullifier> = (u32::from(epoch_start)..u32::from(epoch_next))
            .map(|epoch| nf(EpochIndex::new(epoch)))
            .collect();
        prove(self, app, (epoch_start, epoch_next), &members)
    }
}
