extern crate alloc;

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{iter, ops::RangeInclusive};

use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use ragu_core::pasta::Pasta;
use rand_core::CryptoRng;
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, QrDiscriminant, Tachygram, TachygramSetCommit,
    TachygramSetPoly, note,
    nullifier::Nullifier,
    pasta::Fp,
    stamp::proof::{App, pool},
    witness,
};

use super::qr::{QrBucketEntry, QrIntakeEntry, build_qr_roots, merge_qr_run};

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
    pub(crate) fn qr_intakes<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        (start, end): (Anchor, Anchor),
        discriminant: QrDiscriminant,
        capacity: usize,
        depth: u32,
    ) -> Vec<QrIntakeEntry> {
        let mut layer = build_qr_roots(rng, app, self, (start, end), discriminant, capacity);
        for _ in 0..depth {
            let mut residue = Vec::new();
            let mut non_residue = Vec::new();
            let mut empty = Vec::new();
            for intake in layer {
                if intake.members.is_empty() {
                    empty.push(intake);
                    continue;
                }
                let (nqr_side, qr_side) = intake.split(rng, app);
                non_residue.push(nqr_side);
                residue.push(qr_side);
            }
            layer = merge_qr_run(rng, app, residue, capacity);
            layer.extend(merge_qr_run(rng, app, non_residue, capacity));
            layer.extend(empty);
        }
        layer
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

    pub(crate) fn anchor_span<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        range: RangeInclusive<BlockHeight>,
    ) -> (
        ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>,
        Vec<Anchor>,
    ) {
        let start = *range.start();
        let end = *range.end();
        assert_eq!(start.epoch(), end.epoch());
        assert!(start <= end);

        let mut state = self.block(start).prev;
        let mut span: Option<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>> = None;
        let mut members = Vec::new();
        let mut height = start;
        loop {
            for tgs in &self
                .block(height)
                .stamps
                .iter()
                .map(|stamp| stamp.1.clone())
                .collect::<Vec<_>>()
            {
                let witness = witness::anchor_span_seed(((), ()), state, height.epoch(), tgs);
                let next_state = state.next_stamp(witness.1, &witness.2.commit()).unwrap();
                let (seed, ()) = app.seed(rng, pool::AnchorSpanSeed, witness).unwrap();
                span = Some(match span.take() {
                    None => seed,
                    Some(left) => {
                        let fuse_witness = witness::anchor_span_fuse(
                            (*left.data(), *seed.data()),
                            &members,
                            &[next_state],
                        );
                        let (fused, ()) = app
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

    pub(crate) fn epoch_bucket<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        epoch: EpochIndex,
    ) -> QrBucketEntry {
        let entry = self.block(epoch.first_block()).prev;
        let final_anchor = self.block(epoch.last_block()).anchor();
        let anchor_final_prev = u32::from(epoch).checked_sub(1).map_or_else(
            || Anchor::from(Fp::ZERO),
            |prev| self.block(EpochIndex::new(prev).last_block()).anchor(),
        );
        let discriminant = QrDiscriminant::random(rng);
        let intake = if entry == final_anchor {
            QrIntakeEntry::empty(rng, app, entry, epoch, discriminant)
        } else {
            let mut roots = self.qr_intakes(
                rng,
                app,
                (entry, final_anchor),
                discriminant,
                (1 << ProductionRank::RANK) - 1,
                0,
            );
            assert_eq!(roots.len(), 1);
            roots.pop().unwrap()
        };
        intake.seal(rng, app, anchor_final_prev)
    }

    pub(crate) fn unspent<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        (epoch_start, epoch_next): (EpochIndex, EpochIndex),
        nf: impl Fn(EpochIndex) -> Nullifier,
    ) -> ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent> {
        assert!(u32::from(epoch_start) < u32::from(epoch_next));
        let mut segments = Vec::new();
        for epoch in (u32::from(epoch_start)..u32::from(epoch_next)).map(EpochIndex::new) {
            let bucket = self.epoch_bucket(rng, app, epoch);
            segments.push(bucket.segment(rng, app, &nf));
        }
        let members: Vec<Nullifier> = (u32::from(epoch_start)..u32::from(epoch_next))
            .map(|epoch| nf(EpochIndex::new(epoch)))
            .collect();
        fuse_unspent_tree(rng, app, &members, epoch_start, segments)
    }
}

pub(crate) fn small_epoch<RNG: CryptoRng>(rng: &mut RNG) -> (PoolSim, Anchor) {
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let final_anchor = pool.block(pool.height()).anchor();
    (pool, final_anchor)
}

fn fuse_unspent_tree<RNG: CryptoRng>(
    rng: &mut RNG,
    app: &App<'_>,
    nf: &[Nullifier],
    base: EpochIndex,
    mut chains: Vec<ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent>>,
) -> ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent> {
    assert!(!chains.is_empty());
    if chains.len() == 1 {
        return chains.pop().unwrap();
    }
    let right_chains = chains.split_off(chains.len() / 2);
    let left = fuse_unspent_tree(rng, app, nf, base, chains);
    let right = fuse_unspent_tree(rng, app, nf, base, right_chains);

    let elapsed_slice = |lo: EpochIndex, hi: EpochIndex| -> &[Nullifier] {
        let from = usize::try_from(u64::from(lo - base)).unwrap();
        let to = usize::try_from(u64::from(hi - base)).unwrap();
        &nf[from..to]
    };
    let (_, left_epoch_start, left_epoch_next, _) = *left.data();
    let (_, right_epoch_start, right_epoch_next, _) = *right.data();
    let left_el = elapsed_slice(left_epoch_start, left_epoch_next);
    let right_el = elapsed_slice(right_epoch_start, right_epoch_next);
    assert_eq!(u32::from(right_epoch_start), u32::from(left_epoch_next));
    let witness = witness::unspent_fuse((*left.data(), *right.data()), left_el, right_el);
    let (fused, ()) = app
        .fuse(rng, pool::UnspentFuse, witness, left, right)
        .unwrap();
    fused
}
