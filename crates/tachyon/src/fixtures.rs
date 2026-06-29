#![allow(unreachable_pub, reason = "test code")]
#![allow(clippy::as_conversions, reason = "test code")]
#![allow(clippy::cast_possible_truncation, reason = "test code")]
#![allow(clippy::type_complexity, reason = "test code")]
#![allow(clippy::partial_pub_fields, reason = "test code")]
#![allow(clippy::too_many_lines, reason = "test code")]
#![allow(clippy::too_many_arguments, reason = "test code")]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::{array, cell::RefCell, iter, ops::RangeInclusive};

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Pcd, Polynomial};
use rand_core::{CryptoRng, RngCore};

use crate::{
    EpochIndex, EpochOffset,
    action::{self, Action},
    bundle::{self, Bundle},
    constants::{EPOCH_SIZE, NF_EMITTERS},
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{ExpandedKey, NoteMasterKey, ProofAuthorizingKey, private},
    note::{self, Note, Nullifier, NullifierTrapdoor},
    primitives::{
        ActionDigest, Anchor, BlockHeight, NfEmitterPoly, NfSeqPoly, Tachygram, TachygramSetCommit,
        TachygramSetPoly, effect,
    },
    relations::quotient::LIFT_SPLITS,
    stamp::{
        Stamp,
        proof::{PROOF_SYSTEM, delegation, pool, spendable},
    },
    value, witness,
};

pub fn mock_sighash(bundle_digest: [u8; 64]) -> [u8; 32] {
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

pub fn action_digests(actions: &[Action]) -> Vec<ActionDigest> {
    actions
        .iter()
        .map(|action| action.digest().expect("valid action"))
        .collect()
}

pub fn random_action(rng: &mut (impl RngCore + CryptoRng)) -> Action {
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(rng, 400);
    let (_, _, plan) = build_output_plan(rng, note);
    let bundle_plan = bundle::Plan::new(alloc::vec![], alloc::vec![plan]);
    let sighash = mock_sighash(bundle_plan.commitment().expect("fixture commitment"));
    let unproven = bundle_plan
        .sign(&sighash, &ask, rng)
        .expect("sign foreign output");
    unproven.actions[0]
}

pub fn spend_witness(
    rng: &mut (impl RngCore + CryptoRng),
    note: &Note,
) -> (
    value::CommitmentTrapdoor,
    ActionEntropy,
    ActionRandomizer<effect::Spend>,
) {
    let rcv = value::CommitmentTrapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let alpha = theta.randomizer::<effect::Spend>(note.commitment());
    (rcv, theta, alpha)
}

pub fn build_output_plan(
    rng: &mut (impl RngCore + CryptoRng),
    note: Note,
) -> (
    value::CommitmentTrapdoor,
    ActionRandomizer<effect::Output>,
    action::Plan<effect::Output>,
) {
    let rcv = value::CommitmentTrapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let plan = action::Plan::output(note, theta, rcv);
    let alpha = theta.randomizer::<effect::Output>(note.commitment());
    (rcv, alpha, plan)
}

pub fn build_output_stamp(
    rng: &mut (impl RngCore + CryptoRng),
    anchor: Anchor,
    note: Note,
) -> (Stamp, action::Plan<effect::Output>) {
    let (rcv, alpha, plan) = build_output_plan(rng, note);
    let stamp = Stamp::prove_output(rng, rcv, alpha, note, anchor).expect("prove_output");
    (stamp, plan)
}

pub fn build_autonome(
    rng: &mut (impl RngCore + CryptoRng),
    wallet: &WalletSim,
    spend_value: u64,
    output_value: u64,
) -> Bundle<Stamp> {
    let spend_note = wallet.random_note(rng, spend_value);
    let output_note = wallet.random_note(rng, output_value);
    let mut pool = PoolSim::genesis(rng);
    let stamps_cms = vec![vec![spend_note.commitment()]];
    pool.mine(random_block_with(rng, &stamps_cms, 50));
    let height = pool.height();
    let spendable_pcd = wallet.fresh_spend(rng, &pool, height, &spend_note);
    let spend_epoch = height.epoch();
    let anchor = spendable_pcd.data().2;
    wallet.autonome(
        rng,
        anchor,
        alloc::vec![(spend_note, spendable_pcd, spend_epoch)],
        alloc::vec![output_note],
    )
}

pub fn random_block(
    rng: &mut (impl RngCore + CryptoRng),
    stamp_size: usize,
    n_stamps: usize,
) -> Vec<Vec<Tachygram>> {
    iter::repeat_with(|| {
        iter::repeat_with(|| Tachygram::from(Fp::random(&mut *rng)))
            .take(stamp_size)
            .collect()
    })
    .take(n_stamps)
    .collect()
}

pub fn random_block_with(
    rng: &mut (impl RngCore + CryptoRng),
    stamps_cms: &[Vec<note::Commitment>],
    n_stamps: usize,
) -> Vec<Vec<Tachygram>> {
    assert!(
        n_stamps >= stamps_cms.len(),
        "n_stamps must accommodate every stamp in stamps_cms"
    );
    let mut stamps: Vec<Vec<Tachygram>> = stamps_cms
        .iter()
        .map(|cms| cms.iter().map(|&cm| Tachygram::from(cm)).collect())
        .collect();
    stamps.extend(
        iter::repeat_with(|| alloc::vec![Tachygram::from(Fp::random(&mut *rng))])
            .take(n_stamps - stamps_cms.len()),
    );
    stamps
}

#[derive(Clone, Debug)]
struct PoolSimBlock {
    prev: Anchor,
    stamps: Vec<Vec<Tachygram>>,
}

impl PoolSimBlock {
    /// Per-stamp tachygram-set commitments, in stamp order.
    fn commits(&self) -> Vec<TachygramSetCommit> {
        self.stamps
            .iter()
            .map(|tgs| tgs.iter().copied().collect::<TachygramSetPoly>().commit())
            .collect()
    }

    /// The block's post anchors: one per stamp (folding `next_stamp` from
    /// `prev`), or a single `next_empty` tick for an empty block.
    fn anchors(&self) -> Vec<Anchor> {
        if self.stamps.is_empty() {
            return alloc::vec![self.prev.next_empty()];
        }
        self.commits().iter().fold(Vec::new(), |mut acc, commit| {
            let last = acc.last().unwrap_or(&self.prev);
            acc.push(last.next_stamp(commit));
            acc
        })
    }
}

pub struct PoolSim {
    history: Vec<PoolSimBlock>,
}

impl PoolSim {
    #[must_use]
    pub fn genesis(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::genesis_with(random_block(rng, 1, 50))
    }

    pub fn genesis_with(stamps: Vec<Vec<Tachygram>>) -> Self {
        Self {
            history: alloc::vec![PoolSimBlock {
                prev: Anchor::default(),
                stamps
            }],
        }
    }

    #[must_use]
    pub fn height(&self) -> BlockHeight {
        BlockHeight::from(self.history.len() - 1)
    }

    #[must_use]
    pub fn anchor(&self) -> Anchor {
        self.anchor_at(self.height())
    }

    #[must_use]
    pub fn tachygrams_at(&self, height: BlockHeight) -> Vec<Vec<Tachygram>> {
        self.history
            .get(usize::try_from(height).expect("fits usize"))
            .expect("query height should exist")
            .stamps
            .clone()
    }

    #[must_use]
    pub fn stamp_commits_at(&self, height: BlockHeight) -> Vec<TachygramSetCommit> {
        self.tachygrams_at(height)
            .iter()
            .map(|tgs| tgs.iter().copied().collect::<TachygramSetPoly>().commit())
            .collect()
    }

    #[must_use]
    pub fn prev_anchor_at(&self, height: BlockHeight) -> Anchor {
        self.history
            .get(usize::try_from(height).expect("fits usize"))
            .expect("query height should exist")
            .prev
    }

    #[must_use]
    pub fn anchor_at(&self, height: BlockHeight) -> Anchor {
        let prev = self.prev_anchor_at(height);
        let commits = self.stamp_commits_at(height);
        if commits.is_empty() {
            prev.next_empty()
        } else {
            commits.iter().fold(prev, Anchor::next_stamp)
        }
    }

    /// The prior-epoch terminal anchor that folds into `epoch`'s boundary
    /// `B_epoch = pre_epoch_anchor(epoch).next_epoch(epoch)`. This is the
    /// single owner of the genesis convention: `Fp::ZERO` for the genesis
    /// epoch (matching [`Anchor::default`]'s `ZERO.next_epoch(0)`),
    /// otherwise the terminal anchor of the previous epoch's final block.
    #[must_use]
    pub fn pre_epoch_anchor(&self, epoch: EpochIndex) -> Anchor {
        epoch_first_of(epoch)
            .prev()
            .map_or_else(|| Anchor::from(Fp::ZERO), |height| self.anchor_at(height))
    }

    /// The block that produced `anchor` (matched by its post anchors). An
    /// epoch-boundary anchor `B_E = old_tip.next_epoch(E)` is no block's post
    /// anchor (it is `E`'s first block's entry), so it returns
    /// `Err((pre_boundary_anchor, E))`; `Anchor::default()` is the epoch-0
    /// boundary.
    fn locate_anchor(&self, anchor: Anchor) -> Result<(BlockHeight, PoolSimBlock), (Anchor, EpochIndex)> {
        if anchor == Anchor::default() {
            return Err((self.pre_epoch_anchor(EpochIndex(0)), EpochIndex(0)));
        }
        for (height_idx, block) in self.history.iter().enumerate() {
            let height = BlockHeight::from(height_idx);
            if block.anchors().contains(&anchor) {
                return Ok((height, block.clone()));
            }
            if height.is_epoch_first() && block.prev == anchor {
                let epoch = height.epoch();
                return Err((self.pre_epoch_anchor(epoch), epoch));
            }
        }
        unreachable!("anchor not found: {anchor:?}");
    }

    /// Walk the blocks an anchor span covers, head/tail-trimmed for mid-block
    /// endpoints. `Ok((height, stamps))` is a covered block's (trimmed) stamps;
    /// `Err(epoch)` marks each epoch boundary crossed. Either endpoint may sit
    /// mid-block.
    fn anchor_steps(
        &self,
        start: Anchor,
        end: Anchor,
    ) -> Vec<Result<(BlockHeight, Vec<Vec<Tachygram>>), EpochIndex>> {
        let mut steps: Vec<Result<(BlockHeight, Vec<Vec<Tachygram>>), EpochIndex>> = Vec::new();
        let (start_height, from) = match self.locate_anchor(start) {
            Ok((height, block)) => {
                let position = block
                    .anchors()
                    .iter()
                    .position(|&post| post == start)
                    .expect("located by its own anchors");
                (height, (position + 1).min(block.stamps.len()))
            },
            Err((_pre_boundary, epoch)) => {
                steps.push(Err(epoch));
                (epoch_first_of(epoch), 0)
            },
        };

        let (end_height, end_block) = self.locate_anchor(end).expect("end anchor must exist");
        let to = end_block
            .anchors()
            .iter()
            .position(|&post| post == end)
            .map_or(0, |position| position + 1)
            .min(end_block.stamps.len());

        for height_idx in start_height.0..=end_height.0 {
            let height = BlockHeight(height_idx);
            let block = &self.history[usize::try_from(height_idx).expect("fits usize")];
            if height_idx != start_height.0 && height.is_epoch_first() {
                steps.push(Err(height.epoch()));
            }
            let lo = if height_idx == start_height.0 { from } else { 0 };
            let hi = if height_idx == end_height.0 {
                to
            } else {
                block.stamps.len()
            };
            let stamps = block.stamps[lo..hi].to_vec();
            // Skip a head-trimmed first block emptied by a mid-block `start`, but
            // keep a genuinely empty block (it still advanced the anchor).
            if height_idx == start_height.0 && stamps.is_empty() && !block.stamps.is_empty() {
                continue;
            }
            steps.push(Ok((height, stamps)));
        }

        steps
    }

    pub fn advance(
        &mut self,
        count: usize,
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
        // Epoch-first blocks are preceded by a boundary anchor lift;
        // intra-epoch blocks advance directly from the previous tip.
        let prev = if new_height.is_epoch_first() {
            old_tip.next_epoch(new_height.epoch())
        } else {
            old_tip
        };
        self.history.push(PoolSimBlock { prev, stamps });
    }
}

/// Build an [`AnchorChain`] covering blocks `range`, rooted at the block-start
/// anchor of `*range.start()`. When `last_block_upto` is `Some(n)` the final
/// block absorbs only its first `n` stamps (stopping the chain right after the
/// cm-stamp); `None` absorbs every block in full.
///
/// Per non-empty block: one [`AnchorSeed`] per absorbed stamp, fused via
/// [`AnchorFuse`]. Per empty block: one [`EmptyBlockSeed`]. All segments fused
/// linearly.
fn build_anchor_chain_inner(
    rng: &mut (impl RngCore + CryptoRng),
    pool: &PoolSim,
    range: RangeInclusive<BlockHeight>,
    last_block_upto: Option<usize>,
) -> Pcd<pool::AnchorChain> {
    let start = *range.start();
    let end = *range.end();
    assert_eq!(start.epoch(), end.epoch(), "AnchorChain single-epoch range");
    assert!(start <= end);

    let mut state = pool.prev_anchor_at(start);
    let mut chain: Option<Pcd<pool::AnchorChain>> = None;
    let mut height = start;
    loop {
        let commits = pool.stamp_commits_at(height);
        if commits.is_empty() {
            let next_state = state.next_empty();
            let (seed, ()) = PROOF_SYSTEM
                .seed(rng, pool::EmptyBlockSeed, (state,))
                .expect("EmptyBlockSeed");
            chain = Some(match chain.take() {
                None => seed,
                Some(left) => {
                    let (fused, ()) = PROOF_SYSTEM
                        .fuse(rng, pool::AnchorFuse, (), left, seed)
                        .expect("AnchorFuse");
                    fused
                },
            });
            state = next_state;
        } else {
            // The final block may be truncated (cm-block prefix); others absorb all.
            let upto = if height == end {
                last_block_upto.unwrap_or(commits.len())
            } else {
                commits.len()
            };
            for commit in &commits[..upto] {
                let next_state = state.next_stamp(commit);
                let (seed, ()) = PROOF_SYSTEM
                    .seed(rng, pool::AnchorSeed, (state, *commit))
                    .expect("AnchorSeed");
                chain = Some(match chain.take() {
                    None => seed,
                    Some(left) => {
                        let (fused, ()) = PROOF_SYSTEM
                            .fuse(rng, pool::AnchorFuse, (), left, seed)
                            .expect("AnchorFuse");
                        fused
                    },
                });
                state = next_state;
            }
        }
        if height >= end {
            break;
        }
        height = height.next().expect("height < max");
    }

    chain.expect("AnchorChain range must cover at least one block")
}

/// Build an [`AnchorChain`] covering blocks `range` in full, rooted at the
/// block-start anchor of `*range.start()`.
pub(crate) fn build_anchor_chain_pcd(
    rng: &mut (impl RngCore + CryptoRng),
    pool: &PoolSim,
    range: RangeInclusive<BlockHeight>,
) -> Pcd<pool::AnchorChain> {
    build_anchor_chain_inner(rng, pool, range, None)
}

/// Build the boundary->cm segment [`spendable::SpendableInit`] consumes to pin
/// a spendable's starting epoch: an [`AnchorChain`](pool::AnchorChain) rooted
/// at the epoch boundary `B_E = prev_anchor_at(epoch_first)` and ending at
/// `post_cm_anchor`, covering blocks `epoch_first..=cm_height` with the final
/// (cm) block truncated to its stamps `[0..=cm_idx]` so the cm-stamp is the
/// chain's last absorbed link. A note created first-in-epoch (`epoch_first ==
/// cm_height`, `cm_idx == 0`) produces a single-link chain.
pub(crate) fn build_anchor_chain_prefix_pcd(
    rng: &mut (impl RngCore + CryptoRng),
    pool: &PoolSim,
    epoch_first: BlockHeight,
    cm_height: BlockHeight,
    cm_idx: usize,
) -> Pcd<pool::AnchorChain> {
    assert_eq!(
        epoch_first.epoch(),
        cm_height.epoch(),
        "prefix chain is single-epoch"
    );
    assert!(epoch_first <= cm_height);
    // The cm-block must be non-empty and `cm_idx` in range; otherwise the
    // truncation is silently dropped and the chain would not end at the
    // cm-stamp (surfacing only later as SpendableInit's "cm-stamp is not the
    // chain's final link").
    let cm_commits = pool.stamp_commits_at(cm_height);
    assert!(
        !cm_commits.is_empty(),
        "cm-block at {cm_height:?} has no stamps; cm_idx is meaningless"
    );
    assert!(
        cm_idx < cm_commits.len(),
        "cm_idx {cm_idx} out of range for {}-stamp cm-block",
        cm_commits.len()
    );
    build_anchor_chain_inner(rng, pool, epoch_first..=cm_height, Some(cm_idx + 1))
}

/// The honest [`spendable::SpendableInit`] inputs for `cm` at `height`,
/// reconstructed from pool state: the witness `(pre_epoch_anchor,
/// pre_cm_anchor, stamp_tg_set)` plus the boundary-rooted
/// [`AnchorChain`](pool::AnchorChain) for the left input. Shared by
/// [`WalletSim::spendable_init`] (which `.expect`s the fuse) and tests that
/// drive a raw fuse to capture the `Err`.
pub(crate) fn spendable_init_inputs(
    rng: &mut (impl RngCore + CryptoRng),
    pool: &PoolSim,
    cm: note::Commitment,
    height: BlockHeight,
) -> (Anchor, Anchor, TachygramSetPoly, Pcd<pool::AnchorChain>) {
    let stamps = pool.tachygrams_at(height);
    let stamp_commits = pool.stamp_commits_at(height);
    let cm_idx = stamps
        .iter()
        .position(|tgs| tgs.contains(&cm.into()))
        .expect("cm not found in any stamp at the cm-block");

    // Anchor immediately before the cm-stamp (the cm-block prefix fold).
    let pre_cm_anchor = stamp_commits[..cm_idx]
        .iter()
        .fold(pool.prev_anchor_at(height), Anchor::next_stamp);

    // Root the lineage at the epoch boundary `B_E = pre_epoch_anchor.next_epoch(E)
    // == prev_anchor_at(epoch_first)`; the boundary->cm chain ends at
    // post_cm_anchor.
    let epoch = height.epoch();
    let pre_epoch_anchor = pool.pre_epoch_anchor(epoch);
    let chain = build_anchor_chain_prefix_pcd(rng, pool, epoch_first_of(epoch), height, cm_idx);
    let stamp_tg_set = stamps[cm_idx].iter().copied().collect::<TachygramSetPoly>();

    (pre_epoch_anchor, pre_cm_anchor, stamp_tg_set, chain)
}

pub(crate) fn build_unspent_seed_pcd(
    rng: &mut (impl RngCore + CryptoRng),
    start: Anchor,
    epoch: EpochIndex,
    tgs: &[Tachygram],
    nf: Nullifier,
) -> Pcd<pool::Unspent> {
    let (pcd, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::UnspentSeed,
            witness::unspent_seed(((), ()), start, epoch, tgs, nf),
        )
        .expect("UnspentSeed");
    pcd
}

/// Block-range wrapper over [`build_unspent_pcd_between_anchors`]: spans the
/// block-entry anchor of `range.start()` to the block anchor of `range.end()`.
/// `nf` holds one nullifier per epoch the range spans (`nf[0]` for
/// `range.start().epoch()`).
pub(crate) fn build_unspent_pcd_between_blocks(
    rng: &mut (impl RngCore + CryptoRng),
    pool: &PoolSim,
    nf: &[Nullifier],
    range: RangeInclusive<BlockHeight>,
) -> Pcd<pool::Unspent> {
    build_unspent_pcd_between_anchors(
        rng,
        pool,
        nf,
        (
            pool.prev_anchor_at(*range.start()),
            pool.anchor_at(*range.end()),
        ),
    )
}

/// Build an [`Unspent`] for the anchor span `(start_anchor, end_anchor)`,
/// covering every stamp / empty block that advances the anchor between them;
/// either endpoint may sit mid-block. `nf` holds one nullifier per epoch
/// spanned, `nf[0]` for `start_anchor`'s epoch. Seeds one leaf per stamp /
/// empty block and merges them as a balanced tree: [`UnspentFuse`] within an
/// epoch, [`UnspentEpochFuse`] across a boundary.
pub(crate) fn build_unspent_pcd_between_anchors(
    rng: &mut (impl RngCore + CryptoRng),
    pool: &PoolSim,
    nf: &[Nullifier],
    (start_anchor, end_anchor): (Anchor, Anchor),
) -> Pcd<pool::Unspent> {
    // The merge derives epoch and fuse kind from block heights, so the boundary
    // markers are dropped; only `Ok` blocks seed leaves. The first block runs
    // from `start_anchor` (possibly mid-block), the rest from their entry anchor.
    let steps: Vec<(BlockHeight, Vec<Vec<Tachygram>>)> = pool
        .anchor_steps(start_anchor, end_anchor)
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    let base = steps
        .first()
        .expect("anchor span covers at least one block")
        .0
        .epoch();
    let nf_at = |epoch: EpochIndex| -> Nullifier {
        nf[usize::try_from(epoch.0 - base.0).expect("epoch within span")]
    };
    let mut leaves: Vec<(Pcd<pool::Unspent>, EpochIndex)> = Vec::with_capacity(steps.len());
    for (index, (height, block_stamps)) in steps.into_iter().enumerate() {
        let epoch = height.epoch();
        let leaf_nf = nf_at(epoch);
        let mut entry = if index == 0 {
            start_anchor
        } else {
            pool.prev_anchor_at(height)
        };
        if block_stamps.is_empty() {
            let (seed, ()) = PROOF_SYSTEM
                .seed(rng, pool::EmptyBlockUnspentSeed, (entry, (epoch, leaf_nf)))
                .expect("EmptyBlockUnspentSeed");
            leaves.push((seed, epoch));
        } else {
            for tgs in block_stamps {
                let commit = tgs.iter().copied().collect::<TachygramSetPoly>().commit();
                leaves.push((build_unspent_seed_pcd(rng, entry, epoch, &tgs, leaf_nf), epoch));
                entry = entry.next_stamp(&commit);
            }
        }
    }

    // Balanced bottom-up merge. Each item tracks the inclusive epoch range
    // `[lo..=hi]` its chain covers, so its `elapsed` is `nf[lo..hi]` (one per
    // crossed boundary). Adjacent chains merge as a mid-epoch concat when they
    // share an epoch (`rlo == lhi`) and a boundary splice when consecutive.
    let elapsed_slice = |lo: EpochIndex, hi: EpochIndex| -> &[Nullifier] {
        let from = usize::try_from(lo.0 - base.0).expect("epoch within span");
        let to = usize::try_from(hi.0 - base.0).expect("epoch within span");
        &nf[from..to]
    };
    let mut level: Vec<(Pcd<pool::Unspent>, EpochIndex, EpochIndex)> = leaves
        .into_iter()
        .map(|(pcd, epoch)| (pcd, epoch, epoch))
        .collect();
    assert!(!level.is_empty(), "anchor span covers at least one leaf");
    while level.len() > 1 {
        let mut next: Vec<(Pcd<pool::Unspent>, EpochIndex, EpochIndex)> = Vec::new();
        let mut pairs = level.into_iter();
        while let Some((left, llo, lhi)) = pairs.next() {
            match pairs.next() {
                None => next.push((left, llo, lhi)),
                Some((right, rlo, rhi)) => {
                    let left_el = elapsed_slice(llo, lhi);
                    let right_el = elapsed_slice(rlo, rhi);
                    let fused = if rlo.0 == lhi.0 {
                        let witness =
                            witness::unspent_fuse((*left.data(), *right.data()), left_el, right_el);
                        let (fused, ()) = PROOF_SYSTEM
                            .fuse(rng, pool::UnspentFuse, witness, left, right)
                            .expect("UnspentFuse mid-epoch");
                        fused
                    } else {
                        debug_assert_eq!(rlo.0, lhi.0 + 1, "merged chains must be contiguous");
                        let witness = witness::unspent_epoch_fuse(
                            (*left.data(), *right.data()),
                            left_el,
                            right_el,
                        );
                        let (fused, ()) = PROOF_SYSTEM
                            .fuse(rng, pool::UnspentEpochFuse, witness, left, right)
                            .expect("UnspentEpochFuse boundary");
                        fused
                    };
                    next.push((fused, llo, rhi));
                },
            }
        }
        level = next;
    }
    level
        .into_iter()
        .next()
        .expect("non-empty level yields the merged chain")
        .0
}

/// A note's certified derivation, memoized so the (expensive) certify proof is
/// produced once per `(cm, creation_epoch)` and reused across `spendable_init`
/// and the spend.
struct CachedDerivation {
    cm: note::Commitment,
    creation_epoch: EpochIndex,
    pcd: Pcd<delegation::NullifierDerivation>,
    polys: [NfEmitterPoly; NF_EMITTERS],
    keyset: ExpandedKey,
}

pub struct WalletSim {
    pub sk: private::SpendingKey,
    pub pak: ProofAuthorizingKey,
    derivations: RefCell<Vec<CachedDerivation>>,
}

impl WalletSim {
    pub fn new(sk: private::SpendingKey) -> Self {
        Self {
            sk,
            pak: sk.derive_proof_private(),
            derivations: RefCell::new(Vec::new()),
        }
    }

    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::new(private::SpendingKey::random(rng))
    }

    pub fn random_note(&self, rng: &mut (impl RngCore + CryptoRng), value_amount: u64) -> Note {
        Note {
            pk: self.sk.derive_payment_key(),
            value: note::Value::try_from(value_amount).expect("fixture value in range"),
            psi: NullifierTrapdoor::random(rng),
            rcm: note::CommitmentTrapdoor::random(rng),
        }
    }

    /// The note's `MK_LENGTH`-part master key, one part per index.
    #[must_use]
    pub fn master_key(&self, note: &Note) -> NoteMasterKey {
        NoteMasterKey(array::from_fn(|index| {
            self.pak.nk.derive_note_private(&note.psi, index as u64)
        }))
    }

    /// The new-scheme nullifier at epoch offset `d` from the note's creation:
    /// `nf_d = Σ_j ρ_j^d·T_j(c·γ^d)`, the query the spend circuit reproduces.
    #[must_use]
    pub fn query_nf(&self, note: &Note, offset: EpochOffset) -> Nullifier {
        let mk = self.master_key(note);
        let keyset = mk.derive_expanded();
        keyset.derive_nullifier(&mk, offset)
    }

    /// Seed one half of the note's master key (the three parts at `part_idx`),
    /// proving they are the note's master secrets.
    pub fn note_master_half(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
        part_idx: [u64; 3],
    ) -> Pcd<delegation::NfMasterHeader> {
        let (pcd, ()) = PROOF_SYSTEM
            .seed(rng, delegation::NfMasterSeed, (note, self.pak, part_idx))
            .expect("note seed");
        pcd
    }

    /// Certify a note's `N`-polynomial derivation: prove the key expansion
    /// ([`NfMasterExpand`](delegation::NfMasterExpand)) by fusing the two
    /// complementary master-key seeds, then certify the derivation polynomials
    /// against the committed keyset
    /// ([`NullifierDerivationStep`](delegation::NullifierDerivationStep)).
    pub fn derivation_pcd(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
        creation_epoch: EpochIndex,
    ) -> Pcd<delegation::NullifierDerivation> {
        let mk = self.master_key(&note);

        // Even half (cipher window 0..EK_HALF) and odd half
        // (EK_HALF..2·EK_HALF), each certified by one NfMasterExpand fusing the
        // two complementary master-key seeds (parts 0,1,2 and 3,4,5).
        let even_left = self.note_master_half(rng, note, [0, 1, 2]);
        let even_right = self.note_master_half(rng, note, [3, 4, 5]);
        let (even_spectrum, even_keys) = mk.derive_expanded_trace(0);
        let key_a = ExpandedKey::half_key_poly(&even_keys);
        let (keyset_even_pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                delegation::NfMasterExpand,
                witness::nf_master_expand(
                    (*even_left.data(), *even_right.data()),
                    &mk,
                    &even_spectrum,
                    &even_keys,
                    0,
                ),
                even_left,
                even_right,
            )
            .expect("NfMasterExpand even");

        let odd_left = self.note_master_half(rng, note, [0, 1, 2]);
        let odd_right = self.note_master_half(rng, note, [3, 4, 5]);
        let (odd_spectrum, odd_keys) = mk.derive_expanded_trace(1);
        let key_b = ExpandedKey::half_key_poly(&odd_keys);
        let (keyset_odd_pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                delegation::NfMasterExpand,
                witness::nf_master_expand(
                    (*odd_left.data(), *odd_right.data()),
                    &mk,
                    &odd_spectrum,
                    &odd_keys,
                    1,
                ),
                odd_left,
                odd_right,
            )
            .expect("NfMasterExpand odd");

        // Assemble the interleaved 256-key schedule and certify the derivation
        // polynomials against both halves.
        let keyset = ExpandedKey::from_halves(&even_keys, &odd_keys);
        let polys = keyset.derivation_polys(&mk.query_salts());
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                delegation::NullifierDerivationStep,
                witness::nullifier_derivation(
                    (*keyset_even_pcd.data(), *keyset_odd_pcd.data()),
                    &keyset,
                    key_a,
                    key_b,
                    &mk,
                    &polys,
                    creation_epoch,
                ),
                keyset_even_pcd,
                keyset_odd_pcd,
            )
            .expect("NullifierDerivationStep");
        pcd
    }

    /// The note's certified derivation, its `N` polynomials, and its keyset,
    /// memoized per `(cm, creation_epoch)`. The first call proves
    /// [`NullifierDerivationStep`](delegation::NullifierDerivationStep) (the
    /// expensive certify); later calls for the same note return the cached PCD.
    pub fn derivation(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: &Note,
        creation_epoch: EpochIndex,
    ) -> (
        Pcd<delegation::NullifierDerivation>,
        [NfEmitterPoly; NF_EMITTERS],
        ExpandedKey,
    ) {
        let cm = note.commitment();
        {
            let cache = self.derivations.borrow();
            if let Some(entry) = cache
                .iter()
                .find(|entry| entry.cm == cm && entry.creation_epoch == creation_epoch)
            {
                return (entry.pcd.clone(), entry.polys.clone(), entry.keyset);
            }
        }

        let mk = self.master_key(note);
        let keyset = mk.derive_expanded();
        let polys = keyset.derivation_polys(&mk.query_salts());
        let pcd = self.derivation_pcd(rng, *note, creation_epoch);
        self.derivations.borrow_mut().push(CachedDerivation {
            cm,
            creation_epoch,
            pcd: pcd.clone(),
            polys: polys.clone(),
            keyset,
        });
        (pcd, polys, keyset)
    }

    pub fn spendable_init(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: &Note,
        pool: &PoolSim,
        init_height: BlockHeight,
    ) -> Pcd<spendable::SpendableHeader> {
        let cm = note.commitment();
        let epoch = init_height.epoch();
        let (pre_epoch_anchor, pre_cm_anchor, creation_set, chain) =
            spendable_init_inputs(rng, pool, cm, init_height);
        // The creation epoch E_0 is this init height's epoch; SpendableInit pins
        // it to the creation anchor and computes present_nf = nf_0 in-circuit.
        let (derivation, polys, _keyset) = self.derivation(rng, note, epoch);

        let (spendable, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spendable::SpendableInit,
                witness::spendable_init(
                    (*chain.data(), *derivation.data()),
                    &polys,
                    pre_epoch_anchor,
                    pre_cm_anchor,
                    creation_set,
                ),
                chain,
                derivation,
            )
            .expect("SpendableInit");
        spendable
    }

    pub fn fresh_spend(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        pool: &PoolSim,
        height: BlockHeight,
        spend_note: &Note,
    ) -> Pcd<spendable::SpendableHeader> {
        self.spendable_init(rng, spend_note, pool, height)
    }

    /// Bind a sync [`Unspent`](pool::Unspent) to the note's genuine derivation
    /// nullifiers via the homomorphic lift. The tested values are the query
    /// nullifiers `query_nf` at offsets `[start − E_0, present − E_0]`; the
    /// lift witnesses (per-poly weights `w_j`, accumulator `A`, quotients)
    /// are built for the challenge `β` over the certified digest and the
    /// tested poly `q`. Build the honest
    /// [`VerifyUnspent`](pool::VerifyUnspent) witness and the derivation
    /// PCD for the tested range `[start, present]`. Split out so the
    /// negative tests can fuse the honest witness against a tampered
    /// [`Unspent`](pool::Unspent), or tamper one witness field.
    pub fn verify_unspent_witness(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        unspent: &Pcd<pool::Unspent>,
        note: &Note,
        creation_epoch: EpochIndex,
        start_epoch: EpochIndex,
        present_epoch: EpochIndex,
    ) -> (
        (
            NfSeqPoly,
            NfSeqPoly,
            NfSeqPoly,
            [NfEmitterPoly; NF_EMITTERS],
            [[Polynomial; LIFT_SPLITS]; NF_EMITTERS],
            [Polynomial; LIFT_SPLITS],
            [Polynomial; NF_EMITTERS],
            Polynomial,
        ),
        Pcd<delegation::NullifierDerivation>,
    ) {
        let (derivation, polys, keyset) = self.derivation(rng, note, creation_epoch);
        let mk = self.master_key(note);

        // Tested values q over [start, present]: query nullifiers at offsets E_0,
        // reusing the expanded keyset for every offset (one FFT, N queries).
        let nfs: Vec<Nullifier> = (start_epoch.0..=present_epoch.0)
            .map(|epoch| {
                keyset.derive_nullifier(&mk, EpochIndex(epoch).offset_from(creation_epoch))
            })
            .collect();

        (
            witness::verify_unspent(
                (*unspent.data(), *derivation.data()),
                &polys,
                &mk,
                &nfs,
                start_epoch,
                present_epoch,
            ),
            derivation,
        )
    }

    pub fn verify_unspent(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        unspent: Pcd<pool::Unspent>,
        note: &Note,
        creation_epoch: EpochIndex,
        start_epoch: EpochIndex,
        present_epoch: EpochIndex,
    ) -> Pcd<pool::VerifiedUnspent> {
        let (witness, derivation) = self.verify_unspent_witness(
            rng,
            &unspent,
            note,
            creation_epoch,
            start_epoch,
            present_epoch,
        );
        let (verified, ()) = PROOF_SYSTEM
            .fuse(rng, pool::VerifyUnspent, witness, unspent, derivation)
            .expect("VerifyUnspent");
        verified
    }

    pub fn lift(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        spendable: Pcd<spendable::SpendableHeader>,
        unspent: Pcd<pool::Unspent>,
        note: &Note,
        start_epoch: EpochIndex,
        present_epoch: EpochIndex,
    ) -> Pcd<spendable::SpendableHeader> {
        // The lift's offset origin E_0 is the lineage's consensus-bound creation
        // epoch, carried on the spendable header; SpendableLift reconciles it.
        let creation_epoch = spendable.data().3;
        let verified = self.verify_unspent(
            rng,
            unspent,
            note,
            creation_epoch,
            start_epoch,
            present_epoch,
        );
        let (lifted, ()) = PROOF_SYSTEM
            .fuse(rng, spendable::SpendableLift, (), spendable, verified)
            .expect("SpendableLift");
        lifted
    }

    pub fn lift_over_creation_epoch(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        pool: &PoolSim,
        note: &Note,
        cm_height: BlockHeight,
        spendable: Pcd<spendable::SpendableHeader>,
    ) -> Pcd<spendable::SpendableHeader> {
        let start_anchor = spendable.data().2;
        let creation_epoch = cm_height.epoch();
        let end_height = BlockHeight(epoch_final_of(creation_epoch).0 + 1);
        let unspent = build_unspent_pcd_between_anchors(
            rng,
            pool,
            &[
                self.query_nf(note, EpochOffset(0)),
                self.query_nf(note, EpochOffset(1)),
            ],
            (start_anchor, pool.anchor_at(end_height)),
        );
        self.lift(
            rng,
            spendable,
            unspent,
            note,
            creation_epoch,
            creation_epoch.next(),
        )
    }

    pub fn autonome(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        anchor: Anchor,
        spends: Vec<(Note, Pcd<spendable::SpendableHeader>, EpochIndex)>,
        output_notes: Vec<Note>,
    ) -> Bundle<Stamp> {
        let ask = self.sk.derive_auth_private();

        let mut spend_plans = Vec::with_capacity(spends.len());
        let mut spend_pcds = Vec::with_capacity(spends.len());
        for (note, spendable_pcd, spend_epoch) in spends {
            // The spend offset is measured from the lineage's true creation epoch
            // E_0, threaded on the spendable header (field .3) and pinned to
            // consensus at SpendableInit. A spendable lifted to `spend_epoch`
            // carries present_nf = nf_{spend_epoch − E_0}, so the spend reproduces
            // that present-epoch nullifier and its successor at the same offset.
            let creation_epoch = spendable_pcd.data().3;
            let offset = spend_epoch.offset_from(creation_epoch);
            let (derivation_pcd, polys, keyset) = self.derivation(rng, &note, creation_epoch);
            let mk = self.master_key(&note);
            let pair = [
                keyset.derive_nullifier(&mk, offset),
                keyset.derive_nullifier(&mk, offset.next()),
            ];
            let rcv = value::CommitmentTrapdoor::random(rng);
            let theta = ActionEntropy::random(rng);
            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                self.pak.ak.derive_action_public(&alpha)
            });
            spend_plans.push(plan);
            spend_pcds.push((derivation_pcd, polys, pair, spendable_pcd));
        }

        let output_plans: Vec<action::Plan<effect::Output>> = output_notes
            .into_iter()
            .map(|note| {
                let rcv = value::CommitmentTrapdoor::random(rng);
                let theta = ActionEntropy::random(rng);
                action::Plan::output(note, theta, rcv)
            })
            .collect();

        let bundle_plan = bundle::Plan::new(spend_plans, output_plans);
        let sighash = mock_sighash(bundle_plan.commitment().expect("fixture commitment"));
        let unproven = bundle_plan
            .sign(&sighash, &ask, rng)
            .expect("sign autonome");

        let stamp_plan = bundle_plan.stamp_plan(anchor);
        let stamp = stamp_plan
            .prove(rng, &self.pak, spend_pcds)
            .expect("prove autonome stamp");

        unproven.stamp(stamp)
    }
}

pub struct SyncSim {
    entries: Vec<SyncEntry>,
}

struct SyncEntry {
    handle: usize,
    nfs: Vec<Nullifier>,
    consumed: u32,
    next_height: BlockHeight,
    cursor_anchor: Anchor,
}

impl SyncSim {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn accept_delegation(
        &mut self,
        handle: usize,
        nfs: Vec<Nullifier>,
        cm_height: BlockHeight,
        start_anchor: Anchor,
    ) {
        let entry = SyncEntry {
            handle,
            nfs,
            consumed: 0,
            next_height: cm_height,
            cursor_anchor: start_anchor,
        };
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|stored| stored.handle == handle)
        {
            *slot = entry;
        } else {
            self.entries.push(entry);
        }
    }

    pub fn consumed(&self, handle: usize) -> u32 {
        self.entry(handle).consumed
    }

    pub fn build_next_unspent(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
        handle: usize,
        pool: &PoolSim,
        target_height: BlockHeight,
    ) -> Pcd<pool::Unspent> {
        let idx = self
            .entries
            .iter()
            .position(|entry| entry.handle == handle)
            .expect("no delegation for handle");
        let entry = &self.entries[idx];
        assert!(
            target_height >= entry.next_height,
            "target_height must be at least the next uncovered height"
        );
        let nfs_from = usize::try_from(entry.consumed).expect("fits usize");
        let unspent = build_unspent_pcd_between_anchors(
            rng,
            pool,
            &entry.nfs[nfs_from..],
            (entry.cursor_anchor, pool.anchor_at(target_height)),
        );
        let new_consumed = entry.consumed + (target_height.epoch().0 - entry.next_height.epoch().0);
        self.entries[idx].consumed = new_consumed;
        self.entries[idx].next_height = BlockHeight(target_height.0 + 1);
        self.entries[idx].cursor_anchor = pool.anchor_at(target_height);
        unspent
    }

    fn entry(&self, handle: usize) -> &SyncEntry {
        self.entries
            .iter()
            .find(|entry| entry.handle == handle)
            .expect("no delegation for handle")
    }
}

impl Default for SyncSim {
    fn default() -> Self {
        Self::new()
    }
}

fn epoch_first_of(epoch: EpochIndex) -> BlockHeight {
    BlockHeight(epoch.0 * EPOCH_SIZE)
}

fn epoch_final_of(epoch: EpochIndex) -> BlockHeight {
    let next_first = (epoch.0 + 1) * EPOCH_SIZE;
    BlockHeight(next_first - 1)
}

