#![allow(
    unreachable_pub,
    clippy::type_complexity,
    clippy::as_conversions,
    clippy::partial_pub_fields,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "test code"
)]

extern crate alloc;
extern crate std;

use alloc::{collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::{
    cell::{Cell, RefCell},
    iter,
    ops::RangeInclusive,
};

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use ragu::Pcd;
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::{CryptoRng, RngCore};

use crate::{
    action::{self, Action},
    bundle::{self, Bundle},
    constants::EPOCH_SIZE,
    digest::blake2b,
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{NoteMasterKey, PaymentKey, ProofAuthorizingKey, private},
    note::{self, Note, Nullifier, NullifierTrapdoor},
    primitives::{
        Anchor, BlockHeight, EpochIndex, Tachygram, TachygramSetCommit, TachygramSetPoly, effect,
    },
    stamp::{
        PointerStamp, ProofStamp,
        proof::{PROOF_SYSTEM, delegation, pool, spendable},
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

/// A stand-in for the covering aggregate's `wtxid = txid || auth_digest`:
/// a mock txid over the bundle commitment, beside the real `auth_digest`.
pub fn mock_wtxid(bundle: &Bundle<ProofStamp>) -> PointerStamp {
    let txid = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend txid")
        .to_state()
        .update(&bundle.commitment())
        .finalize();

    let mut wtxid = [0u8; 64];
    wtxid[..32].copy_from_slice(txid.as_bytes());
    wtxid[32..].copy_from_slice(&bundle.auth_digest());
    PointerStamp::try_from(wtxid).expect("nonzero wtxid")
}

pub fn random_action(rng: &mut (impl RngCore + CryptoRng)) -> Action {
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(400);
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
    value::Trapdoor,
    ActionEntropy,
    ActionRandomizer<effect::Spend>,
) {
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let alpha = theta.randomizer::<effect::Spend>(note.commitment());
    (rcv, theta, alpha)
}

pub fn build_output_plan(
    rng: &mut (impl RngCore + CryptoRng),
    note: Note,
) -> (
    value::Trapdoor,
    ActionRandomizer<effect::Output>,
    action::Plan<effect::Output>,
) {
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let plan = action::Plan::output(note, theta, rcv);
    let alpha = theta.randomizer::<effect::Output>(note.commitment());
    (rcv, alpha, plan)
}

pub fn build_output_stamp(
    rng: &mut (impl RngCore + CryptoRng),
    anchor: Anchor,
    note: Note,
) -> (ProofStamp, action::Plan<effect::Output>) {
    let (rcv, alpha, plan) = build_output_plan(rng, note);
    let (tachygrams, stamp_anchor, proof) =
        ProofStamp::prove_output(rng, rcv, alpha, note, anchor).expect("prove_output");
    let stamp = ProofStamp {
        actions: blake2b::action_descriptor_digest(
            &iter::once(plan.descriptor()).collect::<Vec<[u8; 64]>>(),
        ),
        tachygrams,
        anchor: stamp_anchor,
        proof,
    };
    (stamp, plan)
}

pub fn build_autonome(
    rng: &mut (impl RngCore + CryptoRng),
    wallet: &WalletSim,
    spend_value: u64,
    output_value: u64,
) -> Bundle<ProofStamp> {
    let spend_note = wallet.random_note(spend_value);
    let output_note = wallet.random_note(output_value);
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

/// A block's memoized curve work: its per-stamp tachygram-set commitments and
/// the post anchors those commitments fold to. Both require a polynomial commit
/// (MSM) per stamp, so they are computed once per block and shared via [`Rc`].
struct BlockDigest {
    commits: Vec<TachygramSetCommit>,
    anchors: Vec<Anchor>,
}

impl PoolSimBlock {
    /// Per-stamp tachygram-set commitments, in stamp order.
    fn commits(&self) -> Vec<TachygramSetCommit> {
        self.stamps
            .iter()
            .map(|tgs| tgs.iter().copied().collect::<TachygramSetPoly>().commit())
            .collect()
    }

    /// The block's commitments and post anchors in one pass: one anchor per
    /// stamp (folding `next_stamp` from `prev`), or a single `next_empty` tick
    /// for an empty block. The anchors reuse the commitments, so the MSMs run
    /// once.
    fn digest(&self) -> BlockDigest {
        let commits = self.commits();
        let anchors = if commits.is_empty() {
            alloc::vec![self.prev.next_empty()]
        } else {
            commits.iter().fold(Vec::new(), |mut acc, commit| {
                let last = acc.last().unwrap_or(&self.prev);
                acc.push(last.next_stamp(commit));
                acc
            })
        };
        BlockDigest { commits, anchors }
    }
}

pub struct PoolSim {
    history: Vec<PoolSimBlock>,
    /// Per-block digest memo, keyed by block height. The history is
    /// append-only, so a cached digest never goes stale.
    digests: RefCell<BTreeMap<usize, Rc<BlockDigest>>>,
    /// Post-anchor -> (height, stamp position) index, populated alongside the
    /// digests, so anchor lookup is a map hit rather than a full-history scan.
    /// Keyed by the anchor's inner `Fp` (an ordering of `Anchor` itself would
    /// mean by field value, not chain relationship, so it is not exposed).
    anchor_locs: RefCell<BTreeMap<Fp, (BlockHeight, usize)>>,
    /// Block-digest cache tallies (misses = one-time MSM work, hits = saved),
    /// summarized once when the pool is dropped rather than per height.
    digest_misses: Cell<usize>,
    digest_hits: Cell<usize>,
}

impl Drop for PoolSim {
    fn drop(&mut self) {
        let (misses, hits) = (self.digest_misses.get(), self.digest_hits.get());
        if misses + hits > 0 {
            std::eprintln!(
                "[poolsim] block: {misses} digested, {hits} reused ({} blocks)",
                self.history.len(),
            );
        }
    }
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
            digests: RefCell::new(BTreeMap::new()),
            anchor_locs: RefCell::new(BTreeMap::new()),
            digest_misses: Cell::new(0),
            digest_hits: Cell::new(0),
        }
    }

    /// The block's memoized digest, computed (and its anchors indexed) once.
    fn digest_at(&self, height: BlockHeight) -> Rc<BlockDigest> {
        let idx = usize::try_from(height).expect("fits usize");
        if let Some(digest) = self.digests.borrow().get(&idx) {
            self.digest_hits.set(self.digest_hits.get() + 1);
            return Rc::clone(digest);
        }
        self.digest_misses.set(self.digest_misses.get() + 1);
        let digest = Rc::new(self.history[idx].digest());
        let mut locs = self.anchor_locs.borrow_mut();
        for (position, anchor) in digest.anchors.iter().enumerate() {
            locs.insert(Fp::from(*anchor), (height, position));
        }
        drop(locs);
        self.digests.borrow_mut().insert(idx, Rc::clone(&digest));
        digest
    }

    /// Ensure every block's anchors are indexed, so [`anchor_locs`] is
    /// authoritative for a lookup miss.
    fn ensure_digests(&self) {
        for idx in 0..self.history.len() {
            drop(self.digest_at(BlockHeight::from(idx)));
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
        self.digest_at(height).commits.clone()
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
        // The block's terminal anchor is the last of its memoized post anchors
        // (the single `next_empty` tick for an empty block).
        *self
            .digest_at(height)
            .anchors
            .last()
            .expect("block digest has at least one anchor")
    }

    /// The pool blocks spanning the anchor range `(start, end]`, in forward
    /// order: each `Ok((height, stamps))` is a block's in-span tachygrams
    /// (empty for an empty block), each `Err(epoch)` a `next_epoch` lift
    /// into `epoch`. `start`/`end` may sit mid-block; the first and last
    /// blocks are trimmed to the span. Anchors are not returned (the caller
    /// folds them).
    #[must_use]
    pub fn anchor_steps(
        &self,
        start: Anchor,
        end: Anchor,
    ) -> Vec<Result<(BlockHeight, Vec<Vec<Tachygram>>), EpochIndex>> {
        // `start` enters the first stamp. A post anchor sits mid-block, so the
        // span starts at the next stamp. An epoch-boundary lift (including the
        // genesis entry) is produced by no stamp: the span then starts at the
        // entered block's stamp 0, with the lift contributing a leading marker.
        let mut steps: Vec<Result<(BlockHeight, Vec<Vec<Tachygram>>), EpochIndex>> = Vec::new();
        let stamp_len = |height: BlockHeight| -> usize {
            self.history[usize::try_from(height).expect("fits usize")]
                .stamps
                .len()
        };
        let (start_height, from) = match self.locate_anchor(start) {
            Ok((height, position)) => (height, (position + 1).min(stamp_len(height))),
            Err((_pre_boundary, epoch)) => {
                steps.push(Err(epoch));
                (epoch_first_of(epoch), 0)
            },
        };

        // One past the last included stamp of the end block (whose post is `end`).
        let (end_height, end_position) = self.locate_anchor(end).expect("end anchor must exist");
        let to = (end_position + 1).min(stamp_len(end_height));

        // Forward walk. The first block is trimmed at its head (`from`), the last
        // at its tail (`to`); a `start`-terminal first block contributes no `Ok`
        // entry. A boundary marker precedes every epoch-first block after the
        // start block.
        for height_idx in start_height.0..=end_height.0 {
            let height = BlockHeight(height_idx);
            let block = &self.history[usize::try_from(height_idx).expect("fits usize")];
            if height_idx != start_height.0 && height.is_epoch_first() {
                steps.push(Err(height.epoch()));
            }
            let lo = if height_idx == start_height.0 {
                from
            } else {
                0
            };
            let hi = if height_idx == end_height.0 {
                to
            } else {
                block.stamps.len()
            };
            let stamps = block.stamps[lo..hi].to_vec();
            // Skip a head-trimmed first block that the `start` terminal empties,
            // but keep a genuinely empty block (it still advances the anchor).
            if height_idx == start_height.0 && stamps.is_empty() && !block.stamps.is_empty() {
                continue;
            }
            steps.push(Ok((height, stamps)));
        }

        steps
    }

    /// The block that produced `anchor` (matched by its post anchors). An
    /// epoch-boundary anchor `B_E = old_tip.next_epoch(E)` is no block's post
    /// anchor (it is `E`'s first block's entry), so it instead returns
    /// `Err((pre_boundary_anchor, E))` with the lifted previous-epoch terminal;
    /// `Anchor::default()` is the epoch-0 boundary, resolved up front.
    /// Returns `(height, position)` where `position` is the anchor's index
    /// among its block's post anchors.
    fn locate_anchor(&self, anchor: Anchor) -> Result<(BlockHeight, usize), (Anchor, EpochIndex)> {
        if anchor == Anchor::default() {
            return Err((self.pre_epoch_anchor(EpochIndex(0)), EpochIndex(0)));
        }
        self.ensure_digests();
        if let Some(&location) = self.anchor_locs.borrow().get(&Fp::from(anchor)) {
            return Ok(location);
        }
        // Not a post anchor: an epoch boundary `B_E = old_tip.next_epoch(E)`, no
        // block's post anchor but the epoch-first block's `prev` (a distinct
        // domain from post anchors, so no post/boundary overlap is possible).
        for (height_idx, block) in self.history.iter().enumerate() {
            let height = BlockHeight::from(height_idx);
            if height.is_epoch_first() && block.prev == anchor {
                let epoch = height.epoch();
                return Err((self.pre_epoch_anchor(epoch), epoch));
            }
        }
        unreachable!("anchor not found: {anchor:?}");
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
        let stamps = pool.tachygrams_at(height);
        if stamps.is_empty() {
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
                last_block_upto.unwrap_or(stamps.len())
            } else {
                stamps.len()
            };
            for tgs in &stamps[..upto] {
                let witness = witness::anchor_seed(((), ()), state, tgs);
                let next_state = state.next_stamp(&witness.1);
                let (seed, ()) = PROOF_SYSTEM
                    .seed(rng, pool::AnchorSeed, witness)
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
/// pre_cm_anchor, creation_tgs)` plus the boundary-rooted
/// [`AnchorChain`](pool::AnchorChain) for the left input. Shared by
/// [`WalletSim::spendable_init`] (which `.expect`s the fuse) and tests that
/// drive a raw fuse to capture the `Err`.
pub(crate) fn spendable_init_inputs(
    rng: &mut (impl RngCore + CryptoRng),
    pool: &PoolSim,
    cm: note::Commitment,
    height: BlockHeight,
) -> (Anchor, Anchor, Vec<Tachygram>, Pcd<pool::AnchorChain>) {
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
    let creation_tgs = stamps[cm_idx].clone();

    (pre_epoch_anchor, pre_cm_anchor, creation_tgs, chain)
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
/// spanned, `nf[0]` for `start_anchor`'s epoch. Seeds one leaf per anchor
/// step and fuses them as a binary tree via [`fuse_unspent_tree`].
pub(crate) fn build_unspent_pcd_between_anchors(
    rng: &mut (impl RngCore + CryptoRng),
    pool: &PoolSim,
    nf: &[Nullifier],
    (start_anchor, end_anchor): (Anchor, Anchor),
) -> Pcd<pool::Unspent> {
    // One leaf per anchor step: each stamp advances its block's running anchor,
    // each empty block advances the block anchor once. The tree fold derives
    // seams from headers, so the interleaved boundary markers are dropped; only
    // `Ok` segments seed leaves. Anchors are folded here: the first block runs
    // from `start_anchor` (possibly mid-block), every other from its recorded
    // entry anchor.
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
    let mut leaves: Vec<Pcd<pool::Unspent>> = Vec::with_capacity(steps.len());
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
            leaves.push(seed);
        } else {
            for tgs in block_stamps {
                let commit = TachygramSetPoly::from_iter(tgs.clone()).commit();
                leaves.push(build_unspent_seed_pcd(rng, entry, epoch, &tgs, leaf_nf));
                entry = entry.next_stamp(&commit);
            }
        }
    }
    fuse_unspent_tree(rng, nf, base, leaves)
}

/// Fuse contiguous [`Unspent`] chains as a binary tree: split at the midpoint,
/// fuse each half, then join the halves at whatever seam their headers meet:
/// a shared epoch concatenates ([`UnspentFuse`]), consecutive epochs splice at
/// the boundary ([`UnspentEpochFuse`]). Everything a seam needs is read off
/// the halves' headers; a chain's elapsed slice is
/// `nf[epoch_start - base..epoch_end - base]` (one nullifier per crossed
/// boundary).
fn fuse_unspent_tree(
    rng: &mut (impl RngCore + CryptoRng),
    nf: &[Nullifier],
    base: EpochIndex,
    mut chains: Vec<Pcd<pool::Unspent>>,
) -> Pcd<pool::Unspent> {
    assert!(!chains.is_empty(), "tree fuses at least one chain");
    if chains.len() == 1 {
        return chains.pop().expect("single chain");
    }
    #[expect(
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "midpoint split"
    )]
    let right_chains = chains.split_off(chains.len() / 2);
    let left = fuse_unspent_tree(rng, nf, base, chains);
    let right = fuse_unspent_tree(rng, nf, base, right_chains);

    let elapsed_slice = |lo: EpochIndex, hi: EpochIndex| -> &[Nullifier] {
        let from = usize::try_from(lo.0 - base.0).expect("epoch within span");
        let to = usize::try_from(hi.0 - base.0).expect("epoch within span");
        &nf[from..to]
    };
    let (_, (left_epoch_start, _), _, (left_epoch_end, _), _) = *left.data();
    let (_, (right_epoch_start, _), _, (right_epoch_end, _), _) = *right.data();
    let left_el = elapsed_slice(left_epoch_start, left_epoch_end);
    let right_el = elapsed_slice(right_epoch_start, right_epoch_end);
    if right_epoch_start.0 == left_epoch_end.0 {
        let witness = witness::unspent_fuse((*left.data(), *right.data()), left_el, right_el);
        let (fused, ()) = PROOF_SYSTEM
            .fuse(rng, pool::UnspentFuse, witness, left, right)
            .expect("UnspentFuse mid-epoch");
        fused
    } else {
        debug_assert_eq!(
            right_epoch_start.0,
            left_epoch_end.0 + 1,
            "fused chains must be contiguous"
        );
        let witness = witness::unspent_epoch_fuse((*left.data(), *right.data()), left_el, right_el);
        let (fused, ()) = PROOF_SYSTEM
            .fuse(rng, pool::UnspentEpochFuse, witness, left, right)
            .expect("UnspentEpochFuse boundary");
        fused
    }
}

/// A fixed, deterministic spending key. Tests that don't need a distinct wallet
/// build from this so their notes' `cm`s collide and shared per-note work is
/// reused across tests instead of busted by fresh random key material.
pub(crate) fn shared_sk() -> private::SpendingKey {
    private::SpendingKey::random(&mut StdRng::seed_from_u64(0x7AC0_05EED))
}

/// A `StdRng` seed derived as `BLAKE2b(pk, value)`, so each `(pk, value)` pair
/// gets a distinct, fully value-dependent note-material stream. Test-only.
fn note_stream_seed(pk: PaymentKey, value: u64) -> [u8; 32] {
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"Tachyon-NoteRnd")
        .to_state()
        .update(&pk.0.to_repr())
        .update(&value.to_le_bytes())
        .finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(digest.as_bytes());
    seed
}

pub struct WalletSim {
    pub sk: private::SpendingKey,
    pub pak: ProofAuthorizingKey,
    /// One note-material stream per requested value, each seeded
    /// deterministically from `(sk, value)` (independent of any caller
    /// RNG). `random_note(value)` draws the next note from that value's
    /// stream, so the k-th note of a given value is identical across every
    /// wallet built from the same `sk`, and its `cm` collides, reusing
    /// shared per-note work. Keying by value keeps distinct asks independent:
    /// different values draw from disjoint field sequences, and interleaved
    /// draws of other values never shift a stream's position.
    notes: RefCell<BTreeMap<u64, StdRng>>,
}

impl WalletSim {
    pub fn new(sk: private::SpendingKey) -> Self {
        Self {
            sk,
            pak: sk.derive_proof_private(),
            notes: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::new(private::SpendingKey::random(rng))
    }

    /// The next note in this value's stream, at the given value. Each value has
    /// its own stream seeded from `(pk, value)`, so the k-th note of a given
    /// value is identical across wallets built from the same `sk` (its `cm`
    /// collides, reusing shared per-note work), while distinct values draw
    /// fully independent field sequences.
    pub fn random_note(&self, value_amount: u64) -> Note {
        let pk = self.sk.derive_payment_key();
        let mut streams = self.notes.borrow_mut();
        let notes = streams
            .entry(value_amount)
            .or_insert_with(|| StdRng::from_seed(note_stream_seed(pk, value_amount)));
        Note {
            pk,
            value: value::Positive::try_from(value_amount).expect("fixture value in range"),
            psi: NullifierTrapdoor::random(notes),
            rcm: note::CommitmentTrapdoor::random(notes),
        }
    }

    #[must_use]
    pub fn mk(&self, note: &Note) -> NoteMasterKey {
        self.pak.nk.derive_note_private(&note.psi)
    }

    #[must_use]
    pub fn nf_at(&self, note: &Note, epoch: EpochIndex) -> Nullifier {
        self.mk(note).derive_nullifier(epoch)
    }

    pub fn note_master(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
    ) -> Pcd<delegation::NfPrefixHeader> {
        let (pcd, ()) = PROOF_SYSTEM
            .seed(rng, delegation::NfMasterSeed, (note, self.pak))
            .expect("note seed");
        pcd
    }

    pub fn nullifier_pcd(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
        target_epoch: EpochIndex,
    ) -> Pcd<delegation::NullifierHeader> {
        let master = self.note_master(rng, note);
        ggm_tools::nullifier_from_master(rng, master, target_epoch)
    }

    pub fn derived_range(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: &Note,
        epoch_start: EpochIndex,
        len: u32,
    ) -> Pcd<delegation::NullifierHeader> {
        let master = self.note_master(rng, *note);
        ggm_tools::nullifier_range_from_master(rng, &master, epoch_start, len)
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
        let present_nf = self.nf_at(note, epoch);
        let (pre_epoch_anchor, pre_cm_anchor, creation_tgs, chain) =
            spendable_init_inputs(rng, pool, cm, init_height);
        let nf_header = self.nullifier_pcd(rng, *note, epoch);

        let (spendable, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spendable::SpendableInit,
                witness::spendable_init(
                    (*chain.data(), *nf_header.data()),
                    pre_epoch_anchor,
                    pre_cm_anchor,
                    &creation_tgs,
                    present_nf,
                ),
                chain,
                nf_header,
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

    pub fn verify_unspent(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        unspent: Pcd<pool::Unspent>,
        note: &Note,
        epoch_start: EpochIndex,
        present_epoch: EpochIndex,
    ) -> Pcd<pool::VerifiedUnspent> {
        let len = present_epoch.0 - epoch_start.0 + 1;
        let range = self.derived_range(rng, note, epoch_start, len);
        let elapsed: Vec<Nullifier> = (epoch_start.0..present_epoch.0)
            .map(|epoch| self.nf_at(note, EpochIndex(epoch)))
            .collect();
        let (verified, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                pool::VerifyUnspent,
                witness::verify_unspent((*unspent.data(), *range.data()), &elapsed),
                unspent,
                range,
            )
            .expect("VerifyUnspent");
        verified
    }

    pub fn lift(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        spendable: Pcd<spendable::SpendableHeader>,
        unspent: Pcd<pool::Unspent>,
        note: &Note,
        epoch_start: EpochIndex,
        present_epoch: EpochIndex,
    ) -> Pcd<spendable::SpendableHeader> {
        let verified = self.verify_unspent(rng, unspent, note, epoch_start, present_epoch);
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
                self.nf_at(note, creation_epoch),
                self.nf_at(note, creation_epoch.next()),
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
    ) -> Bundle<ProofStamp> {
        let ask = self.sk.derive_auth_private();

        let mut spend_plans = Vec::with_capacity(spends.len());
        let mut spend_pcds = Vec::with_capacity(spends.len());
        for (note, spendable_pcd, spend_epoch) in spends {
            let range_pcd = self.derived_range(rng, &note, spend_epoch, 2);
            let pair = [
                self.nf_at(&note, spend_epoch),
                self.nf_at(&note, spend_epoch.next()),
            ];
            let rcv = value::Trapdoor::random(rng);
            let theta = ActionEntropy::random(rng);
            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                self.pak.ak.derive_action_public(&alpha)
            });
            spend_plans.push(plan);
            spend_pcds.push((range_pcd, pair, spendable_pcd));
        }

        let output_plans: Vec<action::Plan<effect::Output>> = output_notes
            .into_iter()
            .map(|note| {
                let rcv = value::Trapdoor::random(rng);
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

pub mod ggm_tools {
    extern crate alloc;
    use alloc::vec::Vec;

    use ragu::{Pcd, Proof};
    use rand_core::{CryptoRng, RngCore};

    use crate::{
        EpochIndex,
        digest::poseidon,
        keys::{GGM_CHUNK_SIZE, GGM_TREE_DEPTH},
        note::Nullifier,
        stamp::proof::{PROOF_SYSTEM, delegation},
        witness,
    };

    pub fn walk_master_to_depth(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<delegation::NfPrefixHeader>,
        epoch: EpochIndex,
        target_depth: u8,
    ) -> Pcd<delegation::NfPrefixHeader> {
        assert!(
            (1..=GGM_TREE_DEPTH).contains(&target_depth),
            "target_depth must be in 1..=GGM_DEPTH",
        );

        let mut pcd = master_pcd;
        while pcd.data().2 < target_depth {
            let next_step = pcd.data().2 + 1;
            let chunk = chunk_at(epoch.0, next_step);
            let (next_pcd, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    delegation::NfPrefixStep,
                    (chunk,),
                    pcd,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("note step");
            pcd = next_pcd;
        }

        pcd
    }

    pub fn nullifier_from_master(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<delegation::NfPrefixHeader>,
        target_epoch: EpochIndex,
    ) -> Pcd<delegation::NullifierHeader> {
        let prefix_pcd = walk_master_to_depth(rng, master_pcd, target_epoch, GGM_TREE_DEPTH);
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                delegation::NullifierStep,
                (),
                prefix_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("nullifier step");
        pcd
    }

    pub fn nullifier_range_from_master(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: &Pcd<delegation::NfPrefixHeader>,
        epoch_start: EpochIndex,
        len: u32,
    ) -> Pcd<delegation::NullifierHeader> {
        assert!(len >= 1, "range length must be at least 1");
        let mut nfs: Vec<Nullifier> = Vec::new();
        let mut acc: Option<Pcd<delegation::NullifierHeader>> = None;
        for offset in 0..len {
            let epoch = EpochIndex(epoch_start.0 + offset);
            let prefix_pcd = walk_master_to_depth(rng, master_pcd.clone(), epoch, GGM_TREE_DEPTH);
            let nf = Nullifier::from(poseidon::nullifier(prefix_pcd.data().1));
            let (leaf, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    delegation::NullifierStep,
                    (),
                    prefix_pcd,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("nullifier step");
            acc = Some(match acc {
                None => {
                    nfs.push(nf);
                    leaf
                },
                Some(left) => {
                    let fuse_witness =
                        witness::nullifier_fuse((*left.data(), *leaf.data()), nfs.as_slice(), nf);
                    nfs.push(nf);
                    let (fused, ()) = PROOF_SYSTEM
                        .fuse(rng, delegation::NullifierFuse, fuse_witness, left, leaf)
                        .expect("NullifierFuse");
                    fused
                },
            });
        }
        acc.expect("len >= 1 produced a range")
    }

    fn chunk_at(epoch_bits: u32, level: u8) -> u8 {
        let shift = (GGM_TREE_DEPTH * GGM_CHUNK_SIZE) - level * GGM_CHUNK_SIZE;
        let chunk_mask = (1u32 << GGM_CHUNK_SIZE) - 1u32;
        let chunk_u32 = (epoch_bits >> shift) & chunk_mask;
        u8::try_from(chunk_u32).expect("chunk fits in u8")
    }
}
