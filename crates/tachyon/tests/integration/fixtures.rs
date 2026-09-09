extern crate alloc;

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{cell::RefCell, iter, mem, ops::RangeInclusive};

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use ragu::{Pcd, Proof};
use ragu_arithmetic::PoseidonPermutation as _;
use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use ragu_pasta::PoseidonFp;
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use zcash_tachyon::{
    ActionSetPoly, Anchor, BlockHeight, EpochIndex, QrDiscriminant, QrProfile, Tachygram,
    TachygramSetCommit, TachygramSetPoly,
    action::{self, Action},
    bundle::{self, Bundle},
    digest::blake2b,
    effect,
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{NoteMasterKey, PaymentKey, ProofAuthorizingKey, private},
    note::{self, Note},
    nullifier::{self, NF_DERIVATION_WIDTH, Nullifier},
    stamp::{
        PointerStamp, ProofStamp, StampState,
        proof::{
            PROOF_SYSTEM, delegation, pool, qr, spendable,
            stamp::{MergeStamp, StampHeader},
            summary,
        },
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

pub fn mock_txid(bundle_commitment: [u8; 32]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend txid")
        .to_state()
        .update(&bundle_commitment)
        .finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub fn mock_auth_digest(bundle_auth_digest: [u8; 32]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend auth")
        .to_state()
        .update(&bundle_auth_digest)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// A stand-in for the covering aggregate's `wtxid = txid || auth_digest`.
///
/// Kept distinct from [`mock_sighash`] on purpose: the transaction sighash
/// equals the txid only for a fully shielded transaction, and `Bundle::verify`
/// takes the sighash and the covering wtxid as independent inputs. Deriving the
/// txid half from a separate transform lets tests catch any regression that
/// conflates the two.
pub fn mock_wtxid<S: StampState + 'static>(bundle: &Bundle<S>) -> PointerStamp {
    let mut wtxid = [0u8; 64];
    wtxid[..32].copy_from_slice(&mock_txid(bundle.commitment()));
    wtxid[32..].copy_from_slice(&mock_auth_digest(bundle.auth_digest()));

    PointerStamp::try_from(wtxid).expect("nonzero wtxid")
}

pub fn random_action<RNG: CryptoRng>(rng: &mut RNG) -> Action {
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(400);
    let (_, _, plan) = build_output_plan(rng, note);
    let bundle_plan = bundle::Plan::new(alloc::vec![], alloc::vec![plan]);
    let sighash = mock_sighash(bundle_plan.commitment().expect("fixture commitment"));
    let unproven = bundle_plan
        .sign(rng, &sighash, &ask)
        .expect("sign foreign output");
    unproven.actions[0]
}

pub fn spend_witness<RNG: CryptoRng>(
    rng: &mut RNG,
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

pub fn build_output_plan<RNG: CryptoRng>(
    rng: &mut RNG,
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

pub fn build_output_stamp<RNG: CryptoRng>(
    rng: &mut RNG,
    anchor: Anchor,
    note: Note,
) -> (ProofStamp, action::Plan<effect::Output>) {
    let (rcv, alpha, plan) = build_output_plan(rng, note);
    let (tachygrams, stamp_anchor, proof) =
        ProofStamp::prove_output(rng, rcv, alpha, note, anchor).expect("prove_output");
    let stamp = ProofStamp {
        coverage: blake2b::action_descriptor_digest(
            &iter::once(plan.descriptor()).collect::<Vec<[u8; 64]>>(),
        ),
        anchor: stamp_anchor,
        tachygram_set: tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit(),
        tachygrams,
        proof,
    };
    (stamp, plan)
}

pub fn build_autonome<RNG: CryptoRng>(
    rng: &mut RNG,
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

/// An honest prover will not merge intersecting stamps.
///
/// However, `MergeStamp` actually handles a commitment scheme that represents a
/// multiset, and proves a relationship equivalent to a multiset union. So, a
/// dishonest prover can feasibly prove a merge that violates consensus rules.
///
/// Normal tools in this crate don't allow you to carry out such operations, so
/// this utility will fuse a `MergeStamp` without checking for intersection.
pub fn forge_overlapping_merge<RNG: CryptoRng>(
    rng: &mut RNG,
    (stamp_a, descriptors_a): (&ProofStamp, &Vec<action::Descriptor>),
    (stamp_b, descriptors_b): (&ProofStamp, &Vec<action::Descriptor>),
) -> Pcd<StampHeader> {
    let left_acts = descriptors_a
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .collect::<ActionSetPoly>();
    let right_acts = descriptors_b
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .collect::<ActionSetPoly>();
    let left_tg = stamp_a
        .tachygrams
        .iter()
        .copied()
        .collect::<TachygramSetPoly>();
    let right_tg = stamp_b
        .tachygrams
        .iter()
        .copied()
        .collect::<TachygramSetPoly>();

    let left_pcd = stamp_a.proof.clone().carry::<StampHeader>((
        left_acts.commit(),
        left_tg.commit(),
        stamp_a.anchor,
    ));
    let right_pcd = stamp_b.proof.clone().carry::<StampHeader>((
        right_acts.commit(),
        right_tg.commit(),
        stamp_b.anchor,
    ));

    let merged_acts = descriptors_a
        .iter()
        .chain(descriptors_b.iter())
        .map(|desc| desc.digest().expect("action digest"))
        .collect::<ActionSetPoly>();
    let merged_tg = stamp_a
        .tachygrams
        .iter()
        .chain(stamp_b.tachygrams.iter())
        .copied()
        .collect::<TachygramSetPoly>();

    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            MergeStamp,
            (
                (left_acts, left_tg),
                (merged_acts, merged_tg),
                (right_acts, right_tg),
            ),
            left_pcd,
            right_pcd,
        )
        .expect("multiset merge must prove");

    pcd
}

pub fn random_block<RNG: CryptoRng>(
    rng: &mut RNG,
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

pub fn random_block_with<RNG: CryptoRng>(
    rng: &mut RNG,
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

/// A published stamp: the anchor its link opens at, its tachygrams, their
/// commitment, and the anchor its link closes at.
pub type StampEntry = (Anchor, Vec<Tachygram>, TachygramSetCommit, Anchor);

#[derive(Clone, Debug)]
pub struct PoolSimBlock {
    pub prev: Anchor,
    pub stamps: Vec<StampEntry>,
}

impl PoolSimBlock {
    /// Commit each stamp's tachygrams and fold the anchor onward from `prev`,
    /// binding `epoch`, the epoch of the block at `height`. Each stamp costs
    /// one MSM, paid here so reads are lookups.
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

    /// The block's terminal anchor: its last stamp's, or its entry anchor
    /// unchanged when the block published no stamp.
    pub fn anchor(&self) -> Anchor {
        match self.stamps.last() {
            Some(&(_, _, _, anchor)) => anchor,
            None => self.prev,
        }
    }

    pub fn tachygrams(&self) -> Vec<Vec<Tachygram>> {
        self.stamps.iter().map(|stamps| stamps.1.clone()).collect()
    }

    pub fn stamp_commits(&self) -> Vec<TachygramSetCommit> {
        self.stamps.iter().map(|stamps| stamps.2).collect()
    }
}

pub struct PoolSim {
    history: Vec<PoolSimBlock>,
    anchor_index: BTreeMap<Anchor, (BlockHeight, usize)>,
}

impl PoolSim {
    #[must_use]
    pub fn genesis<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self::genesis_with(random_block(rng, 1, 50))
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
        self.history
            .get(usize::try_from(height).expect("fits usize"))
            .expect("query height should exist")
    }

    /// Append a block entered at `prev`, indexing the cursor each of its
    /// anchors opens. An epoch-first block's entry anchor is the epoch lift's
    /// product and so is indexed too; any other entry anchor is the previous
    /// block's terminal, already indexed there.
    fn push_block(&mut self, prev: Anchor, stamps: Vec<Vec<Tachygram>>) {
        let height = BlockHeight::from(self.history.len());
        let block = PoolSimBlock::new(prev, height, stamps);
        if height.is_epoch_first() {
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

    /// The stamps whose anchor links run from `start` to `end`, in publication
    /// order. Either endpoint may sit mid-block.
    ///
    /// The walk asserts the links chain, which is what keeps an epoch boundary
    /// out of the span: a boundary tick advances the anchor without publishing
    /// a stamp, so no run of stamps spans one.
    pub fn stamps_between(&self, start: Anchor, end: Anchor) -> Vec<&StampEntry> {
        // The cursor an endpoint opens: its block, and that block's first stamp
        // the endpoint does not already cover. The span is that half-open
        // interval of stamp slots, ordered by block and then by position.
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

        let (first, rest) = entries
            .split_first()
            .expect("anchor span must cover at least one stamp");
        assert_eq!(first.0, start, "the span opens at its start anchor");
        let mut cursor = first.3;
        for entry in rest {
            assert_eq!(entry.0, cursor, "the span's stamps chain without a gap");
            cursor = entry.3;
        }
        assert_eq!(cursor, end, "the span closes at its end anchor");

        entries
    }

    /// The epoch a stamp entered at `anchor` belongs to.
    pub fn epoch_at(&self, anchor: Anchor) -> EpochIndex {
        self.anchor_index[&anchor].0.epoch()
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

    /// Mine a block publishing the stamps of `bundles`, in order.
    pub fn mine_bundles(&mut self, bundles: &[&Bundle<ProofStamp>]) {
        self.mine(
            bundles
                .iter()
                .map(|&bundle| bundle.stamp.tachygrams.iter().copied().collect())
                .collect(),
        );
    }

    pub fn mine(&mut self, stamps: Vec<Vec<Tachygram>>) {
        let new_height = BlockHeight::from(self.history.len());
        let old_tip = self.anchor();
        // Epoch-first blocks are preceded by a boundary anchor lift;
        // intra-epoch blocks advance directly from the previous tip.
        let prev = if new_height.is_epoch_first() {
            old_tip.next_epoch(new_height.epoch()).unwrap()
        } else {
            old_tip
        };
        self.push_block(prev, stamps);
    }
}

/// Build an [`AnchorChain`] covering blocks `range` in full, rooted at the
/// block-start anchor of `*range.start()`.
///
/// One [`AnchorSeed`] per absorbed stamp, fused linearly via [`AnchorFuse`].
/// A stampless block advances no anchor and so contributes no segment; the
/// range must therefore cover at least one stamp.
pub(crate) fn build_anchor_chain_pcd<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    range: RangeInclusive<BlockHeight>,
) -> Pcd<pool::AnchorChain> {
    let start = *range.start();
    let end = *range.end();
    assert_eq!(start.epoch(), end.epoch(), "AnchorChain single-epoch range");
    assert!(start <= end);

    let mut state = pool.block(start).prev;
    let mut chain: Option<Pcd<pool::AnchorChain>> = None;
    let mut height = start;
    loop {
        for tgs in &pool.block(height).tachygrams() {
            let witness = witness::anchor_seed(((), ()), state, height.epoch(), tgs);
            let next_state = state.next_stamp(witness.1, &witness.2).unwrap();
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
        if height >= end {
            break;
        }
        height = height.next();
    }

    chain.expect("AnchorChain range must cover at least one stamp")
}

/// Build a [`Summary`](summary::Summary) over the anchor span `(start, end)`,
/// accumulating every stamp whose link falls inside it, and return the
/// tachygrams it accumulates.
///
/// A summary is anchor-bound: it runs from one published anchor to another,
/// carries whatever stamps lie between them, and holds them in a single
/// polynomial. Block boundaries mean nothing to it, and the epoch boundary is
/// excluded by [`PoolSim::stamps_between`].
pub(crate) fn build_summary_pcd<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    (start, end): (Anchor, Anchor),
) -> (Pcd<summary::Summary>, Vec<Tachygram>) {
    let entries = pool.stamps_between(start, end);
    let members: usize = entries.iter().map(|entry| entry.1.len()).sum();
    assert!(
        members < (1 << ProductionRank::RANK),
        "span exceeds one summary"
    );
    let epoch = pool.anchor_index[&start].0.epoch();

    let (first, rest) = entries
        .split_first()
        .expect("anchor span must cover at least one stamp");
    let (seeded, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &first.1),
        )
        .expect("SummarySeed");

    let mut acc = first.1.clone();
    let mut pcd = seeded;
    for entry in rest {
        let (advanced, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                summary::SummaryAdvance,
                witness::summary_advance((*pcd.data(), ()), &acc, &entry.1),
                pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("SummaryAdvance");
        acc.extend(entry.1.iter().copied());
        pcd = advanced;
    }
    assert_eq!(pcd.data().2, end, "the summary closes at the span's end");

    (pcd, acc)
}

/// An intake with the members its contents commit.
pub(crate) struct QrIntakeEntry {
    pub pcd: Pcd<qr::QrIntake>,
    pub members: Vec<Tachygram>,
}

/// A sealed bucket with the members its contents commit.
pub(crate) struct QrBucketEntry {
    pub pcd: Pcd<qr::QrBucket>,
    pub members: Vec<Tachygram>,
}

/// Seal `intake`; `prev_last` is the terminal anchor of the preceding epoch.
pub(crate) fn seal_qr_intake<RNG: CryptoRng>(
    rng: &mut RNG,
    intake: QrIntakeEntry,
    prev_last: Anchor,
) -> QrBucketEntry {
    let witness = witness::qr_bucket_seal((*intake.pcd.data(), ()), prev_last);
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness,
            intake.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrBucketSeal");
    QrBucketEntry {
        pcd,
        members: intake.members,
    }
}

/// The discriminant an epoch's buckets carry: the closing boundary anchor
/// its terminal anchor `terminal` ticks to.
pub(crate) fn qr_discriminant_of(pool: &PoolSim, terminal: Anchor) -> QrDiscriminant {
    terminal
        .next_epoch(pool.epoch_at(terminal).next())
        .expect("epoch after the terminal is nonzero")
        .into()
}

/// Root an intake on one published stamp, which a summary need not be able to
/// hold.
pub(crate) fn seed_qr_stamp_intake<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    stamp: &StampEntry,
    discriminant: QrDiscriminant,
) -> QrIntakeEntry {
    let (entry, members) = (stamp.0, stamp.1.clone());
    let epoch = pool.epoch_at(entry);
    let witness = witness::qr_stamp_intake_seed(((), ()), entry, epoch, discriminant, &members);
    let (pcd, ()) = PROOF_SYSTEM
        .seed(rng, qr::QrStampIntakeSeed, witness)
        .expect("QrStampIntakeSeed");
    QrIntakeEntry { pcd, members }
}

/// Open root intakes over the anchor span `(start, end)`, each holding at most
/// `capacity` members.
///
/// A run of consecutive stamps closes before the next stamp would carry it past
/// `capacity`, and is rooted over its summary. A stamp that alone exceeds
/// `capacity` is rooted on its own through
/// [`QrStampIntakeSeed`](qr::QrStampIntakeSeed), skipping the summary steps.
/// Chunking counts members, and is indifferent to block boundaries.
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
        let (first, last) = (
            run.first().expect("nonempty run"),
            run.last().expect("nonempty run"),
        );
        if run.len() == 1 && first.1.len() > capacity {
            roots.push(seed_qr_stamp_intake(rng, pool, first, discriminant));
            continue;
        }
        let (summary, members) = build_summary_pcd(rng, pool, (first.0, last.3));
        let witness = witness::qr_summary_intake_init((*summary.data(), ()), discriminant);
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSummaryIntakeInit,
                witness,
                summary,
                Proof::trivial().carry::<()>(()),
            )
            .expect("QrSummaryIntakeInit");
        roots.push(QrIntakeEntry { pcd, members });
    }
    roots
}

/// Merge intakes left to right, closing the accumulator at a profile change or
/// whenever the next merge would carry more than `capacity` members.
///
/// A layer holds its intakes grouped by profile and span-ordered within each
/// group, so neighbours that share a profile are exactly the pairs whose spans
/// meet.
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
                    .expect("QrIntakeMerge");
                Some(QrIntakeEntry { pcd, members })
            },
        };
    }
    merged.extend(acc);
    merged
}

/// Split one intake and descend into both sides.
pub(crate) fn split_qr_intake<RNG: CryptoRng>(
    rng: &mut RNG,
    intake: QrIntakeEntry,
) -> (QrIntakeEntry, QrIntakeEntry) {
    let (_epoch, _anchor_prev, _anchor_last, discriminant, profile, _contents) = *intake.pcd.data();
    let split_witness = witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members);
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            split_witness,
            intake.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");

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
                Proof::trivial().carry::<()>(()),
            )
            .expect("QrSideDescend");
        QrIntakeEntry { pcd, members }
    };
    let residue = descend(true);
    let non_residue = descend(false);
    (residue, non_residue)
}

/// Route the anchor span `(start, end)`'s tachygrams to `depth`, over intakes
/// holding at most `capacity` members each.
///
/// Each layer splits every intake, descends into both sides, and merges
/// same-profile neighbours as far as `capacity` allows. A profile ends up as
/// one intake only where the span's members at that profile fit one
/// polynomial, and as a run of adjacent intakes otherwise.
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
            let (left, right) = split_qr_intake(rng, intake);
            residue.push(left);
            non_residue.push(right);
        }
        layer = merge_qr_run(rng, residue, capacity);
        layer.extend(merge_qr_run(rng, non_residue, capacity));
    }
    layer
}

/// Route the anchor span `(start, end)`'s tachygrams to `depth` along
/// `value`'s own path, over intakes holding at most `capacity` members each.
///
/// Each layer splits every intake on the path, keeps `value`'s side, and
/// merges same-profile neighbours as far as `capacity` allows. The work grows
/// with the depth, not with the number of profiles.
pub(crate) fn build_qr_branch<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    (start, end): (Anchor, Anchor),
    discriminant: QrDiscriminant,
    capacity: usize,
    value: Fp,
    depth: u32,
) -> Vec<QrIntakeEntry> {
    let mut layer = build_qr_roots(rng, pool, (start, end), discriminant, capacity);
    for level in 0..depth {
        let side = qr::classify(value, discriminant.at(level)).0;
        let mut kept = Vec::with_capacity(layer.len());
        for intake in layer {
            let (residue, non_residue) = split_qr_intake(rng, intake);
            kept.push(if side { residue } else { non_residue });
        }
        layer = merge_qr_run(rng, kept, capacity);
    }
    layer
}

/// The profile a value takes at `depth` levels of the progression from
/// `discriminant`.
pub(crate) fn qr_profile_of(value: Fp, discriminant: QrDiscriminant, depth: u32) -> QrProfile {
    let mut profile = QrProfile::ROOT;
    for level in 0..depth {
        profile = profile.descend(qr::classify(value, discriminant.at(level)).0);
    }
    profile
}

pub(crate) fn build_unspent_seed_pcd<RNG: CryptoRng>(
    rng: &mut RNG,
    start: Anchor,
    epoch: EpochIndex,
    tgs: &[Tachygram],
    nf: Nullifier,
) -> Pcd<pool::ArbitraryUnspent> {
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
pub(crate) fn build_unspent_pcd_between_blocks<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    nf: &[Nullifier],
    range: RangeInclusive<BlockHeight>,
) -> Pcd<pool::ArbitraryUnspent> {
    build_unspent_pcd_between_anchors(
        rng,
        pool,
        nf,
        (
            pool.block(*range.start()).prev,
            pool.block(*range.end()).anchor(),
        ),
    )
}

/// The nullifier a span's `nf` holds for `epoch`, indexed from `base`, the
/// epoch the span starts in.
fn nf_at(nf: &[Nullifier], base: EpochIndex, epoch: EpochIndex) -> Nullifier {
    nf[usize::try_from(u64::from(epoch - base)).expect("epoch within span")]
}

/// Build an [`ArbitraryUnspent`] for the anchor span `(start_anchor,
/// end_anchor)`, covering every stamp that advances the anchor between them;
/// either endpoint may sit mid-block. `nf` holds one nullifier per epoch
/// spanned, `nf[0]` for the span's starting epoch. Seeds one leaf per stamp
/// and fuses them as a binary tree via [`fuse_unspent_tree`].
///
/// Every epoch boundary the span crosses gets an
/// [`EndEpochUnspentSeed`](pool::EndEpochUnspentSeed) leaf spanning the
/// boundary tick, seeded from the leaving epoch's terminal anchor.
pub(crate) fn build_unspent_pcd_between_anchors<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    nf: &[Nullifier],
    (start_anchor, end_anchor): (Anchor, Anchor),
) -> Pcd<pool::ArbitraryUnspent> {
    // The cursor an endpoint opens: its block, and that block's first stamp
    // the endpoint does not already cover. Either endpoint may be a boundary
    // anchor, which no stamp produced and which opens its epoch's first block.
    let (start_height, start_inner) = pool.anchor_index[&start_anchor];
    let (end_height, end_inner) = pool.anchor_index[&end_anchor];

    // The span is that half-open interval of stamp slots, ordered by block and
    // then by position within the block.
    let span = (start_height, start_inner)..(end_height, end_inner);

    // `nf` is indexed from the epoch `start_anchor` sits in.
    let base_epoch = start_height.epoch();

    // A span between two anchors is an interval of stamps. Cut that interval by
    // epoch. Each epoch after the first segment begins with a crossing out of
    // the one before it.
    let leaves: Vec<Pcd<pool::ArbitraryUnspent>> = (base_epoch.0..=end_height.epoch().0)
        .map(EpochIndex)
        .map(|epoch| {
            let crossing = (epoch != base_epoch).then(|| {
                let leaving = EpochIndex(epoch.0 - 1);
                (leaving, pool.block(leaving.last_block()).anchor())
            });
            let stamps: Vec<_> = (start_height.0.max(epoch.first_block().0)
                ..=end_height.0.min(epoch.last_block().0))
                .map(BlockHeight)
                .flat_map(|height| {
                    pool.block(height)
                        .stamps
                        .iter()
                        .enumerate()
                        .map(move |(position, stamp)| ((height, position), stamp))
                })
                .filter(|&(slot, _)| span.contains(&slot))
                .map(|(_, stamp)| (stamp.0, stamp.1.as_slice()))
                .collect();
            (epoch, crossing, stamps)
        })
        .flat_map(|(epoch, crossing, stamps)| {
            let epoch_nf = nf_at(nf, base_epoch, epoch);
            let crossing_leaf = crossing.map(|(leaving, terminal)| {
                let witness = witness::end_epoch_unspent_seed(
                    ((), ()),
                    terminal,
                    leaving,
                    nf_at(nf, base_epoch, leaving),
                    epoch_nf,
                );
                PROOF_SYSTEM
                    .seed(rng, pool::EndEpochUnspentSeed, witness)
                    .expect("EndEpochUnspentSeed")
                    .0
            });
            let seeded: Vec<_> = stamps
                .into_iter()
                .map(|(entry, tgs)| {
                    let witness = witness::unspent_seed(((), ()), entry, epoch, tgs, epoch_nf);
                    PROOF_SYSTEM
                        .seed(rng, pool::UnspentSeed, witness)
                        .expect("UnspentSeed")
                        .0
                })
                .collect();
            crossing_leaf.into_iter().chain(seeded)
        })
        .collect();

    fuse_unspent_tree(rng, nf, base_epoch, leaves)
}

/// Fuse contiguous [`ArbitraryUnspent`] chains as a binary tree: split at the
/// midpoint, fuse each half, then concatenate the halves at their shared epoch
/// ([`UnspentFuse`]). Every seam is a shared junction, since a boundary is
/// itself a chain link. Everything a seam needs is read off the halves'
/// headers; a chain's member slice is
/// `nf[epoch_start - base..=epoch_last - base]` (one nullifier per covered
/// epoch).
fn fuse_unspent_tree<RNG: CryptoRng>(
    rng: &mut RNG,
    nf: &[Nullifier],
    base: EpochIndex,
    mut chains: Vec<Pcd<pool::ArbitraryUnspent>>,
) -> Pcd<pool::ArbitraryUnspent> {
    assert!(!chains.is_empty(), "tree fuses at least one chain");
    if chains.len() == 1 {
        return chains.pop().expect("single chain");
    }
    let right_chains = chains.split_off(chains.len() / 2);
    let left = fuse_unspent_tree(rng, nf, base, chains);
    let right = fuse_unspent_tree(rng, nf, base, right_chains);

    let elapsed_slice = |lo: EpochIndex, hi: EpochIndex| -> &[Nullifier] {
        let from = usize::try_from(u64::from(lo - base)).expect("epoch within span");
        let to = usize::try_from(u64::from(hi - base)).expect("epoch within span");
        &nf[from..=to]
    };
    let (_, (left_epoch_start, _), _, (left_epoch_last, _), _) = *left.data();
    let (_, (right_epoch_start, _), _, (right_epoch_last, _), _) = *right.data();
    let left_el = elapsed_slice(left_epoch_start, left_epoch_last);
    let right_el = elapsed_slice(right_epoch_start, right_epoch_last);
    assert_eq!(
        right_epoch_start.0, left_epoch_last.0,
        "fused chains must meet inside one epoch"
    );
    let witness = witness::unspent_fuse((*left.data(), *right.data()), left_el, right_el);
    let (fused, ()) = PROOF_SYSTEM
        .fuse(rng, pool::UnspentFuse, witness, left, right)
        .expect("UnspentFuse");
    fused
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
        .update(&Fp::from(pk).to_repr())
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
    pub notes: RefCell<BTreeMap<u64, StdRng>>,
    /// Per-note master seed PCDs, keyed by the note's `cm` tachygram.
    pub masters: RefCell<BTreeMap<Tachygram, Pcd<delegation::NfMasterHeader>>>,
    /// Per-(note, range) derivation PCDs, keyed by `(cm, epoch_start,
    /// epoch_end)`: repeated derivations of the same exact range share the
    /// proof.
    pub derivations: RefCell<BTreeMap<(Tachygram, u32, u32), Pcd<delegation::NullifierDerivation>>>,
}

impl WalletSim {
    pub fn new(sk: private::SpendingKey) -> Self {
        Self {
            sk,
            pak: sk.derive_proof_private(),
            notes: RefCell::new(BTreeMap::new()),
            masters: RefCell::new(BTreeMap::new()),
            derivations: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
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
            psi: nullifier::Trapdoor::random(notes),
            rcm: note::CommitmentTrapdoor::random(notes),
        }
    }

    #[must_use]
    pub fn mk(&self, note: &Note) -> NoteMasterKey {
        self.pak.nk.derive_note_private(note.psi)
    }

    #[must_use]
    /// The covering sequence's members over a derivation PCD's range, one
    /// per epoch, for the witness builders to segment.
    pub fn covering_window(
        &self,
        note: &Note,
        range: &Pcd<delegation::NullifierDerivation>,
    ) -> Vec<Nullifier> {
        let (_, start, _, end) = *range.data();
        (start.0..end.0)
            .map(|epoch| self.nf_at(note, EpochIndex(epoch)))
            .collect()
    }

    pub fn nf_at(&self, note: &Note, epoch: EpochIndex) -> Nullifier {
        self.mk(note).derive_nullifier(epoch)
    }

    /// The certified master-key seed PCD for this note, cached by `cm`. The
    /// note is witnessed once; every window fuses against the same seed.
    pub fn master_pcd<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        note: Note,
    ) -> Pcd<delegation::NfMasterHeader> {
        let cm = Tachygram::from(note.commitment());
        if let Some(pcd) = self.masters.borrow().get(&cm) {
            return pcd.clone();
        }
        let (pcd, ()) = PROOF_SYSTEM
            .seed(
                rng,
                delegation::NfMasterSeed,
                witness::nf_master_seed(((), ()), note, self.pak),
            )
            .expect("NfMasterSeed");

        self.masters.borrow_mut().insert(cm, pcd.clone());
        pcd
    }

    /// The certified derivation PCD covering `[epoch_start, epoch_end)`,
    /// built from whole windows and cached by the covering range.
    ///
    /// The first window is the one opened by `epoch_start`'s group; further
    /// windows chain through [`delegation::NullifierFuse`] until the requested
    /// bound is covered. Consumers read their own epochs out of the covering
    /// PCD, so every request inside the same covering range shares one proof.
    pub fn derivation_pcd<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        note: Note,
        epoch_start: EpochIndex,
        epoch_end: EpochIndex,
    ) -> Pcd<delegation::NullifierDerivation> {
        let base = epoch_start.0 - epoch_start.0 % PoseidonFp::RATE as u32;
        let windows = (epoch_end.0 - base).div_ceil(NF_DERIVATION_WIDTH as u32);
        let cover_end = base + windows * NF_DERIVATION_WIDTH as u32;
        let key = (Tachygram::from(note.commitment()), base, cover_end);
        if let Some(pcd) = self.derivations.borrow().get(&key) {
            return pcd.clone();
        }
        let master = self.master_pcd(rng, note);

        let mut merged: Option<Pcd<delegation::NullifierDerivation>> = None;
        for window in 0..windows {
            let chunk_start = EpochIndex(base + window * NF_DERIVATION_WIDTH as u32);
            let chunk_end = EpochIndex(chunk_start.0 + NF_DERIVATION_WIDTH as u32);
            let (leaf, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    delegation::NfDerive,
                    witness::nf_derive((*master.data(), ()), chunk_start),
                    master.clone(),
                    Proof::trivial().carry::<()>(()),
                )
                .expect("NfDerive");
            merged = Some(match merged {
                None => leaf,
                Some(left) => {
                    let left_nfs: Vec<Nullifier> = (base..chunk_start.0)
                        .map(|epoch| self.nf_at(&note, EpochIndex(epoch)))
                        .collect();
                    let right_nfs: Vec<Nullifier> = (chunk_start.0..chunk_end.0)
                        .map(|epoch| self.nf_at(&note, EpochIndex(epoch)))
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
                        .expect("NullifierFuse");
                    fused
                },
            });
        }
        let pcd = merged.expect("nonempty range");

        self.derivations.borrow_mut().insert(key, pcd.clone());
        pcd
    }

    pub fn spendable_init<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        note: &Note,
        pool: &PoolSim,
        init_height: BlockHeight,
    ) -> Pcd<spendable::SpendableHeader> {
        let cm = note.commitment();
        let epoch = init_height.epoch();
        let (pre_cm_anchor, creation_tgs) = {
            let stamps = pool.block(init_height).tachygrams();
            let stamp_commits = pool.block(init_height).stamp_commits();
            let cm_idx = stamps
                .iter()
                .position(|tgs| tgs.contains(&cm.into()))
                .expect("cm not found in any stamp at the cm-block");

            // Anchor immediately before the cm-stamp (the cm-block prefix fold).
            let pre_cm_anchor = stamp_commits[..cm_idx]
                .iter()
                .fold(pool.block(init_height).prev, |anchor, commit| {
                    anchor.next_stamp(init_height.epoch(), commit).unwrap()
                });

            (pre_cm_anchor, stamps[cm_idx].clone())
        };
        let deriv = self.derivation_pcd(rng, *note, epoch, epoch.next());

        let (spendable, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spendable::SpendableInit,
                witness::spendable_init(
                    (*deriv.data(), ()),
                    pre_cm_anchor,
                    &creation_tgs,
                    epoch,
                    &self.covering_window(note, &deriv),
                ),
                deriv,
                Proof::trivial().carry::<()>(()),
            )
            .expect("SpendableInit");
        spendable
    }

    pub fn fresh_spend<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        pool: &PoolSim,
        height: BlockHeight,
        spend_note: &Note,
    ) -> Pcd<spendable::SpendableHeader> {
        self.spendable_init(rng, spend_note, pool, height)
    }

    /// Attribute `arbitrary`'s tested values to `note`, over a window derived
    /// to cover the span the segment announces on its own header.
    pub fn unspent_bind<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        arbitrary: Pcd<pool::ArbitraryUnspent>,
        note: &Note,
    ) -> Pcd<pool::Unspent> {
        let (_, (epoch_start, _), _, (present_epoch, _), _) = *arbitrary.data();
        let range = self.derivation_pcd(rng, *note, epoch_start, present_epoch.next());
        let elapsed: Vec<Nullifier> = (epoch_start.0..=present_epoch.0)
            .map(|epoch| self.nf_at(note, EpochIndex(epoch)))
            .collect();
        let (unspent, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                pool::UnspentBind,
                witness::unspent_bind(
                    (*arbitrary.data(), *range.data()),
                    &self.covering_window(note, &range),
                    &elapsed,
                ),
                arbitrary,
                range,
            )
            .expect("UnspentBind");
        unspent
    }

    pub fn lift<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        spendable: Pcd<spendable::SpendableHeader>,
        arbitrary: Pcd<pool::ArbitraryUnspent>,
        note: &Note,
    ) -> Pcd<spendable::SpendableHeader> {
        let unspent = self.unspent_bind(rng, arbitrary, note);
        let (lifted, ()) = PROOF_SYSTEM
            .fuse(rng, spendable::SpendableLift, (), spendable, unspent)
            .expect("SpendableLift");
        lifted
    }

    /// Advance `spendable` from wherever it rests to `target`, over a segment
    /// this builds: from its current anchor to `target`'s first block, so the
    /// span carries every crossing on the way plus a tested nullifier in
    /// `target`. The starting epoch comes off the header, so the caller needs
    /// no height.
    pub fn lift_to_epoch<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        pool: &PoolSim,
        note: &Note,
        spendable: Pcd<spendable::SpendableHeader>,
        target: EpochIndex,
    ) -> Pcd<spendable::SpendableHeader> {
        let (_, (epoch, _), start_anchor) = *spendable.data();
        let elapsed: Vec<Nullifier> = (epoch.0..=target.0)
            .map(|index| self.nf_at(note, EpochIndex(index)))
            .collect();
        let unspent = build_unspent_pcd_between_anchors(
            rng,
            pool,
            &elapsed,
            (start_anchor, pool.block(target.first_block()).anchor()),
        );
        self.lift(rng, spendable, unspent, note)
    }

    pub fn autonome<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        anchor: Anchor,
        spends: Vec<(Note, Pcd<spendable::SpendableHeader>, EpochIndex)>,
        output_notes: Vec<Note>,
    ) -> Bundle<ProofStamp> {
        let ask = self.sk.derive_auth_private();

        let mut spend_plans = Vec::with_capacity(spends.len());
        let mut spend_pcds = Vec::with_capacity(spends.len());
        for (note, spendable_pcd, spend_epoch) in spends {
            let range_pcd =
                self.derivation_pcd(rng, note, spend_epoch, EpochIndex(spend_epoch.0 + 2));
            let rcv = value::Trapdoor::random(rng);
            let theta = ActionEntropy::random(rng);
            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                self.pak.ak.derive_action_public(&alpha)
            });
            spend_plans.push(plan);
            spend_pcds.push((range_pcd, spendable_pcd));
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
            .sign(rng, &sighash, &ask)
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
    pub const fn new() -> Self {
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

    pub fn build_next_unspent<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        handle: usize,
        pool: &PoolSim,
        target_height: BlockHeight,
    ) -> Pcd<pool::ArbitraryUnspent> {
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
            (entry.cursor_anchor, pool.block(target_height).anchor()),
        );
        let new_consumed = entry.consumed + (target_height.epoch().0 - entry.next_height.epoch().0);
        self.entries[idx].consumed = new_consumed;
        self.entries[idx].next_height = BlockHeight(target_height.0 + 1);
        self.entries[idx].cursor_anchor = pool.block(target_height).anchor();
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
