extern crate alloc;

use alloc::{collections::BTreeMap, string::ToString as _, vec, vec::Vec};
use core::{cell::RefCell, iter, mem, ops::RangeInclusive};

use ragu::{Header, Pcd, Proof};
use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use ragu_core::{PoseidonPermutation as _, pasta::PoseidonFp};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};
use zcash_tachyon::{
    ActionDigest, ActionSetPoly, Anchor, AnchorSetPoly, BlockHeight, EpochIndex, EvidenceTreeRoot,
    QrDiscriminant, QrProfile, Tachygram, TachygramSetCommit, TachygramSetPoly, action,
    bundle::{self, Bundle},
    constants::EVIDENCE_TREE_ARITY,
    digest::blake2b,
    effect,
    entropy::ActionEntropy,
    fee,
    keys::{NoteMasterKey, ProofAuthorizingKey, private},
    note::{self, Note},
    nullifier::{self, NF_DERIVATION_WIDTH, Nullifier},
    pasta::{Eq, Fp},
    stamp::{
        self, AggregateId, ProofStamp, StampState, Unproven,
        proof::{
            PROOF_SYSTEM, delegation, evidence, pool, qr, spendable,
            stamp::{Stamp, StampMerge},
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

pub fn fee_digests(
    fees: impl IntoIterator<Item = fee::Descriptor>,
) -> impl Iterator<Item = ActionDigest> {
    fees.into_iter()
        .map(|fee| fee.digest().expect("fee digest"))
}

pub fn stamp_coverage(descriptors: &[[u8; 64]], fees: &[fee::Descriptor]) -> [u8; 32] {
    let mut fee_bytes: Vec<[u8; 40]> = fees.iter().copied().map(Into::into).collect();
    fee_bytes.sort_unstable();
    blake2b::stamp_coverage_digest(
        &blake2b::action_descriptor_digest(descriptors),
        &blake2b::stamp_fees_digest(&fee_bytes),
    )
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

/// Distinct from [`mock_sighash`] to catch conflating sighash with txid.
pub fn mock_wtxid<S: StampState + 'static>(bundle: &Bundle<S>) -> AggregateId {
    let mut wtxid = [0u8; 64];
    wtxid[..32].copy_from_slice(&mock_txid(bundle.commitment()));
    wtxid[32..].copy_from_slice(&mock_auth_digest(bundle.auth_digest()));

    AggregateId::try_from(wtxid).expect("nonzero wtxid")
}

pub fn random_action<RNG: CryptoRng>(rng: &mut RNG) -> action::Action {
    let wallet = WalletSim::random(rng);
    let (_, _, plan) = build_output_plan(rng, wallet.random_note(400));
    let bundle_plan = bundle::Plan::new(vec![], vec![plan], wallet.random_note(0));
    let sighash = mock_sighash(bundle_plan.commitment().expect("fixture commitment"));
    bundle_plan
        .sign(rng, &sighash, &wallet.sk.derive_auth_private())
        .expect("sign a foreign output")
        .actions[0]
}

pub fn build_output_plan<RNG: CryptoRng>(
    rng: &mut RNG,
    note: Note,
) -> (value::Trapdoor, ActionEntropy, action::Plan<effect::Output>) {
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let plan = action::Plan::output(note, theta, rcv);
    (rcv, theta, plan)
}

pub fn build_output_stamp<RNG: CryptoRng>(
    rng: &mut RNG,
    anchor: Anchor,
    note: Note,
) -> (ProofStamp, action::Plan<effect::Output>, fee::Descriptor) {
    let (rcv, theta, plan) = build_output_plan(rng, note);
    // An output-only plan never reads the proof authorizing key.
    let wallet = WalletSim::random(rng);
    let max_fee_note = wallet.random_note(0);
    let stamp = stamp::Plan::new(
        vec![],
        vec![(plan.descriptor(), theta, note, rcv)],
        anchor,
        max_fee_note,
        value::Positive::ZERO,
    )
    .prove(rng, &wallet.pak, vec![])
    .expect("prove an output stamp");
    (
        stamp,
        plan,
        fee::Descriptor {
            max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
            value: value::Positive::ZERO,
        },
    )
}

/// `StampMerge` proves a multiset union, so intersecting stamps still merge.
pub fn forge_overlapping_merge<RNG: CryptoRng>(
    rng: &mut RNG,
    (stamp_a, descriptors_a, fee_descriptors_a): (
        &ProofStamp,
        &Vec<action::Descriptor>,
        &[fee::Descriptor],
    ),
    (stamp_b, descriptors_b, fee_descriptors_b): (
        &ProofStamp,
        &Vec<action::Descriptor>,
        &[fee::Descriptor],
    ),
) -> Pcd<Stamp> {
    let left_acts = descriptors_a
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests(fee_descriptors_a.iter().copied()))
        .collect::<ActionSetPoly>();
    let right_acts = descriptors_b
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests(fee_descriptors_b.iter().copied()))
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

    let left_pcd = stamp_a.proof.clone().carry::<Stamp>((
        left_acts.commit(),
        left_tg.commit(),
        stamp_a.anchor,
    ));
    let right_pcd = stamp_b.proof.clone().carry::<Stamp>((
        right_acts.commit(),
        right_tg.commit(),
        stamp_b.anchor,
    ));

    let merged_acts = descriptors_a
        .iter()
        .chain(descriptors_b.iter())
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests(
            fee_descriptors_a.iter().chain(fee_descriptors_b).copied(),
        ))
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
            StampMerge,
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
    assert!(
        n_stamps >= stamps_cms.len(),
        "n_stamps must accommodate every stamp in stamps_cms"
    );
    let mut stamps: Vec<Vec<Tachygram>> = stamps_cms
        .iter()
        .map(|cms| cms.iter().map(|&cm| Tachygram::from(cm)).collect())
        .collect();
    stamps.extend(
        iter::repeat_with(|| alloc::vec![Tachygram::random(rng)]).take(n_stamps - stamps_cms.len()),
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
                let stamp_after = anchor
                    .next_stamp(epoch, &commit)
                    .expect("a stamp advances the anchor");
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

    /// Only an epoch-first block enters at an anchor not yet indexed.
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

    pub fn epoch_of(&self, tachygram: Tachygram) -> EpochIndex {
        let height = self
            .history
            .iter()
            .position(|block| {
                block
                    .stamps
                    .iter()
                    .any(|stamp| stamp.1.contains(&tachygram))
            })
            .expect("the tachygram was published");
        BlockHeight::from(height).epoch()
    }

    pub fn epoch_at(&self, anchor: Anchor) -> EpochIndex {
        self.anchor_index[&anchor].0.epoch()
    }

    pub fn mine(&mut self, stamps: Vec<Vec<Tachygram>>) {
        let new_height = BlockHeight::from(self.history.len());
        let old_tip = self.anchor();
        let prev = if new_height.is_first_in_epoch() {
            old_tip
                .next_epoch(new_height.epoch())
                .expect("the epoch advances the anchor")
        } else {
            old_tip
        };
        self.push_block(prev, stamps);
    }
}

pub fn small_epoch<RNG: CryptoRng>(rng: &mut RNG) -> (PoolSim, Anchor) {
    let mut pool = PoolSim::genesis_with(random_block(rng, 3, 2));
    for _ in 0..3 {
        pool.mine(random_block(rng, 3, 2));
    }
    let end = pool.anchor();
    (pool, end)
}

/// Mock ragu doesn't bind a header to its proof; the consuming step rejects it.
pub fn recarry<H: Header<Data: Copy>>(pcd: &Pcd<H>, alter: impl FnOnce(&mut H::Data)) -> Pcd<H> {
    let mut data = *pcd.data();
    alter(&mut data);
    pcd.proof().clone().carry::<H>(data)
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
        for tgs in &pool.block(height).tachygrams() {
            let witness = witness::anchor_span_seed(((), ()), state, height.epoch(), tgs);
            let next_state = state
                .next_stamp(witness.1, &witness.2)
                .expect("a stamp advances the anchor");
            let (seed, ()) = PROOF_SYSTEM
                .seed(rng, pool::AnchorSpanSeed, witness)
                .expect("AnchorSpanSeed");
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
                        .expect("AnchorSpanFuse");
                    fused
                },
            });
            members.push(next_state);
            state = next_state;
        }
        if height >= end {
            break;
        }
        height = height.next().expect("a block follows");
    }

    (
        span.expect("AnchorSpan range must cover at least one stamp"),
        members,
    )
}

pub(crate) fn build_lift_span<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    range: RangeInclusive<BlockHeight>,
) -> (Pcd<pool::AnchorSpan>, AnchorSetPoly) {
    let (span, members) = build_anchor_span_pcd(rng, pool, range);
    (span, AnchorSetPoly::from_iter(members))
}

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
                Proof::bootstrap().carry::<()>(()),
            )
            .expect("SummaryAdvance");
        acc.extend(entry.1.iter().copied());
        pcd = advanced;
    }
    assert_eq!(pcd.data().2, end, "the summary closes at the span's end");

    (pcd, acc)
}

#[derive(Clone)]
pub(crate) struct QrIntakeEntry {
    pub pcd: Pcd<qr::QrIntake>,
    pub members: Vec<Tachygram>,
}

#[derive(Clone)]
pub(crate) struct QrBucketEntry {
    pub pcd: Pcd<qr::QrBucket>,
    pub members: Vec<Tachygram>,
}

pub(crate) fn seal_qr_intake<RNG: CryptoRng>(
    rng: &mut RNG,
    intake: QrIntakeEntry,
    anchor_final_prev: Anchor,
) -> QrBucketEntry {
    let witness = witness::qr_bucket_seal((*intake.pcd.data(), ()), anchor_final_prev);
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness,
            intake.pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .expect("QrBucketSeal");
    QrBucketEntry {
        pcd,
        members: intake.members,
    }
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
        let (first, last) = (
            run.first().expect("nonempty run"),
            run.last().expect("nonempty run"),
        );
        if run.len() == 1 && first.1.len() > capacity {
            let (entry, members) = (first.0, first.1.clone());
            let witness = witness::qr_stamp_intake_seed(
                ((), ()),
                entry,
                pool.epoch_at(entry),
                discriminant,
                &members,
            );
            let (pcd, ()) = PROOF_SYSTEM
                .seed(rng, qr::QrStampIntakeSeed, witness)
                .expect("QrStampIntakeSeed");
            roots.push(QrIntakeEntry { pcd, members });
            continue;
        }
        let (summary, members) = build_summary_pcd(rng, pool, (first.0, last.3));
        let witness = witness::qr_summary_intake((*summary.data(), ()), discriminant);
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSummaryIntake,
                witness,
                summary,
                Proof::bootstrap().carry::<()>(()),
            )
            .expect("QrSummaryIntake");
        roots.push(QrIntakeEntry { pcd, members });
    }
    roots
}

/// Same-profile neighbours in a layer are exactly the pairs whose spans meet.
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
                Proof::bootstrap().carry::<()>(()),
            )
            .expect("QrSideDescend");
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
        let last = buckets.last().expect("nonempty tree").clone();
        buckets.push(last);
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
            .expect("EvidenceTreeLeafPair");
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
            .expect("EvidenceTreeFuse");
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
                .expect("EvidenceTreePairFuse");
            let (right, ()) = PROOF_SYSTEM
                .fuse(rng, evidence::EvidenceTreePairFuse, (), third, fourth)
                .expect("EvidenceTreePairFuse");
            let (pcd, ()) = PROOF_SYSTEM
                .fuse(rng, evidence::EvidenceTreeFuse, (), left, right)
                .expect("EvidenceTreeFuse");
            parents.push(pcd);
        }
        levels.push(parents.iter().map(|pcd| pcd.data().4).collect());
        layer = parents;
    }

    let mut root = layer.pop().expect("one root");
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
            .expect("EvidenceTreeCap");
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
        let path =
            <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(chunk).expect("a full descent");
        let witness = witness::evidence_tree_descend((*node.data(), ()), path);
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                evidence::EvidenceTreeDescend,
                witness,
                node,
                Proof::bootstrap().carry::<()>(()),
            )
            .expect("EvidenceTreeDescend");
        node = pcd;
    }
    node
}

pub(crate) fn open_evidence_tree<RNG: CryptoRng>(
    rng: &mut RNG,
    tree: Pcd<evidence::EvidenceTree>,
    leaf: &EvidenceLeaf,
) -> QrBucketEntry {
    let node = descend_evidence_tree(rng, tree, leaf);
    let witness = witness::evidence_tree_open((*node.data(), ()), leaf.profile, leaf.contents);
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            evidence::EvidenceTreeOpen,
            witness,
            node,
            Proof::bootstrap().carry::<()>(()),
        )
        .expect("EvidenceTreeOpen");
    QrBucketEntry {
        pcd,
        members: leaf.members.clone(),
    }
}

pub(crate) fn qr_profile_of(value: Fp, discriminant: QrDiscriminant, depth: u32) -> QrProfile {
    let mut profile = QrProfile::ROOT;
    for level in 0..depth {
        profile = profile.descend(qr::classify(value, discriminant.at(level)).0);
    }
    profile
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
    let intake = branch.pop().expect("one intake");
    assert_eq!(
        intake.pcd.data().4,
        qr_profile_of(value, discriminant, depth)
    );
    seal_qr_intake(rng, intake, anchor_final_prev)
}

pub fn qr_epoch_unspent<RNG: CryptoRng>(
    rng: &mut RNG,
    wallet: &WalletSim,
    note: &Note,
    bucket: &QrBucketEntry,
) -> Pcd<pool::NoteUnspent> {
    let arbitrary = qr_bucket_segment(rng, bucket, |epoch| wallet.nf_at(note, epoch));
    wallet.unspent_bind(rng, arbitrary, note)
}

pub fn detached_segment<RNG: CryptoRng>(
    rng: &mut RNG,
    epoch: EpochIndex,
    nf: impl Fn(EpochIndex) -> Nullifier,
) -> Pcd<pool::ArbitraryUnspent> {
    let anchor_final_prev = Anchor::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let discriminant = QrDiscriminant::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let entry = anchor_final_prev
        .next_epoch(epoch)
        .expect("a detached epoch is not epoch zero");
    let intake = seed_qr_empty_intake(rng, entry, epoch, discriminant);
    let bucket = seal_qr_intake(rng, intake, anchor_final_prev);
    qr_bucket_segment(rng, &bucket, nf)
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
            pool.mine(random_block(rng, 1, 1));
        } else {
            pool.mine(Vec::new());
        }
    }
}

pub(crate) fn seed_qr_empty_intake<RNG: CryptoRng>(
    rng: &mut RNG,
    anchor: Anchor,
    epoch: EpochIndex,
    discriminant: QrDiscriminant,
) -> QrIntakeEntry {
    let (pcd, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrEmptyIntakeSeed,
            witness::qr_empty_intake_seed(((), ()), anchor, epoch, discriminant),
        )
        .expect("QrEmptyIntakeSeed");
    QrIntakeEntry {
        pcd,
        members: Vec::new(),
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
        seed_qr_empty_intake(rng, entry, epoch, discriminant)
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
        roots.pop().expect("one root")
    };
    seal_qr_intake(rng, intake, anchor_final_prev)
}

pub(crate) fn qr_bucket_segment<RNG: CryptoRng>(
    rng: &mut RNG,
    bucket: &QrBucketEntry,
    nf: impl Fn(EpochIndex) -> Nullifier,
) -> Pcd<pool::ArbitraryUnspent> {
    let (epoch, ..) = *bucket.pcd.data();
    let witness =
        witness::qr_unspent_init((*bucket.pcd.data(), ()), nf(epoch).into(), &bucket.members);
    let (segment, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrUnspentInit,
            witness,
            bucket.pcd.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .expect("QrUnspentInit");
    segment
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
        segments.push(qr_bucket_segment(rng, &bucket, &nf));
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
        return chains.pop().expect("single chain");
    }
    let right_chains = chains.split_off(chains.len() / 2);
    let left = fuse_unspent_tree(rng, nf, base, chains);
    let right = fuse_unspent_tree(rng, nf, base, right_chains);

    let elapsed_slice = |lo: EpochIndex, hi: EpochIndex| -> &[Nullifier] {
        let from = usize::try_from(u64::from(lo - base)).expect("epoch within span");
        let to = usize::try_from(u64::from(hi - base)).expect("epoch within span");
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
        .expect("UnspentFuse");
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
    pub fn covering_window(
        &self,
        note: &Note,
        range: &Pcd<delegation::NoteNullifiers>,
    ) -> Vec<Nullifier> {
        let (_, start, _, last) = *range.data();
        (u32::from(start)..=u32::from(last))
            .map(|epoch| self.nf_at(note, EpochIndex::new(epoch)))
            .collect()
    }

    pub fn nf_at(&self, note: &Note, epoch: EpochIndex) -> Nullifier {
        self.mk(note).derive_nullifier(epoch)
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
            .expect("NoteSeed");

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
                .expect("NullifierDerive");
            merged = Some(match merged {
                None => leaf,
                Some(left) => {
                    let left_nfs: Vec<Nullifier> = (base..u32::from(chunk_start))
                        .map(|epoch| self.nf_at(&note, EpochIndex::new(epoch)))
                        .collect();
                    let right_nfs: Vec<Nullifier> = (u32::from(chunk_start)..=u32::from(chunk_end))
                        .map(|epoch| self.nf_at(&note, EpochIndex::new(epoch)))
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
    ) -> Pcd<spendable::NoteSpendable> {
        let cm = note.commitment();
        let epoch = init_height.epoch();
        let (anchor_prev, creation_tgs) = {
            let stamps = pool.block(init_height).tachygrams();
            let stamp_commits = pool.block(init_height).stamp_commits();
            let cm_idx = stamps
                .iter()
                .position(|tgs| tgs.contains(&cm.into()))
                .expect("cm not found in any stamp at the cm-block");

            let anchor_prev = stamp_commits[..cm_idx].iter().fold(
                pool.block(init_height).prev,
                |anchor, commit| {
                    anchor
                        .next_stamp(init_height.epoch(), commit)
                        .expect("a stamp advances the anchor")
                },
            );

            (anchor_prev, stamps[cm_idx].clone())
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
            .expect("SpendableInit");
        spendable
    }

    pub fn fresh_spend<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        pool: &PoolSim,
        height: BlockHeight,
        spend_note: &Note,
    ) -> Pcd<spendable::NoteSpendable> {
        self.spendable_init(rng, spend_note, pool, height)
    }

    pub fn unspent_bind<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        arbitrary: Pcd<pool::ArbitraryUnspent>,
        note: &Note,
    ) -> Pcd<pool::NoteUnspent> {
        let (_, epoch_start, _, epoch_next, _) = *arbitrary.data();
        let range = self.derivation_pcd(rng, *note, epoch_start, epoch_next);
        let elapsed: Vec<Nullifier> = (u32::from(epoch_start)..u32::from(epoch_next))
            .map(|epoch| self.nf_at(note, EpochIndex::new(epoch)))
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
        spendable: Pcd<spendable::NoteSpendable>,
        arbitrary: Pcd<pool::ArbitraryUnspent>,
        note: &Note,
    ) -> Pcd<spendable::NoteSpendable> {
        let unspent = self.unspent_bind(rng, arbitrary, note);
        let (lifted, ()) = PROOF_SYSTEM
            .fuse(rng, spendable::SpendableLift, (), spendable, unspent)
            .expect("SpendableLift");
        lifted
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
        let unspent = build_unspent_pcd_over_epochs(
            rng,
            pool,
            |covered| self.nf_at(note, covered),
            (epoch, target),
        );
        self.lift(rng, spendable, unspent, note)
    }

    pub fn spendable_at<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        pool: &PoolSim,
        note: &Note,
        target: EpochIndex,
    ) -> Pcd<spendable::NoteSpendable> {
        let creation = pool.epoch_of(Tachygram::from(note.commitment()));
        let bucket = epoch_bucket(rng, pool, creation);
        let arbitrary = qr_bucket_segment(rng, &bucket, |epoch| self.nf_at(note, epoch));
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
            .expect("QrSpendableInit");
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
        let stamp = stamp_plan
            .prove(rng, &self.pak, spend_pcds)
            .expect("prove autonome stamp");

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
        let sighash = mock_sighash(bundle_plan.commitment().expect("fixture commitment"));
        let unproven = bundle_plan
            .sign(rng, &sighash, &ask)
            .expect("sign autonome");

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

/// A member whose factor $(m + (i+1)X)^3 - 2$ matches `member`'s at `z`.
pub fn cube_root_twin(epoch: EpochIndex, member: Fp, z: Fp) -> Fp {
    let shift = (Fp::from(u64::from(epoch)) + Fp::ONE) * z;
    (Fp::ZETA * (member + shift)) - shift
}

pub fn tachygrams<RNG: CryptoRng>(rng: &mut RNG, count: usize) -> Vec<Tachygram> {
    iter::repeat_with(|| Tachygram::from(Fp::random(|bytes| rng.fill_bytes(bytes))))
        .take(count)
        .collect()
}

#[track_caller]
pub fn assert_rejected(result: ragu_core::Result<()>, expected: &str) {
    match result {
        Ok(()) => panic!("the step accepted a witness it should reject with {expected:?}"),
        Err(ragu_core::Error::InvalidWitness(inner)) => {
            assert_eq!(inner.to_string(), expected, "the rejection");
        },
        Err(err) => panic!("expected InvalidWitness {expected:?}, got {err:?}"),
    }
}
