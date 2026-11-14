extern crate alloc;

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{cell::RefCell, iter, mem, ops::RangeInclusive};

use ragu::{
    header::Header,
    step::{Encoded, HeaderInput, Index, Oracles, Step},
};
use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use ragu_core::{
    PoseidonPermutation as _,
    drivers::{Driver, DriverValue},
    pasta::{Pasta, PoseidonFp},
};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use udon::field::Field as _;
use zcash_tachyon::{
    ActionSetPoly, Anchor, BlockHeight, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile,
    Tachygram, TachygramSetCommit, TachygramSetPoly,
    action::{self, Action},
    bundle::{self, Bundle},
    constants::EVIDENCE_TREE_ARITY,
    digest::blake2b,
    effect,
    entropy::ActionEntropy,
    fee,
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    nullifier::{self, NF_DERIVATION_WIDTH, Nullifier},
    pasta::Fp,
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

pub(crate) struct WithPolynomials<S>(pub S, pub [Vec<Fp>; 2]);

impl<S: Step<Pasta>> Step<Pasta> for WithPolynomials<S> {
    type Aux<'source> = S::Aux<'source>;
    type Left = S::Left;
    type Output = S::Output;
    type Right = S::Right;
    type Witness<'source> = S::Witness<'source>;

    const INDEX: Index = S::INDEX;
    const NUM_STAGED: usize = S::NUM_STAGED;

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        self.0.staged(witness, left, right)
    }

    fn polynomials(
        &self,
        _: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok(self.1.clone())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        self.0.witness(dr, oracles, witness, left, right)
    }
}

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

pub fn stamp_coverage(
    descriptors: impl IntoIterator<Item = action::Descriptor>,
    fees: &[fee::Descriptor],
) -> [u8; 32] {
    let mut descriptor_bytes: Vec<[u8; 64]> = descriptors.into_iter().collect();
    descriptor_bytes.sort_unstable();
    let mut fee_bytes: Vec<[u8; 40]> = fees.iter().copied().map(Into::into).collect();
    fee_bytes.sort_unstable();
    blake2b::stamp_coverage_digest(
        &blake2b::action_descriptor_digest(&descriptor_bytes),
        &blake2b::stamp_fees_digest(&fee_bytes),
    )
}

pub fn mock_wtxid<S: StampState + 'static>(bundle: &Bundle<S>) -> AggregateId {
    let txid = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend txid")
        .to_state()
        .update(&bundle.commitment())
        .finalize();
    let auth_digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend auth")
        .to_state()
        .update(&bundle.auth_digest())
        .finalize();
    let mut wtxid = [0u8; 64];
    wtxid[..32].copy_from_slice(txid.as_bytes());
    wtxid[32..].copy_from_slice(auth_digest.as_bytes());
    AggregateId::try_from(wtxid).unwrap()
}

pub fn random_action<RNG: CryptoRng>(rng: &mut RNG) -> Action {
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(400);
    let (_, _, plan) = build_output_plan(rng, note);
    let bundle_plan = bundle::Plan::new(
        vec![],
        vec![plan],
        WalletSim::new(shared_sk()).random_note(0),
    );
    let sighash = mock_sighash(bundle_plan.commitment().unwrap());
    let unproven = bundle_plan.sign(rng, &sighash, &ask).unwrap();
    unproven.actions[0]
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
) -> (
    ProofStamp<stamp::Uncompressed>,
    action::Plan<effect::Output>,
    fee::Descriptor,
) {
    let (stamp, plan, max_fee_note) = build_output_stamp_with_fee(rng, anchor, note);
    (
        stamp,
        plan,
        fee::Descriptor {
            cv_feemax: max_fee_note.cv_feemax(),
            v_fee: value::Positive::ZERO,
        },
    )
}

pub fn build_output_stamp_with_fee<RNG: CryptoRng>(
    rng: &mut RNG,
    anchor: Anchor,
    note: Note,
) -> (
    ProofStamp<stamp::Uncompressed>,
    action::Plan<effect::Output>,
    Note,
) {
    let (rcv, theta, plan) = build_output_plan(rng, note);
    let pak = WalletSim::new(shared_sk()).pak;
    let max_fee_note = WalletSim::random(rng).random_note(0);
    let stamp = stamp::Plan::new(
        vec![],
        vec![(plan.descriptor(), theta, note, rcv)],
        anchor,
        max_fee_note,
        value::Positive::ZERO,
    )
    .prove(rng, &pak, vec![])
    .unwrap();
    (stamp, plan, max_fee_note)
}

pub fn build_autonome<RNG: CryptoRng>(
    rng: &mut RNG,
    wallet: &WalletSim,
    spend_value: u64,
    output_value: u64,
) -> Bundle<ProofStamp<stamp::Uncompressed>> {
    let spend_note = wallet.random_note(spend_value);
    let output_note = wallet.random_note(output_value);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let stamps_cms = vec![vec![spend_note.commitment()]];
    pool.mine(random_block_with(rng, &stamps_cms, 50));
    let height = pool.height();
    let spendable_pcd = wallet.spendable_init(rng, &spend_note, &pool, height);
    let anchor = spendable_pcd.data().2;
    wallet.autonome(
        rng,
        anchor,
        vec![(spend_note, spendable_pcd)],
        vec![output_note],
    )
}

pub fn forge_overlapping_merge<RNG: CryptoRng>(
    rng: &mut RNG,
    (stamp_a, descriptors_a, fee_descriptors_a): (
        &ProofStamp<stamp::Uncompressed>,
        &Vec<action::Descriptor>,
        &[fee::Descriptor],
    ),
    (stamp_b, descriptors_b, fee_descriptors_b): (
        &ProofStamp<stamp::Uncompressed>,
        &Vec<action::Descriptor>,
        &[fee::Descriptor],
    ),
) -> ragu::Pcd<Pasta, ProductionRank, Stamp> {
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

    let left_pcd = stamp_a
        .proof
        .clone()
        .carry::<Stamp>((left_tg.commit().bridge().unwrap(), stamp_a.anchor));
    let right_pcd = stamp_b
        .proof
        .clone()
        .carry::<Stamp>((right_tg.commit().bridge().unwrap(), stamp_b.anchor));

    let merged_acts = descriptors_a
        .iter()
        .chain(descriptors_b.iter())
        .map(|desc| desc.digest().unwrap())
        .chain(
            fee_descriptors_a
                .iter()
                .chain(fee_descriptors_b)
                .copied()
                .map(|descriptor| descriptor.digest().unwrap()),
        )
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
            witness::stamp_merge(
                (*left_pcd.data(), *right_pcd.data()),
                merged_acts,
                merged_tg,
            ),
            left_pcd,
            right_pcd,
        )
        .unwrap();

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
}

pub(crate) fn build_anchor_span_pcd<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    range: RangeInclusive<BlockHeight>,
) -> (
    ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>,
    Vec<Anchor>,
) {
    let start = *range.start();
    let end = *range.end();
    assert_eq!(start.epoch(), end.epoch());
    assert!(start <= end);

    let mut state = pool.block(start).prev;
    let mut span: Option<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>> = None;
    let mut members = Vec::new();
    let mut height = start;
    loop {
        for tgs in &pool
            .block(height)
            .stamps
            .iter()
            .map(|stamp| stamp.1.clone())
            .collect::<Vec<_>>()
        {
            let witness = witness::anchor_span_seed(((), ()), state, height.epoch(), tgs);
            let next_state = state.next_stamp(witness.1, &witness.2.commit()).unwrap();
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

pub(crate) fn build_lift_span<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    range: RangeInclusive<BlockHeight>,
) -> ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan> {
    build_anchor_span_pcd(rng, pool, range).0
}

pub(crate) struct QrIntakeEntry {
    pub pcd: ragu::Pcd<Pasta, ProductionRank, qr::QrIntake>,
    pub members: Vec<Tachygram>,
}

pub(crate) struct QrBucketEntry {
    pub pcd: ragu::Pcd<Pasta, ProductionRank, qr::QrBucket>,
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
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
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
        let first = run.first().unwrap();
        let epoch = pool.anchor_index[&first.0].0.epoch();
        if run.len() == 1 && first.1.len() > capacity {
            let witness =
                witness::qr_stamp_intake_seed(((), ()), first.0, epoch, discriminant, &first.1);
            let (pcd, ()) = PROOF_SYSTEM
                .seed(rng, qr::QrStampIntakeSeed, witness)
                .unwrap();
            roots.push(QrIntakeEntry {
                pcd,
                members: first.1.clone(),
            });
            continue;
        }
        let (mut summary, ()) = PROOF_SYSTEM
            .seed(
                rng,
                summary::SummarySeed,
                witness::summary_seed(((), ()), first.0, epoch, &first.1),
            )
            .unwrap();
        let mut members = first.1.clone();
        for entry in &run[1..] {
            let (advanced, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    summary::SummaryAdvance,
                    witness::summary_advance((*summary.data(), ()), &members, &entry.1),
                    summary,
                    PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
                )
                .unwrap();
            members.extend(entry.1.iter().copied());
            summary = advanced;
        }
        let witness = witness::qr_summary_intake((*summary.data(), ()), discriminant);
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSummaryIntake,
                witness,
                summary,
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
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
        let (_, _, _, _, left_profile) = *left.pcd.data();
        let (_, _, _, _, right_profile) = *right.pcd.data();
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
    let (_epoch, _anchor_prev, _anchor_end, discriminant, profile) = *intake.pcd.data();
    let split_witness = witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members);
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            split_witness,
            intake.pcd,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();

    let mut descend = |side: bool| {
        let (selection, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideSelect,
                witness::qr_side_select((*sides.data(), ()), &intake.members, side),
                sides.clone(),
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
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
                witness::qr_side_descend((*sides.data(), *selection.data()), side),
                sides.clone(),
                selection,
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
        let mut empty = Vec::new();
        for intake in layer {
            if intake.members.is_empty() {
                empty.push(intake);
                continue;
            }
            let (nqr_side, qr_side) = split_qr_intake(rng, intake);
            non_residue.push(nqr_side);
            residue.push(qr_side);
        }
        layer = merge_qr_run(rng, residue, capacity);
        layer.extend(merge_qr_run(rng, non_residue, capacity));
        layer.extend(empty);
    }
    layer
}

pub(crate) struct EvidenceLeaf {
    pub profile: QrProfile,
    pub contents: TachygramSetPoly,
    pub members: Vec<Tachygram>,
    pub path: Vec<([bool; 2], [EvidenceTreeRoot; EVIDENCE_TREE_ARITY])>,
}

pub(crate) struct EvidenceTreeEntry {
    pub pcd: ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>,
    pub leaves: Vec<EvidenceLeaf>,
}

pub(crate) fn build_evidence_tree<RNG: CryptoRng>(
    rng: &mut RNG,
    mut buckets: Vec<QrBucketEntry>,
) -> EvidenceTreeEntry {
    assert!(!buckets.is_empty());

    let mut width = EVIDENCE_TREE_ARITY;
    let mut depth = 1;
    while width < buckets.len() {
        width *= EVIDENCE_TREE_ARITY;
        depth += 1;
    }
    while buckets.len() < width {
        let last = buckets.last().unwrap();
        buckets.push(QrBucketEntry {
            pcd: last.pcd.clone(),
            members: last.members.clone(),
        });
    }

    let (proofs, held): (Vec<_>, Vec<_>) = buckets
        .into_iter()
        .map(|bucket| {
            let (_epoch, _anchor_start, _anchor_next, _discriminant, profile, _) =
                *bucket.pcd.data();
            let contents = bucket.members.iter().copied().collect::<TachygramSetPoly>();
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
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
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

pub(crate) fn open_evidence_tree<RNG: CryptoRng>(
    rng: &mut RNG,
    tree: ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>,
    leaf: &EvidenceLeaf,
) -> QrBucketEntry {
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
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        node = pcd;
    }

    let witness =
        witness::evidence_tree_open((*node.data(), ()), leaf.profile, leaf.contents.clone());
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            evidence::EvidenceTreeOpen,
            witness,
            node,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
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
        .unwrap();
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
        assert_eq!(roots.len(), 1);
        roots.pop().unwrap()
    };
    seal_qr_intake(rng, intake, anchor_final_prev)
}

pub(crate) fn small_epoch<RNG: CryptoRng>(rng: &mut RNG) -> (PoolSim, Anchor) {
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let final_anchor = pool.block(pool.height()).anchor();
    (pool, final_anchor)
}

pub(crate) fn qr_bucket_at<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    (start, final_anchor): (Anchor, Anchor),
    discriminant: QrDiscriminant,
    capacity: usize,
    depth: u32,
    value: Fp,
    anchor_final_prev: Anchor,
) -> QrBucketEntry {
    let profile = qr_profile_of(value, discriminant, depth);
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
    assert_eq!(branch.len(), 1);
    let intake = branch.pop().unwrap();
    assert_eq!(intake.pcd.data().4, profile);
    seal_qr_intake(rng, intake, anchor_final_prev)
}

pub(crate) fn qr_epoch_unspent<RNG: CryptoRng>(
    rng: &mut RNG,
    user: &WalletSim,
    note: &Note,
    bucket: &QrBucketEntry,
) -> ragu::Pcd<Pasta, ProductionRank, pool::NoteUnspent> {
    let arbitrary = qr_bucket_segment(rng, bucket, |epoch| {
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch)
    });
    user.unspent_bind(rng, arbitrary, note)
}

pub(crate) fn qr_bucket_segment<RNG: CryptoRng>(
    rng: &mut RNG,
    bucket: &QrBucketEntry,
    nf: impl Fn(EpochIndex) -> Nullifier,
) -> ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent> {
    let (epoch, ..) = *bucket.pcd.data();
    let witness = witness::qr_unspent_init((*bucket.pcd.data(), ()), nf(epoch).into());
    let (segment, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrUnspentInit,
            witness,
            bucket.pcd.clone(),
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    segment
}

pub(crate) fn build_unspent_pcd_over_epochs<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    nf: impl Fn(EpochIndex) -> Nullifier,
    (epoch_start, epoch_next): (EpochIndex, EpochIndex),
) -> ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent> {
    assert!(u32::from(epoch_start) < u32::from(epoch_next));
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
    mut chains: Vec<ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent>>,
) -> ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent> {
    assert!(!chains.is_empty());
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
    let (_, left_epoch_start, left_epoch_next, _) = *left.data();
    let (_, right_epoch_start, right_epoch_next, _) = *right.data();
    let left_el = elapsed_slice(left_epoch_start, left_epoch_next);
    let right_el = elapsed_slice(right_epoch_start, right_epoch_next);
    assert_eq!(u32::from(right_epoch_start), u32::from(left_epoch_next));
    let witness = witness::unspent_fuse((*left.data(), *right.data()), left_el, right_el);
    let (fused, ()) = PROOF_SYSTEM
        .fuse(rng, pool::UnspentFuse, witness, left, right)
        .unwrap();
    fused
}

pub(crate) fn shared_sk() -> private::SpendingKey {
    private::SpendingKey::random(&mut StdRng::seed_from_u64(0x7AC0_05EED))
}

pub struct WalletSim {
    pub sk: private::SpendingKey,
    pub pak: ProofAuthorizingKey,
    pub notes: RefCell<BTreeMap<u64, StdRng>>,
    pub secrets:
        RefCell<BTreeMap<Tachygram, ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret>>>,
    pub derivations: RefCell<
        BTreeMap<
            (Tachygram, u32, u32),
            ragu::Pcd<Pasta, ProductionRank, delegation::NoteNullifiers>,
        >,
    >,
}

impl WalletSim {
    pub fn new(sk: private::SpendingKey) -> Self {
        Self {
            sk,
            pak: sk.derive_proof_private(),
            notes: RefCell::new(BTreeMap::new()),
            secrets: RefCell::new(BTreeMap::new()),
            derivations: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self::new(private::SpendingKey::random(rng))
    }

    pub fn random_note(&self, value_amount: u64) -> Note {
        let pk = self.sk.derive_payment_key();
        let mut streams = self.notes.borrow_mut();
        let notes = streams.entry(value_amount).or_insert_with(|| {
            let digest = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"Tachyon-NoteRnd")
                .to_state()
                .update(&Fp::from(pk).to_bytes())
                .update(&value_amount.to_le_bytes())
                .finalize();
            let mut seed = [0u8; 32];
            seed.copy_from_slice(digest.as_bytes());
            StdRng::from_seed(seed)
        });
        Note {
            pk,
            value: value::Positive::try_from(value_amount).unwrap(),
            psi: nullifier::Trapdoor::random(notes),
            rcm: note::CommitmentTrapdoor::random(notes),
        }
    }

    #[must_use]
    pub fn covering_window(
        &self,
        note: &Note,
        range: &ragu::Pcd<Pasta, ProductionRank, delegation::NoteNullifiers>,
    ) -> Vec<Nullifier> {
        let (_, start, last) = *range.data();
        let mk = self.pak.nk.derive_note_private(note.psi);
        (u32::from(start)..=u32::from(last))
            .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
            .collect()
    }

    pub fn secret_pcd<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        note: Note,
    ) -> ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret> {
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
    ) -> ragu::Pcd<Pasta, ProductionRank, delegation::NoteNullifiers> {
        let base = u32::from(epoch_start) - u32::from(epoch_start) % PoseidonFp::RATE as u32;
        let windows = (u32::from(epoch_end) - base + 1).div_ceil(NF_DERIVATION_WIDTH as u32);
        let cover_end = base + windows * NF_DERIVATION_WIDTH as u32 - 1;
        let key = (Tachygram::from(note.commitment()), base, cover_end);
        if let Some(pcd) = self.derivations.borrow().get(&key) {
            return pcd.clone();
        }
        let secret = self.secret_pcd(rng, note);
        let mk = self.pak.nk.derive_note_private(note.psi);

        let mut merged: Option<ragu::Pcd<Pasta, ProductionRank, delegation::NoteNullifiers>> = None;
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
                    PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
                )
                .unwrap();
            merged = Some(match merged {
                None => leaf,
                Some(left) => {
                    let left_nfs: Vec<Nullifier> = (base..u32::from(chunk_start))
                        .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
                        .collect();
                    let right_nfs: Vec<Nullifier> = (u32::from(chunk_start)..=u32::from(chunk_end))
                        .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
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
    ) -> ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        let cm = note.commitment();
        let epoch = init_height.epoch();
        let (anchor_prev, creation_tgs) = {
            let stamps = pool
                .block(init_height)
                .stamps
                .iter()
                .map(|stamp| stamp.1.clone())
                .collect::<Vec<_>>();
            let cm_idx = stamps
                .iter()
                .position(|tgs| tgs.contains(&cm.into()))
                .unwrap();

            let anchor_prev = pool.block(init_height).stamps[..cm_idx]
                .iter()
                .fold(pool.block(init_height).prev, |anchor, stamp| {
                    anchor.next_stamp(init_height.epoch(), &stamp.2).unwrap()
                });

            (anchor_prev, stamps[cm_idx].clone())
        };
        let deriv = self.derivation_pcd(rng, *note, epoch, epoch);

        let (spendable, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spendable::SpendableInit,
                witness::spendable_init((*deriv.data(), ()), anchor_prev, &creation_tgs, epoch),
                deriv,
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        spendable
    }

    pub fn unspent_bind<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        arbitrary: ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent>,
        note: &Note,
    ) -> ragu::Pcd<Pasta, ProductionRank, pool::NoteUnspent> {
        let (_, epoch_start, epoch_next, _) = *arbitrary.data();
        let range = self.derivation_pcd(rng, *note, epoch_start, epoch_next);
        let mk = self.pak.nk.derive_note_private(note.psi);
        let elapsed: Vec<Nullifier> = (u32::from(epoch_start)..u32::from(epoch_next))
            .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
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
            .unwrap();
        unspent
    }

    pub fn lift<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        spendable: ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
        arbitrary: ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent>,
        note: &Note,
    ) -> ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        let unspent = self.unspent_bind(rng, arbitrary, note);
        let (lifted, ()) = PROOF_SYSTEM
            .fuse(rng, spendable::SpendableLift, (), spendable, unspent)
            .unwrap();
        lifted
    }

    pub fn lift_to_epoch<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        pool: &PoolSim,
        note: &Note,
        spendable: ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
        target: EpochIndex,
    ) -> ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        let (_, epoch, _) = *spendable.data();
        let mk = self.pak.nk.derive_note_private(note.psi);
        if epoch == target {
            return spendable;
        }
        let unspent = build_unspent_pcd_over_epochs(
            rng,
            pool,
            |covered| mk.derive_nullifier(covered),
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
    ) -> ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        let creation_height = pool
            .history
            .iter()
            .position(|block| {
                block
                    .stamps
                    .iter()
                    .any(|stamp| stamp.1.contains(&Tachygram::from(note.commitment())))
            })
            .unwrap();
        let creation = BlockHeight::from(creation_height).epoch();
        let bucket = epoch_bucket(rng, pool, creation);
        let mk = self.pak.nk.derive_note_private(note.psi);
        let arbitrary = qr_bucket_segment(rng, &bucket, |epoch| mk.derive_nullifier(epoch));
        let unspent = self.unspent_bind(rng, arbitrary, note);
        let (spendable, ()) = PROOF_SYSTEM
            .fuse(rng, spendable::QrSpendableInit, (), unspent, bucket.pcd)
            .unwrap();
        self.lift_to_epoch(rng, pool, note, spendable, target)
    }

    pub fn autonome<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        anchor: Anchor,
        spends: Vec<(
            Note,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
        )>,
        output_notes: Vec<Note>,
    ) -> Bundle<ProofStamp<stamp::Uncompressed>> {
        let (bundle_plan, unproven, spend_pcds) =
            self.signed(rng, spends, output_notes, self.random_note(0));
        let stamp_plan = bundle_plan.stamp_plan(anchor, value::Positive::ZERO);
        let stamp = stamp_plan.prove(rng, &self.pak, spend_pcds).unwrap();

        unproven.stamp(stamp)
    }

    pub fn signed<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        spends: Vec<(
            Note,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
        )>,
        output_notes: Vec<Note>,
        max_fee_note: Note,
    ) -> (
        bundle::Plan,
        Bundle<Unproven>,
        Vec<(
            ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
            Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
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

    pub fn fee_bundle<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        spend_value: u64,
        output_value: u64,
        feemax: u64,
    ) -> (
        bundle::Plan,
        Bundle<Unproven>,
        Vec<(
            ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
            Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
        )>,
        Anchor,
        Note,
    ) {
        let spend_note = self.random_note(spend_value);
        let output_note = self.random_note(output_value);
        let max_fee_note = self.random_note(feemax);

        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
        pool.mine(random_block_with(rng, &[vec![spend_note.commitment()]], 50));
        let height = pool.height();
        let spendable_pcd = self.spendable_init(rng, &spend_note, &pool, height);
        let anchor = spendable_pcd.data().2;

        let (bundle_plan, signed, spend_pcds) = self.signed(
            rng,
            vec![(spend_note, spendable_pcd)],
            vec![output_note],
            max_fee_note,
        );
        (bundle_plan, signed, spend_pcds, anchor, max_fee_note)
    }
}
