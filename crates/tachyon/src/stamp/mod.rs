//! Stamps and anchors.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

pub mod proof;

use alloc::{boxed::Box, collections::BTreeSet, vec, vec::Vec};
use core::fmt;

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, Into, PartialEq};
use ff::PrimeField as _;
use group::Group as _;
use pasta_curves::Fp;
use proof::{
    PROOF_SYSTEM, output,
    pool::{AnchorChain, AnchorFuse, AnchorSeed, EmptyBlockSeed},
    stamp::{MergeStamp, OutputStamp, SpendStamp, StampHeader, StampLift},
};
use ragu::{self, proof::PROOF_SIZE_COMPRESSED};
use rand_core::{CryptoRng, RngCore};

use crate::{
    ActionSetPoly, Note, TachygramSetPoly, action,
    bundle::{BundleState, StateByte},
    digest::blake2b,
    effect,
    entropy::ActionRandomizer,
    keys::ProofAuthorizingKey,
    primitives::{
        ActionDigest, ActionDigestError, Anchor, EpochIndex, Tachygram, TachygramSetCommit,
    },
    serialization,
    stamp::proof::{delegation, spend, spendable},
    value,
};

/// Marker for a bundle that has not yet been proven.
///
/// This is the initial state for a newly constructed bundle.
/// Proving produces a [`ProofStamp`].
///
/// `Unproven` has no wire representation: it does not implement
/// [`StampState`], so an unproven bundle cannot be serialized.
///
/// ```compile_fail,E0599
/// use zcash_tachyon::{Bundle, Unproven, bundle::Signature};
///
/// let unproven = Bundle {
///     actions: vec![],
///     value_balance: 0,
///     binding_sig: Signature::from([0u8; 64]),
///     stamp: Unproven,
/// };
///
/// let mut buf = vec![];
/// unproven.write(&mut buf); // no `write` on `Bundle<Unproven>`
/// ```
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct Unproven;

/// The 64-byte `wtxid` of the covering aggregate in the same block, assigned by
/// the miner during block assembly.
///
/// Use of the wtxid unambiguously pins the aggregate's specific auth state.
///
/// The all-zero wtxid (which refers to no aggregate) is rejected.
#[derive(Clone, Copy, Debug, Into, PartialEq, TotalEq)]
pub struct PointerStamp([u8; 64]);

#[derive(Clone, Copy, Debug, Display, Error)]
/// Errors that can occur when handling an aggregate id.
pub enum AggregateIdError {
    /// The aggregate id is zero and refers to no aggregate.
    #[display("aggregate id is zero and refers to no aggregate")]
    Zero,
}

impl TryFrom<(&[u8; 32], &[u8; 32])> for PointerStamp {
    type Error = AggregateIdError;

    fn try_from((sighash, auth_digest): (&[u8; 32], &[u8; 32])) -> Result<Self, Self::Error> {
        let mut wtxid = [0u8; 64];
        wtxid[..32].copy_from_slice(sighash);
        wtxid[32..].copy_from_slice(auth_digest);
        Self::try_from(wtxid)
    }
}

impl TryFrom<[u8; 64]> for PointerStamp {
    type Error = AggregateIdError;

    fn try_from(wtxid: [u8; 64]) -> Result<Self, Self::Error> {
        if wtxid == [0u8; 64] {
            return Err(AggregateIdError::Zero);
        }
        Ok(Self(wtxid))
    }
}

/// Bundle states that carry a stamp: [`ProofStamp`] or [`PointerStamp`].
/// The intermediate [`Unproven`] state has no stamp.
pub trait StampState: BundleState {
    /// A stamp's 64-byte `tachyonStampState`.
    ///
    /// For a [`ProofStamp`], this is a digest of the stamp data.
    /// For a [`PointerStamp`], this is the wtxid directly.
    fn stamp_digest(&self) -> [u8; 64];

    /// The `tachyonBundleState` wire byte for this state.
    fn state_byte() -> StateByte
    where
        Self: Sized;

    /// Read the stamp trailer from the consensus wire format.
    fn read<R: Read>(reader: R) -> io::Result<Self>
    where
        Self: Sized;

    /// Write the stamp trailer in the consensus wire format.
    fn write<W: Write>(&self, writer: W) -> io::Result<()>
    where
        Self: Sized;
}

impl StampState for PointerStamp {
    fn stamp_digest(&self) -> [u8; 64] {
        self.0
    }

    fn state_byte() -> StateByte {
        StateByte::PointerStamped
    }

    /// Read an aggregate id from the consensus wire format.
    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut wtxid = [0u8; 64];
        reader.read_exact(&mut wtxid)?;
        Self::try_from(wtxid).map_err(|_err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "aggregate id is zero and refers to no aggregate",
            )
        })
    }

    /// Write an aggregate id to the consensus wire format.
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.0 == [0u8; 64] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "aggregate id is zero and refers to no aggregate",
            ));
        }
        writer.write_all(&self.0)
    }
}

impl StampState for ProofStamp {
    fn stamp_digest(&self) -> [u8; 64] {
        let stamp_data_digest: [u8; 32] = {
            let proof = self.proof.serialize();
            let anchor: [u8; 32] = self.anchor.0.into();

            // Do NOT sort here: a constructed stamp should already be canonical.
            let tachygrams: Vec<[u8; 32]> = self
                .tachygrams
                .iter()
                .map(|&tg| Fp::from(tg).to_repr())
                .collect();

            blake2b::stamp_data_digest(
                blake2b::stamp_proof_digest(proof.as_ref()),
                anchor,
                self.tachygram_set.to_bytes(),
                &tachygrams,
            )
        };

        let mut stamp_digest = [0u8; 64];
        stamp_digest[..32].copy_from_slice(&self.coverage);
        stamp_digest[32..].copy_from_slice(&stamp_data_digest);

        stamp_digest
    }

    fn state_byte() -> StateByte {
        StateByte::ProofStamped
    }

    /// Read a stamp from the consensus wire format. The proof blob has a
    /// known constant size.
    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut covered_actions = [0u8; 32];
        reader.read_exact(&mut covered_actions)?;

        let anchor = Anchor::read(&mut reader)?;

        // Parsing does not confirm this against the tachygrams below: an MSM
        // over attacker-supplied bytes is a denial-of-service vector. See
        // `ProofStamp::is_accumulating`.
        let tachygram_set = TachygramSetCommit::read(&mut reader)?;

        // `n_tachygrams` is attacker-controlled up to MAX_COMPACT_SIZE (2^25), so
        // do not pre-allocate vector capacity. vector reads are ASSUMED to hit
        // invalid data or EOF before significant problems occur.
        // TODO: assert a reasonable maximum, to allow pre-allocation?
        let n_tachygrams = usize::try_from(serialization::read_compactsize(&mut reader)?)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        let mut tachygrams: BTreeSet<Tachygram> = BTreeSet::new();
        for _ in 0..n_tachygrams {
            let tg = Tachygram::from(serialization::read_fp(&mut reader)?);

            if !tachygrams.insert(tg) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tachygrams are not unique",
                ));
            }

            if tachygrams.last().is_none_or(|&last| last != tg) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tachygrams are not canonically sorted",
                ));
            }
        }

        let proof = {
            let mut bytes = vec![0u8; PROOF_SIZE_COMPRESSED];
            reader.read_exact(&mut bytes)?;

            let proof_bytes: &[u8; PROOF_SIZE_COMPRESSED] =
                bytes.as_slice().try_into().map_err(|_err| {
                    io::Error::new(io::ErrorKind::InvalidData, "failed to read proof")
                })?;

            ragu::Proof::try_from(proof_bytes).map_err(|_err| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid proof encoding")
            })?
        };

        Ok(Self {
            coverage: covered_actions,
            anchor,
            tachygram_set,
            tachygrams,
            proof: Box::new(proof),
        })
    }

    /// Write a stamp to the consensus wire format. The proof blob has a
    /// known constant size.
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.coverage)?;
        self.anchor.write(&mut writer)?;
        self.tachygram_set.write(&mut writer)?;
        serialization::write_compactsize(
            &mut writer,
            u64::try_from(self.tachygrams.len()).map_err(|_err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tachygram vector length exceeds u64",
                )
            })?,
        )?;
        for &tg in &self.tachygrams {
            serialization::write_fp(&mut writer, &Fp::from(tg))?;
        }
        writer.write_all(self.proof.serialize().as_ref())
    }
}

/// Everything needed to produce a [`ProofStamp`].
///
/// Each action is described by a public descriptor `(cv, rk)` and a
/// private witness `(alpha, note, rcv)`. The `prove` method generates
/// a leaf proof for each action, then merges pairwise into a single
/// stamp.
///
/// Construct via [`Plan::new`] with pre-derived action witnesses, or
/// via [`Plan::stamp_plan`](crate::bundle::Plan::stamp_plan)
/// for the typed single-party path.
#[derive(Clone, Debug)]
pub struct Plan {
    spends: Vec<(
        action::Descriptor,
        ActionRandomizer<effect::Spend>,
        Note,
        value::Trapdoor,
    )>,
    outputs: Vec<(
        action::Descriptor,
        ActionRandomizer<effect::Output>,
        Note,
        value::Trapdoor,
    )>,
    anchor: Anchor,
}

impl Plan {
    /// Create a stamp plan from paired action descriptors and witnesses.
    #[must_use]
    pub const fn new(
        spends: Vec<(
            action::Descriptor,
            ActionRandomizer<effect::Spend>,
            Note,
            value::Trapdoor,
        )>,
        outputs: Vec<(
            action::Descriptor,
            ActionRandomizer<effect::Output>,
            Note,
            value::Trapdoor,
        )>,
        anchor: Anchor,
    ) -> Self {
        Self {
            spends,
            outputs,
            anchor,
        }
    }

    /// Prove a single [`ProofStamp`] for this plan.
    ///
    /// For each **spend**, uses [`spend::SpendBind`] to prepare PCD inputs,
    /// then runs [`SpendStamp`] to attach the live nullifier pair.
    ///
    /// For each **output**, runs [`OutputStamp`] with no PCD inputs.
    ///
    /// Stamps are recursively merged via [`MergeStamp`] into a single stamp.
    ///
    /// `spendbind_inputs` items must correspond to each planned spend, in
    /// order.
    ///
    /// TODO: nf_next parameter may need to come back
    /// TODO: provide a way to lift spend stamps when necessary to merge
    pub fn prove<RNG: RngCore + CryptoRng>(
        self,
        rng: &mut RNG,
        pak: &ProofAuthorizingKey,
        spendbind_inputs: Vec<(
            ragu::Pcd<delegation::NullifierHeader>,
            ragu::Pcd<spendable::SpendableHeader>,
        )>,
    ) -> Result<ProofStamp, ProveError> {
        // Each entry pairs leaf stamp components with the descriptor and
        // action digest of its covered action; merges concatenate both
        // lists. Digests are computed once per leaf and carried through the
        // fold rather than re-derived at each merge step. The covered-actions
        // digest is computed once, on the final stamp.
        let mut entries = Vec::with_capacity(self.spends.len() + self.outputs.len());

        if self.spends.len() != spendbind_inputs.len() {
            return Err(ProveError::SpendableMismatch);
        }

        for ((desc, alpha, note, rcv), (nf_pcd, spendable_pcd)) in
            self.spends.into_iter().zip(spendbind_inputs)
        {
            // SpendBind: confirm the live pair against the derived range.
            let (_, _, _, (_, nf_next)) = *nf_pcd.data();
            let (bind_pcd, ()) = PROOF_SYSTEM
                .fuse(rng, spend::SpendBind, (nf_next,), spendable_pcd, nf_pcd)
                .map_err(ProveError::ProofFailed)?;

            // SpendStamp: prove the action and publish.
            let (tachygrams, anchor, proof) =
                ProofStamp::prove_spend(rng, bind_pcd, note, rcv, alpha, *pak)
                    .map_err(ProveError::ProofFailed)?;

            let digest = desc.digest().map_err(ProveError::ActionDigest)?;
            entries.push((
                BTreeSet::from_iter([desc]),
                BTreeSet::from_iter([digest]),
                tachygrams,
                anchor,
                proof,
            ));
        }

        for (desc, alpha, note, rcv) in self.outputs {
            let (tachygrams, anchor, proof) =
                ProofStamp::prove_output(rng, rcv, alpha, note, self.anchor)
                    .map_err(ProveError::ProofFailed)?;

            let digest = desc.digest().map_err(ProveError::ActionDigest)?;
            entries.push((
                BTreeSet::from_iter([desc]),
                BTreeSet::from_iter([digest]),
                tachygrams,
                anchor,
                proof,
            ));
        }

        let (descriptors, _digests, tachygrams, anchor, proof) = entries
            .into_iter()
            .map(Ok::<_, ProveError>)
            .reduce(|acc, next| {
                let (left_desc, left_digests, left_tachygrams, left_anchor, left_proof) = acc?;
                let (right_desc, right_digests, right_tachygrams, right_anchor, right_proof) =
                    next?;

                let (merged_digests, merged_tachygrams, merged_anchor, merged_proof) =
                    ProofStamp::prove_merge(
                        rng,
                        (left_digests, left_tachygrams, left_anchor, left_proof),
                        (right_digests, right_tachygrams, right_anchor, right_proof),
                    )
                    .map_err(ProveError::MergeFailed)?;

                let merged_descs = left_desc.union(&right_desc).copied().collect();

                Ok((
                    merged_descs,
                    merged_digests,
                    merged_tachygrams,
                    merged_anchor,
                    merged_proof,
                ))
            })
            .ok_or(ProveError::NoActions)??;

        let coverage = blake2b::action_descriptor_digest(&Vec::<[u8; 64]>::from_iter(descriptors));
        let tachygram_set = tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit();

        Ok(ProofStamp {
            coverage,
            anchor,
            tachygram_set,
            tachygrams,
            proof,
        })
    }
}

/// Errors that can occur while proving a stamp.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ProveError {
    /// The plan has no actions to prove.
    #[display("no actions to prove")]
    NoActions,
    /// Action digest construction failed (cv or rk was the identity point).
    #[display("action digest failed: {_0}")]
    ActionDigest(ActionDigestError),
    /// Proof creation failed for an action; carries the underlying
    /// step-level error.
    #[display("action proof failed: {_0}")]
    ProofFailed(ragu::Error),
    /// Stamp merge failed; carries the underlying step-level error.
    #[display("stamp merge failed: {_0}")]
    MergeFailed(ragu::Error),
    /// A lift's segment does not start at the stamp's anchor.
    #[display("anchor segment starts at {segment_start:?}, stamp is at {stamp_anchor:?}")]
    LiftStartMismatch {
        /// The stamp's current anchor.
        stamp_anchor: Anchor,
        /// The supplied segment's starting anchor.
        segment_start: Anchor,
    },
    /// Stamp lift failed; carries the underlying step-level error.
    #[display("stamp lift failed: {_0}")]
    LiftFailed(ragu::Error),
    /// Number of spendable PCDs doesn't match number of spends.
    #[display("spendable PCD count mismatch")]
    SpendableMismatch,
}

/// A stamp carrying tachygrams, anchor, and a proof for specific actions.
///
/// The PCD header `(action_acc, tachygram_acc, anchor)` is entirely not stored
/// here.  The covered actions are present only as reference. A verifier must
/// reconstruct the header from public data.
#[derive(Clone, Debug)]
pub struct ProofStamp {
    /// The digest $\mathsf{hStampActionsTachyon}$ of the proof's covered action
    /// descriptors from this stamp's bundle and all covered bundles.
    ///
    /// See [`blake2b::action_descriptor_digest`]
    pub coverage: [u8; 32],

    /// Pool state at the anchor block.
    pub anchor: Anchor,

    /// Commitment to the tachygram multiset below, so that anchor advancement
    /// reads the point rather than rebuilding it.
    ///
    /// Carried, not derived, so full validation must confirm it against
    /// `tachygrams`. See [`ProofStamp::is_accumulating`].
    pub tachygram_set: TachygramSetCommit,

    /// Tachygrams (nullifiers and note commitments) for data availability.
    pub tachygrams: BTreeSet<Tachygram>,

    /// The Ragu proof bytes.
    #[debug(skip)]
    pub proof: Box<ragu::Proof>,
}

/// Stamp components threaded through the merge fold: the covered actions'
/// digests, the tachygrams, the shared anchor, and the proof.
type StampComponents = (
    BTreeSet<ActionDigest>,
    BTreeSet<Tachygram>,
    Anchor,
    Box<ragu::Proof>,
);

/// An invalid [`AnchorStep`].
#[derive(Clone, Copy, Debug, Display, Error, PartialEq, TotalEq)]
#[non_exhaustive]
pub enum AnchorStepError {
    /// A stamp step carried the identity point instead of a real set
    /// commitment.
    #[display("stamp tachygram-set commitment is the identity point")]
    IdentityTachygramSet,
}

/// One transition in an intra-epoch anchor segment.
///
/// A node derives these from validated blocks: one stamp step per proof stamp,
/// in transaction order, or one empty-block step when a block contains no
/// proof stamps. The epoch is carried once by [`AnchorSegment`], rather than in
/// every step, so a segment cannot accidentally mix epochs.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct AnchorStep(AnchorStepKind);

#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
enum AnchorStepKind {
    Stamp { tachygram_set: TachygramSetCommit },
    EmptyBlock,
}

impl AnchorStep {
    /// Construct a step that absorbs one proof stamp.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorStepError::IdentityTachygramSet`] if `tachygram_set` is
    /// the identity point, which no real set-polynomial commitment can be.
    pub fn stamp(tachygram_set: TachygramSetCommit) -> Result<Self, AnchorStepError> {
        let point: pasta_curves::Eq = tachygram_set.into();
        if bool::from(point.is_identity()) {
            return Err(AnchorStepError::IdentityTachygramSet);
        }

        Ok(Self(AnchorStepKind::Stamp { tachygram_set }))
    }

    /// Construct the single step contributed by a block with no proof stamps.
    #[must_use]
    pub const fn empty_block() -> Self {
        Self(AnchorStepKind::EmptyBlock)
    }

    /// Whether this is an empty-block step.
    #[must_use]
    pub const fn is_empty_block(self) -> bool {
        matches!(self.0, AnchorStepKind::EmptyBlock)
    }

    /// Advance `anchor` across this step in `epoch`, matching what the circuit
    /// computes.
    ///
    /// Folding this method over a step sequence predicts its endpoint without
    /// proving. Construction rejects the only input on which
    /// [`Anchor::next_stamp`] can panic.
    #[must_use]
    pub fn advance(self, anchor: Anchor, epoch: EpochIndex) -> Anchor {
        match self.0 {
            AnchorStepKind::Stamp { tachygram_set } => anchor.next_stamp(epoch, &tachygram_set),
            AnchorStepKind::EmptyBlock => anchor.next_empty(epoch),
        }
    }
}

/// Errors constructing a reusable [`AnchorSegment`].
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum AnchorSegmentError {
    /// A segment had no steps.
    #[display("anchor segment has no steps")]
    Empty,
    /// The supplied steps do not reach the expected endpoint.
    #[display("anchor segment ends at {actual:?}, expected {expected:?}")]
    EndMismatch {
        /// The endpoint supplied by the caller from consensus state.
        expected: Anchor,
        /// The endpoint obtained by folding the supplied steps.
        actual: Anchor,
    },
    /// Proving the anchor segment failed.
    #[display("anchor segment proof failed: {_0}")]
    Proof(ragu::Error),
}

/// A reusable proof of an intra-epoch anchor segment.
///
/// Constructing the segment separately lets an aggregator reuse its proof for
/// multiple stamps at the same anchor. Its endpoint is checked against the
/// caller's consensus-state anchor before any proof work begins.
#[derive(Clone)]
pub struct AnchorSegment {
    epoch: EpochIndex,
    chain: ragu::Pcd<AnchorChain>,
}

impl fmt::Debug for AnchorSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnchorSegment")
            .field("epoch", &self.epoch)
            .field("start", &self.start())
            .field("end", &self.end())
            .finish_non_exhaustive()
    }
}

impl AnchorSegment {
    /// Prove that `steps` advance `start` to `expected_end` within `epoch`.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorSegmentError::Empty`] for an empty segment,
    /// [`AnchorSegmentError::EndMismatch`] when the host-side fold does not
    /// reach `expected_end`, or [`AnchorSegmentError::Proof`] if recursive
    /// proof construction fails.
    pub fn prove<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        start: Anchor,
        epoch: EpochIndex,
        expected_end: Anchor,
        steps: &[AnchorStep],
    ) -> Result<Self, AnchorSegmentError> {
        let Some((&first, rest)) = steps.split_first() else {
            return Err(AnchorSegmentError::Empty);
        };

        let actual = steps
            .iter()
            .fold(start, |anchor, step| step.advance(anchor, epoch));
        if actual != expected_end {
            return Err(AnchorSegmentError::EndMismatch {
                expected: expected_end,
                actual,
            });
        }

        let chain = build_anchor_chain(rng, start, epoch, (first, rest))
            .map_err(AnchorSegmentError::Proof)?;

        Ok(Self { epoch, chain })
    }

    /// The epoch containing every step in this segment.
    #[must_use]
    pub const fn epoch(&self) -> EpochIndex {
        self.epoch
    }

    /// The segment's starting anchor.
    #[must_use]
    pub fn start(&self) -> Anchor {
        self.chain.data().0
    }

    /// The segment's ending anchor.
    #[must_use]
    pub fn end(&self) -> Anchor {
        self.chain.data().1
    }
}

/// Seeds the one-step [`AnchorChain`] segment that `step` spans, rooted at
/// `start`.
fn seed_anchor_step<RNG: RngCore + CryptoRng>(
    rng: &mut RNG,
    start: Anchor,
    epoch: EpochIndex,
    step: AnchorStep,
) -> Result<ragu::Pcd<AnchorChain>, ragu::Error> {
    let (seed, ()) = match step.0 {
        AnchorStepKind::Stamp { tachygram_set } => {
            PROOF_SYSTEM.seed(rng, AnchorSeed, (start, epoch, tachygram_set))?
        },
        AnchorStepKind::EmptyBlock => PROOF_SYSTEM.seed(rng, EmptyBlockSeed, (start, epoch))?,
    };

    Ok(seed)
}

/// Builds the [`AnchorChain`] segment rooted at `start` that spans `first`
/// followed by `rest`, by seeding each step and composing adjacent segments.
///
/// Taking the first step separately keeps the segment non-empty by
/// construction: [`AnchorChain`] has no identity element to start a fold from.
fn build_anchor_chain<RNG: RngCore + CryptoRng>(
    rng: &mut RNG,
    start: Anchor,
    epoch: EpochIndex,
    (first, rest): (AnchorStep, &[AnchorStep]),
) -> Result<ragu::Pcd<AnchorChain>, ragu::Error> {
    let mut chain = seed_anchor_step(rng, start, epoch, first)?;

    for &step in rest {
        let next_start = chain.data().1;
        let seed = seed_anchor_step(rng, next_start, epoch, step)?;

        let (fused, ()) = PROOF_SYSTEM.fuse(rng, AnchorFuse, (), chain, seed)?;
        chain = fused;
    }

    Ok(chain)
}

impl ProofStamp {
    /// Proves a single output action, returning the stamp components
    /// `(tachygrams, anchor, proof)`.
    ///
    /// [`output::OutputBind`] settles the tachygram pair, then [`OutputStamp`]
    /// proves the action over it. Both tachygrams are derived inside the
    /// circuit and placed on the stamp for data availability.
    pub fn prove_output<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        rcv: value::Trapdoor,
        alpha: ActionRandomizer<effect::Output>,
        note: Note,
        anchor: Anchor,
    ) -> Result<(BTreeSet<Tachygram>, Anchor, Box<ragu::Proof>), ragu::Error> {
        let (bind_pcd, ()) = PROOF_SYSTEM.seed(rng, output::OutputBind, (note,))?;
        let tgs = *bind_pcd.data();
        let tachygrams = BTreeSet::from_iter(<[Tachygram; 2]>::from(tgs));

        let (pcd, ()) = PROOF_SYSTEM.fuse(
            rng,
            OutputStamp,
            (rcv, alpha, note, anchor),
            bind_pcd,
            ragu::Proof::trivial().carry::<()>(()),
        )?;
        let rerand = PROOF_SYSTEM.rerandomize(pcd, rng)?;

        Ok((tachygrams, anchor, Box::new(rerand.proof().clone())))
    }

    /// Proves a single spend action from a pre-built [`spend::SpendBind`]
    /// PCD, returning the stamp components `(tachygrams, anchor, proof)`.
    ///
    /// The spend's `anchor` is taken as the stamp's anchor — chain
    /// validation lives inside the spendable lineage, not here.
    pub fn prove_spend<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        bind_pcd: ragu::Pcd<spend::SpendHeader>,
        note: Note,
        rcv: value::Trapdoor,
        alpha: ActionRandomizer<effect::Spend>,
        pak: ProofAuthorizingKey,
    ) -> Result<(BTreeSet<Tachygram>, Anchor, Box<ragu::Proof>), ragu::Error> {
        let (_cm, present_nf, nf_next, anchor) = *bind_pcd.data();
        let tachygrams =
            BTreeSet::from_iter([Tachygram::from(present_nf), Tachygram::from(nf_next)]);

        let (pcd, ()) = PROOF_SYSTEM.fuse(
            rng,
            SpendStamp,
            (note, rcv, alpha, pak),
            bind_pcd,
            ragu::Proof::trivial().carry::<()>(()),
        )?;
        let rerand = PROOF_SYSTEM.rerandomize(pcd, rng)?;

        Ok((tachygrams, anchor, Box::new(rerand.proof().clone())))
    }

    /// Proves the merge of two stamps, returning the merged stamp
    /// components `(digests, tachygrams, anchor, proof)`.
    ///
    /// Both stamps must share the same anchor (use StampLift to align first).
    ///
    /// Each side is `(digests, tachygrams, anchor, proof)` — the digest list
    /// reconstructs the `ActionCommit` multiset that `MergeStamp` verifies via
    /// Schwartz-Zippel. Digests are derived from public action data by the
    /// caller and are never stored on the stamp; the merged (concatenated)
    /// digest list is returned so a fold can carry it forward without
    /// re-deriving.
    pub fn prove_merge<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        (left_digests, left_tachygrams, left_anchor, left_proof): StampComponents,
        (right_digests, right_tachygrams, right_anchor, right_proof): StampComponents,
    ) -> Result<StampComponents, ragu::Error> {
        let (left_acts_poly, left_tg_poly) = (
            left_digests.iter().copied().collect::<ActionSetPoly>(),
            left_tachygrams
                .iter()
                .copied()
                .collect::<TachygramSetPoly>(),
        );

        let (right_acts_poly, right_tg_poly) = (
            right_digests.iter().copied().collect::<ActionSetPoly>(),
            right_tachygrams
                .iter()
                .copied()
                .collect::<TachygramSetPoly>(),
        );

        let left_pcd = left_proof.carry::<StampHeader>((
            left_acts_poly.commit(),
            left_tg_poly.commit(),
            left_anchor,
        ));
        let right_pcd = right_proof.carry::<StampHeader>((
            right_acts_poly.commit(),
            right_tg_poly.commit(),
            right_anchor,
        ));

        let merged_digests: BTreeSet<ActionDigest> =
            left_digests.union(&right_digests).copied().collect();
        let tachygrams: BTreeSet<Tachygram> =
            left_tachygrams.union(&right_tachygrams).copied().collect();

        let (pcd, ()) = PROOF_SYSTEM.fuse(
            rng,
            MergeStamp,
            (
                (left_acts_poly, left_tg_poly),
                (
                    ActionSetPoly::from_iter(merged_digests.clone()),
                    TachygramSetPoly::from_iter(tachygrams.clone()),
                ),
                (right_acts_poly, right_tg_poly),
            ),
            left_pcd,
            right_pcd,
        )?;
        let anchor = pcd.data().2;
        let rerand = PROOF_SYSTEM.rerandomize(pcd, rng)?;

        Ok((
            merged_digests,
            tachygrams,
            anchor,
            Box::new(rerand.proof().clone()),
        ))
    }

    /// Merges two stamps into one covering stamp.
    ///
    /// Each side pairs a stamp with the descriptors of its covered actions.
    /// The action digests for the merge proof and the merged
    /// `covered_actions` are both derived from the descriptor lists.
    ///
    /// TODO: confirm desc list against stamp? it's forbidden by the proof
    /// system, but we might want to fail early.
    pub fn merge<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        (left_stamp, left_desc): (Self, BTreeSet<action::Descriptor>),
        (right_stamp, right_desc): (Self, BTreeSet<action::Descriptor>),
    ) -> Result<Self, ProveError> {
        let left_actions_digest = left_desc
            .iter()
            .map(action::Descriptor::digest)
            .collect::<Result<BTreeSet<ActionDigest>, ActionDigestError>>()
            .map_err(ProveError::ActionDigest)?;
        let right_actions_digest = right_desc
            .iter()
            .map(action::Descriptor::digest)
            .collect::<Result<BTreeSet<ActionDigest>, ActionDigestError>>()
            .map_err(ProveError::ActionDigest)?;

        let (_merged_digests, tachygrams, anchor, proof) = Self::prove_merge(
            rng,
            (
                left_actions_digest,
                left_stamp.tachygrams,
                left_stamp.anchor,
                left_stamp.proof,
            ),
            (
                right_actions_digest,
                right_stamp.tachygrams,
                right_stamp.anchor,
                right_stamp.proof,
            ),
        )
        .map_err(ProveError::MergeFailed)?;

        let coverage = blake2b::action_descriptor_digest(
            &left_desc
                .union(&right_desc)
                .copied()
                .collect::<Vec<[u8; 64]>>(),
        );

        let tachygram_set = tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit();

        Ok(Self {
            coverage,
            anchor,
            tachygram_set,
            tachygrams,
            proof,
        })
    }

    /// Advances this stamp's anchor along `segment`, so it can [`merge`] with
    /// stamps that already sit at the segment's later anchor.
    ///
    /// [`MergeStamp`] constrains both sides to one anchor, but wallets stamp
    /// against whatever anchor was current when they built, and every block
    /// mints a new one. Lifting is what lets an aggregator collect stamps from
    /// different heights into a single merge.
    ///
    /// The stamp pairs with the descriptors of its covered actions, as it does
    /// for [`merge`], because the PCD header is reconstructed rather than
    /// stored. A segment can be cloned and reused to lift multiple stamps from
    /// the same anchor.
    ///
    /// Only `anchor` and `proof` change. [`StampLift`] passes the action and
    /// tachygram commitments through untouched, so `coverage`, `tachygrams`,
    /// and `tachygram_set` all survive the lift, and a lifted stamp still
    /// covers exactly the actions it covered before.
    ///
    /// # Errors
    ///
    /// Returns [`ProveError::LiftStartMismatch`] if the segment does not start
    /// at this stamp's anchor. The proof system also verifies the stamp against
    /// the commitments reconstructed from `descriptors` and the stamp's
    /// tachygrams.
    ///
    /// [`merge`]: ProofStamp::merge
    pub fn lift<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        (stamp, descriptors): (Self, BTreeSet<action::Descriptor>),
        segment: &AnchorSegment,
    ) -> Result<Self, ProveError> {
        let Self {
            coverage,
            anchor,
            tachygrams,
            proof,
            ..
        } = stamp;

        let segment_start = segment.start();
        if segment_start != anchor {
            return Err(ProveError::LiftStartMismatch {
                stamp_anchor: anchor,
                segment_start,
            });
        }

        let action_commit = descriptors
            .iter()
            .map(action::Descriptor::digest)
            .collect::<Result<BTreeSet<ActionDigest>, ActionDigestError>>()
            .map_err(ProveError::ActionDigest)?
            .into_iter()
            .collect::<ActionSetPoly>()
            .commit();

        // Recomputed rather than trusting the carried cache, as `prove_merge`
        // does. The proof binds the accumulator the circuit witnessed, so
        // tachygrams that disagree with the proof fail the fuse.
        let tachygram_commit = tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit();

        let stamp_pcd = proof.carry::<StampHeader>((action_commit, tachygram_commit, anchor));

        let (pcd, ()) = PROOF_SYSTEM
            .fuse(rng, StampLift, (), stamp_pcd, segment.chain.clone())
            .map_err(ProveError::LiftFailed)?;
        let lifted_anchor = pcd.data().2;
        let rerand = PROOF_SYSTEM
            .rerandomize(pcd, rng)
            .map_err(ProveError::LiftFailed)?;

        Ok(Self {
            coverage,
            anchor: lifted_anchor,
            tachygram_set: tachygram_commit,
            tachygrams,
            proof: Box::new(rerand.proof().clone()),
        })
    }

    /// Confirm `hStampActionsTachyon` represents the given action descriptors.
    ///
    /// # Soundness
    ///
    /// The parameter is a multiset: order does not matter, multiplicity does.
    #[must_use]
    pub(crate) fn is_covering(
        &self,
        action_descs: impl IntoIterator<Item = action::Descriptor>,
    ) -> bool {
        let mut desc_bytes = action_descs.into_iter().collect::<Vec<[u8; 64]>>();
        desc_bytes.sort_unstable();
        blake2b::action_descriptor_digest(&desc_bytes) == self.coverage
    }

    /// Confirm `tachygram_set` commits to the published tachygrams.
    ///
    /// # Soundness
    ///
    /// Required for full validation, at mempool admission or when validating
    /// the containing block. The proof binds the accumulator to the tachygrams
    /// the circuit witnessed, not to the published list; without this check a
    /// stamp could publish a list omitting a nullifier the accumulator
    /// contains, which is what the two-epoch duplicate scan reads.
    #[must_use]
    pub(crate) fn is_accumulating(&self) -> bool {
        self.tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit()
            == self.tachygram_set
    }

    /// Reconstruct the PCD header and verify the proof. Call
    /// [`ProofStamp::is_covering`] first to cheaply predict a mismatch.
    ///
    /// # Soundness
    ///
    /// The parameter is a multiset: order does not matter, multiplicity does.
    pub(crate) fn verify_proof<RNG: RngCore + CryptoRng>(
        &self,
        rng: &mut RNG,
        action_digests: impl IntoIterator<Item = ActionDigest>,
    ) -> Result<bool, ragu::Error> {
        if !self.is_accumulating() {
            return Ok(false);
        }

        let action_set = action_digests.into_iter().collect::<ActionSetPoly>();

        let pcd = self.proof.clone().carry::<StampHeader>((
            action_set.commit(),
            self.tachygram_set,
            self.anchor,
        ));

        PROOF_SYSTEM.verify(&pcd, rng)
    }
}

#[cfg(test)]
mod tests;
