//! Stamps and anchors.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]
#![allow(
    clippy::multiple_inherent_impl,
    clippy::same_name_method,
    reason = "todo: take read/write off StampState"
)]

extern crate alloc;

pub mod proof;

use alloc::{boxed::Box, collections::BTreeSet, format, vec, vec::Vec};
use core::error;

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, Into, PartialEq};
use ff::PrimeField as _;
use group::{Curve as _, GroupEncoding as _};
use pasta_curves::{Eq, Fp};
use proof::{
    PROOF_SYSTEM, output,
    stamp::{MergeStamp, OutputStamp, SpendStamp, StampHeader, StampLift},
};
use ragu::PROOF_SIZE_COMPRESSED;
use rand_core::CryptoRng;

use crate::{
    ActionSetPoly, Note, TachygramSetPoly, action,
    bundle::{BundleState, StateByte},
    digest::blake2b,
    effect,
    entropy::ActionRandomizer,
    keys::ProofAuthorizingKey,
    nullifier::Nullifier,
    primitives::{
        ActionDigest, ActionDigestError, Anchor, EpochIndex, Tachygram, TachygramSetCommit,
    },
    serialization,
    stamp::proof::{delegation, pool, spend, spendable},
    value, witness,
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
    fn read<R: Read>(reader: &mut R) -> io::Result<Self>
    where
        Self: Sized;

    /// Write the stamp trailer in the consensus wire format.
    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()>
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

    fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        Self::read(reader)
    }

    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.write(writer)
    }
}

impl PointerStamp {
    /// Read an aggregate id from the consensus wire format.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
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
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
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
                self.tachygram_set.as_ref().to_affine().to_bytes(),
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

    fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        Self::read(reader)
    }

    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.write(writer)
    }
}

impl ProofStamp {
    /// Read a stamp from the consensus wire format. The proof blob has a
    /// known constant size.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut covered_actions = [0u8; 32];
        reader.read_exact(&mut covered_actions)?;

        let anchor = Anchor::read(&mut reader)?;

        // Parsing does not confirm this against the tachygrams below: an MSM
        // over attacker-supplied bytes is a denial-of-service vector. See
        // `ProofStamp::is_accumulating`.
        let tachygram_set =
            TachygramSetCommit::from(Eq::from(serialization::read_eq_affine(&mut reader)?));

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
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.coverage)?;
        self.anchor.write(&mut writer)?;
        serialization::write_eq_affine(&mut writer, &self.tachygram_set.as_ref().to_affine())?;
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
    /// `spend_pcds` items must correspond to each planned spend, in
    /// order.
    ///
    /// TODO: provide a way to lift spend stamps when necessary to merge
    pub fn prove<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        pak: &ProofAuthorizingKey,
        spend_pcds: Vec<(
            ragu::Pcd<delegation::NullifierDerivation>,
            ragu::Pcd<spendable::SpendableHeader>,
        )>,
    ) -> Result<ProofStamp, ProveError> {
        // Each entry pairs leaf stamp components with the descriptor and
        // action digest of its covered action; merges concatenate both
        // lists. Digests are computed once per leaf and carried through the
        // fold rather than re-derived at each merge step. The covered-actions
        // digest is computed once, on the final stamp.
        let mut entries = Vec::with_capacity(self.spends.len() + self.outputs.len());

        if self.spends.len() != spend_pcds.len() {
            return Err(ProveError::MissingPcd(
                format!(
                    "cannot prove {} spend actions with {} spendbind inputs",
                    self.spends.len(),
                    spend_pcds.len(),
                )
                .into(),
            ));
        }

        for ((desc, alpha, note, rcv), (range_pcd, spendable_pcd)) in
            self.spends.into_iter().zip(spend_pcds)
        {
            // SpendBind: confirm the live pair against the covering
            // derivation. The covering sequence is rebuilt natively from the
            // note's master key (the succinct header carries only the
            // commitment); the witness segments its read and complement.
            let mk = pak.nk.derive_note_private(note.psi);
            let (_, deriv_start, _, deriv_end) = *range_pcd.data();
            let window: Vec<Nullifier> = (deriv_start.0..deriv_end.0)
                .map(|epoch| mk.derive_nullifier(EpochIndex(epoch)))
                .collect();
            let bind_witness =
                witness::spend_bind((*spendable_pcd.data(), *range_pcd.data()), &window);
            let (bind_pcd, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    spend::SpendBind,
                    bind_witness,
                    spendable_pcd,
                    range_pcd,
                )
                .map_err(ProveError::ProofFailed)?;

            // SpendStamp: prove the action and publish. The tachygram pair is
            // read straight off the bind header.
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
            .map(Ok)
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
                    .map_err(ProveError::ProofFailed)?;

                let merged_descs = left_desc.union(&right_desc).copied().collect();

                Ok((
                    merged_descs,
                    merged_digests,
                    merged_tachygrams,
                    merged_anchor,
                    merged_proof,
                ))
            })
            .transpose()?
            .ok_or(ProveError::MissingPcd(
                "no proof for no planned actions".into(),
            ))?;

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
    /// Missing PCD inputs for the operation.
    #[display("missing pcd inputs: {_0}")]
    MissingPcd(Box<dyn error::Error + Send + Sync + 'static>),
    /// Action digest construction failed (cv or rk was the identity point).
    #[display("action digest failed: {_0}")]
    ActionDigest(ActionDigestError),
    /// Proof creation failed; carries the underlying step-level error.
    #[display("proof failed: {_0}")]
    ProofFailed(ragu_core::Error),
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

    /// The historic pool state for which this stamp is valid.
    pub anchor: Anchor,

    /// The commitment to this stamp's tachygram set.
    pub tachygram_set: TachygramSetCommit,

    /// This stamp's tachygram set.
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

impl ProofStamp {
    /// Proves a single output action, returning the stamp components
    /// `(tachygrams, anchor, proof)`.
    ///
    /// [`output::OutputBind`] settles the tachygram pair, then [`OutputStamp`]
    /// proves the action over it. Both tachygrams are derived inside the
    /// circuit and placed on the stamp for data availability.
    pub fn prove_output<RNG: CryptoRng>(
        rng: &mut RNG,
        rcv: value::Trapdoor,
        alpha: ActionRandomizer<effect::Output>,
        note: Note,
        anchor: Anchor,
    ) -> Result<(BTreeSet<Tachygram>, Anchor, Box<ragu::Proof>), ragu_core::Error> {
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

    /// Creates a stamp for a spend action from a bound
    /// [`SpendHeader`](spend::SpendHeader) PCD.
    ///
    /// The nullifier pair `{present_nf, nf_next}` published for data
    /// availability is read straight off the bind header (already confirmed
    /// against the derivation at [`SpendBind`](spend::SpendBind)); this step
    /// only proves the action `(cv, rk)`. The spend's `anchor` is taken as the
    /// stamp's anchor; chain validation lives inside the spendable lineage.
    pub fn prove_spend<RNG: CryptoRng>(
        rng: &mut RNG,
        bind_pcd: ragu::Pcd<spend::SpendHeader>,
        note: Note,
        rcv: value::Trapdoor,
        alpha: ActionRandomizer<effect::Spend>,
        pak: ProofAuthorizingKey,
    ) -> Result<(BTreeSet<Tachygram>, Anchor, Box<ragu::Proof>), ragu_core::Error> {
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
    pub fn prove_merge<RNG: CryptoRng>(
        rng: &mut RNG,
        (left_digests, left_tachygrams, left_anchor, left_proof): StampComponents,
        (right_digests, right_tachygrams, right_anchor, right_proof): StampComponents,
    ) -> Result<StampComponents, ragu_core::Error> {
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

    /// Advances the stamp's anchor with the provided anchor chain proof.
    pub fn prove_lift<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        action_digests: impl IntoIterator<Item = ActionDigest>,
        anchor_chain: ragu::Pcd<pool::AnchorChain>,
    ) -> Result<Self, ragu_core::Error> {
        let action_set = action_digests.into_iter().collect::<ActionSetPoly>();
        let stamp_pcd =
            self.proof
                .carry::<StampHeader>((action_set.commit(), self.tachygram_set, self.anchor));

        let (pcd, ()) = PROOF_SYSTEM.fuse(rng, StampLift, (), stamp_pcd, anchor_chain)?;
        let anchor = pcd.data().2;
        let rerand = PROOF_SYSTEM.rerandomize(pcd, rng)?;

        Ok(Self {
            coverage: self.coverage,
            anchor,
            tachygram_set: self.tachygram_set,
            tachygrams: self.tachygrams,
            proof: Box::new(rerand.proof().clone()),
        })
    }

    /// Advances the stamp's anchor with a proof of the provided sequence.
    pub fn lift<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        descriptors: &BTreeSet<action::Descriptor>,
        seed_witnesses: Vec<(Anchor, EpochIndex, TachygramSetCommit)>,
    ) -> Result<Self, ProveError> {
        let anchor_seeds = seed_witnesses
            .into_iter()
            .map(|witness| {
                PROOF_SYSTEM
                    .seed(rng, pool::AnchorSeed, witness)
                    .map(|(pcd, _aux)| pcd)
                    .map_err(ProveError::ProofFailed)
            })
            .collect::<Result<Vec<_>, ProveError>>()?;

        let anchor_chain = anchor_seeds
            .into_iter()
            .map(Ok)
            .reduce(|left, right| {
                PROOF_SYSTEM
                    .fuse(rng, pool::AnchorFuse, (), left?, right?)
                    .map(|(pcd, _aux)| pcd)
                    .map_err(ProveError::ProofFailed)
            })
            .transpose()?
            .ok_or(ProveError::MissingPcd(
                "no anchor chain proof for no anchor advance".into(),
            ))?;

        let action_digests = descriptors
            .iter()
            .map(action::Descriptor::digest)
            .collect::<Result<BTreeSet<ActionDigest>, ActionDigestError>>()
            .map_err(ProveError::ActionDigest)?;

        self.prove_lift(rng, action_digests, anchor_chain)
            .map_err(ProveError::ProofFailed)
    }

    /// Merges two stamps into one covering stamp.
    ///
    /// Each side pairs a stamp with the descriptors of its covered actions.
    /// The action digests for the merge proof and the merged
    /// `covered_actions` are both derived from the descriptor lists.
    ///
    /// TODO: confirm desc list against stamp? it's forbidden by the proof
    /// system, but we might want to fail early.
    pub fn merge<RNG: CryptoRng>(
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
        .map_err(ProveError::ProofFailed)?;

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

    /// Confirm `hStampActionsTachyon` represents the given action descriptors.
    ///
    /// # Soundness
    ///
    /// The parameter is a multiset: order does not matter, multiplicity does.
    #[must_use]
    pub fn is_covering(&self, action_descs: impl IntoIterator<Item = action::Descriptor>) -> bool {
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
    fn is_accumulating(&self) -> bool {
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
    pub fn verify_proof<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        action_digests: impl IntoIterator<Item = ActionDigest>,
    ) -> Result<bool, ragu_core::Error> {
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
