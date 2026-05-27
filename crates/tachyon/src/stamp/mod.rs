//! Stamps and anchors.
//!
//! A stamp carries the tachygram list, the anchor, and the proof:
//!
//! - **Tachygrams**: Listed individually
//! - **Anchor**: A `Fp` from the per-block Poseidon hash chain
//! - **Proof**: The Ragu PCD proof (rerandomized)
//!
//! The PCD header data `(action_acc, tachygram_acc, anchor)` is **not
//! serialized** on the stamp — the verifier reconstructs the accumulators from
//! public data and passes them as the header to Ragu `verify()`.

#![allow(clippy::type_complexity, reason = "todo")]
#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

pub mod proof;

use alloc::{boxed::Box, vec::Vec};
use core::{error::Error, fmt};

use corez::io::{self, Read, Write};
use pasta_curves::Fp;
use proof::{
    PROOF_SYSTEM,
    stamp::{MergeStamp, OutputStamp, SpendStamp, StampHeader},
};
use ragu::{self, proof::PROOF_SIZE_COMPRESSED};
use rand_core::{CryptoRng, RngCore};

use crate::{
    ActionSetCommit, ActionSetPoly, Note, TachygramSetCommit, TachygramSetPoly,
    action::Action,
    effect,
    entropy::ActionRandomizer,
    keys::{ProofAuthorizingKey, public},
    note::Nullifier,
    primitives::{ActionDigest, ActionDigestError, Anchor, Tachygram},
    serialization,
    stamp::proof::{delegation, spend, spendable},
    value,
};

/// Marker for a bundle that has not yet been proven.
///
/// This is the initial state for a newly constructed bundle.
/// Proving produces a [`Stamp`]; stripping produces a `Bundle<Stripped>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unproven;

/// Marker for a stripped bundle whose covering-aggregate `wtxid` has not
/// yet been assigned.
///
/// Produced by [`strip()`](crate::Bundle::strip). Must transition to a
/// `Bundle<AggregateId>` via [`assign_wtxid`](crate::Bundle::assign_wtxid)
/// before serialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stripped;

/// A 64-byte `wtxid` of the covering aggregate in the same block, assigned by
/// the miner during block assembly.
///
/// This uses the aggregate's wtxid (not txid) so it unambiguously pins the
/// covering aggregate's authorization state, including stamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateId([u8; 64]);

impl AggregateId {
    /// This zero wtxid is only suitable for a bundle with no actions.
    pub const ZERO: Self = Self([0u8; 64]);

    pub(super) fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut wtxid = [0u8; 64];
        reader.read_exact(&mut wtxid)?;
        Ok(Self(wtxid))
    }

    pub(super) fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Errors that can occur when handling an aggregate id.
pub enum AggregateIdError {
    /// The aggregate id is zero and refers to no aggregate.
    Zero,
}
impl Error for AggregateIdError {}

impl fmt::Display for AggregateIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::Zero => {
                write!(f, "aggregate id is zero and refers to no aggregate")
            },
        }
    }
}

impl TryFrom<[u8; 64]> for AggregateId {
    type Error = AggregateIdError;

    fn try_from(wtxid: [u8; 64]) -> Result<Self, Self::Error> {
        if wtxid == [0u8; 64] {
            return Err(AggregateIdError::Zero);
        }
        Ok(Self(wtxid))
    }
}

impl From<AggregateId> for [u8; 64] {
    fn from(aggregate_id: AggregateId) -> Self {
        aggregate_id.0
    }
}

/// Error during stamp verification.
#[derive(Clone, Debug)]
pub enum VerificationError {
    /// An action's cv or rk is the identity point.
    ActionDigest(ActionDigestError),
    /// The proof system returned an error.
    ProofSystem,
    /// The proof did not verify against the reconstructed header.
    Disproved,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | &Self::ActionDigest(err) => write!(f, "action digest error: {err}"),
            | &Self::ProofSystem => write!(f, "proof system error"),
            | &Self::Disproved => write!(f, "proof did not verify"),
        }
    }
}

impl Error for VerificationError {}

/// Everything needed to produce a [`Stamp`].
///
/// Each action is described by a public descriptor `(cv, rk)` and a
/// private witness `(alpha, note, rcv)`. The `prove` method generates
/// a leaf proof for each action, then merges pairwise into a single
/// stamp.
///
/// Construct via [`Plan::new`] with pre-derived action witnesses, or
/// via [`bundle::Plan::stamp_plan`](crate::bundle::Plan::stamp_plan)
/// for the typed single-party path.
#[derive(Clone, Debug)]
pub struct Plan {
    spends: Vec<(
        (value::Commitment, public::ActionVerificationKey),
        (
            ActionRandomizer<effect::Spend>,
            Note,
            value::CommitmentTrapdoor,
        ),
    )>,
    outputs: Vec<(
        (value::Commitment, public::ActionVerificationKey),
        (
            ActionRandomizer<effect::Output>,
            Note,
            value::CommitmentTrapdoor,
        ),
    )>,
    anchor: Anchor,
}

impl Plan {
    /// Create a stamp plan from paired action descriptors and witnesses.
    #[must_use]
    pub const fn new(
        spends: Vec<(
            (value::Commitment, public::ActionVerificationKey),
            (
                ActionRandomizer<effect::Spend>,
                Note,
                value::CommitmentTrapdoor,
            ),
        )>,
        outputs: Vec<(
            (value::Commitment, public::ActionVerificationKey),
            (
                ActionRandomizer<effect::Output>,
                Note,
                value::CommitmentTrapdoor,
            ),
        )>,
        anchor: Anchor,
    ) -> Self {
        Self {
            spends,
            outputs,
            anchor,
        }
    }

    /// Prove a single [`Stamp`] for this plan.
    ///
    /// For each **spend**, uses [`SpendBind`] to prepare PCD inputs, then runs
    /// [`SpendStamp`] to attach the live nullifier pair.
    ///
    /// For each **output**, runs [`OutputStamp`] with no PCD inputs.
    ///
    /// Stamps are recursively merged via [`MergeStamp`] into a single stamp.
    ///
    /// `spend_pcds` items must correspond to each planned spend, in order.
    pub fn prove<RNG: RngCore + CryptoRng>(
        self,
        rng: &mut RNG,
        pak: &ProofAuthorizingKey,
        spend_pcds: Vec<(
            ragu::Pcd<delegation::NullifierHeader>,
            [Nullifier; 2],
            ragu::Pcd<spendable::SpendableHeader>,
        )>,
    ) -> Result<Stamp, ProveError> {
        // Each entry is (stamp, action_digests). The digest list is ephemeral —
        // needed to reconstruct the PCD header's action multiset during merge,
        // never stored.
        let mut entries: Vec<(Stamp, Vec<ActionDigest>)> = Vec::new();

        if self.spends.len() != spend_pcds.len() {
            return Err(ProveError::SpendableMismatch);
        }

        for (((cv, rk), (alpha, note, rcv)), (range_pcd, [nf_now, nf_next], spendable_pcd)) in
            self.spends.into_iter().zip(spend_pcds)
        {
            let action_digest = ActionDigest::new(cv, rk).map_err(ProveError::ActionDigest)?;

            let app = &*PROOF_SYSTEM;

            let (bind_pcd, ()) = app
                .fuse(
                    rng,
                    spend::SpendBind,
                    ((note.pk, note.value, note.rcm, note.psi), rcv, alpha, *pak),
                    spendable_pcd,
                    ragu::Proof::trivial().carry::<()>(()),
                )
                .map_err(ProveError::ProofFailed)?;

            // SpendStamp: bind the live pair to the derived range and publish.
            let tachygrams = alloc::vec![Tachygram::from(nf_now), Tachygram::from(nf_next)];
            let stamp = Stamp::prove_spend(rng, bind_pcd, range_pcd, nf_next, tachygrams)
                .map_err(ProveError::ProofFailed)?;

            entries.push((stamp, alloc::vec![action_digest]));
        }

        for ((cv, rk), (alpha, note, rcv)) in self.outputs {
            let action_digest = ActionDigest::new(cv, rk).map_err(ProveError::ActionDigest)?;

            let stamp = Stamp::prove_output(rng, rcv, alpha, note, self.anchor)
                .map_err(ProveError::ProofFailed)?;

            entries.push((stamp, alloc::vec![action_digest]));
        }

        entries
            .into_iter()
            .map(Ok::<_, ProveError>)
            .reduce(|acc, next| {
                let (left, left_digests) = acc?;
                let (right, right_digests) = next?;
                let merged =
                    Stamp::prove_merge(rng, (left, &left_digests), (right, &right_digests))
                        .map_err(ProveError::MergeFailed)?;
                let mut merged_digests = left_digests;
                merged_digests.extend_from_slice(&right_digests);
                Ok((merged, merged_digests))
            })
            .ok_or(ProveError::NoActions)?
            .map(|(stamp, _digests)| stamp)
    }
}

/// Errors that can occur while proving a stamp.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProveError {
    /// The plan has no actions to prove.
    NoActions,
    /// Action digest construction failed (cv or rk was the identity point).
    ActionDigest(ActionDigestError),
    /// Proof creation failed for an action; carries the underlying
    /// step-level error.
    ProofFailed(ragu::Error),
    /// Stamp merge failed; carries the underlying step-level error.
    MergeFailed(ragu::Error),
    /// Number of spendable PCDs doesn't match number of spends.
    SpendableMismatch,
}

impl fmt::Display for ProveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::NoActions => write!(f, "no actions to prove"),
            | Self::ActionDigest(err) => write!(f, "action digest failed: {err}"),
            | Self::ProofFailed(inner) => write!(f, "action proof failed: {inner}"),
            | Self::MergeFailed(inner) => write!(f, "stamp merge failed: {inner}"),
            | Self::SpendableMismatch => write!(f, "spendable PCD count mismatch"),
        }
    }
}

impl Error for ProveError {}

/// A stamp carrying tachygrams, anchor, and proof.
///
/// Present in `Bundle<Stamp>` bundles.
/// Stripped during aggregation and merged into the aggregate's stamp.
///
/// The PCD header `(action_acc, tachygram_acc, anchor)` is not stored here —
/// the verifier reconstructs it from public data and passes it as the header
/// to Ragu `verify()`.
#[derive(Clone)]
pub struct Stamp {
    /// Tachygrams (nullifiers and note commitments) for data availability.
    pub tachygrams: Vec<Tachygram>,

    /// Pool state at the anchor block.
    pub anchor: Anchor,

    /// The Ragu proof bytes.
    pub proof: ragu::Proof,
}

impl fmt::Debug for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Stamp {{ tachygrams: {:?}, anchor: {:?} }}",
            self.tachygrams, self.anchor,
        )
    }
}

impl Stamp {
    /// Creates a stamp for a single output action.
    ///
    /// The output tachygram (note commitment) is derived inside the circuit
    /// and placed on the stamp for data availability.
    pub fn prove_output<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        rcv: value::CommitmentTrapdoor,
        alpha: ActionRandomizer<effect::Output>,
        note: Note,
        anchor: Anchor,
    ) -> Result<Self, ragu::Error> {
        let app = &*PROOF_SYSTEM;

        let (pcd, ()) = app.seed(rng, OutputStamp, (rcv, alpha, note, anchor))?;
        let tachygram = Tachygram::from(note.commitment());
        let rerand = app.rerandomize(pcd, rng)?;

        Ok(Self {
            tachygrams: alloc::vec![tachygram],
            anchor,
            proof: rerand.proof().clone(),
        })
    }

    /// Creates a stamp for a spend action from pre-built spend and
    /// nullifier-range PCDs.
    ///
    /// The spend's `anchor` is taken as the stamp's anchor — chain
    /// validation lives inside the spendable lineage, not here.
    pub fn prove_spend<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        spend_pcd: ragu::Pcd<spend::SpendHeader>,
        range_pcd: ragu::Pcd<delegation::NullifierHeader>,
        nf_next: Nullifier,
        tachygrams: Vec<Tachygram>,
    ) -> Result<Self, ragu::Error> {
        let app = &*PROOF_SYSTEM;

        let anchor = spend_pcd.data().3;

        let (pcd, ()) = app.fuse(rng, SpendStamp, (nf_next,), spend_pcd, range_pcd)?;
        let rerand = app.rerandomize(pcd, rng)?;

        Ok(Self {
            tachygrams,
            anchor,
            proof: rerand.proof().clone(),
        })
    }

    /// Merges two stamps, combining tachygrams and proofs.
    ///
    /// Both stamps must share the same anchor (use StampLift to align first).
    ///
    /// Each side is `(stamp, &[ActionDigest])` — the digest list reconstructs
    /// the `ActionCommit` multiset that `MergeStamp` verifies via
    /// Schwartz-Zippel. Digests are derived from public action data by the
    /// caller and are never stored on the stamp.
    pub fn prove_merge<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        (left, left_digests): (Self, &[ActionDigest]),
        (right, right_digests): (Self, &[ActionDigest]),
    ) -> Result<Self, ragu::Error> {
        let app = &*PROOF_SYSTEM;

        let (left_acts_poly, left_tg_poly) = (
            ActionSetPoly::from(left_digests),
            TachygramSetPoly::from(&*left.tachygrams),
        );

        let (right_acts_poly, right_tg_poly) = (
            ActionSetPoly::from(right_digests),
            TachygramSetPoly::from(&*right.tachygrams),
        );

        let left_pcd = left.proof.carry::<StampHeader>((
            left_acts_poly.commit(),
            left_tg_poly.commit(),
            left.anchor,
        ));
        let right_pcd = right.proof.carry::<StampHeader>((
            right_acts_poly.commit(),
            right_tg_poly.commit(),
            right.anchor,
        ));

        let anchor = left.anchor;
        let mut tachygrams = left.tachygrams;
        tachygrams.extend(right.tachygrams.iter().copied());

        let (pcd, ()) = app.fuse(
            rng,
            MergeStamp,
            (left_acts_poly, right_acts_poly, left_tg_poly, right_tg_poly),
            left_pcd,
            right_pcd,
        )?;
        let rerand = app.rerandomize(pcd, rng)?;

        Ok(Self {
            tachygrams,
            anchor,
            proof: rerand.proof().clone(),
        })
    }

    /// Verifies this stamp's proof by reconstructing the PCD header from
    /// public data.
    ///
    /// The verifier recomputes action and tachygram accumulators as raw Fp
    /// products, constructs the PCD header, and calls Ragu `verify()`.
    pub fn verify<RNG: RngCore + CryptoRng>(
        &self,
        rng: &mut RNG,
        actions: &[Action],
    ) -> Result<(), VerificationError> {
        let app = &*PROOF_SYSTEM;

        let header = (
            ActionSetCommit::try_from(actions).map_err(VerificationError::ActionDigest)?,
            TachygramSetCommit::from(&*self.tachygrams),
            self.anchor,
        );

        let pcd = self.proof.clone().carry::<StampHeader>(header);

        let valid = app
            .verify(&pcd, rng)
            .map_err(|_err| VerificationError::ProofSystem)?;

        if valid {
            Ok(())
        } else {
            Err(VerificationError::Disproved)
        }
    }

    /// Read a stamp from the consensus wire format.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let anchor = Anchor::read(&mut reader)?;

        let tachygrams = serialization::read_fp_list(&mut reader)?
            .into_iter()
            .map(Tachygram::from)
            .collect();

        let proof = read_proof(&mut reader)?;

        Ok(Self {
            tachygrams,
            anchor,
            proof,
        })
    }

    /// Write a stamp to the consensus wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.anchor.write(&mut writer)?;
        serialization::write_fp_list(
            &mut writer,
            &self
                .tachygrams
                .iter()
                .map(|&tg| Fp::from(tg))
                .collect::<Vec<Fp>>(),
        )?;
        write_proof(&mut writer, &self.proof)
    }
}

/// Read a proof of known constant size.
pub(crate) fn read_proof<R: Read>(mut reader: R) -> io::Result<ragu::Proof> {
    let mut bytes = alloc::vec![0u8; PROOF_SIZE_COMPRESSED];
    reader.read_exact(&mut bytes)?;
    let arr: Box<[u8; PROOF_SIZE_COMPRESSED]> = bytes
        .into_boxed_slice()
        .try_into()
        .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "proof buffer wrong size"))?;
    ragu::Proof::try_from(arr.as_ref())
        .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "invalid proof encoding"))
}

/// Write a proof of known constant size.
pub(crate) fn write_proof<W: Write>(mut writer: W, proof: &ragu::Proof) -> io::Result<()> {
    let bytes = proof.serialize();
    writer.write_all(bytes.as_ref())
}

#[cfg(test)]
mod tests;
