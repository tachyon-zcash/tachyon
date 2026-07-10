//! Stamps and anchors.

#![allow(clippy::type_complexity, reason = "todo")]
#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

pub mod proof;

use alloc::{boxed::Box, vec, vec::Vec};

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, Into, PartialEq};
use pasta_curves::Fp;
use proof::{
    PROOF_SYSTEM,
    stamp::{MergeStamp, OutputStamp, SpendStamp, StampHeader},
};
use ragu::{self, proof::PROOF_SIZE_COMPRESSED};
use rand_core::{CryptoRng, RngCore};

use crate::{
    ActionSetPoly, Note, TachygramSetPoly, action,
    digest::blake2b,
    effect,
    entropy::ActionRandomizer,
    keys::ProofAuthorizingKey,
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
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct Unproven;

/// Marker for a stripped bundle whose covering-aggregate `wtxid` has not
/// yet been assigned.
///
/// Produced by [`strip()`](crate::Bundle::strip). Must transition to a
/// `Bundle<AggregateId>` via [`assign_wtxid`](crate::Bundle::assign_wtxid)
/// before serialization.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct Stripped;

/// The 64-byte `wtxid` of the covering aggregate in the same block, assigned
/// by the miner during block assembly.
///
/// A `wtxid` is `txid || auth_digest`: two 32-byte transaction digests as
/// defined by ZIP 244, concatenated per ZIP 239 into the 64-byte identifier
/// used for transaction relay.
///
/// This uses the aggregate's wtxid (not txid) so it unambiguously pins the
/// covering aggregate's authorization state, including stamp.
///
/// An `AggregateId` is always nonzero: every stripped bundle, innocent or
/// adjunct, names a covering transaction, so the all-zero wtxid (which refers
/// to no aggregate) is rejected at every construction site.
#[derive(Clone, Copy, Debug, Into, PartialEq, TotalEq)]
pub struct PointerStamp([u8; 64]);

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

#[derive(Clone, Copy, Debug, Display, Error)]
/// Errors that can occur when handling an aggregate id.
pub enum AggregateIdError {
    /// The aggregate id is zero and refers to no aggregate.
    #[display("aggregate id is zero and refers to no aggregate")]
    Zero,
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

/// Error during stamp verification.
#[derive(Clone, Debug, Display, Error)]
pub enum VerificationError {
    /// An action's cv or rk is the identity point.
    #[display("action digest error: {_0}")]
    ActionDigest(ActionDigestError),
    /// The proof system returned an error.
    #[display("proof system error")]
    ProofSystem,
    /// The proof did not verify against the reconstructed header.
    #[display("proof did not verify")]
    Disproved,
    /// The carried `hActionsTachyon` indicator does not match the actions.
    #[display("covered actions indicator mismatch")]
    ActionsMismatch,
}

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
        action::Descriptor,
        (
            ActionRandomizer<effect::Spend>,
            Note,
            value::CommitmentTrapdoor,
        ),
    )>,
    outputs: Vec<(
        action::Descriptor,
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
            action::Descriptor,
            (
                ActionRandomizer<effect::Spend>,
                Note,
                value::CommitmentTrapdoor,
            ),
        )>,
        outputs: Vec<(
            action::Descriptor,
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
        spendbind_inputs: Vec<(
            ragu::Pcd<delegation::NullifierHeader>,
            [Nullifier; 2],
            ragu::Pcd<spendable::SpendableHeader>,
        )>,
    ) -> Result<ProofStamp, ProveError> {
        // Each entry pairs leaf stamp components with the descriptor of its
        // covered action; merges concatenate the descriptor lists. The
        // covered-actions digest is computed once, on the final stamp.
        let mut entries: Vec<(
            (Vec<Tachygram>, Anchor, Box<ragu::Proof>),
            Vec<action::Descriptor>,
        )> = Vec::new();

        if self.spends.len() != spendbind_inputs.len() {
            return Err(ProveError::SpendableMismatch);
        }

        for ((desc, (alpha, note, rcv)), (range_pcd, [_nf_now, nf_next], spendable_pcd)) in
            self.spends.into_iter().zip(spendbind_inputs)
        {
            let app = &*PROOF_SYSTEM;

            let (bind_pcd, ()) = app
                .fuse(
                    rng,
                    spend::SpendBind,
                    (note, rcv, alpha, *pak),
                    spendable_pcd,
                    ragu::Proof::trivial().carry::<()>(()),
                )
                .map_err(ProveError::ProofFailed)?;

            // SpendStamp: bind the live pair to the derived range and publish.
            let components = ProofStamp::prove_spend(rng, bind_pcd, range_pcd, nf_next)
                .map_err(ProveError::ProofFailed)?;

            entries.push((components, vec![desc]));
        }

        for (desc, (alpha, note, rcv)) in self.outputs {
            let components = ProofStamp::prove_output(rng, rcv, alpha, note, self.anchor)
                .map_err(ProveError::ProofFailed)?;

            entries.push((components, vec![desc]));
        }

        let ((tachygrams, anchor, proof), descriptors) = entries
            .into_iter()
            .map(Ok::<_, ProveError>)
            .reduce(|acc, next| {
                let ((left_tachygrams, left_anchor, left_proof), left_desc) = acc?;
                let ((right_tachygrams, right_anchor, right_proof), right_desc) = next?;

                let left_digests: Vec<ActionDigest> = left_desc
                    .iter()
                    .map(action::Descriptor::digest)
                    .collect::<Result<_, _>>()
                    .map_err(ProveError::ActionDigest)?;
                let right_digests: Vec<ActionDigest> = right_desc
                    .iter()
                    .map(action::Descriptor::digest)
                    .collect::<Result<_, _>>()
                    .map_err(ProveError::ActionDigest)?;

                let merged = ProofStamp::prove_merge(
                    rng,
                    (left_proof, (left_digests, left_tachygrams, left_anchor)),
                    (right_proof, (right_digests, right_tachygrams, right_anchor)),
                )
                .map_err(ProveError::MergeFailed)?;

                Ok((merged, [left_desc, right_desc].concat()))
            })
            .ok_or(ProveError::NoActions)??;

        let descriptor_bytes: Vec<[u8; 64]> =
            descriptors.into_iter().map(<[u8; 64]>::from).collect();

        Ok(ProofStamp {
            covered_actions: blake2b::stamp_actions_digest(&descriptor_bytes),
            tachygrams,
            anchor,
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
    /// `hActionsTachyon`: digest of the covered action descriptors,
    /// indicating which actions this stamp's proof covers. See
    /// [`blake2b::stamp_actions_digest`].
    pub covered_actions: [u8; 32],

    /// Tachygrams (nullifiers and note commitments) for data availability.
    pub tachygrams: Vec<Tachygram>,

    /// Pool state at the anchor block.
    pub anchor: Anchor,

    /// The Ragu proof bytes.
    #[debug(skip)]
    pub proof: Box<ragu::Proof>,
}

impl ProofStamp {
    /// Proves a single output action, returning the stamp components
    /// `(tachygrams, anchor, proof)`.
    ///
    /// The output tachygram (note commitment) is derived inside the circuit
    /// and placed on the stamp for data availability.
    pub fn prove_output<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        rcv: value::CommitmentTrapdoor,
        alpha: ActionRandomizer<effect::Output>,
        note: Note,
        anchor: Anchor,
    ) -> Result<(Vec<Tachygram>, Anchor, Box<ragu::Proof>), ragu::Error> {
        let app = &*PROOF_SYSTEM;

        let (pcd, ()) = app.seed(rng, OutputStamp, (rcv, alpha, note, anchor))?;
        let tachygrams = vec![Tachygram::from(note.commitment())];
        let rerand = app.rerandomize(pcd, rng)?;

        Ok((tachygrams, anchor, Box::new(rerand.proof().clone())))
    }

    /// Proves a single spend action from pre-built spend and
    /// nullifier-range PCDs, returning the stamp components
    /// `(tachygrams, anchor, proof)`.
    ///
    /// The spend's `anchor` is taken as the stamp's anchor — chain
    /// validation lives inside the spendable lineage, not here.
    pub fn prove_spend<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        bind_pcd: ragu::Pcd<spend::SpendHeader>,
        nf_pcd: ragu::Pcd<delegation::NullifierHeader>,
        nf_next: Nullifier,
    ) -> Result<(Vec<Tachygram>, Anchor, Box<ragu::Proof>), ragu::Error> {
        let app = &*PROOF_SYSTEM;

        let (_, _, nf_present, anchor) = *bind_pcd.data();

        let tachygrams = vec![Tachygram::from(nf_next), Tachygram::from(nf_present)];

        let (pcd, ()) = app.fuse(rng, SpendStamp, (nf_next,), bind_pcd, nf_pcd)?;

        let rerand = app.rerandomize(pcd, rng)?;

        Ok((tachygrams, anchor, Box::new(rerand.proof().clone())))
    }

    /// Proves the merge of two stamps, returning the merged stamp
    /// components `(tachygrams, anchor, proof)`.
    ///
    /// Both stamps must share the same anchor (use StampLift to align first).
    ///
    /// Each side is `(proof, (digests, tachygrams, anchor))` — the digest
    /// list reconstructs the `ActionCommit` multiset that `MergeStamp`
    /// verifies via Schwartz-Zippel. Digests are derived from public action
    /// data by the caller and are never stored on the stamp.
    pub fn prove_merge<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        (left_proof, left_data): (
            Box<ragu::Proof>,
            (Vec<ActionDigest>, Vec<Tachygram>, Anchor),
        ),
        (right_proof, right_data): (
            Box<ragu::Proof>,
            (Vec<ActionDigest>, Vec<Tachygram>, Anchor),
        ),
    ) -> Result<(Vec<Tachygram>, Anchor, Box<ragu::Proof>), ragu::Error> {
        let (left_digests, left_tachygrams, left_anchor) = left_data;
        let (right_digests, right_tachygrams, right_anchor) = right_data;

        let app = &*PROOF_SYSTEM;

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

        let tachygrams = [left_tachygrams, right_tachygrams].concat();
        let merged_tg_poly = TachygramSetPoly::from_iter(tachygrams.clone());
        let merged_acts_poly = ActionSetPoly::from_iter([left_digests, right_digests].concat());

        let (pcd, ()) = app.fuse(
            rng,
            MergeStamp,
            (
                (left_acts_poly, left_tg_poly),
                (merged_acts_poly, merged_tg_poly),
                (right_acts_poly, right_tg_poly),
            ),
            left_pcd,
            right_pcd,
        )?;
        let anchor = pcd.data().2;
        let rerand = app.rerandomize(pcd, rng)?;

        Ok((tachygrams, anchor, Box::new(rerand.proof().clone())))
    }

    /// Merges two stamps into one covering stamp.
    ///
    /// Each side pairs a stamp with the descriptors of its covered actions.
    /// The action digests for the merge proof and the merged
    /// `covered_actions` are both derived from the descriptor lists.
    ///
    /// TODO: confirm desc list against stamp?
    pub fn merge<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        (left_stamp, left_desc): (Self, Vec<action::Descriptor>),
        (right_stamp, right_desc): (Self, Vec<action::Descriptor>),
    ) -> Result<Self, ProveError> {
        let left_actions_digest = left_desc
            .iter()
            .map(|desc| ActionDigest::new(desc.cv, desc.rk))
            .collect::<Result<Vec<ActionDigest>, ActionDigestError>>()
            .map_err(ProveError::ActionDigest)?;
        let right_actions_digest = right_desc
            .iter()
            .map(|desc| ActionDigest::new(desc.cv, desc.rk))
            .collect::<Result<Vec<ActionDigest>, ActionDigestError>>()
            .map_err(ProveError::ActionDigest)?;

        let (tachygrams, anchor, proof) = Self::prove_merge(
            rng,
            (
                left_stamp.proof,
                (
                    left_actions_digest,
                    left_stamp.tachygrams,
                    left_stamp.anchor,
                ),
            ),
            (
                right_stamp.proof,
                (
                    right_actions_digest,
                    right_stamp.tachygrams,
                    right_stamp.anchor,
                ),
            ),
        )
        .map_err(ProveError::MergeFailed)?;

        let covered_actions: Vec<[u8; 64]> = [left_desc, right_desc]
            .concat()
            .into_iter()
            .map(<[u8; 64]>::from)
            .collect();

        let merged_stamp = Self {
            covered_actions: blake2b::stamp_actions_digest(&covered_actions),
            tachygrams,
            anchor,
            proof,
        };

        Ok(merged_stamp)
    }

    /// Checks if this stamp covers the given action descriptors.
    #[must_use]
    pub fn covers(&self, descs: &[action::Descriptor]) -> bool {
        let desc_bytes: Vec<[u8; 64]> = descs
            .iter()
            .map(|&desc| <[u8; 64]>::from(desc))
            .collect::<Vec<[u8; 64]>>();
        blake2b::stamp_actions_digest(&desc_bytes) == self.covered_actions
    }

    /// Verifies this stamp's proof by reconstructing the PCD header from
    /// public data.
    ///
    /// The verifier recomputes the covered-actions digest, fails early if
    /// it disagrees with the carried `hActionsTachyon`, then reconstructs
    /// the action and tachygram accumulators and calls Ragu `verify()`.
    pub fn verify<RNG: RngCore + CryptoRng>(
        &self,
        rng: &mut RNG,
        actions: &[action::Descriptor],
    ) -> Result<(), VerificationError> {
        let app = &*PROOF_SYSTEM;

        let descriptor_bytes: Vec<[u8; 64]> =
            actions.iter().copied().map(<[u8; 64]>::from).collect();

        if blake2b::stamp_actions_digest(&descriptor_bytes) != self.covered_actions {
            return Err(VerificationError::ActionsMismatch);
        }

        let action_digests = actions
            .iter()
            .map(action::Descriptor::digest)
            .collect::<Result<Vec<ActionDigest>, ActionDigestError>>()
            .map_err(VerificationError::ActionDigest)?;
        let action_set = action_digests
            .into_iter()
            .collect::<ActionSetPoly>()
            .commit();
        let header = (
            action_set,
            self.tachygrams
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit(),
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
        let mut covered_actions = [0u8; 32];
        reader.read_exact(&mut covered_actions)?;

        let anchor = Anchor::read(&mut reader)?;

        let tachygrams = serialization::read_fp_list(&mut reader)?
            .into_iter()
            .map(Tachygram::from)
            .collect();

        let proof = Box::new(read_proof(&mut reader)?);

        Ok(Self {
            covered_actions,
            tachygrams,
            anchor,
            proof,
        })
    }

    /// Write a stamp to the consensus wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.covered_actions)?;
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
    let mut bytes = vec![0u8; PROOF_SIZE_COMPRESSED];
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
