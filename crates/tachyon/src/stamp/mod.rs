//! Stamps and anchors.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

pub mod proof;

use alloc::{boxed::Box, vec, vec::Vec};

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, Into, PartialEq};
use ff::PrimeField as _;
use pasta_curves::Fp;
use proof::{
    PROOF_SYSTEM,
    stamp::{MergeStamp, OutputStamp, SpendStamp, StampHeader},
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
    primitives::{ActionDigest, ActionDigestError, Anchor, Tachygram},
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
                &tachygrams,
            )
        };

        let mut stamp_digest = [0u8; 64];
        stamp_digest[..32].copy_from_slice(&self.actions);
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

        let tachygrams: Vec<Tachygram> = serialization::read_fp_list(&mut reader)?
            .into_iter()
            .map(Tachygram::from)
            .collect();
        if !tachygrams.is_sorted() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tachygrams are not canonically sorted",
            ));
        }

        let mut bytes = vec![0u8; PROOF_SIZE_COMPRESSED];
        reader.read_exact(&mut bytes)?;
        let arr: Box<[u8; PROOF_SIZE_COMPRESSED]> =
            bytes.into_boxed_slice().try_into().map_err(|_err| {
                io::Error::new(io::ErrorKind::InvalidData, "proof buffer wrong size")
            })?;
        let proof = ragu::Proof::try_from(arr.as_ref())
            .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "invalid proof encoding"))?;

        Ok(Self {
            actions: covered_actions,
            tachygrams,
            anchor,
            proof: Box::new(proof),
        })
    }

    /// Write a stamp to the consensus wire format. The proof blob has a
    /// known constant size.
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.actions)?;
        self.anchor.write(&mut writer)?;
        serialization::write_fp_list(
            &mut writer,
            &self
                .tachygrams
                .iter()
                .map(|&tg| Fp::from(tg))
                .collect::<Vec<Fp>>(),
        )?;
        writer.write_all(self.proof.serialize().as_ref())
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
    /// The carried `hStampActionsTachyon` indicator does not match the actions.
    #[display("covered actions indicator mismatch")]
    ActionsMismatch,
}

/// Everything needed to produce a [`ProofStamp`].
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
    /// For each **spend**, uses [`spend::SpendBind`] to bind the live
    /// nullifier pair against the derived range, then runs [`SpendStamp`] to
    /// prove the action and publish the stamp.
    ///
    /// For each **output**, runs [`OutputStamp`] with no PCD inputs.
    ///
    /// Stamps are recursively merged via [`MergeStamp`] into a single stamp.
    ///
    /// `spendbind_inputs` items must correspond to each planned spend, in
    /// order.
    pub fn prove<RNG: RngCore + CryptoRng>(
        self,
        rng: &mut RNG,
        pak: &ProofAuthorizingKey,
        spendbind_inputs: Vec<(
            ragu::Pcd<spendable::SpendableHeader>,
            ragu::Pcd<delegation::NullifierHeader>,
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

        for ((desc, alpha, note, rcv), (sp_pcd, nf_pcd)) in
            self.spends.into_iter().zip(spendbind_inputs)
        {
            let app = &*PROOF_SYSTEM;

            let (bind_pcd, ()) = app
                .fuse(rng, spend::SpendBind, (), sp_pcd, nf_pcd)
                .map_err(ProveError::ProofFailed)?;

            let (tachygrams, anchor, proof) =
                ProofStamp::prove_spend(rng, rcv, alpha, note, *pak, bind_pcd)
                    .map_err(ProveError::ProofFailed)?;

            let digest = desc.digest().map_err(ProveError::ActionDigest)?;
            entries.push((vec![desc], vec![digest], tachygrams, anchor, proof));
        }

        for (desc, alpha, note, rcv) in self.outputs {
            let (tachygrams, anchor, proof) =
                ProofStamp::prove_output(rng, rcv, alpha, note, self.anchor)
                    .map_err(ProveError::ProofFailed)?;

            let digest = desc.digest().map_err(ProveError::ActionDigest)?;
            entries.push((vec![desc], vec![digest], tachygrams, anchor, proof));
        }

        let (mut descriptors, _digests, mut tachygrams, anchor, proof) = entries
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

                Ok((
                    [left_desc, right_desc].concat(),
                    merged_digests,
                    merged_tachygrams,
                    merged_anchor,
                    merged_proof,
                ))
            })
            .ok_or(ProveError::NoActions)??;

        descriptors.sort_unstable();
        tachygrams.sort_unstable();

        Ok(ProofStamp {
            actions: blake2b::action_descriptor_digest(&Vec::<[u8; 64]>::from_iter(descriptors)),
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
    /// The digest $\mathsf{hStampActionsTachyon}$ of the proof's covered action
    /// descriptors from this stamp's bundle and all covered bundles.
    ///
    /// See [`blake2b::action_descriptor_digest`]
    pub actions: [u8; 32],

    /// Tachygrams (nullifiers and note commitments) for data availability.
    pub tachygrams: Vec<Tachygram>,

    /// Pool state at the anchor block.
    pub anchor: Anchor,

    /// The Ragu proof bytes.
    #[debug(skip)]
    pub proof: Box<ragu::Proof>,
}

/// Stamp components threaded through the merge fold: the covered actions'
/// digests, the tachygrams, the shared anchor, and the proof.
type StampComponents = (Vec<ActionDigest>, Vec<Tachygram>, Anchor, Box<ragu::Proof>);

impl ProofStamp {
    /// Proves a single output action, returning the stamp components
    /// `(tachygrams, anchor, proof)`.
    ///
    /// The output tachygram (note commitment) is derived inside the circuit
    /// and placed on the stamp for data availability.
    pub fn prove_output<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        rcv: value::Trapdoor,
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

    /// Proves a single spend action from a pre-built [`spend::SpendBind`]
    /// PCD, returning the stamp components `(tachygrams, anchor, proof)`.
    ///
    /// The spend's `anchor` is taken as the stamp's anchor — chain
    /// validation lives inside the spendable lineage, not here.
    pub fn prove_spend<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        rcv: value::Trapdoor,
        alpha: ActionRandomizer<effect::Spend>,
        note: Note,
        pak: ProofAuthorizingKey,
        bind_pcd: ragu::Pcd<spend::SpendHeader>,
    ) -> Result<(Vec<Tachygram>, Anchor, Box<ragu::Proof>), ragu::Error> {
        let app = &*PROOF_SYSTEM;

        let (_, present_nf, nf_next, anchor) = *bind_pcd.data();
        let tachygrams = vec![Tachygram::from(present_nf), Tachygram::from(nf_next)];

        let (pcd, ()) = app.fuse(
            rng,
            SpendStamp,
            (note, rcv, alpha, pak),
            bind_pcd,
            ragu::Proof::trivial().carry::<()>(()),
        )?;

        let rerand = app.rerandomize(pcd, rng)?;

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

        let merged_digests = [left_digests, right_digests].concat();
        let tachygrams = [left_tachygrams, right_tachygrams].concat();
        let merged_tg_poly = TachygramSetPoly::from_iter(tachygrams.clone());
        let merged_acts_poly = ActionSetPoly::from_iter(merged_digests.clone());

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
        (left_stamp, left_desc): (Self, Vec<action::Descriptor>),
        (right_stamp, right_desc): (Self, Vec<action::Descriptor>),
    ) -> Result<Self, ProveError> {
        let left_actions_digest = left_desc
            .iter()
            .map(action::Descriptor::digest)
            .collect::<Result<Vec<ActionDigest>, ActionDigestError>>()
            .map_err(ProveError::ActionDigest)?;
        let right_actions_digest = right_desc
            .iter()
            .map(action::Descriptor::digest)
            .collect::<Result<Vec<ActionDigest>, ActionDigestError>>()
            .map_err(ProveError::ActionDigest)?;

        let (_merged_digests, mut tachygrams, anchor, proof) = Self::prove_merge(
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
        tachygrams.sort_unstable();

        let mut covered_actions = Vec::<[u8; 64]>::from_iter([left_desc, right_desc].concat());
        covered_actions.sort_unstable();

        Ok(Self {
            actions: blake2b::action_descriptor_digest(&covered_actions),
            tachygrams,
            anchor,
            proof,
        })
    }

    /// Checks if this stamp covers the given action descriptors. The
    /// descriptors are sorted into canonical order before hashing, so the
    /// check is independent of the order the caller presents them in.
    #[must_use]
    pub fn covers(&self, descs: &[action::Descriptor]) -> bool {
        let mut desc_bytes = descs.iter().copied().collect::<Vec<[u8; 64]>>();
        desc_bytes.sort_unstable();
        blake2b::action_descriptor_digest(&desc_bytes) == self.actions
    }

    /// Verifies this stamp's proof by reconstructing the PCD header from
    /// public data.
    ///
    /// The verifier recomputes the covered-actions digest, fails early if
    /// it disagrees with the carried `hStampActionsTachyon`, then reconstructs
    /// the action and tachygram accumulators and calls Ragu `verify()`.
    pub fn verify<RNG: RngCore + CryptoRng>(
        &self,
        rng: &mut RNG,
        actions: &[action::Descriptor],
    ) -> Result<(), VerificationError> {
        let app = &*PROOF_SYSTEM;

        if !self.covers(actions) {
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
}

#[cfg(test)]
mod tests;
