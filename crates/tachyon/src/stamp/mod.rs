//! Stamps and anchors.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

pub mod proof;

use alloc::{boxed::Box, collections::BTreeSet, vec, vec::Vec};

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
            tachygrams,
            proof: Box::new(proof),
        })
    }

    /// Write a stamp to the consensus wire format. The proof blob has a
    /// known constant size.
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.coverage)?;
        self.anchor.write(&mut writer)?;
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
            let (bind_pcd, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    spend::SpendBind,
                    (note, rcv, alpha, *pak),
                    spendable_pcd,
                    ragu::Proof::trivial().carry::<()>(()),
                )
                .map_err(ProveError::ProofFailed)?;

            // SpendStamp: bind the live pair to the derived range and publish.
            let (tachygrams, anchor, proof) =
                ProofStamp::prove_spend(rng, bind_pcd, nf_pcd).map_err(ProveError::ProofFailed)?;

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

        Ok(ProofStamp {
            coverage,
            anchor,
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
    ) -> Result<(BTreeSet<Tachygram>, Anchor, Box<ragu::Proof>), ragu::Error> {
        let (pcd, ()) = PROOF_SYSTEM.seed(rng, OutputStamp, (rcv, alpha, note, anchor))?;
        let tachygrams = BTreeSet::from_iter([Tachygram::from(note.commitment())]);

        let rerand = PROOF_SYSTEM.rerandomize(pcd, rng)?;

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
    ) -> Result<(BTreeSet<Tachygram>, Anchor, Box<ragu::Proof>), ragu::Error> {
        let (_, _, nf_present, anchor) = *bind_pcd.data();
        let (_, _, _, (_, nf_next)) = *nf_pcd.data();

        let tachygrams =
            BTreeSet::from_iter([Tachygram::from(nf_present), Tachygram::from(nf_next)]);

        let (pcd, ()) = PROOF_SYSTEM.fuse(rng, SpendStamp, (nf_next,), bind_pcd, nf_pcd)?;

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

        Ok(Self {
            coverage,
            anchor,
            tachygrams,
            proof,
        })
    }

    /// Confirm `hStampActionsTachyon` represents the given action descriptors.
    ///
    /// # Soundness
    ///
    /// The input parameter represents a multiset. Order does not matter, but
    /// multiplicity does. A set containing duplicate members is not the same as
    /// a similar set without duplicates.
    #[must_use]
    pub fn covers(&self, action_descs: &[action::Descriptor]) -> bool {
        let mut desc_bytes = action_descs.iter().copied().collect::<Vec<[u8; 64]>>();
        desc_bytes.sort_unstable();
        blake2b::action_descriptor_digest(&desc_bytes) == self.coverage
    }

    /// Verifies this stamp's proof by reconstructing the PCD header from
    /// public data.
    ///
    /// You might want to call [`ProofStamp::covers`] first, to check if the
    /// verification may be expected to fail.
    ///
    /// # Soundness
    ///
    /// The input parameter represents a multiset. Order does not matter, but
    /// multiplicity does. A set containing duplicate members is not the same as
    /// a similar set without duplicates.
    pub fn verify_proof<RNG: RngCore + CryptoRng>(
        &self,
        rng: &mut RNG,
        action_digests: &[ActionDigest],
    ) -> Result<bool, ragu::Error> {
        let action_set = action_digests.iter().copied().collect::<ActionSetPoly>();

        let tachygram_set = self
            .tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>();

        let pcd = self.proof.clone().carry::<StampHeader>((
            action_set.commit(),
            tachygram_set.commit(),
            self.anchor,
        ));

        PROOF_SYSTEM.verify(&pcd, rng)
    }
}

#[cfg(test)]
mod tests;
