//! Stamps and anchors.
//!
//! A stamp carries the tachygram list, the anchor, and the proof:
//!
//! - **Tachygrams**: Listed individually
//! - **Anchor**: Block height, block/pool commits, block/epoch chain hashes
//! - **Proof**: The Ragu PCD proof (rerandomized)
//!
//! The PCD header data `(action_acc, tachygram_acc, anchor)` is **not
//! serialized** on the stamp — the verifier reconstructs the accumulators from
//! public data and passes them as the header to Ragu `verify()`.

#![allow(clippy::type_complexity, reason = "todo")]
#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

pub mod proof;

use alloc::vec::Vec;
use core::{error::Error, fmt};

use core2::io::{self, Read, Write};
use ff::Field as _;
use mock_ragu::{self, proof::PROOF_SIZE_COMPRESSED};
use pasta_curves::Fp;
use proof::{
    PROOF_SYSTEM,
    stamp::{MergeStamp, OutputStamp, SpendStamp, StampHeader},
};
use rand_core::CryptoRng;

use crate::{
    Note,
    action::Action,
    effect,
    entropy::ActionRandomizer,
    keys::{ProofAuthorizingKey, public},
    primitives::{
        ActionCommit, ActionDigest, ActionDigestError, ActionSet, Anchor, BlockAcc, BlockHeight,
        DelegationTrapdoor, PoolChain, Tachygram, TachygramAcc, TachygramCommit,
    },
    stamp::proof::{compute_action_acc, delegation, spend, spendable},
    value,
};

/// Marker for a bundle that has not yet been proven.
///
/// This is the initial state for a newly constructed bundle.
/// Proving produces a [`Stamp`]; stripping produces an [`Adjunct`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unproven;

/// Marker for a stripped bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adjunct {
    /// 64-byte `wtxid` (`txid || auth_digest`) of the covering aggregate in
    /// the block. Assigned by the miner during block assembly; defaults to
    /// all-zero bytes.
    ///
    /// The ref is the aggregate's wtxid (not txid) so it uniquely pins the
    /// covering aggregate's physical auth form — different stamps on the
    /// same effecting data produce different wtxids, so this ref remains
    /// unambiguous even across aggregation forms.
    pub wtxid: [u8; 64],
}

impl Default for Adjunct {
    fn default() -> Self {
        Self { wtxid: [0u8; 64] }
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
            DelegationTrapdoor,
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
    ///
    /// The caller is responsible for deriving alpha from theta (or
    /// obtaining it through other means). Each spend witness carries the
    /// `DelegationTrapdoor` that was used to construct the corresponding
    /// nullifier-header PCDs, so `SpendBind` can recompute and equality-check
    /// the `DelegationId`.
    #[must_use]
    pub const fn new(
        spends: Vec<(
            (value::Commitment, public::ActionVerificationKey),
            (
                ActionRandomizer<effect::Spend>,
                Note,
                value::CommitmentTrapdoor,
                DelegationTrapdoor,
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
    /// [`SpendStamp`] to attach the spendable chain.
    ///
    /// For each **output**, runs [`OutputStamp`] with no PCD inputs.
    ///
    /// Stamps are recursively merged via [`MergeStamp`] into a single stamp.
    ///
    /// `spend_pcds` items must correspond to each planned spend, in order.
    pub fn prove<'source, RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        pak: &ProofAuthorizingKey,
        spend_pcds: Vec<(
            mock_ragu::Pcd<'source, delegation::NullifierHeader>,
            mock_ragu::Pcd<'source, delegation::NullifierHeader>,
            mock_ragu::Pcd<'source, spendable::SpendableHeader>,
            PoolChain,
            BlockAcc,
            BlockHeight,
        )>,
    ) -> Result<Stamp, ProveError> {
        // Each entry is (stamp, action_digests). The digest list is ephemeral —
        // needed to reconstruct the PCD header's action multiset during merge,
        // never stored.
        let mut entries: Vec<(Stamp, Vec<ActionDigest>)> = Vec::new();

        if self.spends.len() != spend_pcds.len() {
            return Err(ProveError::SpendableMismatch);
        }

        for (
            ((cv, rk), (alpha, note, rcv, delegation_trap)),
            (nf_now_pcd, nf_next_pcd, spendable_pcd, prev_chain, block, height),
        ) in self.spends.into_iter().zip(spend_pcds.into_iter())
        {
            let action_digest =
                ActionDigest::new(cv, rk).map_err(|_err| ProveError::ProofFailed)?;

            // Extract nullifier data before fuse consumes the PCDs.
            let (nf0, epoch, delegation_id) = nf_now_pcd.data;
            let nf1 = nf_next_pcd.data.0;

            let app = &*PROOF_SYSTEM;

            // SpendBind: fuse two epoch-adjacent nullifier headers with action data
            let (bind_proof, ()) = app
                .fuse(
                    rng,
                    &spend::SpendBind,
                    (rcv, alpha, *pak, note, delegation_trap),
                    nf_now_pcd,
                    nf_next_pcd,
                )
                .map_err(|_err| ProveError::ProofFailed)?;

            let bind_pcd = bind_proof.carry::<spend::SpendHeader>((
                action_digest,
                [nf0, nf1],
                epoch,
                delegation_id,
            ));

            // SpendStamp: fuse spend with spendable chain
            let tachygrams = alloc::vec![Tachygram::from(&nf0), Tachygram::from(&nf1),];
            let stamp = Stamp::prove_spend(
                rng,
                bind_pcd,
                spendable_pcd,
                tachygrams,
                prev_chain,
                block,
                height,
            )
            .map_err(|_err| ProveError::ProofFailed)?;

            entries.push((stamp, alloc::vec![action_digest]));
        }

        for ((cv, rk), (alpha, note, rcv)) in self.outputs {
            let action_digest =
                ActionDigest::new(cv, rk).map_err(|_err| ProveError::ProofFailed)?;

            let stamp = Stamp::prove_output(rng, rcv, alpha, note, self.anchor)
                .map_err(|_err| ProveError::ProofFailed)?;

            entries.push((stamp, alloc::vec![action_digest]));
        }

        if entries.is_empty() {
            return Err(ProveError::NoActions);
        }

        // Merge pairwise.
        while entries.len() > 1 {
            let (right, right_digests) = entries.pop().ok_or(ProveError::NoActions)?;
            let (left, left_digests) = entries.pop().ok_or(ProveError::NoActions)?;
            let merged = Stamp::prove_merge(rng, (left, &left_digests), (right, &right_digests))
                .map_err(|_err| ProveError::MergeFailed)?;
            let mut merged_digests = left_digests;
            merged_digests.extend_from_slice(&right_digests);
            entries.push((merged, merged_digests));
        }

        entries
            .pop()
            .map(|(stamp, _digests)| stamp)
            .ok_or(ProveError::NoActions)
    }
}

/// Errors that can occur while proving a stamp.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProveError {
    /// The plan has no actions to prove.
    NoActions,
    /// Proof creation failed for an action.
    ProofFailed,
    /// Stamp merge failed.
    MergeFailed,
    /// Number of spendable PCDs doesn't match number of spends.
    SpendableMismatch,
}

impl fmt::Display for ProveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::NoActions => write!(f, "no actions to prove"),
            | Self::ProofFailed => write!(f, "action proof failed"),
            | Self::MergeFailed => write!(f, "stamp merge failed"),
            | Self::SpendableMismatch => write!(f, "spendable PCD count mismatch"),
        }
    }
}

impl Error for ProveError {}

/// A stamp carrying tachygrams, anchor, and proof.
///
/// Present in [`Stamped`](crate::Stamped) bundles.
/// Stripped during aggregation and merged into the aggregate's stamp.
///
/// The PCD header `(action_acc, tachygram_acc, anchor)` is not stored here —
/// the verifier reconstructs it from public data and passes it as the header
/// to Ragu `verify()`.
#[derive(Clone, Debug)]
pub struct Stamp {
    /// Tachygrams (nullifiers and note commitments) for data availability.
    pub tachygrams: Vec<Tachygram>,

    /// Pool state at the anchor block.
    pub anchor: Anchor,

    /// The Ragu proof bytes.
    pub proof: mock_ragu::Proof,
}

impl Stamp {
    /// Creates a stamp for a single output action.
    ///
    /// The output tachygram (note commitment) is derived inside the circuit
    /// and placed on the stamp for data availability.
    pub fn prove_output<RNG: CryptoRng>(
        rng: &mut RNG,
        rcv: value::CommitmentTrapdoor,
        alpha: ActionRandomizer<effect::Output>,
        note: Note,
        anchor: Anchor,
    ) -> Result<Self, mock_ragu::Error> {
        let app = &*PROOF_SYSTEM;

        let (proof, (action_acc, tachygram_acc, tachygram)) =
            app.seed(rng, &OutputStamp, (rcv, alpha, note, anchor))?;

        let header = (
            ActionCommit(action_acc.0.commit(Fp::ZERO)),
            TachygramCommit(tachygram_acc.0.commit(Fp::ZERO)),
            anchor,
        );
        let pcd = proof.carry::<StampHeader>(header);
        let rerand = app.rerandomize(pcd, rng)?;

        Ok(Self {
            tachygrams: alloc::vec![tachygram],
            anchor,
            proof: rerand.proof,
        })
    }

    /// Creates a stamp for a spend action from pre-built spend and spendable
    /// PCDs.
    ///
    /// The caller is responsible for building the full pipeline
    /// (SpendNullifier → SpendBind, and the spendable chain) and providing
    /// the resulting PCDs.
    pub fn prove_spend<'source, RNG: CryptoRng>(
        rng: &mut RNG,
        spend_pcd: mock_ragu::Pcd<'source, spend::SpendHeader>,
        spendable_pcd: mock_ragu::Pcd<'source, spendable::SpendableHeader>,
        tachygrams: Vec<Tachygram>,
        prev_chain: PoolChain,
        block: BlockAcc,
        height: BlockHeight,
    ) -> Result<Self, mock_ragu::Error> {
        let app = &*PROOF_SYSTEM;

        let anchor = spendable_pcd.data.2;

        let (proof, (action_acc, tachygram_acc)) = app.fuse(
            rng,
            &SpendStamp,
            (prev_chain, block.into(), height),
            spend_pcd,
            spendable_pcd,
        )?;

        let header = (
            ActionCommit(action_acc.0.commit(Fp::ZERO)),
            TachygramCommit(tachygram_acc.0.commit(Fp::ZERO)),
            anchor,
        );

        let pcd = proof.carry::<StampHeader>(header);
        let rerand = app.rerandomize(pcd, rng)?;

        Ok(Self {
            tachygrams,
            anchor,
            proof: rerand.proof,
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
    pub fn prove_merge<RNG: CryptoRng>(
        rng: &mut RNG,
        (left, left_digests): (Self, &[ActionDigest]),
        (right, right_digests): (Self, &[ActionDigest]),
    ) -> Result<Self, mock_ragu::Error> {
        let app = &*PROOF_SYSTEM;

        let left_fps: Vec<Fp> = left_digests.iter().map(Fp::from).collect();
        let right_fps: Vec<Fp> = right_digests.iter().map(Fp::from).collect();
        let left_action = ActionSet(mock_ragu::Polynomial::from_roots(&left_fps));
        let right_action = ActionSet(mock_ragu::Polynomial::from_roots(&right_fps));
        let left_tachygram = TachygramAcc::from(&*left.tachygrams);
        let right_tachygram = TachygramAcc::from(&*right.tachygrams);

        let left_header = (
            ActionCommit(left_action.0.commit(Fp::ZERO)),
            TachygramCommit(left_tachygram.0.commit(Fp::ZERO)),
            left.anchor,
        );
        let right_header = (
            ActionCommit(right_action.0.commit(Fp::ZERO)),
            TachygramCommit(right_tachygram.0.commit(Fp::ZERO)),
            right.anchor,
        );

        let left_pcd = left.proof.carry::<StampHeader>(left_header);
        let right_pcd = right.proof.carry::<StampHeader>(right_header);

        let anchor = left.anchor;
        let mut tachygrams = left.tachygrams;
        tachygrams.extend(right.tachygrams.iter().copied());

        let merged_action = left_action.0.multiply(&right_action.0);
        let merged_tachygram = left_tachygram.0.multiply(&right_tachygram.0);

        let (proof, ()) = app.fuse(
            rng,
            &MergeStamp,
            (
                left_action.into(),
                right_action.into(),
                left_tachygram.into(),
                right_tachygram.into(),
            ),
            left_pcd,
            right_pcd,
        )?;

        let merged_header = (
            ActionCommit(merged_action.commit(Fp::ZERO)),
            TachygramCommit(merged_tachygram.commit(Fp::ZERO)),
            anchor,
        );
        let carried = proof.carry::<StampHeader>(merged_header);
        let rerand = app.rerandomize(carried, rng)?;

        Ok(Self {
            tachygrams,
            anchor,
            proof: rerand.proof,
        })
    }

    /// Verifies this stamp's proof by reconstructing the PCD header from
    /// public data.
    ///
    /// The verifier recomputes action and tachygram accumulators as raw Fp
    /// products, constructs the PCD header, and calls Ragu `verify()`.
    pub fn verify(
        &self,
        actions: &[Action],
        rng: &mut impl CryptoRng,
    ) -> Result<(), VerificationError> {
        let app = &*PROOF_SYSTEM;

        let action_acc = compute_action_acc(actions).map_err(VerificationError::ActionDigest)?;
        let tachygram_acc = TachygramAcc::from(&*self.tachygrams);

        let header = (
            ActionCommit(action_acc.0.commit(Fp::ZERO)),
            TachygramCommit(tachygram_acc.0.commit(Fp::ZERO)),
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

/// The serialized size of a proof, written raw without a length prefix.
pub(crate) const fn proof_serialized_size() -> usize {
    PROOF_SIZE_COMPRESSED
}

/// Read a proof of the given byte length.
pub(crate) fn read_proof_sized<R: Read>(
    mut reader: R,
    size: usize,
) -> io::Result<mock_ragu::Proof> {
    use alloc::boxed::Box;

    if size != PROOF_SIZE_COMPRESSED {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected proof size",
        ));
    }

    let mut bytes = alloc::vec![0u8; size];
    reader.read_exact(&mut bytes)?;
    let arr: Box<[u8; PROOF_SIZE_COMPRESSED]> = bytes
        .into_boxed_slice()
        .try_into()
        .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "proof buffer wrong size"))?;
    mock_ragu::Proof::try_from(arr.as_ref())
        .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "invalid proof encoding"))
}

/// Write a proof's raw bytes (without length prefix).
pub(crate) fn write_proof<W: Write>(mut writer: W, proof: &mock_ragu::Proof) -> io::Result<()> {
    let bytes = proof.serialize();
    writer.write_all(bytes.as_ref())
}

#[cfg(test)]
mod tests;
