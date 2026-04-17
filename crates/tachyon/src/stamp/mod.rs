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

extern crate alloc;

pub mod delegation;
pub mod header;
pub mod pool;
pub mod proof;
pub mod spend;
pub mod spendable;

use alloc::vec::Vec;
use core::{error::Error, fmt};

use core2::io::{self, Read, Write};
use mock_ragu::{self, proof::PROOF_SIZE_COMPRESSED};
use pasta_curves::Fp;
use rand_core::CryptoRng;

pub use self::proof::compute_action_acc;
use self::{
    header::{MergeStamp, OutputStamp, SpendStamp, StampHeader},
    proof::{PROOF_SYSTEM, compute_tachygram_acc},
};
use crate::{
    Note,
    action::Action,
    effect,
    entropy::ActionRandomizer,
    keys::{ProofAuthorizingKey, private, public},
    primitives::{ActionDigest, ActionDigestError, Anchor, Tachygram},
    stamp::{
        spend::{SpendBind, SpendNullifierHeader},
        spendable::SpendableHeader,
    },
    value,
};

/// Marker for a bundle that has not yet been proven.
///
/// This is the initial state for a newly constructed bundle.
/// Proving produces a [`Stamp`]; stripping produces an [`Adjunct`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unproven;

/// Marker for a stripped bundle that depends on an aggregate stamp.
///
/// Carries an optional index referencing the stamped bundle on the surrounding
/// block that covers this bundle's tachygrams.  Assigned by the miner during
/// block assembly; defaults to `None`.
///
/// Serialization will fail if the index has not been assigned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Adjunct(Option<u8>);

impl Adjunct {
    /// Create a new `Adjunct` with the given `stamp_index`.
    ///
    /// # Panics
    ///
    /// Panics if the index is greater than 0xFC.
    #[must_use]
    pub fn new(stamp_index: u8) -> Self {
        assert!(stamp_index <= 0xFC, "stamp index must be <= 0xFC");
        Self(Some(stamp_index))
    }

    /// Set `stamp_index` to associate a stripped adjunct with an aggregate
    /// stamp in the same block.
    ///
    /// # Panics
    ///
    /// Panics if the index is greater than 0xFC.
    pub fn set_index(&mut self, set_index: u8) {
        assert!(set_index <= 0xFC, "stamp index must be <= 0xFC");
        self.0 = Some(set_index);
    }

    /// Get the `stamp_index` associated with this stripped adjunct.
    ///
    /// Returns `None` if the `stamp_index` has not been assigned.
    #[must_use]
    pub const fn get_index(&self) -> Option<u8> {
        self.0
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
    ///
    /// The caller is responsible for deriving alpha from theta (or
    /// obtaining it through other means).
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
            mock_ragu::Pcd<'source, SpendNullifierHeader>,
            mock_ragu::Pcd<'source, SpendableHeader>,
        )>,
    ) -> Result<Stamp, ProveError> {
        // Each entry is (stamp, action_acc). action_acc is ephemeral —
        // needed to reconstruct PCD headers during merge, never stored.
        let mut entries: Vec<(Stamp, Fp)> = Vec::new();

        if self.spends.len() != spend_pcds.len() {
            return Err(ProveError::SpendableMismatch);
        }

        for (((cv, rk), (alpha, note, rcv)), (nf_pcd, spendable_pcd)) in
            self.spends.into_iter().zip(spend_pcds.into_iter())
        {
            let action_digest =
                ActionDigest::new(cv, rk).map_err(|_err| ProveError::ProofFailed)?;

            // Extract nullifier data before fuse consumes the PCD.
            let (nf0, nf1, epoch, note_id) = nf_pcd.data;

            let app = &*PROOF_SYSTEM;

            // SpendBind: fuse nullifier header with action data
            let (bind_proof, ()) = app
                .fuse(
                    rng,
                    &SpendBind,
                    (rcv, alpha, *pak, note),
                    nf_pcd,
                    mock_ragu::Pcd {
                        proof: mock_ragu::Proof::trivial(),
                        data: (),
                    },
                )
                .map_err(|_err| ProveError::ProofFailed)?;

            let bind_pcd = bind_proof.carry::<spend::SpendHeader>((
                Fp::from(action_digest),
                [nf0, nf1],
                epoch,
                note_id,
            ));

            // SpendStamp: fuse spend with spendable chain
            let tachygrams = alloc::vec![
                Tachygram::from(Fp::from(nf0)),
                Tachygram::from(Fp::from(nf1)),
            ];
            let stamp = Stamp::prove_spend(rng, bind_pcd, spendable_pcd, tachygrams)
                .map_err(|_err| ProveError::ProofFailed)?;

            entries.push((stamp, Fp::from(action_digest)));
        }

        for ((cv, rk), (alpha, note, rcv)) in self.outputs {
            let action_digest =
                ActionDigest::new(cv, rk).map_err(|_err| ProveError::ProofFailed)?;

            let stamp = Stamp::prove_output(rng, rcv, alpha, note, self.anchor)
                .map_err(|_err| ProveError::ProofFailed)?;

            entries.push((stamp, Fp::from(action_digest)));
        }

        if entries.is_empty() {
            return Err(ProveError::NoActions);
        }

        // Merge pairwise.
        while entries.len() > 1 {
            let (right, right_acc) = entries.pop().ok_or(ProveError::NoActions)?;
            let (left, left_acc) = entries.pop().ok_or(ProveError::NoActions)?;
            let merged = Stamp::prove_merge(rng, left, left_acc, right, right_acc)
                .map_err(|_err| ProveError::MergeFailed)?;
            let merged_acc = left_acc * right_acc;
            entries.push((merged, merged_acc));
        }

        entries
            .pop()
            .map(|(stamp, _acc)| stamp)
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

        let tachygram = Tachygram::from(Fp::from(note.commitment()));
        let cv = rcv.commit(-i64::from(note.value));
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        let action_digest = ActionDigest::new(cv, rk).map_err(|_err| mock_ragu::Error)?;
        let action_acc = Fp::from(action_digest);
        let tachygram_acc = Fp::from(tachygram);

        let header = (action_acc, tachygram_acc, anchor);

        let (proof, _tg) = app.seed(rng, &OutputStamp, (rcv, alpha, note, anchor))?;
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
        spendable_pcd: mock_ragu::Pcd<'source, SpendableHeader>,
        tachygrams: Vec<Tachygram>,
    ) -> Result<Self, mock_ragu::Error> {
        let app = &*PROOF_SYSTEM;

        let action_acc = spend_pcd.data.0;
        let tachygram_acc = compute_tachygram_acc(&tachygrams);
        let anchor = spendable_pcd.data.2;

        let (proof, ()) = app.fuse(rng, &SpendStamp, (), spend_pcd, spendable_pcd)?;

        let header = (action_acc, tachygram_acc, anchor);

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
    /// `left_action_acc` and `right_action_acc` are the Fp product accumulators
    /// over each side's actions. The caller reconstructs these from public data
    /// (they are never stored on the stamp).
    pub fn prove_merge<RNG: CryptoRng>(
        rng: &mut RNG,
        left: Self,
        left_action_acc: Fp,
        right: Self,
        right_action_acc: Fp,
    ) -> Result<Self, mock_ragu::Error> {
        let app = &*PROOF_SYSTEM;

        let left_tachygram_acc = compute_tachygram_acc(&left.tachygrams);
        let right_tachygram_acc = compute_tachygram_acc(&right.tachygrams);

        let left_header = (left_action_acc, left_tachygram_acc, left.anchor);
        let right_header = (right_action_acc, right_tachygram_acc, right.anchor);

        let left_pcd = left.proof.carry::<StampHeader>(left_header);
        let right_pcd = right.proof.carry::<StampHeader>(right_header);

        let (proof, ()) = app.fuse(rng, &MergeStamp, (), left_pcd, right_pcd)?;

        let action_acc = left_action_acc * right_action_acc;
        let anchor = left.anchor;
        let tachygrams = [left.tachygrams, right.tachygrams].concat();
        let tachygram_acc = compute_tachygram_acc(&tachygrams);

        let merged_header = (action_acc, tachygram_acc, anchor);
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
        let tachygram_acc = compute_tachygram_acc(&self.tachygrams);

        let header = (action_acc, tachygram_acc, self.anchor);

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

/// The serialized size of a proof, for the `stampTachyon` compactsize.
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
