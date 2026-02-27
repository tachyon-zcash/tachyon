//! Stamps and anchors.
//!
//! A stamp carries the tachygram list, the epoch anchor, and the proof:
//!
//! - **Tachygrams**: Listed individually
//! - **Anchor**: Accumulator state reference (epoch)
//! - **Proof**: The Ragu PCD proof (rerandomized)
//!
//! The PCD proof's public output ([`StampDigest`]) contains
//! `actions_acc`, `tachygram_acc`, and `anchor`. These accumulators are
//! **not serialized** on the stamp — the verifier recomputes them from
//! public data (actions and tachygrams) and passes them as the header
//! to Ragu `verify()`.

use serde::{Deserialize, Serialize};

use crate::{
    action::Action,
    keys::ProvingKey,
    primitives::{Anchor, Tachygram},
    proof::{Proof, ValidationError},
    witness::{ActionPrivate, MergePrivate},
};

/// Marker for the absence of a stamp.
#[derive(Clone, Copy, Debug)]
pub struct Stampless;

/// A stamp carrying tachygrams, anchor, and proof.
///
/// Present in [`StampedBundle`](crate::StampedBundle) bundles.
/// Stripped during aggregation and merged into the aggregate's stamp.
///
/// The PCD proof's [`StampDigest`] header contains `actions_acc`,
/// `tachygram_acc`, and `anchor`, but only the anchor is stored here.
/// The accumulators are recomputed by the verifier from public data
/// and passed as the header to Ragu `verify()`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Stamp {
    /// Tachygrams (nullifiers and note commitments) for data availability.
    ///
    /// The number of tachygrams can be greater than the number of actions.
    pub tachygrams: Vec<Tachygram>,

    /// Reference to tachyon accumulator state (epoch).
    pub anchor: Anchor,

    /// The Ragu proof bytes.
    pub proof: Proof,
}

impl Stamp {
    /// Creates a stamp by running the proof over action witnesses.
    ///
    /// The proof system produces the accumulators (`actions_acc`,
    /// `tachygram_acc`) but these are not stored on the stamp. The verifier
    /// recomputes them outside the circuit from public data at verification
    /// time.
    #[must_use]
    pub fn prove(
        witnesses: &[ActionPrivate],
        actions: &[Action],
        anchor: Anchor,
        pak: &ProvingKey,
    ) -> Self {
        let (proof, tachygrams) = Proof::create(actions, witnesses, &anchor, pak);
        Self {
            tachygrams,
            anchor,
            proof,
        }
    }

    /// Merges this stamp with another, combining tachygrams and proofs.
    ///
    /// Assuming the anchor is an append-only accumulator, a later anchor should
    /// be a superset of an earlier anchor.
    ///
    /// The accumulators (`actions_acc`, `tachygram_acc`) are merged inside the
    /// circuit. [`Proof::merge`] enforces non-overlapping tachygram sets and
    /// the anchor subset relationship via the merge witness.
    #[must_use]
    pub fn merge(self, other: Self, witness: MergePrivate) -> Self {
        let anchor = self.anchor.max(other.anchor);
        let mut tachygrams = self.tachygrams;
        tachygrams.extend(other.tachygrams);
        let proof = Proof::merge(self.proof, other.proof, witness);
        Self {
            tachygrams,
            anchor,
            proof,
        }
    }

    /// Compresses this stamp for on-chain serialization.
    ///
    /// Stamps appearing in blocks MUST be compressed per the wire format
    /// specification. The compression scheme is TBD (depends on the Ragu
    /// proof encoding and tachygram batching strategy).
    #[must_use]
    pub fn compress(&self) -> Vec<u8> {
        todo!("stamp compression for wire format");
        Vec::new()
    }

    /// Decompresses a stamp from on-chain bytes.
    ///
    /// Inverse of [`compress`](Self::compress).
    pub fn decompress(_bytes: &[u8]) -> Result<Self, ValidationError> {
        todo!("stamp decompression from wire format");
        Err(ValidationError)
    }
}
