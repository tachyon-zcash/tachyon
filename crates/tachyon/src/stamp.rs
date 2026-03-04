//! Stamps and anchors.
//!
//! A stamp carries the tachygram list, the epoch anchor, and the proof:
//!
//! - **Tachygrams**: Listed individually
//! - **Anchor**: Accumulator state reference (epoch)
//! - **Proof**: The Ragu PCD proof (rerandomized)
//!
//! The PCD proof's public output ([`StampDigest`](crate::proof::StampDigest))
//! contains `action_acc`, `tachygram_acc`, and `anchor`. These accumulators are
//! **not serialized** on the stamp — the verifier recomputes them from
//! public data (actions and tachygrams) and passes them as the header
//! to Ragu `verify()`.

extern crate alloc;

use alloc::vec::Vec;

use rand::CryptoRng;

use crate::{
    action::{Action, Effect},
    keys::ProofAuthorizingKey,
    primitives::{Anchor, Tachygram},
    proof::{ActionStep, ActionWitness, MergeStep, Proof, StampDigest, StampHeader, mock_app},
    witness::ActionPrivate,
};

/// Marker for the absence of a stamp.
#[derive(Clone, Copy, Debug)]
pub struct Stampless;

/// A stamp carrying tachygrams, anchor, and proof.
///
/// Present in [`Stamped`](crate::Stamped) bundles.
/// Stripped during aggregation and merged into the aggregate's stamp.
///
/// The PCD proof's [`StampDigest`](crate::proof::StampDigest) header
/// contains `action_acc`, `tachygram_acc`, and `anchor`, but only the
/// anchor is stored here. The accumulators are recomputed by the
/// verifier from public data and passed as the header to Ragu
/// `verify()`.
#[derive(Clone, Debug)]
#[expect(
    clippy::field_scoped_visibility_modifiers,
    clippy::partial_pub_fields,
    reason = "digest is crate-internal for fuse"
)]
pub struct Stamp {
    /// Tachygrams (nullifiers and note commitments) for data availability.
    ///
    /// The number of tachygrams can be greater than the number of actions.
    pub tachygrams: Vec<Tachygram>,

    /// Reference to tachyon accumulator state (epoch).
    pub anchor: Anchor,

    /// The Ragu proof bytes.
    pub proof: Proof,

    /// PCD header digest — used internally for fuse operations.
    ///
    /// Not serialized on the wire.
    pub(crate) digest: StampDigest,
}

impl Stamp {
    /// Creates a leaf stamp for a single action (ACTION STEP).
    ///
    /// The proof system derives the tachygram internally from the witness:
    /// - Spend: $\mathsf{nf} = F_{\text{KDF}(\psi, nk)}(\text{flavor})$
    /// - Output: $\mathsf{cm} = \text{NoteCommit}(\ldots)$
    ///
    /// Leaf stamps are combined via [`prove_merge`](Self::prove_merge).
    #[expect(clippy::expect_used, reason = "mock proving is infallible")]
    #[must_use]
    pub fn prove_action<RNG: CryptoRng>(
        rng: &mut RNG,
        witness: &ActionPrivate,
        action: &Action,
        effect: Effect,
        anchor: Anchor,
        pak: &ProofAuthorizingKey,
    ) -> Self {
        let app = mock_app();
        let action_witness = ActionWitness {
            action,
            witness,
            effect,
            anchor,
            pak,
        };
        let (proof, (tachygrams, digest)) = app
            .seed(rng, &ActionStep, action_witness)
            .expect("seed should not fail in mock");

        Self {
            tachygrams,
            anchor,
            proof: Proof(proof),
            digest,
        }
    }

    /// Merges this stamp with another, combining tachygrams and proofs.
    ///
    /// Assuming the anchor is an append-only accumulator, a later anchor should
    /// be a superset of an earlier anchor.
    ///
    /// The accumulators (`action_acc`, `tachygram_acc`) are merged inside the
    /// circuit. [`MergeStep`] combines non-overlapping tachygram sets and
    /// the anchor subset relationship.
    #[expect(clippy::expect_used, reason = "mock fuse is infallible")]
    #[must_use]
    pub fn prove_merge<RNG: CryptoRng>(self, other: Self, rng: &mut RNG) -> Self {
        let app = mock_app();

        let left_pcd = self.proof.0.carry::<StampHeader>(self.digest);
        let right_pcd = other.proof.0.carry::<StampHeader>(other.digest);

        let (proof, merged_digest) = app
            .fuse(rng, &MergeStep, (), left_pcd, right_pcd)
            .expect("fuse should not fail in mock");

        let merged_anchor = self.anchor.max(other.anchor);
        let merged_tachygrams = [self.tachygrams, other.tachygrams].concat();

        Self {
            tachygrams: merged_tachygrams,
            anchor: merged_anchor,
            proof: Proof(proof),
            digest: merged_digest,
        }
    }
}
