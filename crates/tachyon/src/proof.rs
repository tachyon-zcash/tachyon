//! Tachyon proofs.
//!
//! Tachyon uses **Ragu PCD** (Proof-Carrying Data) for proof generation and
//! aggregation. A single Ragu proof per aggregate covers all actions across
//! multiple bundles.
//!
//! ## Verification
//!
//! The header is not transmitted on the wire. The verifier reconstructs the PCD
//! header from public data according to consensus rules.
//!
//! 1. Recompute `actions_acc` from the bundle's actions
//! 2. Recompute `tachygram_acc` from the listed tachygrams
//! 3. Construct `StampDigest { actions_acc, tachygram_acc, anchor }`
//! 4. Call Ragu `verify(Pcd { proof, data: header })`
//!
//! A successful verification with a reconstructed header demonstrates that
//! consensus rules were followed.
//!
//! ## Proving
//!
//! The prover supplies an [`ActionWitness`] per action, containing private
//! inputs that the circuit checks against the public action and tachygram.

use crate::action::Action;
use crate::primitives::{Anchor, Fp, Tachygram};
use crate::witness::ActionPrivate;

/// Ragu proof for Tachyon transactions.
///
/// Covers all actions in an aggregate. The internal structure will be
/// defined by the Ragu PCD library; methods on this type are stubs
/// marking the design boundary.
///
/// The proof's public output is a [`StampDigest`](crate::circuit::StampDigest)
/// containing `actions_acc`, `tachygram_acc`, and `anchor`.
#[derive(Clone, Debug)]
pub struct Proof(Vec<u8>);

impl Proof {
    /// Returns the raw proof bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Constructs a proof from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Default for Proof {
    fn default() -> Self {
        Self(vec![0u8; 192]) // placeholder length
    }
}

/// An error returned when proof verification fails.
#[derive(Debug)]
pub struct ValidationError;

impl Proof {
    /// Creates a proof from action witnesses.
    ///
    /// Each witness carries a tachygram (deterministic nullifier for
    /// spends, note commitment for outputs). The proof binds actions
    /// to tachygrams via the `actions_acc` and `tachygram_acc`
    /// accumulators.
    #[must_use]
    pub fn create(
        _witnesses: &[ActionPrivate],
        _actions: &[Action],
        _anchor: &Anchor,
    ) -> (Self, Vec<Tachygram>) {
        todo!("Ragu PCD — tachygrams from witnesses become the stamp's tachygram list");
        (Self(Vec::new()), Vec::new())
    }

    /// Merges two proofs (Ragu PCD fuse).
    ///
    /// Used during aggregation to combine stamps from multiple bundles.
    #[must_use]
    pub fn merge(_left: Self, _right: Self) -> Self {
        todo!("Ragu PCD fuse — merge two proofs into one");
        _left
    }

    /// Verifies this proof by reconstructing the PCD header from public data.
    ///
    /// The verifier recomputes `actions_acc` and `tachygram_acc` from the
    /// public actions and tachygrams, constructs the `StampDigest` header,
    /// and calls Ragu `verify(Pcd { proof, data: header })`. The proof
    /// only verifies against the header that matches the circuit's honest
    /// execution — a mismatched header causes verification failure.
    ///
    /// The `landing_epoch` is the block's epoch; verification succeeds
    /// only if the anchor range contains it.
    pub fn verify(
        &self,
        _actions: &[Action],
        _tachygrams: &[Tachygram],
        _anchor: Anchor,
        _landing_epoch: Fp,
    ) -> Result<(), ValidationError> {
        todo!("Ragu verification — reconstruct the PCD header from public data");
        // 1. Recompute actions_acc from actions
        // 2. Recompute tachygram_acc from tachygrams
        // 3. Construct StampDigest { actions_acc, tachygram_acc, anchor }
        // 4. verify(Pcd { proof: self, data: header })
        // 5. Anchor range check
        Ok(())
    }
}
