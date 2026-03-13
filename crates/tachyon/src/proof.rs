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
//! 1. Recompute `action_acc` from the bundle's actions
//! 2. Recompute `tachygram_acc` from the listed tachygrams
//! 3. Construct the PCD header (`action_acc`, `tachygram_acc`, `anchor`)
//! 4. Call Ragu `verify(Pcd { proof, data: header })`
//!
//! A successful verification with a reconstructed header demonstrates that
//! consensus rules were followed.
//!
//! ## Proving
//!
//! The prover supplies an [`ActionPrivate`] per action, containing private
//! inputs that the circuit checks against the public action and tachygram.

use alloc::vec::Vec;

use crate::{
    action::Action,
    keys::ProofAuthorizingKey,
    primitives::{Anchor, Tachygram},
    witness::ActionPrivate,
};

/// Ragu proof for Tachyon transactions.
///
/// Covers all actions in an aggregate. The internal structure will be
/// defined by the Ragu PCD library; methods on this type are stubs
/// marking the design boundary.
///
/// The proof's public output is a PCD header containing
/// `action_acc`, `tachygram_acc`, and `anchor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Proof;

/// An error returned when proof verification fails.
#[derive(Clone, Copy, Debug)]
pub struct ValidationError;

impl Proof {
    /// Creates a proof from action witnesses.
    ///
    /// Each witness carries a tachygram (deterministic nullifier for
    /// spends, note commitment for outputs). The proof binds actions
    /// to tachygrams via two accumulators:
    ///
    /// - **`action_acc`**: Each action produces a digest $D_i =
    ///   \text{Poseidon}(\mathsf{cv}_i, \mathsf{rk}_i) + 1$. The accumulator is
    ///   $\prod_i D_i$ (multiplicative, order-independent).
    /// - **`tachygram_acc`**: Each tachygram is hashed via Poseidon and
    ///   accumulated multiplicatively: $\prod_i (\text{Poseidon}(\mathsf{tg}_i)
    ///   + 1)$.
    ///
    /// The circuit constrains that every $(D_i, \text{tachygram}_i)$ pair
    /// is consistent with the witness (note fields, alpha, rcv).
    ///
    /// The [`ProofAuthorizingKey`] provides per-wallet key material
    /// shared across all actions:
    /// - $\mathsf{ak}$: constrains $\mathsf{rk} = \mathsf{ak} +
    ///   [\alpha]\,\mathcal{G}$
    /// - $\mathsf{nk}$: constrains nullifier correctness ($\mathsf{nf} =
    ///   F_{\text{KDF}(\psi, nk)}(\text{flavor})$)
    // TODO: take `&[Action]` and `&[ActionPrivate]` instead of `Vec` —
    // ownership is not needed. Deferred to the proof refactor.
    #[must_use]
    pub fn create(
        _actions: Vec<Action>,
        _witnesses: Vec<ActionPrivate>,
        _anchor: &Anchor,
        _pak: &ProofAuthorizingKey,
    ) -> (Self, Vec<Tachygram>) {
        todo!("Ragu PCD");
        // The circuit computes tachygrams internally from witness fields (nf =
        // F_nk(psi, flavor) for spends, cm = NoteCommit(...) for outputs) and
        // returns them as public outputs.
        (Self, Vec::new())
    }

    /// Merges two proofs (Ragu PCD fuse).
    ///
    /// Used during aggregation to combine stamps from multiple bundles.
    /// The merge circuit MUST enforce:
    ///
    /// - **Non-overlapping tachygram sets**: the left and right tachygram
    ///   accumulators must be disjoint. Overlapping aggregates would create
    ///   duplicate nullifiers in the combined set.
    /// - **Anchor subset**: the `anchor_quotient` in [`MergePrivate`] proves
    ///   $\text{left\_anchor} = \text{right\_anchor} \times \text{quotient}$
    ///   (the left accumulator state is a superset of the right's). For
    ///   same-epoch merges the quotient is 1.
    /// - **Accumulator combination**: the merged proof's `action_acc` and
    ///   `tachygram_acc` are the unions of the left and right accumulators.
    #[must_use]
    pub fn merge(left: Self, _right: Self) -> Self {
        todo!("Ragu PCD fuse \u{2014} merge two proofs with non-overlap and anchor subset checks");
        left
    }

    /// Verifies this proof by reconstructing the PCD header from public data.
    ///
    /// The verifier recomputes `action_acc` and `tachygram_acc` from the
    /// public actions and tachygrams, constructs the PCD header,
    /// and calls Ragu `verify(Pcd { proof, data: header })`. The proof
    /// only verifies against the header that matches the circuit's honest
    /// execution — a mismatched header causes verification failure.
    // TODO: take `&[Action]` and `&[Tachygram]` instead of `Vec` —
    // ownership is not needed. Deferred to the proof refactor.
    pub fn verify(
        &self,
        _actions: Vec<Action>,
        _tachygrams: Vec<Tachygram>,
        _anchor: Anchor,
    ) -> Result<(), ValidationError> {
        todo!("Ragu verification \u{2014} reconstruct the PCD header from public data");
        // 1. Recompute action_acc = ∏ (Poseidon(cv_i, rk_i) + 1)
        // 2. Recompute tachygram_acc = ∏ (Poseidon(tg_i) + 1)
        // 3. Construct PCD header { action_acc, tachygram_acc, anchor }
        // 4. verify(Pcd { proof: self, data: header })
        // 5. TODO: Anchor range check — validate that `anchor` falls within the
        //    acceptable range for the landing block. The exact semantics (epoch window,
        //    finality depth) are blocked on protocol spec.
        Ok(())
    }
}

impl Default for Proof {
    fn default() -> Self {
        Self
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 192]> for Proof {
    fn into(self) -> [u8; 192] {
        todo!("Ragu proof serialization");
        [0u8; 192]
    }
}

impl TryFrom<&[u8; 192]> for Proof {
    type Error = &'static str;

    fn try_from(_bytes: &[u8; 192]) -> Result<Self, Self::Error> {
        todo!("Ragu proof deserialization");
        Ok(Self)
    }
}
