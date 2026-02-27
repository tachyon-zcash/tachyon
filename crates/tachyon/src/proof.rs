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
//! 3. Construct the PCD header (`actions_acc`, `tachygram_acc`, `anchor`)
//! 4. Call Ragu `verify(Pcd { proof, data: header })`
//!
//! A successful verification with a reconstructed header demonstrates that
//! consensus rules were followed.
//!
//! ## Proving
//!
//! The prover supplies an [`ActionPrivate`] per action, containing private
//! inputs that the circuit checks against the public action and tachygram.

use crate::{
    action::Action,
    keys::ProvingKey,
    primitives::{Anchor, Tachygram},
    witness::{ActionPrivate, MergePrivate},
};

use serde::{Deserialize, Serialize};

/// Ragu proof for Tachyon transactions.
///
/// Covers all actions in an aggregate. The internal structure will be
/// defined by the Ragu PCD library; methods on this type are stubs
/// marking the design boundary.
///
/// The proof's public output is a PCD header containing
/// `actions_acc`, `tachygram_acc`, and `anchor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof;

impl serde::Serialize for Proof {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes: [u8; 192] = (*self).into();
        bytes.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Proof {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{Error, SeqAccess, Visitor};
        use std::fmt;
        
        struct ArrayVisitor;
        impl<'de> Visitor<'de> for ArrayVisitor {
            type Value = [u8; 192];
            
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of 192 bytes")
            }
            
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [0u8; 192];
                for i in 0..192 {
                    arr[i] = seq.next_element()?.ok_or_else(|| Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }
        
        let bytes = deserializer.deserialize_seq(ArrayVisitor)?;
        Self::try_from(&bytes).map_err(serde::de::Error::custom)
    }
}

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
    /// - **`actions_acc`**: Each action produces a digest $D_i =
    ///   H(\mathsf{cv}_i, \mathsf{rk}_i)$. The accumulator is
    ///   $\text{VectorCommit}(D_1, \ldots, D_n)$.
    /// - **`tachygram_acc`**: $\text{VectorCommit}(\text{tachygrams})$.
    ///
    /// The circuit constrains that every $(D_i, \text{tachygram}_i)$ pair
    /// is consistent with the witness (note fields, alpha, rcv, flavor).
    ///
    /// The [`ProvingKey`] provides per-wallet key material
    /// shared across all actions:
    /// - $\mathsf{ak}$: constrains $\mathsf{rk} = \mathsf{ak} +
    ///   [\alpha]\,\mathcal{G}$
    /// - $\mathsf{nk}$: constrains nullifier correctness ($\mathsf{nf} =
    ///   F_{\text{KDF}(\psi, nk)}(\text{flavor})$)
    #[must_use]
    pub fn create(
        _actions: &[Action],
        witnesses: &[ActionPrivate],
        _anchor: &Anchor,
        _pak: &ProvingKey,
    ) -> (Self, Vec<Tachygram>) {
        todo!("Ragu PCD");
        (Self, witnesses.iter().map(|w| w.tachygram).collect())
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
    /// - **Accumulator combination**: the merged proof's `actions_acc` and
    ///   `tachygram_acc` are the unions of the left and right accumulators.
    #[must_use]
    pub fn merge(left: Self, _right: Self, _witness: MergePrivate) -> Self {
        todo!("Ragu PCD fuse \u{2014} merge two proofs with non-overlap and anchor subset checks");
        left
    }

    /// Verifies this proof by reconstructing the PCD header from public data.
    ///
    /// The verifier recomputes `actions_acc` and `tachygram_acc` from the
    /// public actions and tachygrams, constructs the PCD header,
    /// and calls Ragu `verify(Pcd { proof, data: header })`. The proof
    /// only verifies against the header that matches the circuit's honest
    /// execution — a mismatched header causes verification failure.
    pub fn verify(
        &self,
        _actions: &[Action],
        _tachygrams: &[Tachygram],
        _anchor: Anchor,
    ) -> Result<(), ValidationError> {
        todo!("Ragu verification \u{2014} reconstruct the PCD header from public data");
        // 1. Recompute actions_acc: D_i = H(cv_i, rk_i) for each action actions_acc =
        //    VectorCommit(D_1, ..., D_n)
        // 2. Recompute tachygram_acc = VectorCommit(tachygrams)
        // 3. Construct PCD header { actions_acc, tachygram_acc, anchor }
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
