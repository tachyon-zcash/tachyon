//! Proof keys parameterized by GGM tree depth.
//!
//! - `Key<Master>`: full per-note capability, held by the planner
//! - `Key<Prefix>` ([`ProofDelegateKey`](super::delegate::ProofDelegateKey)):
//!   epoch-restricted, given to a less-trusted prover
//! - `Key<Leaf>`
//!   ([`ProofAuthorizingKey`](super::delegate::ProofAuthorizingKey)):
//!   single-epoch, fully evaluated — the proof input

use super::{note::NoteKey, planner::SpendValidatingKey};

/// A proof key parameterized by GGM tree depth.
///
/// The depth parameter on the note key naturally captures the trust level:
/// - [`Master`]: full per-note nullifier capability
/// - [`Prefix`]: epoch-restricted nullifier capability
/// - [`Leaf`]: single-epoch, fully evaluated — no tree walking in-circuit
// TODO: add proof-construction methods once the Ragu circuit API is available.
#[derive(Clone, Copy, Debug)]
pub struct ProofKey<D> {
    /// The spend validating key `ak = [ask] G`.
    pub ak: SpendValidatingKey,
    /// GGM tree node at depth `D`.
    pub node: NoteKey<D>,
}
