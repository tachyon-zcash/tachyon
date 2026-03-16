//! Private witnesses (prover secrets) for building Tachyon stamp proofs.
//!
//! - **[`ActionPrivate`]** — witness for a single action: note, spend-auth
//!   randomizer, and value commitment trapdoor. The circuit derives the
//!   tachygram and flavor internally.

use crate::{entropy::Randomizer, note::Note, primitives::Effect, value};

/// Private witness for a single action.
///
/// Per-wallet key material ($\mathsf{ak}$, $\mathsf{nk}$) is shared across
/// all actions and passed separately via
/// [`ProofAuthorizingKey`](crate::keys::ProofAuthorizingKey)
/// to [`Stamp::prove_action`](crate::stamp::Stamp::prove_action).
#[derive(Clone, Copy, Debug)]
pub struct ActionPrivate<E: Effect> {
    /// Action randomizer $\alpha$.
    pub alpha: Randomizer<E>,
    /// The note being spent or created.
    pub note: Note,
    /// Value commitment trapdoor.
    pub rcv: value::CommitmentTrapdoor,
}
