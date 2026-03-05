//! Private witnesses (prover secrets) for building Tachyon stamp proofs.
//!
//! - **[`ActionPrivate`]** — witness for a single action: note, spend-auth
//!   randomizer, and value commitment trapdoor. The circuit derives the
//!   tachygram and flavor internally.

use crate::{entropy::ActionRandomizer, note::Note, value};

/// Private witness for a single action.
///
/// The [`ActionRandomizer`] is a bare $\alpha$ scalar — spend and output
/// are intentionally indistinguishable at the witness level.
///
/// Per-wallet key material ($\mathsf{ak}$, $\mathsf{nk}$) is shared across
/// all actions and passed separately via
/// [`ProofAuthorizingKey`](crate::keys::ProofAuthorizingKey)
/// to [`Stamp::prove_action`](crate::stamp::Stamp::prove_action).
#[derive(Clone, Copy, Debug)]
pub struct ActionPrivate {
    /// Action randomizer $\alpha$ with derivation path.
    pub alpha: ActionRandomizer,
    /// The note being spent or created.
    pub note: Note,
    /// Value commitment trapdoor.
    pub rcv: value::CommitmentTrapdoor,
}
