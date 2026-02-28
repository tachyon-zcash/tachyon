//! Private witnesses (prover secrets) for building Tachyon stamp proofs.
//!
//! - **[`ActionPrivate`]** — witness for a single action: note, spend-auth
//!   randomizer, and value commitment trapdoor. The circuit derives the
//!   tachygram and flavor internally.

use crate::{keys::randomizer::ActionRandomizer, note::Note, value};

/// Private witness for a single action.
///
/// The [`ActionRandomizer`] carries both the $\alpha$ scalar and the
/// derivation path ([`Effect`](crate::action::Effect)). The circuit uses
/// [`effect`](ActionRandomizer::effect) to select constraint sets.
///
/// Per-wallet key material ($\mathsf{ak}$, $\mathsf{nk}$) is shared across
/// all actions and passed separately via
/// [`ProofAuthorizingKey`](crate::keys::ProofAuthorizingKey)
/// to [`Proof::create`](crate::proof::Proof::create).
///
/// Produced from
/// [`action::Plan::into_witness`](crate::action::Plan::into_witness).
#[derive(Clone, Copy, Debug)]
pub struct ActionPrivate {
    /// Action randomizer $\alpha$ with derivation path.
    pub alpha: ActionRandomizer,
    /// The note being spent or created.
    pub note: Note,
    /// Value commitment trapdoor.
    pub rcv: value::CommitmentTrapdoor,
}
