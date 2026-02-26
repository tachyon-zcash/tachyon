//! Private witnesses (prover secrets) for building Tachyon stamp proofs.
//!
//! - **[`ActionPrivate`]** — witness for a single action: note, spend-auth
//!   randomizer, and value commitment trapdoor. The circuit derives the
//!   tachygram and flavor internally.

use crate::{
    keys::private::{ActionRandomizer, Witness},
    note::Note,
    value,
};

/// Private witness for a single action.
///
/// Contains the per-action circuit inputs. The circuit derives `flavor`
/// from the shared `anchor` and computes the tachygram (nullifier or
/// note commitment) internally.
///
/// Per-wallet key material ($\mathsf{ak}$, $\mathsf{nk}$) is shared across
/// all actions and passed separately via
/// [`ProofAuthorizingKey`](crate::keys::ProofAuthorizingKey)
/// to [`Proof::create`](crate::proof::Proof::create).
#[derive(Clone, Copy, Debug)]
pub struct ActionPrivate {
    /// Spend authorization randomizer `alpha`.
    /// - Spend: `rsk = ask + alpha`, `rk = ak + [alpha]G`
    /// - Output: `rsk = alpha`, `rk = [alpha]G`
    pub alpha: ActionRandomizer<Witness>,

    /// The note being spent or created.
    pub note: Note, // { pk, v, psi, rcm }

    /// Value commitment trapdoor.
    pub rcv: value::CommitmentTrapdoor,
}
