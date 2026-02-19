//! Private witnesses (prover secrets) for building Tachyon stamp proofs.
//!
//! - **[`MergePrivate`]** — witness for the stamp-merge step: anchor quotient
//!   proving the left epoch anchor state is a superset of the right.
//! - **[`ActionPrivate`]** — witness for a single action: note, spend-auth
//!   randomizer, value commitment trapdoor, epoch (flavor), and the resulting
//!   tachygram (nullifier or note commitment).

use pasta_curves::Fp;

use crate::{
    keys::private::ActionRandomizer,
    note::Note,
    primitives::{Epoch, Tachygram},
    value,
};

/// Private witness for the stamp-merge step.
///
/// Contains the anchor quotient proving that the left sub-proof's
/// accumulator state is a superset of the right's. For an append-only
/// polynomial accumulator:
///
/// $ \mathsf{left\_anchor} = \mathsf{right\_anchor} \times \mathsf{quotient} $
///
/// The quotient encodes the state diff between the two anchors.
/// The prover can only produce a valid quotient if the subset
/// relationship actually holds (polynomial commitment security).
///
/// For same-epoch merges the quotient is `Fp::one()`.
#[derive(Clone, Copy, Debug)]
pub struct MergePrivate {
    /// `left_anchor / right_anchor` in the accumulator's field.
    ///
    /// Proves the left accumulator state is a superset of the right.
    pub anchor_quotient: Fp,
}

/// Private witness for a single action.
///
/// The `flavor` identifies the accumulator epoch. The circuit uses it
/// for both accumulator membership ($\mathsf{cmx} \in
/// \text{acc}(\text{flavor})$) and nullifier constraint ($\mathsf{nf} =
/// F_{\text{KDF}(\psi, nk)}(\text{flavor})$).
///
/// Per-wallet key material ($\mathsf{ak}$, $\mathsf{nk}$) is shared across
/// all actions and passed separately via
/// [`ProvingKey`](crate::keys::ProvingKey)
/// to [`Proof::create`](crate::proof::Proof::create).
#[derive(Clone, Copy, Debug)]
pub struct ActionPrivate {
    /// Spend authorization randomizer `alpha`.
    /// - Spend: `rsk = ask + alpha`, `rk = ak + [alpha]G`
    /// - Output: `rsk = alpha`, `rk = [alpha]G`
    pub alpha: ActionRandomizer,

    /// Accumulator epoch (doubles as nullifier flavor).
    pub flavor: Epoch,

    /// The note being spent or created.
    pub note: Note, // { pk, v, psi, rcm }

    /// Value commitment trapdoor.
    pub rcv: value::CommitmentTrapdoor,

    /// A deterministic nullifier (spend) or note commitment (output).
    /// Computed from note fields and key material with no additional
    /// randomness.
    /// - Spend: $\mathsf{nf} = F_{\mathsf{mk}}(\text{flavor})$ where $mk =
    ///   $\text{KDF}(\psi, nk)$
    /// - Output: $\mathsf{cmx} = \text{NoteCommit}(pk, v, \psi, rcm)$
    pub tachygram: Tachygram,
}
