use crate::keys::SpendAuthRandomizer;
use crate::note::Note;
use crate::primitives::{Epoch, Fp, Fq};

// =============================================================================
// Circuit witnesses (prover-side)
// =============================================================================

/// Private witness for the [`StampMerge`](crate::circuit) step.
///
/// Contains the anchor quotient proving that the left sub-proof's
/// accumulator state is a superset of the right's. For an append-only
/// polynomial accumulator:
///
/// `left_anchor = right_anchor × quotient`
///
/// The quotient encodes the state diff between the two anchors.
/// The prover can only produce a valid quotient if the subset
/// relationship actually holds (polynomial commitment security).
///
/// For same-epoch merges the quotient is `Fp::one()`.
#[derive(Clone, Debug)]
pub struct MergeWitness {
    /// `left_anchor / right_anchor` in the accumulator's field.
    ///
    /// Proves the left accumulator state is a superset of the right.
    pub anchor_quotient: Fp,
}

/// Private witness for a single action.
///
/// The `flavor` identifies the accumulator epoch. The circuit uses it
/// for both accumulator membership (`cmx ∈ acc(flavor)`) and nullifier
/// derivation (`mk = KDF(ψ, nk)`, then `nf = F_mk(flavor)`).
#[derive(Clone, Debug)]
pub struct ActionWitness {
    /// The note being spent or created.
    pub note: Note, // { pk, v, psi, rcm }

    /// Spend authorization randomizer `alpha`.
    /// - Spend: `rsk = ask + alpha`, `rk = ak + [alpha]G`
    /// - Output: `rsk = alpha`, `rk = [alpha]G`
    pub alpha: SpendAuthRandomizer,

    /// Value commitment randomness.
    pub rcv: Fq,

    /// Accumulator epoch (doubles as nullifier flavor).
    pub flavor: Epoch,

    /// A deterministic nullifier (spend) or note commitment (output).
    /// Computed from note fields and key material with no additional randomness.
    /// - Spend: $\mathsf{nf} = F_{\mathsf{mk}}(\text{flavor})$ where $mk = \text{KDF}(\psi, nk)$
    /// - Output: $\mathsf{cmx} = \text{NoteCommit}(pk, v, \psi, rcm)$
    pub tachygram: Fp,
}
