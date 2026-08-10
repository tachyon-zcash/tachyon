extern crate alloc;

use alloc::vec::Vec;
use core::iter;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu::Polynomial;

use crate::nullifier::Nullifier;

/// Pedersen commitment to a nullifier sequence $N$.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfSeqCommit(Eq);

/// Witness polynomial for a nullifier sequence $N$: members encoded as
/// coefficients ordered by ascending degree, terminated by a sentinel
/// coefficient $1$ one degree above the members.
///
/// The sentinel makes the polynomial nonzero for every sequence (the empty
/// sequence is the constant $1$), so the commitment is never the identity
/// point, which the in-circuit point representation cannot hold. It also pins
/// the sequence's exact length: commit-equality alone bounds rank only from
/// above (trailing zeros are invisible), while the sentinel fixes the top
/// coefficient at the statement's span.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NfSeqPoly(Polynomial);

impl NfSeqPoly {
    /// Deterministic (untrapdoored) commitment to the sequence polynomial.
    #[must_use]
    pub fn commit(&self) -> NfSeqCommit {
        NfSeqCommit(self.0.commit())
    }

    /// Evaluate the sequence polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl FromIterator<Nullifier> for NfSeqPoly {
    fn from_iter<I: IntoIterator<Item = Nullifier>>(iter: I) -> Self {
        let coeffs: Vec<Fp> = iter
            .into_iter()
            .map(Fp::from)
            .chain(iter::once(Fp::ONE))
            .collect();
        Self(Polynomial::from_coeffs(coeffs))
    }
}

/// Pedersen commitment to a [`NfMarginPoly`].
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfMarginCommit(Eq);

/// Witness polynomial for a covering read's margin *above* the read: the
/// sentineled sequence $\mathsf{above} + 1$.
///
/// The margin's members are the covering range's epochs above the read in
/// ascending order, followed by the covering sequence's own sentinel $1$ at
/// the margin's top; $+1$ is added at degree $0$, compensated by the read
/// identity's $-1$ at evaluation. Carrying the covering sentinel makes the
/// margin nonzero even when no member sits above the read, and the added
/// degree-$0$ sentinel keeps the constructor uniform with
/// [`NfTailPoly`]'s.
///
/// The one constructor owns both sentinels, so a builder cannot mis-shape a
/// margin.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NfMarginPoly(Polynomial);

impl NfMarginPoly {
    /// Build the sentineled margin from the members above the read, in
    /// chronological order (possibly none).
    #[must_use]
    pub fn new(members: &[Nullifier]) -> Self {
        let mut coeffs: Vec<Fp> = members
            .iter()
            .copied()
            .map(Fp::from)
            .chain(iter::once(Fp::ONE))
            .collect();
        #[expect(clippy::indexing_slicing, reason = "the sentinel guarantees a slot")]
        {
            coeffs[0] += Fp::ONE;
        }
        Self(Polynomial::from_coeffs(coeffs))
    }

    /// Deterministic (untrapdoored) commitment to the margin polynomial.
    #[must_use]
    pub fn commit(&self) -> NfMarginCommit {
        NfMarginCommit(self.0.commit())
    }
}

/// Pedersen commitment to a [`NfTailPoly`].
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfTailCommit(Eq);

/// Witness polynomial for a covering read's margin *below* the read, shifted
/// to the physical cap.
///
/// $\mathsf{tail} = X^{D-m}\cdot\mathsf{below} + 1$ for the $m$-member
/// margin $\mathsf{below}$ and $D$ the coefficient cap.
///
/// Below the read no commitment bounds a witness's degree, so the margin
/// cannot ride as a free polynomial at its own position. The cap shift is
/// the degree bound: a witnessed polynomial holds at most $D$ coefficients,
/// so `tail` cannot reach the read's band at $[D, D+K)$ and nothing a prover
/// controls can perturb the read. The $+1$ sentinel at degree $0$
/// (compensated at evaluation) keeps the empty margin off the identity
/// point, and the read identity forces the slot to exactly $1$.
///
/// The one constructor owns the sentinel and the shift, so a builder cannot
/// mis-shape a margin.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NfTailPoly(Polynomial);

impl NfTailPoly {
    /// Build the cap-shifted sentineled margin from the members below the
    /// read, in chronological order (possibly none).
    #[must_use]
    pub fn new(members: &[Nullifier]) -> Self {
        let cap = 1usize << Polynomial::R;
        let mut coeffs = alloc::vec![Fp::ZERO; cap];
        #[expect(
            clippy::indexing_slicing,
            reason = "the margin is shorter than the cap by construction"
        )]
        {
            coeffs[0] = Fp::ONE;
            for (offset, &member) in members.iter().enumerate() {
                coeffs[cap - members.len() + offset] = Fp::from(member);
            }
        }
        Self(Polynomial::from_coeffs(coeffs))
    }

    /// Deterministic (untrapdoored) commitment to the tail polynomial.
    #[must_use]
    pub fn commit(&self) -> NfTailCommit {
        NfTailCommit(self.0.commit())
    }
}

#[cfg(test)]
mod tests {
    use group::Group as _;

    use super::*;

    /// The empty sequence commits to the sentinel constant $1$, never the
    /// identity point.
    #[test]
    fn empty_sequence_commit_is_not_identity() {
        let empty: NfSeqPoly = iter::empty().collect();
        assert_eq!(empty.eval(Fp::ZERO), Fp::ONE);
        assert_ne!(Eq::from(empty.commit()), Eq::identity());
    }
}
