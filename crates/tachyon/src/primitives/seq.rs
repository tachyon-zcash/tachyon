extern crate alloc;

use alloc::vec::Vec;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu::Polynomial;

use crate::nullifier::Nullifier;

/// Pedersen commitment to a nullifier sequence $N$.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfSeqCommit(Eq);

/// Witness polynomial for a nullifier sequence $N$, in bare Horner order.
///
/// $k$ members encode as $N(X) = n_0 X^{k-1} + \cdots + n_{k-1}$: the first
/// member at the top degree, the latest at degree $0$. Appending a member is
/// the extension $N \mapsto X N + n_k$.
///
/// Every relation over sequences takes its exponents from header-pinned epoch
/// spans, and member content is forced at the bind. Sequences are never empty
/// (the constructor asserts), and honest members are nonzero, so the
/// commitment avoids the identity point the in-circuit point representation
/// cannot hold.
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
        let mut coeffs: Vec<Fp> = iter.into_iter().map(Fp::from).collect();
        assert!(
            !coeffs.is_empty(),
            "a nullifier sequence has at least one member"
        );
        coeffs.reverse();
        Self(Polynomial::from_coeffs(coeffs))
    }
}

/// Pedersen commitment to a [`NfMarginPoly`].
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfMarginCommit(Eq);

/// Witness polynomial for a covering read's *older* margin: the sentineled
/// sequence $\mathsf{older} + 1$.
///
/// The margin's members are the covering range's epochs below the read, in
/// bare Horner order, with $+1$ added at degree $0$; the read identity
/// compensates with $-1$ at evaluation. The sentinel is what makes an
/// **empty** margin witnessable: it keeps that case at the constant $1$,
/// clear of the identity point witnessing rejects.
///
/// [`NfMarginPoly::new`] applies the sentinel.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NfMarginPoly(Polynomial);

impl NfMarginPoly {
    /// Build the sentineled margin from its members in chronological order
    /// (possibly none).
    #[must_use]
    pub fn new(members: &[Nullifier]) -> Self {
        let mut coeffs: Vec<Fp> = members.iter().copied().map(Fp::from).collect();
        coeffs.reverse();
        match coeffs.first_mut() {
            Some(newest) => *newest += Fp::ONE,
            None => coeffs.push(Fp::ONE),
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

/// Witness polynomial for a covering read's *newer* margin, shifted to the
/// physical cap.
///
/// $\mathsf{tail} = X^{D-m}\cdot\mathsf{newer} + 1$ for the $m$-member
/// margin $\mathsf{newer}$ and $D$ the coefficient cap.
///
/// The cap shift is the degree bound, which is what confines a margin sitting
/// below the read where no commitment bounds degree: a witnessed polynomial
/// holds at most $D$ coefficients, so `tail` cannot reach the read's band at
/// $[D, D+K)$ and nothing a prover controls can perturb the read. The $+1$
/// sentinel at degree $0$ (compensated at evaluation) keeps the empty margin
/// off the identity point, and the read identity forces the slot to exactly
/// $1$.
///
/// [`NfTailPoly::new`] is the only constructor, and it applies both the
/// sentinel and the shift.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NfTailPoly(Polynomial);

impl NfTailPoly {
    /// Build the cap-shifted sentineled margin from its members in
    /// chronological order (possibly none).
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
            for (offset, &member) in members.iter().rev().enumerate() {
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
    use core::iter;

    use ff::Field as _;

    use super::*;

    /// Members are Horner-ordered: the first member takes the top degree and
    /// the latest sits at degree $0$, so a two-member sequence evaluates as
    /// $n_0 x + n_1$.
    #[test]
    fn members_are_horner_ordered() {
        let first = Nullifier::from(Fp::from(3));
        let latest = Nullifier::from(Fp::from(5));
        let seq: NfSeqPoly = [first, latest].into_iter().collect();

        let x = Fp::from(1000);
        assert_eq!(seq.eval(x), Fp::from(3 * 1000 + 5));
        assert_eq!(
            seq.eval(Fp::ZERO),
            Fp::from(5),
            "degree 0 holds the latest member"
        );
    }

    /// Sequences always have members; the empty sequence has no encoding.
    #[test]
    #[should_panic(expected = "at least one member")]
    fn empty_sequence_panics() {
        let _unused: NfSeqPoly = iter::empty().collect();
    }
}
