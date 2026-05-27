extern crate alloc;

use alloc::vec::Vec;

use pasta_curves::{EqAffine, Fp};
use ragu::{Commitment, Polynomial, generators};

use crate::note::{self, Nullifier, ProNf};

/// Pedersen commitment to a nullifier sequence $N$.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NfSeqCommit(Commitment);

/// Pedersen commitment to a pronullifier sequence $M$.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProNfSeqCommit(Commitment);

/// Pedersen commitment to a nullifier sequence, additionally cm-trapdoored by
/// blinding with $\mathsf{cm}\cdot H$.
///
/// This is the spendable's `future`: the only way to obtain one is
/// [`NfSeqCommit::blind`], so a bare commitment can never pass as a future.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlindNfSeqCommit(Commitment);

/// Witness polynomial for a nullifier sequence $N$ (members encoded as
/// coefficients, ordered by ascending degree).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfSeqPoly(Polynomial);

/// Witness polynomial for a pronullifier sequence $M$ (members encoded as
/// coefficients, ordered by ascending degree).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProNfSeqPoly(Polynomial);

impl ProNfSeqCommit {
    /// Homomorphically shift every coefficient up by the note commitment `cm`,
    /// turning a commitment to the pronullifier sequence $M$ into one to the
    /// nullifier sequence $N = M + \mathsf{cm}\cdot\mathbb{1}$ by adding
    /// $\mathsf{cm}\cdot\sum_{i} G_i$ over the `len` coefficients. A bare
    /// commitment carries no length, so `len` (the sequence rank) is explicit.
    #[must_use]
    pub fn shift(self, cm: note::Commitment, len: usize) -> NfSeqCommit {
        NfSeqCommit(self.0 + generators::g_sum(len) * Fp::from(cm))
    }
}

impl NfSeqCommit {
    /// The identity commitment — the commit of the empty nullifier sequence.
    /// A constant (no in-step polynomial construction); emitted by the
    /// `Unspent` seeds for a zero-crossing segment and compared against by
    /// `UnspentFuse`.
    #[must_use]
    pub fn identity() -> Self {
        Self(Commitment::identity())
    }

    /// Homomorphically trapdoor this commitment with the note commitment `cm`,
    /// blinding with $\mathsf{cm}\cdot H$ to produce the spendable's `future`.
    #[must_use]
    pub fn blind(self, cm: note::Commitment) -> BlindNfSeqCommit {
        BlindNfSeqCommit(self.0 + generators::h() * Fp::from(cm))
    }
}

impl BlindNfSeqCommit {
    /// Inverse of [`NfSeqCommit::blind`]: remove the `cm·H` trapdoor,
    /// recovering the untrapdoored commitment. Lets a step fold a
    /// future-match into a concat by using `future.unblind(cm)` as the
    /// result commitment.
    #[must_use]
    pub fn unblind(self, cm: note::Commitment) -> NfSeqCommit {
        NfSeqCommit(self.0 + generators::h() * (-Fp::from(cm)))
    }
}

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

impl ProNfSeqPoly {
    /// Deterministic (untrapdoored) commitment to the sequence polynomial.
    #[must_use]
    pub fn commit(&self) -> ProNfSeqCommit {
        ProNfSeqCommit(self.0.commit())
    }

    /// Concatenate two sequences: `self`'s coefficients followed by `other`'s.
    #[must_use]
    pub fn concat(&self, other: &Self) -> Self {
        let mut coeffs = self.0.coefficients().to_vec();
        coeffs.extend_from_slice(other.0.coefficients());
        Self(Polynomial::from_coeffs(&coeffs))
    }

    /// Evaluate the sequence polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl From<NfSeqPoly> for Polynomial {
    fn from(poly: NfSeqPoly) -> Self {
        poly.0
    }
}

impl From<ProNfSeqPoly> for Polynomial {
    fn from(poly: ProNfSeqPoly) -> Self {
        poly.0
    }
}

impl From<&[Nullifier]> for NfSeqPoly {
    fn from(nfs: &[Nullifier]) -> Self {
        let coeffs: Vec<Fp> = nfs.iter().map(|&nf| Fp::from(nf)).collect();
        Self(Polynomial::from_coeffs(&coeffs))
    }
}

impl From<&[ProNf]> for ProNfSeqPoly {
    fn from(pronfs: &[ProNf]) -> Self {
        let coeffs: Vec<Fp> = pronfs.iter().map(|&pronf| Fp::from(pronf)).collect();
        Self(Polynomial::from_coeffs(&coeffs))
    }
}

impl From<&[Nullifier]> for NfSeqCommit {
    fn from(nfs: &[Nullifier]) -> Self {
        NfSeqPoly::from(nfs).commit()
    }
}

impl From<&[ProNf]> for ProNfSeqCommit {
    fn from(pronfs: &[ProNf]) -> Self {
        ProNfSeqPoly::from(pronfs).commit()
    }
}

impl From<NfSeqCommit> for Commitment {
    fn from(commit: NfSeqCommit) -> Self {
        commit.0
    }
}

impl From<ProNfSeqCommit> for Commitment {
    fn from(commit: ProNfSeqCommit) -> Self {
        commit.0
    }
}

impl From<BlindNfSeqCommit> for Commitment {
    fn from(commit: BlindNfSeqCommit) -> Self {
        commit.0
    }
}

impl From<NfSeqCommit> for EqAffine {
    fn from(commit: NfSeqCommit) -> Self {
        *commit.0.inner()
    }
}

impl From<ProNfSeqCommit> for EqAffine {
    fn from(commit: ProNfSeqCommit) -> Self {
        *commit.0.inner()
    }
}
