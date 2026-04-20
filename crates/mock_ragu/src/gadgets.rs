use ff::Field as _;
use pasta_curves::Fp;

use crate::polynomial::{Commitment, Polynomial};

/// Speculative mock of a ragu multiset gadget.
///
/// This mock version carries the underlying polynomial in the clear.
#[derive(Clone, Debug)]
pub struct Multiset(pub(crate) Polynomial);

impl PartialEq for Multiset {
    fn eq(&self, other: &Self) -> bool {
        self.commit() == other.commit()
    }
}

impl Eq for Multiset {}

impl Multiset {
    #[must_use]
    pub fn new(polynomial: Polynomial) -> Self {
        Self(polynomial)
    }

    /// Commit to a polynomial with zero blinding factor.
    #[must_use]
    pub fn commit(&self) -> Commitment {
        self.0.commit(Fp::ZERO)
    }

    /// Commit to a polynomial with the given blinding factor.
    #[must_use]
    pub fn commit_with(&self, blind: Fp) -> Commitment {
        self.0.commit(blind)
    }

    /// Query the committed polynomial at `point`.
    ///
    /// In real ragu this registers a `(commitment, point, value)` PCS opening
    /// claim discharged by the IPA decider. Here we just evaluate directly.
    #[must_use]
    pub fn query(&self, point: Fp) -> Fp {
        self.0.eval(point)
    }

    /// Merge two sets, double-counting any shared elements.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        Self::new(self.0.multiply(&other.0))
    }
}
