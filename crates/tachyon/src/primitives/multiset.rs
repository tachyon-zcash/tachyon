//! Polynomial multiset accumulators for actions and tachygrams.
//!
//! Each accumulator encodes a multiset of domain values as a monic polynomial
//! whose roots are the Poseidon digests of those values. Accumulators merge
//! via polynomial multiplication and commit to a single EC point for the PCD
//! header.

extern crate alloc;

use alloc::vec::Vec;
use core::{marker::PhantomData, ops::Mul};

use ff::Field as _;
use pasta_curves::{EqAffine, Fp};

use crate::{
    action::Action,
    primitives::{ActionDigest, ActionDigestError},
};

/// Blinding factor for multiset polynomial commitments.
///
/// Always zero in Tachyon — multiset commitments are deterministic so the
/// verifier can reconstruct them from public data without a blinding factor.
///
/// ## Type representation
///
/// An $\mathbb{F}_p$ element (Vesta scalar field, 32 bytes).
#[derive(Clone, Copy, Debug)]
pub struct CommitmentTrapdoor(pub Fp);

impl CommitmentTrapdoor {
    /// Commit a multiset polynomial with this blinding factor.
    ///
    /// Returns a typed [`Commitment<T>`] over the Vesta curve.
    #[must_use]
    pub fn commit<T: Into<Fp> + Copy>(self, multiset: &Multiset<T>) -> Commitment<T> {
        Commitment(*multiset.0.commit(self.0).inner(), PhantomData)
    }
}

impl Default for CommitmentTrapdoor {
    fn default() -> Self {
        Self(Fp::ZERO)
    }
}

impl From<Fp> for CommitmentTrapdoor {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

impl From<CommitmentTrapdoor> for Fp {
    fn from(trapdoor: CommitmentTrapdoor) -> Self {
        trapdoor.0
    }
}

// ---------------------------------------------------------------------------
// Commitment<T>
// ---------------------------------------------------------------------------

/// A typed Pedersen commitment to a [`Multiset<T>`] — a Vesta curve point.
///
/// The type parameter prevents action commitments from being passed where
/// tachygram commitments are expected and vice versa.
///
/// Created by [`CommitmentTrapdoor::commit`]. Zero blinding is used throughout
/// — the verifier reconstructs commitments from public data.
///
/// ## Type representation
///
/// An `EqAffine` (Vesta affine curve point, 32 compressed bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(clippy::partial_pub_fields, reason = "control parameterizing type")]
pub struct Commitment<T>(pub EqAffine, PhantomData<T>);

impl<T> From<Commitment<T>> for EqAffine {
    fn from(commitment: Commitment<T>) -> Self {
        commitment.0
    }
}

impl<T> From<Commitment<T>> for [u8; 32] {
    fn from(commitment: Commitment<T>) -> Self {
        use pasta_curves::group::GroupEncoding as _;
        commitment.0.to_bytes()
    }
}

/// A polynomial multiset accumulator parameterized by element type `T`.
///
/// Encodes a multiset of values as a monic polynomial whose roots are the
/// domain encodings of those values. Merged via polynomial multiplication;
/// committed to a single EC point for the PCD header via
/// [`CommitmentTrapdoor::commit`].
#[derive(Clone, Debug)]
pub struct Multiset<T>(mock_ragu::Polynomial, PhantomData<T>);

impl<T: Into<Fp> + Copy> Multiset<T> {
    /// Commits this multiset to an EC point with zero blinding.
    ///
    /// Zero blinding is correct: the verifier reconstructs the commitment
    /// from public data, so non-zero blinding would break verification.
    #[must_use]
    pub fn commit(&self) -> Commitment<T> {
        CommitmentTrapdoor::default().commit(self)
    }
}

/// Single-element multiset: builds `(X - root)` from one element.
impl<T: Into<Fp> + Copy> From<T> for Multiset<T> {
    fn from(element: T) -> Self {
        Self(
            mock_ragu::Polynomial::from_roots(&[element.into()]),
            PhantomData,
        )
    }
}

/// Multi-element multiset: builds `∏(X - rootᵢ)` from a slice.
impl<T: Into<Fp> + Copy> From<&[T]> for Multiset<T> {
    fn from(elements: &[T]) -> Self {
        let roots: Vec<Fp> = elements.iter().copied().map(Into::into).collect();
        Self(mock_ragu::Polynomial::from_roots(&roots), PhantomData)
    }
}

/// Merges two multisets by polynomial multiplication (owned).
impl<T: Into<Fp> + Copy> Mul<Self> for Multiset<T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self(self.0.multiply(&rhs.0), PhantomData)
    }
}

/// Merges two multisets by polynomial multiplication (borrowed).
impl<'multiset, T: Into<Fp> + Copy> Mul<&'multiset Multiset<T>> for &'multiset Multiset<T> {
    type Output = Multiset<T>;

    fn mul(self, rhs: &'multiset Multiset<T>) -> Multiset<T> {
        Multiset(self.0.multiply(&rhs.0), PhantomData)
    }
}

/// Multi-action constructor: builds `∏(X - digestᵢ)` from a slice of actions.
impl TryFrom<&[Action]> for Multiset<ActionDigest> {
    type Error = ActionDigestError;

    fn try_from(actions: &[Action]) -> Result<Self, Self::Error> {
        let roots: Vec<Fp> = actions
            .iter()
            .map(ActionDigest::try_from)
            .collect::<Result<Vec<ActionDigest>, ActionDigestError>>()?
            .into_iter()
            .map(Fp::from)
            .collect();
        Ok(Self(mock_ragu::Polynomial::from_roots(&roots), PhantomData))
    }
}
