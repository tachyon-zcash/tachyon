use core::cmp::Ordering;

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};

use crate::{
    digest::poseidon,
    keys::public,
    pasta::{EpAffine, Fp},
    primitives::Tachygram,
    value,
};

/// Poseidon digest of an action's `cv`, `rk` and unordered tachygram pair.
///
/// Each action produces one digest, which serves as a root in the
/// accumulator polynomial. Multiple actions are accumulated via
/// polynomial commitment, not on this type. A fee digest
/// $d_\mathsf{fee}$ joins the same action set.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct ActionDigest(Fp);

impl PartialOrd for ActionDigest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ActionDigest {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_inner().reduce().cmp(&other.0.as_inner().reduce())
    }
}

impl ActionDigest {
    /// Digests an action and its unordered tachygram pair. The digest absorbs
    /// the pair's sum and product, so member order does not matter.
    ///
    /// # Panics
    ///
    /// Panics if `cv` or `rk` is the identity, which has no affine coordinates
    /// to absorb. Descriptor reading rejects both identities; callers supplying
    /// hand-built values must ensure both points are non-identity.
    #[must_use]
    pub fn new(
        cv: value::Commitment,
        rk: public::ActionVerificationKey,
        tachygrams: (Tachygram, Tachygram),
    ) -> Self {
        Self(poseidon::action_digest(
            EpAffine::from(cv),
            EpAffine::from(rk),
            (Fp::from(tachygrams.0), Fp::from(tachygrams.1)),
        ))
    }
}

#[cfg(test)]
mod tests;
