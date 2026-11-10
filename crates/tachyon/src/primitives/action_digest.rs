use core::cmp::Ordering;

use derive_more::{Debug, Display, Eq as TotalEq, Error, From, Into, PartialEq};
use udon::curve::Affine as _;

use crate::{
    digest::poseidon,
    keys::public,
    pasta::{EpAffine, Fp},
    value,
};

/// Poseidon digest of a single action's $(\mathsf{cv}, \mathsf{rk})$ pair.
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

/// Errors from action digest computation.
#[derive(Clone, Copy, Debug, Display, Error)]
pub enum ActionDigestError {
    /// The cv is the identity point, so the digest cannot be computed.
    #[display("cv is the identity point")]
    IdentityCv,
    /// The rk is the identity point, so the digest cannot be computed.
    #[display("rk is the identity point")]
    IdentityRk,
}

impl ActionDigest {
    /// Digest a single action's $(\mathsf{cv}, \mathsf{rk})$ pair.
    ///
    /// # Errors
    ///
    /// Returns [`ActionDigestError`] if either point is the identity, which
    /// has no affine coordinates to absorb.
    pub fn new(
        cv: value::Commitment,
        rk: public::ActionVerificationKey,
    ) -> Result<Self, ActionDigestError> {
        let cv_point = EpAffine::from(cv);
        if cv_point.is_identity() {
            return Err(ActionDigestError::IdentityCv);
        }
        let rk_point = EpAffine::from(rk);
        if rk_point.is_identity() {
            return Err(ActionDigestError::IdentityRk);
        }
        Ok(Self(poseidon::action_digest(cv_point, rk_point)))
    }
}

#[cfg(test)]
mod tests;
