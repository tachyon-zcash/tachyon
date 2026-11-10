//! Fees and fee descriptors.

use core::cmp;

use derive_more::{Debug, Eq as TotalEq, PartialEq};
use udon::curve::Affine as _;

use crate::{
    digest::poseidon,
    pasta::EpAffine,
    primitives::{ActionDigest, ActionDigestError},
    value,
};

/// A bundle's fee descriptor: the max fee commitment and the fee value.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct Descriptor {
    /// The max fee commitment.
    pub cv_feemax: value::Commitment,

    /// The fee, `vFeeTachyon`.
    pub v_fee: value::Positive,
}

impl Descriptor {
    /// The fee digest [`poseidon::fee_digest`], a member of the action set.
    ///
    /// # Errors
    ///
    /// Returns [`ActionDigestError`] if the commitment is the identity.
    pub fn digest(&self) -> Result<ActionDigest, ActionDigestError> {
        let cv_feemax = EpAffine::from(self.cv_feemax);
        if cv_feemax.is_identity() {
            return Err(ActionDigestError::IdentityCv);
        }
        Ok(ActionDigest::from(poseidon::fee_digest(
            cv_feemax,
            u64::from(self.v_fee),
        )))
    }
}

impl PartialOrd for Descriptor {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Descriptor {
    /// Orders fee descriptors by their coverage entries.
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        <[u8; 40]>::from(*self).cmp(&<[u8; 40]>::from(*other))
    }
}

impl From<Descriptor> for [u8; 40] {
    /// The fee descriptor's coverage entry, `cv_feemax || LE64(fee)`.
    fn from(descriptor: Descriptor) -> Self {
        let mut entry = [0u8; 40];
        entry[..32].copy_from_slice(&EpAffine::from(descriptor.cv_feemax).to_bytes());
        entry[32..].copy_from_slice(&u64::from(descriptor.v_fee).to_le_bytes());
        entry
    }
}
