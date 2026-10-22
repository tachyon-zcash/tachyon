//! Fees and fee descriptors.

use core::cmp;

use derive_more::{Debug, Eq as TotalEq, PartialEq};
use group::GroupEncoding as _;
use pasta_curves::{EpAffine, arithmetic::CurveAffine as _};

use crate::{
    digest::poseidon,
    primitives::{ActionDigest, ActionDigestError},
    value,
};

/// A bundle's fee descriptor: the max fee commitment and the fee value.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct Descriptor {
    /// The max fee commitment.
    pub max_commitment: value::Commitment,

    /// The fee.
    pub value: value::Positive,
}

impl Descriptor {
    /// The fee digest [`poseidon::fee_digest`], a member of the action set.
    ///
    /// # Errors
    ///
    /// Returns [`ActionDigestError`] if the commitment is the identity.
    pub fn digest(&self) -> Result<ActionDigest, ActionDigestError> {
        let cv_max_fee = EpAffine::from(self.max_commitment)
            .coordinates()
            .into_option()
            .ok_or(ActionDigestError::IdentityCv)?;
        Ok(ActionDigest::from(poseidon::fee_digest(
            cv_max_fee,
            u64::from(self.value),
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
    /// The fee descriptor's coverage entry, `cv_maxfee || LE64(fee)`.
    fn from(descriptor: Descriptor) -> Self {
        let mut entry = [0u8; 40];
        entry[..32].copy_from_slice(&EpAffine::from(descriptor.max_commitment).to_bytes());
        entry[32..].copy_from_slice(&u64::from(descriptor.value).to_le_bytes());
        entry
    }
}
