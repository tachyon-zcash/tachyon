//! Fees and fee descriptors.

use core::cmp;

use derive_more::{Debug, Eq as TotalEq, PartialEq};

use crate::{
    digest::poseidon,
    pasta::{EpAffine, Fp},
    primitives::{ActionDigest, Tachygram},
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
    /// # Panics
    ///
    /// Panics if `cv_feemax` is the identity. Bundle reading rejects that
    /// commitment, so only hand-built values can trigger this panic.
    #[must_use]
    pub fn digest(&self, fee_change: Tachygram) -> ActionDigest {
        ActionDigest::from(poseidon::fee_digest(
            EpAffine::from(self.cv_feemax),
            u64::from(self.v_fee),
            Fp::from(fee_change),
        ))
    }
}

impl PartialOrd for Descriptor {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Descriptor {
    /// Orders by compressed commitment, then by fee amount.
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        { <[u8; 32]>::from(self.cv_feemax).cmp(&<[u8; 32]>::from(other.cv_feemax)) }
            .then(self.v_fee.cmp(&other.v_fee))
    }
}
