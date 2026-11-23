//! Prepared fixed bases for Tachyon commitments and authorization keys.

use lazy_static::lazy_static;
use ragu::{primitives::FixedBase, udon::curve::Projective as _};

use crate::{
    constants::{
        MAX_MONEY,
        orchard::{self, ACTION_AUTH_GENERATOR},
    },
    pasta::{Ep, EpAffine, Fq},
};

lazy_static! {
    pub(crate) static ref R_BASE: FixedBase<EpAffine, 254> =
        prepare(*orchard::VALUE_COMMIT_R, Ep::identity());
    pub(crate) static ref G_BASE: FixedBase<EpAffine, 254> =
        prepare(*ACTION_AUTH_GENERATOR, Ep::identity());
    pub(crate) static ref V_BASE: FixedBase<EpAffine, 51> =
        prepare(*orchard::VALUE_COMMIT_V, Ep::identity());
    pub(crate) static ref NEG_V_BASE: FixedBase<EpAffine, 51> =
        prepare(-*orchard::VALUE_COMMIT_V, Ep::identity());
    /// Multiplied by `MAX_MONEY - maximum`, computes $[-\mathsf{maximum}]\mathcal{V}$.
    pub(crate) static ref FEE_V_BASE: FixedBase<EpAffine, 51> = prepare(
        *orchard::VALUE_COMMIT_V,
        -*orchard::VALUE_COMMIT_V * Fq::from(MAX_MONEY)
    );
}

#[expect(clippy::expect_used, reason = "Tachyon's fixed tables must be valid")]
fn prepare<const N: usize>(base: Ep, correction: Ep) -> FixedBase<EpAffine, N> {
    FixedBase::new(base.to_affine(), correction.to_affine()).expect("valid Tachyon fixed base")
}
