//! Prepared fixed bases for Tachyon commitments and authorization keys.
//!
//! # Injectivity
//!
//! Ragu's [`FixedBase`] scales the base by the unsigned integer $n$ its bits
//! encode and adds the table's correction and any supplied point. Each base
//! here has prime order $q$ and $n < 2^{254} < q$, so $\[n\]B$ determines $n$.
//!
//! [`FixedBase::mul`] and [`FixedBase::mul_and_add`] require a finite,
//! non-identity result.

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
    /// Multiplied by a 254-bit $r$, computes $\[r\]\mathcal{R}$, the blind
    /// point of a value commitment.
    ///
    /// A standalone [`FixedBase::mul`] on this zero-correction table admits
    /// exactly $0 < r < 2^{254}$.
    pub(crate) static ref R_BASE: FixedBase<EpAffine, 254> =
        prepare(*orchard::VALUE_COMMIT_R, Ep::identity());
    /// Multiplied by a 254-bit $\alpha$, computes $\[\alpha\]\mathcal{G}$,
    /// the randomizer term of an action verification key.
    pub(crate) static ref G_BASE: FixedBase<EpAffine, 254> =
        prepare(*ACTION_AUTH_GENERATOR, Ep::identity());
    /// Multiplied by a 51-bit $v$, computes $\[v\]\mathcal{V}$, the value
    /// term of a spend.
    pub(crate) static ref V_BASE: FixedBase<EpAffine, 51> =
        prepare(*orchard::VALUE_COMMIT_V, Ep::identity());
    /// Multiplied by a 51-bit $v$, computes $\[-v\]\mathcal{V}$, the value
    /// term of an output. The base is $-\mathcal{V}$.
    pub(crate) static ref NEG_V_BASE: FixedBase<EpAffine, 51> =
        prepare(-*orchard::VALUE_COMMIT_V, Ep::identity());
    /// Multiplied by `MAX_MONEY - maximum`, computes
    /// $\[-\mathsf{maximum}\]\mathcal{V}$, the value term of a max fee
    /// commitment. The base is $\mathcal{V}$ and the correction is
    /// $-\[\mathsf{MAX}\]\mathcal{V}$ for $\mathsf{MAX}$ = `MAX_MONEY`.
    pub(crate) static ref FEE_V_BASE: FixedBase<EpAffine, 51> = prepare(
        *orchard::VALUE_COMMIT_V,
        -*orchard::VALUE_COMMIT_V * Fq::from(MAX_MONEY)
    );
}

#[expect(clippy::expect_used, reason = "Tachyon's fixed tables must be valid")]
fn prepare<const N: usize>(base: Ep, correction: Ep) -> FixedBase<EpAffine, N> {
    FixedBase::new(base.to_affine(), correction.to_affine()).expect("valid Tachyon fixed base")
}
