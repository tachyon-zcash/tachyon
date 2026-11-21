//! Prepared fixed bases for Tachyon commitments and authorization keys.
//!
//! # Injectivity
//!
//! Each base $B$ is a point of the Pallas group other than the identity, and
//! the group has prime order $q$. Ragu's `FixedBase::mul` returns
//! $\[n\]B + C$ and `mul_and_add` returns $\[n\]B + C + P$. $n$ is the
//! integer of the [bit string](super::uint::Uint), $C$ is the constant
//! correction of the table and $P$ is the added point. The gadget does not
//! reduce $n$.
//!
//! No bit string here has more than 254 bits, so $n < 2^{254} < q$. Distinct
//! integers are distinct scalars, and $\[n\]B$ determines $n$.
//!
//! ## Cases without an assignment
//!
//! `mul` has no assignment when its result is the identity. Without a
//! correction that is $n = 0$.
//!
//! `mul_and_add` has no assignment when its result is the identity, or when
//! $P = -\[l + O\]B$. The gadget adds $P$ to the partial sum $\[l + O\]B$,
//! where $l$ is $n$ without the bits of its top window and $O$ is a constant
//! of the table.
//!
//! A step cannot be proved in these cases. They do not change what a
//! satisfied circuit shows, which is the point stated above.
//!
//! ## Value commitments
//!
//! A value commitment is $\mathsf{cv} = \[v\]\mathcal{V} +
//! \[r\]\mathcal{R}$ for a value $v$ and a blind $r$. A step computes the
//! blind point $\[r\]\mathcal{R}$ with [`struct@R_BASE`] and adds the value
//! term to it with `mul_and_add`. The blind is an integer with
//! $0 < r < 2^{254}$, because a zero blind gives the identity.
//!
//! Every point is a commitment to every value under some blind, so the point
//! alone fixes no value. A satisfied step shows that its prover knows an
//! opening $(v, r)$ whose $v$ is the amount the step constrains. Two openings
//! of one point that differ modulo $q$ give the discrete logarithm of
//! $\mathcal{V}$ to the base $\mathcal{R}$, which the
//! [Commitments assumption](crate::stamp::proof#assumptions) says nobody
//! knows. A value commitment therefore determines its opening modulo $q$.
//!
//! A value is an amount or its negation, an integer of absolute value at most
//! `MAX_MONEY`. Such integers are distinct modulo $q$, and so are blinds
//! below $2^{254}$, so the commitment determines the value and the blind as
//! integers.
//!
//! For a value commitment, a case without an assignment needs the blind point
//! to be a known multiple of $\mathcal{V}$, which gives the same discrete
//! logarithm.

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
