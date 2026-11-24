//! Prepared fixed bases for Tachyon commitments and authorization keys.
//!
//! # Injectivity
//!
//! Each base $B$ is a non-identity point in a group of prime order $q$, and no
//! [bit string](super::uint::Uint) here exceeds 254 bits. Because $n < 2^{254}
//! < q$ for the bit string's unreduced integer $n$, $\[n\]B$ determines $n$.
//! Ragu's `FixedBase::mul` returns $\[n\]B + C$ and `mul_and_add` returns
//! $\[n\]B + C + P$, for the table's constant correction $C$ and the added
//! point $P$.
//!
//! ## Cases without an assignment
//!
//! `mul` has no assignment when its result is the identity, which is $n = 0$
//! without a correction. `mul_and_add` has no assignment when its result is the
//! identity or when $P = -\[l + O\]B$ negates the partial sum it adds $P$ to,
//! for $l$ equal to $n$ without its top-window bits and a table constant $O$.
//! These cases prevent proving a step and do not weaken what a satisfied
//! circuit shows.
//!
//! ## Value commitments
//!
//! A value commitment $\mathsf{cv} = \[v\]\mathcal{V} + \[r\]\mathcal{R}$
//! determines its opening $(v,r)$ as integers. Each value-commitment step
//! computes $\[r\]\mathcal{R}$ with `mul` on [`struct@R_BASE`], holding $0 < r
//! < 2^{254}$, and adds any potentially nonzero value term with `mul_and_add`.
//!
//! A satisfied step shows that its prover knows an opening $(v, r)$ with the
//! step's constrained amount $v$. Two openings that differ modulo $q$ yield the
//! discrete logarithm of $\mathcal{V}$ to the base $\mathcal{R}$, so producing
//! them would contradict the [Commitments
//! assumption](crate::stamp::proof#assumptions). Because $|v|$ is at most
//! `MAX_MONEY` and $0 < r < 2^{254}$, openings in these ranges that agree
//! modulo $q$ also agree as integers.
//!
//! Adding a value term introduces further unassigned cases only when the blind
//! point is a known multiple of $\mathcal{V}$, which yields the same discrete
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
