//! Value commitments and related types.
//!
//! A value commitment hides the value transferred in an action:
//! `cv = [v]V + [rcv]R` where `rcv` is the [`CommitmentTrapdoor`].

use core::{iter, ops};
use std::sync::LazyLock;

use ff::Field as _;
use pasta_curves::{
    Ep, EpAffine, Fq,
    arithmetic::CurveExt as _,
    group::{GroupEncoding as _, prime::PrimeCurveAffine as _},
    pallas,
};
use rand::{CryptoRng, RngCore};

use crate::constants::VALUE_COMMITMENT_DOMAIN;

/// Convert a signed integer to an $\mathbb{F}_q$ element.
///
/// `Fq` only implements `From<u64>`, so negative values are handled
/// via field negation: $-|v| \pmod{r_q}$.
fn signed_to_scalar(value: i64) -> Fq {
    if value >= 0 {
        Fq::from(value.unsigned_abs())
    } else {
        -Fq::from(value.unsigned_abs())
    }
}

/// Generator $\mathcal{V}$ for value commitments.
static VALUE_COMMIT_V: LazyLock<pallas::Point> =
    LazyLock::new(|| pallas::Point::hash_to_curve(VALUE_COMMITMENT_DOMAIN)(b"v"));

/// Generator $\mathcal{R}$ for value commitments and binding signatures.
static VALUE_COMMIT_R: LazyLock<pallas::Point> =
    LazyLock::new(|| pallas::Point::hash_to_curve(VALUE_COMMITMENT_DOMAIN)(b"r"));

/// Value commitment trapdoor $\mathsf{rcv}$ — the randomness in a
/// Pedersen commitment.
///
/// Each action gets a fresh trapdoor:
/// $\mathsf{cv} = [v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$.
///
/// The binding signing key is the scalar sum of trapdoors:
/// $\mathsf{bsk} = \boxplus_i \mathsf{rcv}_i$
/// ($\mathbb{F}_q$, Pallas scalar field).
///
/// ## Type representation
///
/// An $\mathbb{F}_q$ element (Pallas scalar field, 32 bytes). Lives
/// in the scalar field because $\mathsf{rcv}$ is used as a scalar in
/// point multiplication $[\mathsf{rcv}]\,\mathcal{R}$.
#[derive(Clone, Copy, Debug)]
pub struct CommitmentTrapdoor(Fq);

impl CommitmentTrapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        // TODO: the selection of `rcv` may be revised to incorporate a hash of
        // the note commitment or other action-specific data, possibly
        // tied to alpha/theta derivation.
        todo!("random commitment trapdoor");
        Self(Fq::random(rng))
    }

    /// Commit to a value with this trapdoor.
    ///
    /// $$\mathsf{cv} = [v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$$
    ///
    /// Positive $v$ for spends (balance contributed), negative for
    /// outputs (balance exhausted).
    #[must_use]
    pub fn commit(self, value: i64) -> Commitment {
        let committed: EpAffine = {
            let commit_value: Ep = *VALUE_COMMIT_V * signed_to_scalar(value);
            let commit_trapdoor: Ep = *VALUE_COMMIT_R * self.0;
            (commit_value + commit_trapdoor).into()
        };

        Commitment(committed)
    }
}

impl Default for CommitmentTrapdoor {
    fn default() -> Self {
        Self(Fq::ZERO)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<Fq> for CommitmentTrapdoor {
    fn into(self) -> Fq {
        self.0
    }
}

/// A value commitment for a Tachyon action.
///
/// Commits to the value being transferred in an action without
/// revealing it. This is a Pedersen commitment (curve point) used in
/// value balance verification.
///
/// $$\mathsf{cv} = [v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$$
///
/// where $v$ is the value, $\mathsf{rcv}$ is the randomness
/// ([`CommitmentTrapdoor`]), and $\mathcal{V}$, $\mathcal{R}$ are
/// generator points derived from [`VALUE_COMMITMENT_DOMAIN`]
/// (§5.4.8.3).
///
/// ## Type representation
///
/// An EpAffine (Pallas affine curve point, 32 compressed bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct Commitment(pub(super) EpAffine);

impl Commitment {
    /// Create the value balance commitment
    /// $\text{ValueCommit}_0(\mathsf{v\_{balance}})$.
    ///
    /// $$\text{ValueCommit}_0(v) = [v]\,\mathcal{V} + [0]\,\mathcal{R}
    ///   = [v]\,\mathcal{V}$$
    ///
    /// This is a **deterministic** commitment with zero randomness.
    /// Used by validators to derive the binding verification key:
    ///
    /// $$\mathsf{bvk} = \left(\bigoplus_i \mathsf{cv}_i\right)
    ///   \ominus \text{ValueCommit}_0(\mathsf{v\_{balance}})$$
    #[must_use]
    pub fn balance(value: i64) -> Self {
        CommitmentTrapdoor::default().commit(value)
    }
}

impl From<Commitment> for EpAffine {
    fn from(cv: Commitment) -> Self {
        cv.0
    }
}

impl From<EpAffine> for Commitment {
    fn from(affine: EpAffine) -> Self {
        Self(affine)
    }
}

impl TryFrom<&[u8; 32]> for Commitment {
    type Error = &'static str;

    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        EpAffine::from_bytes(bytes)
            .into_option()
            .ok_or("invalid curve point")
            .map(Self)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 32]> for Commitment {
    fn into(self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl ops::Add for Commitment {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self((self.0 + rhs.0).into())
    }
}

impl ops::Sub for Commitment {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self((self.0 - rhs.0).into())
    }
}

impl iter::Sum for Commitment {
    /// $\bigoplus_i \mathsf{cv}_i$ — point addition over all value
    /// commitments. Identity element is the point at infinity.
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self(EpAffine::identity()), |acc, cv| acc + cv)
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    /// $v + (-v) = 0$ in the scalar field, regardless of sign encoding.
    #[test]
    fn signed_to_scalar_negation_cancels() {
        let pos = signed_to_scalar(42);
        let neg = signed_to_scalar(-42);
        assert_eq!(pos + neg, Fq::ZERO);
    }

    /// balance(0) must be the identity point — the V-component cancels
    /// and the R-component has zero scalar.
    #[test]
    fn balance_zero_is_identity() {
        assert_eq!(
            CommitmentTrapdoor::default().commit(0),
            Commitment(EpAffine::identity())
        );
    }

    /// The binding property: `cv_a + cv_b - balance(a+b) = [rcv_a + rcv_b]R`.
    /// The V-components cancel, leaving only the R-component.
    #[test]
    fn commit_homomorphic_binding_property() {
        let mut rng = StdRng::seed_from_u64(0);
        let rcv_a = CommitmentTrapdoor::random(&mut rng);
        let cv_a = rcv_a.commit(100);
        let rcv_b = CommitmentTrapdoor::random(&mut rng);
        let cv_b = rcv_b.commit(200);

        let remainder = cv_a + cv_b - Commitment::balance(300);

        let rcv_sum: Fq = Into::<Fq>::into(rcv_a) + Into::<Fq>::into(rcv_b);
        let expected: EpAffine = (*VALUE_COMMIT_R * rcv_sum).into();

        assert_eq!(remainder, Commitment(expected));
    }
}
