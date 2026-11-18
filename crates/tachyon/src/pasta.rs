//! Pasta field and curve types.
//!
//! These name Udon's adapter types directly. Ragu's `pasta` aliases resolve
//! to the same types through `Cycle` projections, which derives on Tachyon's
//! newtypes cannot see through.

use udon::{
    curve::{AffineAdapter, Pallas, ProjectiveAdapter, Vesta},
    field::{Field as _, FieldAdapter, PallasBase, PallasScalar},
};

/// The Pallas base field.
pub type Fp = FieldAdapter<PallasBase>;

/// The Pallas scalar field.
pub type Fq = FieldAdapter<PallasScalar>;

/// Pallas in projective coordinates.
pub type Ep = ProjectiveAdapter<Pallas>;

/// Pallas in affine coordinates, including identity.
pub type EpAffine = AffineAdapter<Pallas>;

/// Vesta in projective coordinates.
pub type Eq = ProjectiveAdapter<Vesta>;

/// Vesta in affine coordinates, including identity.
pub type EqAffine = AffineAdapter<Vesta>;

pub(crate) use ragu_pcd::pasta::baked;

/// The scalar a Poseidon digest represents: its integer value, which the
/// circuits multiply by from 254 bits.
///
/// # Panics
///
/// Panics if `digest` is at least $2^{254}$, which no circuit proves. A
/// Poseidon digest lands there with probability about $2^{-129}$, and steering
/// one there costs about $2^{129}$ hashes.
#[expect(
    clippy::expect_used,
    reason = "a digest below 2^254 < p < q is canonical in Fq"
)]
#[expect(clippy::as_conversions, reason = "constant value")]
pub(crate) fn digest_scalar(digest: Fp) -> Fq {
    assert!(
        !digest
            .to_le_bits()
            .as_ref()
            .iter()
            .skip(Fp::CAPACITY as usize)
            .any(|&bit| bit),
        "a Poseidon digest is below 2^254"
    );
    Fq::from_bytes(digest.to_bytes()).expect("p < q")
}
