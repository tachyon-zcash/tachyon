//! Pasta field and curve types.
//!
//! These name Udon's adapter types directly. Ragu's `pasta` aliases resolve
//! to the same types through `Cycle` projections, which derives on Tachyon's
//! newtypes cannot see through.

use udon::{
    curve::{AffineAdapter, Pallas, ProjectiveAdapter, Vesta},
    field::{FieldAdapter, PallasBase, PallasScalar},
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
