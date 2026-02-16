//! Low-level cryptographic primitives for Tachyon.
//!
//! This module provides the fundamental cryptographic building blocks used
//! throughout the Tachyon protocol, built on top of the Ragu proof system
//! and Pasta curves.
//!
//! ## Field Elements
//!
//! Tachyon uses the Pallas curve's base field $\mathbb{F}_p$ as its primary computation
//! field, consistent with the Orchard protocol. The scalar field $\mathbb{F}_q$ is used
//! for scalar operations on the Vesta curve.

mod internal;
pub use internal::*;

pub use ff::{Field, FromUniformBytes, PrimeField};
pub use pasta_curves::{
    EpAffine, Fp, Fq, arithmetic::CurveAffine, arithmetic::CurveExt, group::GroupEncoding,
    group::prime::PrimeCurveAffine, pallas,
};
