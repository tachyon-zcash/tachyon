//! Circuit gadgets for value values.

scalar_gadget!(ValueGadget, "ValueGadget(..)");

/// A value commitment represented by its circuit point.
#[derive(
    ragu_core::gadgets::Gadget, ragu_primitives::io::Write, derive_more::Debug, derive_more::From,
)]
#[debug("ValueCommitmentGadget(..)")]
pub struct ValueCommitmentGadget<'dr, D: ragu_core::drivers::Driver<'dr>> {
    pub(crate) point: super::point::CurvePoint<'dr, D>,
}
