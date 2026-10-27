//! Circuit gadgets for value values.
use ragu_core::drivers::Driver;

scalar_gadget!(ValueGadget, "ValueGadget(..)");

/// A value commitment represented by its circuit point.
#[derive(
    ragu_core::gadgets::Gadget, ragu_primitives::io::Write, derive_more::Debug, derive_more::From,
)]
#[debug("ValueCommitmentGadget(..)")]
#[expect(
    clippy::module_name_repetitions,
    reason = "the semantic gadget name is explicit at call sites"
)]
pub struct ValueCommitmentGadget<'dr, D: Driver<'dr>> {
    pub(crate) point: super::point::CurvePoint<'dr, D>,
}
