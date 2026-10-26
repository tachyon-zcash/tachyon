//! Circuit gadgets for profile values.

scalar_gadget!(QrDiscriminantGadget, "QrDiscriminantGadget(..)");

/// A QR routing profile with a depth and path register.
#[derive(ragu_core::gadgets::Gadget, ragu_primitives::io::Write, derive_more::Debug)]
#[debug("QrProfileGadget(..)")]
pub struct QrProfileGadget<'dr, D: ragu_core::drivers::Driver<'dr>> {
    pub(crate) depth: ragu_primitives::Element<'dr, D>,
    pub(crate) bits: ragu_primitives::Element<'dr, D>,
}
