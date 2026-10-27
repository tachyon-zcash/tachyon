//! Circuit gadgets for profile values.
use ragu_core::drivers::Driver;
use ragu_primitives::Element;

scalar_gadget!(QrDiscriminantGadget, "QrDiscriminantGadget(..)");

/// A QR routing profile with a depth and path register.
#[derive(ragu_core::gadgets::Gadget, ragu_primitives::io::Write, derive_more::Debug)]
#[debug("QrProfileGadget(..)")]
pub struct QrProfileGadget<'dr, D: Driver<'dr>> {
    pub(crate) depth: Element<'dr, D>,
    pub(crate) bits: Element<'dr, D>,
}
