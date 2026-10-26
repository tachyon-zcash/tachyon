//! Typed circuit representations of committed protocol sets.

/// Circuit representation of `NfSeqCommitGadget`.
#[derive(
    ragu_core::gadgets::Gadget, ragu_primitives::io::Write, derive_more::Debug, derive_more::From,
)]
#[debug("NfSeqCommitGadget(..)")]
pub struct NfSeqCommitGadget<'dr, D: ragu_core::drivers::Driver<'dr>> {
    pub(crate) encoding: super::commitment::HostCommitment<'dr, D>,
}

/// Circuit representation of `ActionSetCommitGadget`.
#[derive(
    ragu_core::gadgets::Gadget, ragu_primitives::io::Write, derive_more::Debug, derive_more::From,
)]
#[debug("ActionSetCommitGadget(..)")]
pub struct ActionSetCommitGadget<'dr, D: ragu_core::drivers::Driver<'dr>> {
    pub(crate) encoding: super::commitment::HostCommitment<'dr, D>,
}

/// Circuit representation of `TachygramSetCommitGadget`.
#[derive(
    ragu_core::gadgets::Gadget, ragu_primitives::io::Write, derive_more::Debug, derive_more::From,
)]
#[debug("TachygramSetCommitGadget(..)")]
pub struct TachygramSetCommitGadget<'dr, D: ragu_core::drivers::Driver<'dr>> {
    pub(crate) encoding: super::commitment::HostCommitment<'dr, D>,
}

/// Circuit representation of `AnchorSetCommitGadget`.
#[derive(
    ragu_core::gadgets::Gadget, ragu_primitives::io::Write, derive_more::Debug, derive_more::From,
)]
#[debug("AnchorSetCommitGadget(..)")]
pub struct AnchorSetCommitGadget<'dr, D: ragu_core::drivers::Driver<'dr>> {
    pub(crate) encoding: super::commitment::HostCommitment<'dr, D>,
}
