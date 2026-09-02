//! The relations the proof system enforces.
//!
//! [`enforce`] is the in-circuit constraint side. Every relation takes a
//! `StepCtx`, derives a Fiat-Shamir challenge from the operand commitments,
//! and opens them to check the identity point-wise.
//!
//! [`constraint`] is the scalar and point side: ragu's enforce-only gadgets,
//! evaluated natively.

pub(crate) mod constraint;
pub(crate) mod enforce;
