//! The relations the proof system enforces.
//!
//! [`enforce`] is the in-circuit constraint side. Every relation takes a
//! `StepCtx`, derives a Fiat-Shamir challenge from the operand commitments,
//! and opens them to check the identity point-wise.

pub(crate) mod enforce;
