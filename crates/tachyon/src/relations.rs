//! The relations the proof system enforces.
//!
//! [`enforce`] is the in-circuit constraint side. Every relation takes a
//! driver and `Oracles`, and opens fixed slots at the framework's challenge
//! to check the identity point-wise.

pub(crate) mod enforce;
