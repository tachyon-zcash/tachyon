//! The relations the proof system enforces.
//!
//! [`arithmetic`] and [`curve`] implement fixed-width scalar and complete
//! point arithmetic. [`enforce`] checks polynomial identities by opening
//! fixed slots at the framework's challenge through a driver and `Oracles`.

pub(crate) mod arithmetic;
pub(crate) mod curve;
pub(crate) mod enforce;
