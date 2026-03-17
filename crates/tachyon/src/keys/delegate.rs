//! Delegated keys — restricted keys given to less-trusted parties.
//!
//! - [`ProofDelegateKey`]: epoch-restricted proof key given to a prover
//! - [`ProofAuthorizingKey`]: single-epoch leaf key derived by the delegate for
//!   each proof

use super::note::{Leaf, Prefix};

/// Epoch-restricted proof key — what the prover receives from the planner.
///
/// The delegate derives a [`ProofAuthorizingKey`] for each proof by
/// evaluating the GGM tree to a leaf for a specific epoch.
pub type ProofDelegateKey = super::proof::ProofKey<Prefix>;

/// Single-epoch proof key — the actual input to each proof.
///
/// Derived by the delegate from a [`ProofDelegateKey`] for a specific
/// epoch. Contains a fully-evaluated GGM leaf — no tree walking
/// in-circuit.
pub type ProofAuthorizingKey = super::proof::ProofKey<Leaf>;

/// Error from constructing a [`Prefix`](super::note::Prefix).
pub type PrefixError = super::note::PrefixError;
