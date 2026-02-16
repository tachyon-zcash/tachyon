//! Value commitments and related types.
//!
//! A value commitment hides the value transferred in an action:
//! `cv = [v]V + [rcv]R` where `rcv` is the [`CommitmentTrapdoor`].

#![allow(clippy::from_over_into)]

use crate::primitives::{Field, Fq};
use rand::RngCore;
use std::ops;

// =============================================================================
// Value commitment trapdoor (rcv)
// =============================================================================

/// Value commitment trapdoor `rcv` — the randomness in a Pedersen commitment.
///
/// Each action gets a fresh trapdoor: `cv = [v]V + [rcv]R`.
/// The binding signing key is derived from the sum of all trapdoors in a bundle.
#[derive(Clone, Debug, Copy)]
pub struct CommitmentTrapdoor(Fq);

impl CommitmentTrapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random(rng: &mut impl RngCore) -> Self {
        Self(Fq::random(rng))
    }
}

impl Into<Fq> for CommitmentTrapdoor {
    fn into(self) -> Fq {
        self.0
    }
}

impl ops::AddAssign<CommitmentTrapdoor> for Fq {
    fn add_assign(&mut self, rcv: CommitmentTrapdoor) {
        *self += &rcv.0;
    }
}
