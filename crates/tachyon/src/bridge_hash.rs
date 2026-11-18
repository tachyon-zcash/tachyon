//! Native mirror of Ragu's `Application::bridge_hash`.
//!
//! `Anchor::next_stamp` is reached from step code and needs the bridge hash
//! without an application. The pinning test compares this mirror with
//! `Application::bridge_hash`. The bridge-stage layout arithmetic goes away
//! when Ragu exposes the bridge generators.

use ragu_circuits::{polynomials::ProductionRank, staging::wire_degree};
use ragu_core::{Cycle as _, FixedGenerators as _, pasta::Pasta};
use ragu_primitives::{ENDOSCALAR_BITS, ENDOSCALAR_PRODUCTS};
use udon::curve::{Affine as _, Projective as _};

use crate::pasta::{self, EpAffine, EqAffine};

/// Computes the bridge hash of a tachygram set commitment.
///
/// # Panics
///
/// Panics if `commitment` is the identity.
pub(crate) fn bridge_hash(commitment: EqAffine) -> EpAffine {
    #[expect(
        clippy::expect_used,
        reason = "no set polynomial commits to the identity"
    )]
    let (x, y) = commitment
        .coordinates()
        .expect("tachygram set commitment is not the identity");
    // The bridge stage starts after the endoscalar values, rounded up to whole
    // gates.
    let x_wire = (ENDOSCALAR_BITS + ENDOSCALAR_PRODUCTS).next_multiple_of(2);
    let y_wire = x_wire + 1;
    let generators = Pasta::nested_generators(pasta::baked()).g();
    #[expect(
        clippy::expect_used,
        reason = "the baked setup holds a nested generator for every ProductionRank degree"
    )]
    let generator = |wire| {
        generators
            .get(wire_degree::<ProductionRank>(wire))
            .expect("the baked setup has the bridge generators")
    };
    let g_x = generator(x_wire);
    let g_y = generator(y_wire);
    (g_x.to_projective() * x + g_y.to_projective() * y).to_affine()
}

#[cfg(test)]
mod tests;
