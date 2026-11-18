//! A step's bridge hash as a curve point.

use alloc::vec::Vec;

use ragu_core::{Result, drivers::Driver, maybe::Maybe as _};
use ragu_pcd::step::BridgeHash;
use ragu_primitives::{Element, GadgetExt as _, Point};
use udon::curve::Affine as _;

use crate::pasta::{EpAffine, Fp};

/// Allocates the oracle's bridge hash as a [`Point`], constrained equal to
/// the coordinates both write.
///
/// The point's allocation constrains the coordinates to the curve, which the
/// oracle alone leaves to the parent.
pub(crate) fn point<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    bridge_hash: &BridgeHash<'dr, D>,
) -> Result<Point<'dr, D, EpAffine>> {
    let [x, y] = [bridge_hash.x(), bridge_hash.y()].map(Element::value);
    let point = Point::alloc(
        dr,
        D::just(|| {
            #[expect(
                clippy::expect_used,
                reason = "Ragu allocates the coordinates of a non-identity commitment"
            )]
            EpAffine::from_xy(*x.take(), *y.take()).expect("the bridge hash is a curve point")
        }),
    )?;
    let mut oracle_coordinates = Vec::new();
    bridge_hash.write(dr, &mut oracle_coordinates)?;
    let mut point_coordinates = Vec::new();
    point.write(dr, &mut point_coordinates)?;
    for (oracle_coordinate, point_coordinate) in oracle_coordinates.iter().zip(&point_coordinates) {
        oracle_coordinate.enforce_equal(dr, point_coordinate)?;
    }
    Ok(point)
}
