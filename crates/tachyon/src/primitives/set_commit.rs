use core::ops::Add;

use ff::Field as _;
use pasta_curves::{
    Eq, EqAffine, Fq,
    arithmetic::{Coordinates, CurveAffine as _},
    group::{Curve as _, prime::PrimeCurveAffine as _},
};

/// Pedersen vector commitment to a polynomial's coefficient vector
/// on Vesta (scalar field = Fp, curve point = EqAffine).
///
/// Used for both per-block and cumulative pool commitments.
/// Additive: `commit(A) + commit(B) = commit(A + B)` (coefficient-wise).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetCommit(EqAffine);

impl SetCommit {
    /// Empty set (identity point — commitment to the zero polynomial).
    #[must_use]
    pub fn identity() -> Self {
        Self(EqAffine::identity())
    }

    /// X-coordinate for chain hash input (Fq).
    #[must_use]
    pub fn to_x(self) -> Fq {
        Option::from(self.0.coordinates())
            .map_or(Fq::ZERO, |coords: Coordinates<EqAffine>| *coords.x())
    }
}

impl From<EqAffine> for SetCommit {
    fn from(point: EqAffine) -> Self {
        Self(point)
    }
}

impl From<SetCommit> for EqAffine {
    fn from(sc: SetCommit) -> Self {
        sc.0
    }
}

/// Extracts x-coordinate for chain hash.
impl From<SetCommit> for Fq {
    fn from(sc: SetCommit) -> Self {
        sc.to_x()
    }
}

impl Add for SetCommit {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self((Eq::from(self.0) + Eq::from(rhs.0)).to_affine())
    }
}

/// Per-block polynomial commitment.
///
/// `block_commit = commit(∏(x - tg_i))` for the block's tachygrams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockCommit(pub SetCommit);

impl From<BlockCommit> for Fq {
    fn from(bc: BlockCommit) -> Self {
        bc.0.to_x()
    }
}

/// Cumulative epoch polynomial commitment.
///
/// `pool_commit = ∑ C_d` — sum of subset commitments. Resets at epoch
/// boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolCommit(pub SetCommit);

impl From<PoolCommit> for Fq {
    fn from(pc: PoolCommit) -> Self {
        pc.0.to_x()
    }
}
