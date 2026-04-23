use ff::PrimeField as _;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{Fp, arithmetic::CurveAffine as _};

use super::PoolCommit;
use crate::constants::EPOCH_SEED_DOMAIN;

/// A tachyon epoch — a point in the accumulator's history.
///
/// The tachyon accumulator evolves as tachygrams are included. Each
/// epoch identifies a specific pool accumulator state.
///
/// Used as **flavor** in nullifier derivation:
/// $mk = \text{KDF}(\psi, nk)$, then $nf = F_{mk}(\text{flavor})$.
/// Different epochs produce different nullifiers for the same note,
/// enabling range-restricted delegation via the GGM tree PRF.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EpochIndex(pub u32);

impl EpochIndex {
    /// Returns the next epoch index.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<u32> for EpochIndex {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<EpochIndex> for u32 {
    fn from(epoch: EpochIndex) -> Self {
        epoch.0
    }
}

/// Derive the epoch-boundary seed root from the previous epoch's final pool
/// commitment.
// At each epoch boundary, consensus inserts `epoch_seed_hash(pool_E_final)`
// as a root of E+1's pool multiset. `SpendableEpochLift` proves cross-epoch
// continuity by querying `right_pool.query(epoch_seed_hash(left_pool)) == 0`.
#[must_use]
pub fn epoch_seed_hash(last_epoch: &PoolCommit) -> Fp {
    let domain = Fp::from_u128(u128::from_le_bytes(*EPOCH_SEED_DOMAIN));

    let point = last_epoch.0.inner();
    let coords = point
        .coordinates()
        .expect("commitment should be a valid curve point");

    let (x, y) = (
        Fp::from_repr(coords.x().to_repr()).expect("interpret as Fp"),
        Fp::from_repr(coords.y().to_repr()).expect("interpret as Fp"),
    );

    Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([domain, x, y])
}
