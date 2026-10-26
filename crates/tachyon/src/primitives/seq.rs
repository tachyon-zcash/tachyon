extern crate alloc;

use core::ops::Mul;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::{
    Cycle as _,
    pasta::{Fp, Pasta},
};
use ragu_pcd::pasta::baked;
use udon::{
    curve::{ProjectiveAdapter, Vesta},
    field::Field as _,
};

use crate::{
    collections::{indexed_multiset, poly_mul},
    nullifier::Nullifier,
    primitives::EpochIndex,
};

/// Pedersen commitment to a nullifier sequence.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfSeqCommit(ProjectiveAdapter<Vesta>);

/// Witness polynomial for a nullifier sequence: the product of its members'
/// encodings, one per member.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NfSeqPoly(Polynomial<Fp, ProductionRank>);

impl NfSeqPoly {
    /// Build the sequence polynomial for one contiguous run: the members of
    /// the consecutive epochs starting at `epoch_start`.
    #[must_use]
    pub fn new(epoch_start: EpochIndex, nfs: &[Nullifier]) -> Self {
        Self(indexed_multiset::encode(
            (epoch_start.into()..).zip(nfs.iter().copied().map(Fp::from)),
        ))
    }

    /// Deterministic (untrapdoored) commitment to the sequence polynomial.
    #[must_use]
    pub fn commit(&self) -> NfSeqCommit {
        NfSeqCommit(self.0.commit(Pasta::host_generators(baked())))
    }

    /// Evaluate the sequence polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl Default for NfSeqPoly {
    fn default() -> Self {
        Self(Polynomial::from_coeffs(alloc::vec![Fp::ONE]))
    }
}

impl Mul for NfSeqPoly {
    type Output = Self;

    /// Multiset union: the product of two sequences' member multisets.
    ///
    /// # Panics
    ///
    /// If the product exceeds the polynomial coefficient cap.
    fn mul(self, rhs: Self) -> Self {
        Self(poly_mul(&self.0, &rhs.0))
    }
}

#[cfg(test)]
mod tests {
    use ff::PrimeField as _;
    use group::{Curve as _, Group as _, GroupEncoding as _};
    use pasta_curves::{Fp as LegacyFp, vesta::Point as LegacyVesta};
    use ragu::{FixedGenerators as _, pasta::Pasta};
    use ragu_arithmetic::{Cycle as _, FixedGenerators as _};
    use ragu_pasta::Pasta as LegacyPasta;
    use udon::curve::{Affine as _, Projective as _};

    use super::*;
    use crate::nullifier::Nullifier;

    #[test]
    fn sequence_commitment_matches_the_legacy_generator_provider() {
        let legacy_generators = LegacyPasta::host_generators(LegacyPasta::baked());
        let current_generators = Pasta::host_generators(baked());
        let legacy_first = *legacy_generators
            .g()
            .first()
            .expect("host generators exist");
        let current_first = *current_generators
            .g()
            .first()
            .expect("host generators exist");
        assert_eq!(legacy_first.to_bytes(), current_first.to_bytes());

        let sequence = NfSeqPoly::new(
            EpochIndex::new(0),
            &[
                Nullifier::from(Fp::from(17)),
                Nullifier::from(Fp::from(23)),
                Nullifier::from(Fp::from(41)),
            ],
        );
        let legacy_commitment = sequence
            .as_ref()
            .iter_coeffs()
            .zip(legacy_generators.g())
            .fold(
                LegacyVesta::identity(),
                |commitment, (coefficient, generator)| {
                    let scalar = LegacyFp::from_repr(coefficient.to_bytes())
                        .into_option()
                        .expect("canonical coefficient bytes decode in the legacy scalar field");
                    commitment + (*generator * scalar)
                },
            );
        let current_commitment: ProjectiveAdapter<Vesta> = sequence.commit().into();

        assert_eq!(
            legacy_commitment.to_affine().to_bytes(),
            current_commitment.to_affine().to_bytes()
        );
    }
}
