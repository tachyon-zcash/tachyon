extern crate alloc;

use alloc::{vec, vec::Vec};
use core::ops::Mul;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ragu::{Cycle as _, Polynomial, ProductionRank, pasta::Pasta};
use udon::{
    exec::{ExecutionOptions, SerialExecutor},
    fft::{Domain, Expansion, Transform},
    field::Field as _,
};

use crate::{
    collections::indexed_multiset,
    nullifier::Nullifier,
    pasta,
    pasta::{Eq, Fp},
    primitives::EpochIndex,
};

/// Pedersen commitment to a nullifier sequence.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfSeqCommit(Eq);

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
        NfSeqCommit(self.0.commit(Pasta::host_generators(pasta::baked())))
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
    #[expect(
        clippy::expect_used,
        reason = "the FFT domain fits the product and expands onto itself"
    )]
    fn mul(self, rhs: Self) -> Self {
        let [left, right] = [self.0, rhs.0].map(|poly| {
            let mut coeffs: Vec<Fp> = poly.iter_coeffs().collect();
            coeffs.truncate(
                coeffs
                    .iter()
                    .rposition(|coeff| coeff != &Fp::ZERO)
                    .map_or(0, |idx| idx + 1),
            );
            coeffs
        });
        if left.is_empty() || right.is_empty() {
            return Self(Polynomial::new());
        }

        let result_len = left.len() + right.len() - 1;
        let size = result_len.next_power_of_two();
        let transform = Transform::new(
            Domain::for_size(size)
                .expect("the product fits the FFT domain")
                .subgroup(),
        );
        let expansion = Expansion::new(transform, transform.domain(), None)
            .expect("a subgroup expands onto itself");
        let options = ExecutionOptions::default();
        let mut coeffs = vec![Fp::ZERO; 2 * size];
        let (product, factor) = Fp::as_slice_mut(&mut coeffs).split_at_mut(size);
        expansion
            .coefficients(
                Fp::as_slice(&right),
                factor,
                options,
                &SerialExecutor,
                &mut [],
            )
            .expect("the factor fits the FFT domain");
        expansion
            .short_product(
                Fp::as_slice(&left),
                expansion.view(factor),
                product,
                options,
                &SerialExecutor,
                &mut [],
            )
            .expect("the product fits the FFT domain");
        transform
            .inverse(product, options, &SerialExecutor, &mut [])
            .expect("the serial inverse needs no scratch");
        coeffs.truncate(result_len);
        Self(Polynomial::from_coeffs(coeffs))
    }
}
