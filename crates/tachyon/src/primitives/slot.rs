extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use derive_more::Debug;
use ragu::header::{Has, Header, OnlinePoly};
use ragu::step::{HeaderInput, Prepared};
use ragu::udon::field::Field as _;
use ragu::{Polynomial, ProductionRank};

use crate::pasta::Fp;

/// Names a header's online polynomial of type `P`.
///
/// `W` says which one, in a header that carries two polynomials of one type.
#[derive(Debug)]
#[debug("PolySlot")]
pub struct PolySlot<P, W = ()>(PhantomData<fn() -> (P, W)>);

impl<P, W> PolySlot<P, W> {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }

    /// Sets the output's polynomial at this slot to `polynomial`, without its
    /// trailing zeros.
    #[must_use]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "the last nonzero coefficient's index is less than the vector length, so adding one fits usize"
    )]
    pub fn poly<O, I>(self, prepared: Prepared<Fp, O>, polynomial: &P) -> Prepared<Fp, O>
    where
        O: Header<Fp>,
        O::OnlinePolyCommit: Has<Self, I>,
        P: AsRef<Polynomial<Fp, ProductionRank>>,
    {
        let mut coefficients = polynomial.as_ref().iter_coeffs().collect::<Vec<_>>();
        coefficients.truncate(
            coefficients
                .iter()
                .rposition(|coefficient| coefficient != &Fp::ZERO)
                .map_or(0, |degree| degree + 1),
        );
        prepared.poly(self, coefficients)
    }

    /// Sets the output's polynomial at this slot to an input's polynomial of
    /// the same type.
    #[must_use]
    pub fn copy_from<O, I, H, V, J>(
        self,
        prepared: Prepared<Fp, O>,
        input: &HeaderInput<'_, Fp, H>,
        source: PolySlot<P, V>,
    ) -> Prepared<Fp, O>
    where
        O: Header<Fp>,
        O::OnlinePolyCommit: Has<Self, I>,
        H: Header<Fp>,
        H::OnlinePolyCommit: Has<PolySlot<P, V>, J>,
    {
        prepared.poly(self, input.polynomial(source))
    }
}

impl<P, W> Clone for PolySlot<P, W> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P, W> Copy for PolySlot<P, W> {}

impl<P: 'static, W: 'static> OnlinePoly for PolySlot<P, W> {}
