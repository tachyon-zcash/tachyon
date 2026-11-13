//! Halo2-style unsigned radix-8 fixed-base multiplication with a `+2` offset.
//!
//! Window $i$ holds little-endian bits of $k_i \in [0, 8)$. Interior windows
//! add $[(k_i + 2) 8^i]B$, and the top window adds
//! $[k_{W-1} 8^{W-1} - \sum_{i < W-1} 2 \cdot 8^i]B + C$, so the
//! multiplication computes $[\sum_i k_i 8^i]B + C$ for the binary value of the
//! bits. Ragu has no lookups, so halo2's Lagrange interpolation becomes a
//! two-gate selection precomputed per window (see [`Window`]).
//!
//! The running sum's coordinates are constrained directly. Each window's
//! digit is selected exactly from Boolean bits, so for every assignment, free
//! bits included, the interior prefix satisfies
//! $0 < A_j \le 9(8^j - 1)/7 < 2 \cdot 8^j \le D_j$ and
//! $A_j + D_j \le 9(8^{j+1} - 1)/7 < q$ for $j \le 83$: no interior addition
//! meets equal or inverse operands, so its slope gate alone fixes the slope.
//! No such bound covers the top addition or a join with a variable point, and
//! there the multiplication constrains the x difference nonzero. A
//! multiplication is therefore unsatisfiable when its result would be the
//! identity (e.g. $k \equiv 0$ on a zero correction) or when the prefix equals
//! the top entry, a doubling. A value multiplication joins onto the blind
//! point $P$ before its top entry, so $v = 0$ yields $P$ rather than an
//! identity intermediate.

use alloc::vec::Vec;
use core::array;

use lazy_static::lazy_static;
use ragu_core::{
    Error, Result,
    drivers::{Coeff, Driver, DriverValue},
    maybe::Maybe as _,
};
use ragu_primitives::{
    Boolean, Element, GadgetExt as _, Point, multiadd, multipack,
    vec::{ConstLen, FixedVec},
};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use super::uint::Uint;
use crate::{
    constants::{
        MAX_MONEY,
        orchard::{self, ACTION_AUTH_GENERATOR},
    },
    pasta::{Ep, EpAffine, Fp, Fq},
};

lazy_static! {
    pub(crate) static ref R_BASE: FixedBase<85> = FixedBase::new(*orchard::VALUE_COMMIT_R, Ep::identity());
    pub(crate) static ref G_BASE: FixedBase<85> = FixedBase::new(*ACTION_AUTH_GENERATOR, Ep::identity());
    pub(crate) static ref V_BASE: FixedBase<17> = FixedBase::new(*orchard::VALUE_COMMIT_V, Ep::identity());
    pub(crate) static ref NEG_V_BASE: FixedBase<17> =
        FixedBase::new(-*orchard::VALUE_COMMIT_V, Ep::identity());
    /// Multiplied by `MAX_MONEY - maximum`, computes $[-\mathsf{maximum}]\mathcal{V}$.
    pub(crate) static ref FEE_V_BASE: FixedBase<17> = FixedBase::new(
        *orchard::VALUE_COMMIT_V,
        -*orchard::VALUE_COMMIT_V * Fq::from(MAX_MONEY)
    );
}

/// Two-gate selection of one of eight fixed points by three little-endian
/// bits $b_0, b_1, b_2$.
///
/// $q = x_{012} y - y_{012} x$ has no $b_0 b_1 b_2$ term, where $x_S, y_S$ are
/// the coordinates' multilinear coefficients. The first gate realizes $q$'s
/// quadratic part as $p = (b_0 + \beta b_2)(q_{01} b_1 + q_{02} b_2)$; the
/// second is $c = b_2 (\lambda_0 b_0 + \lambda_1 b_1 + \rho p)$, which matches
/// $x$'s cubic and $b_0 b_2, b_1 b_2$ terms up to multiples of $q$. Both
/// coordinates are then affine in $(b_0, b_1, b_2, p, c)$. Construction checks
/// all eight entries, so selection is exact on every Boolean assignment.
struct Window {
    left: [Fp; 3],
    right: [Fp; 3],
    inner: [Fp; 3],
    x: [Fp; 6],
    y: [Fp; 6],
}

impl Window {
    /// Multilinear coefficients of a function on $\{0, 1\}^3$, indexed by the
    /// bit mask of each monomial.
    #[expect(
        clippy::indexing_slicing,
        reason = "the Möbius transform indexes a fixed eight-entry array"
    )]
    fn monomials(mut values: [Fp; 8]) -> [Fp; 8] {
        for dimension in 0..3 {
            for index in 0..8 {
                if index & (1 << dimension) != 0 {
                    values[index] -= values[index ^ (1 << dimension)];
                }
            }
        }
        values
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "fixed eight-entry cube and six-term basis"
    )]
    #[expect(
        clippy::expect_used,
        reason = "fixed tables must admit two-gate selection"
    )]
    fn new(entries: &[(Fp, Fp); 8]) -> Self {
        let x = Self::monomials(entries.map(|entry| entry.0));
        let y = Self::monomials(entries.map(|entry| entry.1));
        let [q01, q02, q12] = [3, 5, 6].map(|mask| x[7] * y[mask] - y[7] * x[mask]);
        let inverse = q01
            .invert()
            .expect("q must have a b0 b1 term in a fixed window");
        let shift = x[3] * inverse;
        let rho = x[7] * inverse;
        let left = [Fp::ONE, Fp::ZERO, q12 * inverse];
        let right = [Fp::ZERO, q01, q02];
        let inner = [x[5] - (shift + rho) * q02, x[6] - (shift + rho) * q12, rho];

        let bit = |index: usize, position: usize| Fp::from(u64::from(index & (1 << position) != 0));
        let linear = |coefficients: &[Fp; 3], terms: [Fp; 3]| {
            coefficients
                .iter()
                .zip(terms)
                .fold(Fp::ZERO, |sum, (coefficient, term)| {
                    sum + *coefficient * term
                })
        };
        let basis: [[Fp; 6]; 8] = array::from_fn(|index| {
            let bits = [bit(index, 0), bit(index, 1), bit(index, 2)];
            let quadratic = linear(&left, bits) * linear(&right, bits);
            let cubic = bits[2] * linear(&inner, [bits[0], bits[1], quadratic]);
            [Fp::ONE, bits[0], bits[1], bits[2], quadratic, cubic]
        });
        let quadratic = Self::monomials(basis.map(|row| row[4]));
        let cubic = Self::monomials(basis.map(|row| row[5]));
        let cubic_inverse = cubic[7]
            .invert()
            .expect("x must have a b0 b1 b2 term in a fixed window");
        let quadratic_inverse = quadratic[3]
            .invert()
            .expect("p must have a b0 b1 term in a fixed window");
        let solve = |coordinate: [Fp; 8]| {
            let gamma = coordinate[7] * cubic_inverse;
            let alpha = (coordinate[3] - gamma * cubic[3]) * quadratic_inverse;
            let rest =
                |mask: usize| coordinate[mask] - alpha * quadratic[mask] - gamma * cubic[mask];
            [rest(0), rest(1), rest(2), rest(4), alpha, gamma]
        };
        let window = Self {
            left,
            right,
            inner,
            x: solve(x),
            y: solve(y),
        };
        for (row, entry) in basis.iter().zip(*entries) {
            let evaluate = |coefficients: &[Fp; 6]| {
                coefficients
                    .iter()
                    .zip(row)
                    .fold(Fp::ZERO, |sum, (coefficient, term)| {
                        sum + *coefficient * *term
                    })
            };
            assert_eq!(
                (evaluate(&window.x), evaluate(&window.y)),
                entry,
                "two-gate selection must reproduce every fixed entry"
            );
        }
        window
    }

    /// Selects the entry's coordinates in two gates.
    fn select<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        bits: [&Boolean<'dr, D>; 3],
    ) -> Result<[Element<'dr, D>; 2]> {
        let [low, middle, high] = bits.map(Boolean::element);
        let left = multiadd(dr, &[low.clone(), middle.clone(), high.clone()], &self.left);
        let right = multiadd(
            dr,
            &[low.clone(), middle.clone(), high.clone()],
            &self.right,
        );
        let quadratic = left.mul(dr, &right)?;
        let inner = multiadd(
            dr,
            &[low.clone(), middle.clone(), quadratic.clone()],
            &self.inner,
        );
        let cubic = high.mul(dr, &inner)?;
        let basis = [Element::one(), low, middle, high, quadratic, cubic];
        Ok([multiadd(dr, &basis, &self.x), multiadd(dr, &basis, &self.y)])
    }
}

/// A radix-8 table of $W$ windows for the base $B$ with correction $C$.
pub(crate) struct FixedBase<const W: usize> {
    // Native constant storage only. Circuit iteration is bounded by const W.
    interior: Vec<Window>,
    top: Window,
}

impl<const W: usize> FixedBase<W> {
    #[expect(
        clippy::expect_used,
        reason = "fixed tables must contain only finite points"
    )]
    pub(crate) fn new(base: Ep, correction: Ep) -> Self {
        assert!(!base.is_identity(), "fixed bases must be nonidentity");
        let mut power = Fq::ONE;
        let mut offset = Fq::ZERO;
        let mut interior = Vec::with_capacity(W - 1);
        for _ in 1..W {
            interior.push(Window::new(&[2u64, 3, 4, 5, 6, 7, 8, 9].map(|digit| {
                (base * (Fq::from(digit) * power))
                    .to_affine()
                    .coordinates()
                    .expect("every fixed interior entry must be finite")
            })));
            offset += Fq::from(2) * power;
            power *= Fq::from(8);
        }
        let top = Window::new(&[0u64, 1, 2, 3, 4, 5, 6, 7].map(|digit| {
            (base * (Fq::from(digit) * power - offset) + correction)
                .to_affine()
                .coordinates()
                .expect("every fixed top entry must be finite")
        }));
        Self { interior, top }
    }

    /// Returns the interior prefix $A_{W-1}$ and the selected top entry.
    #[expect(
        clippy::indexing_slicing,
        reason = "const assertions fix the bit count; new() constructs exactly W - 1 interior windows"
    )]
    fn prefix_and_top<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
    ) -> Result<[[Element<'dr, D>; 2]; 2]> {
        const {
            assert!(W > 1 && W <= 85, "the offset bound covers W=2..85");
            assert!(N == 3 * W, "the bit width must match the fixed-base table");
        }
        let window = |index: usize| [&bits[3 * index], &bits[3 * index + 1], &bits[3 * index + 2]];
        let mut prefix = self.interior[0].select(dr, window(0))?;
        for (index, interior) in self.interior.iter().enumerate().skip(1) {
            let [x, y] = interior.select(dr, window(index))?;
            // The offset bound leaves the entry's x distinct from the
            // prefix's on every Boolean assignment, so the slope gate alone
            // fixes the slope.
            let [prefix_x, prefix_y] = prefix.each_ref();
            let rise = y.sub(dr, prefix_y);
            let run = x.sub(dr, prefix_x);
            let slope_value = D::try_just(|| {
                Ok(*rise.value().take()
                    * run.value().take().invert().ok_or_else(|| {
                        Error::InvalidWitness("interior window entry shares the prefix's x".into())
                    })?)
            })?;
            let (slope, run_wire, rise_wire) = dr.mul(|| {
                Ok((
                    Coeff::Arbitrary(*slope_value.snag()),
                    Coeff::Arbitrary(*run.value().take()),
                    Coeff::Arbitrary(*rise.value().take()),
                ))
            })?;
            dr.enforce_equal(&run_wire, run.wire())?;
            dr.enforce_equal(&rise_wire, rise.wire())?;
            prefix = add_with_slope(
                dr,
                prefix.each_ref(),
                &Element::promote(slope, slope_value),
                &x,
            )?;
        }
        let top = self.top.select(dr, window(W - 1))?;
        Ok([prefix, top])
    }

    /// $\[k\]B + C + P$ for the binary value $k$ of `bits`, joining `onto`
    /// ($P$, when present) between the prefix and the top entry. The result
    /// is allocated as a [`Point`] constrained equal to the computed
    /// coordinates.
    fn multiply<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
        onto: Option<&Point<'dr, D, EpAffine>>,
    ) -> Result<Point<'dr, D, EpAffine>> {
        let [mut sum, top] = self.prefix_and_top(dr, bits)?;
        if let Some(point) = onto {
            let mut coordinates = Vec::new();
            point.write(dr, &mut coordinates)?;
            let Ok([x, y]) = <[Element<'dr, D>; 2]>::try_from(coordinates) else {
                return Err(Error::InvalidWitness(
                    "a point writes two coordinates".into(),
                ));
            };
            sum = add_checked(dr, sum.each_ref(), [&x, &y])?;
        }
        let result = add_checked(dr, sum.each_ref(), top.each_ref())?;
        let [x, y] = result.each_ref().map(Element::value);
        let point = Point::alloc(
            dr,
            D::try_just(|| {
                EpAffine::from_xy(*x.take(), *y.take()).ok_or_else(|| {
                    Error::InvalidWitness("fixed-base result is not on the curve".into())
                })
            })?,
        )?;
        let mut written = Vec::new();
        point.write(dr, &mut written)?;
        let Ok([written_x, written_y]) = <[Element<'dr, D>; 2]>::try_from(written) else {
            return Err(Error::InvalidWitness(
                "a point writes two coordinates".into(),
            ));
        };
        let [computed_x, computed_y] = result.each_ref();
        written_x.enforce_equal(dr, computed_x)?;
        written_y.enforce_equal(dr, computed_y)?;
        Ok(point)
    }
}

/// Adds `point` to `sum` in four gates, constraining their x coordinates
/// distinct.
fn add_checked<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    sum: [&Element<'dr, D>; 2],
    [x, y]: [&Element<'dr, D>; 2],
) -> Result<[Element<'dr, D>; 2]> {
    let [sum_x, sum_y] = sum;
    let run = x.sub(dr, sum_x).enforce_nonzero(dr)?;
    let slope = y.sub(dr, sum_y).divide(dr, &run)?;
    add_with_slope(dr, sum, &slope, x)
}

/// Completes an addition onto `sum` from the slope and the other operand's x
/// coordinate, in two gates.
fn add_with_slope<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    [sum_x, sum_y]: [&Element<'dr, D>; 2],
    slope: &Element<'dr, D>,
    x: &Element<'dr, D>,
) -> Result<[Element<'dr, D>; 2]> {
    let result_x = slope.square(dr)?.sub(dr, sum_x).sub(dr, x);
    let difference = sum_x.sub(dr, &result_x);
    let result_y = slope.mul(dr, &difference)?.sub(dr, sum_y);
    Ok([result_x, result_y])
}

impl FixedBase<85> {
    /// $\[h\]B + P$ for the canonical value of a digest $h$. The 255 bits are
    /// compared against $p - 1$, so $h$ and $h + p$ cannot both decode.
    #[expect(
        clippy::indexing_slicing,
        reason = "multipack splits 255 bits into a 254-bit and a 1-bit chunk"
    )]
    pub(crate) fn mul_digest<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        digest: &Element<'dr, D>,
        onto: Option<&Point<'dr, D, EpAffine>>,
    ) -> Result<Point<'dr, D, EpAffine>> {
        let bits = FixedVec::<_, ConstLen<255>>::try_from_fn(|index| {
            Boolean::alloc(
                dr,
                &mut (),
                digest
                    .value()
                    .map(|candidate| candidate.to_le_bits().as_ref()[index]),
            )
        })?;
        let packed = multipack(dr, &bits)?;
        let high = packed[1].scale(dr, Coeff::Arbitrary(Fp::from(2).pow_u64(254)));
        packed[0].add(dr, &high).enforce_equal(dr, digest)?;
        Self::enforce_canonical(dr, &bits)?;
        self.multiply(dr, &bits, onto)
    }

    /// $\[k\]B$ for some $k$ whose 255 free bits nothing recomposes: $r$ or
    /// $r + q$, for a blind nothing else binds.
    #[expect(clippy::indexing_slicing, reason = "native fixed field representation")]
    pub(crate) fn mul_blinding<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        scalar: &DriverValue<D, Fq>,
    ) -> Result<Point<'dr, D, EpAffine>> {
        let bits = FixedVec::<_, ConstLen<255>>::try_from_fn(|index| {
            Boolean::alloc(
                dr,
                &mut (),
                scalar
                    .as_ref()
                    .map(|candidate| candidate.to_le_bits().as_ref()[index]),
            )
        })?;
        self.multiply(dr, &bits, None)
    }

    /// Compares the canonical field bits with $p - 1$, sharing a product across
    /// each maximal zero run. Its sum has at most 254 Boolean terms and cannot
    /// wrap.
    #[expect(clippy::indexing_slicing, reason = "fixed 255-bit canonical encoding")]
    fn enforce_canonical<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        bits: &FixedVec<Boolean<'dr, D>, ConstLen<255>>,
    ) -> Result<()> {
        let maximum = (-Fp::ONE).to_le_bits();
        let mut equal = bits[254].element();
        let mut run = Element::zero(dr);
        let mut pending = false;
        for index in (0..254).rev() {
            if maximum.as_ref()[index] {
                if pending {
                    equal.mul(dr, &run)?.enforce_zero(dr)?;
                    run = Element::zero(dr);
                    pending = false;
                }
                equal = equal.mul(dr, &bits[index].element())?;
            } else {
                run = run.add(dr, &bits[index].element());
                pending = true;
            }
        }
        if pending {
            equal.mul(dr, &run)?.enforce_zero(dr)?;
        }
        Ok(())
    }
}

impl FixedBase<17> {
    /// $\[v\]B + C + P$ for the 51 bits of $v$. As in Orchard's short path, $v$
    /// is a magnitude and a sign; Tachyon's sign is constant per step and
    /// lives in the base.
    pub(crate) fn mul_amount<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        value: &Uint<'dr, D, 51>,
        onto: &Point<'dr, D, EpAffine>,
    ) -> Result<Point<'dr, D, EpAffine>> {
        self.multiply(dr, value.bits(), Some(onto))
    }
}

#[cfg(test)]
mod tests;
