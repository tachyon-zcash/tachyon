//! # Indexed multiset
//!
//! An indexed multiset may contain any number of unique or repeated members at
//! each index. Conceptually, it is a multiset of `(index, member)` tuples.
//!
//! ## Irreducible encoding
//!
//! For a member `m` at index `i`, the encoding is the factor
//! `F_{i,m}(X) = (m + (i + 1)X)^3 - c`, where `c = 2` is the smallest cubic
//! non-residue. Each factor is irreducible because `(m + (i + 1)X)^3 != c`.
//!
//! ## Product composition
//!
//! Construct a larger indexed multiset as the product of smaller ones:
//! `S(X) = product_{(i, m) in S} F_{i,m}(X)`.
//!
//! Combined indexed multisets will maintain input multiplicity. The inputs
//! may be contiguous, disjoint, or overlapping.
//!
//! ## Quotient decomposition
//!
//! Since a union is a product of irreducible factors, correct division confirms
//! membership. For multisets, `Q union R = S` exactly when `R = S minus Q`.
//! For their polynomials, `Q(X) * R(X) = S(X)` exactly when
//! `R(X) = S(X) / Q(X)`.
//!
//! Sequences `Q` and `R` combine to produce `S`, or subsequence `R` is
//! extracted from `S` by complement `Q`. Select a challenge and evaluate.
//!
//! ## Injectivity
//!
//! Single-member encodings collide when the ratio of their linear terms is a
//! cube root of unity. Precisely, the factors collide if
//! `(m_1 + (i_1 + 1)X) / (m_2 + (i_2 + 1)X) in {1, zeta, zeta^2}`.
//! Then `(i_1, m_1)` cannot be distinguished from `(i_2, m_2)` in an
//! indexed multiset.
//!
//! Specifying `i_max + 1` below `floor(sqrt(p / 3))` is sufficient to prevent
//! collisions.

extern crate alloc;

use alloc::vec;

use ragu::{Polynomial, ProductionRank};
use udon::field::Field as _;
use udon::polynomial::fold_weighted;

use crate::pasta::Fp;

pub(crate) const NON_RESIDUE: Fp = Fp::new(udon::fp_hex!(
    "0x0000000000000000000000000000000000000000000000000000000000000002"
));

/// Encode the provided indexed members.
///
/// # Panics
///
/// Panics if more than 2730 members are supplied, counting duplicates, because
/// each adds three degrees to the polynomial. The internal shifts and weighted
/// fold fit by construction.
#[expect(
    clippy::expect_used,
    reason = "the padding supplies all four shifts, each with a weight and room in the output"
)]
pub(crate) fn encode(
    members: impl IntoIterator<Item = (u64, Fp)>,
) -> Polynomial<Fp, ProductionRank> {
    Polynomial::from_coeffs(
        members
            .into_iter()
            .fold([Fp::ONE].to_vec(), |product, (idx, m)| {
                let i = Fp::from(idx) + Fp::ONE;
                let cubic = [
                    m.pow_u64(3) - NON_RESIDUE,
                    Fp::from(3) * i * m.square(),
                    Fp::from(3) * i.square() * m,
                    i.pow_u64(3),
                ];
                // Multiply by the cubic by weighting P, XP, X^2 P, and X^3 P.
                let mut padded = vec![Fp::ZERO; 3];
                padded.extend(product);
                let shifted = [3, 2, 1, 0].map(|offset| {
                    Fp::as_slice(padded.get(offset..).expect("padding covers the shift"))
                });
                let mut coeffs = vec![Fp::ZERO; padded.len()];
                fold_weighted(
                    &shifted,
                    Fp::as_slice(&cubic),
                    Fp::as_slice_mut(&mut coeffs),
                )
                .expect("the output fits every shift, with one weight per shift");
                coeffs
            }),
    )
}
