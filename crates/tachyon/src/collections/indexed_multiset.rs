//! # Indexed multiset
//!
//! An indexed multiset may contain any number of unique or repeated members at
//! each index. Conceptually, it is a multiset of `(index, member)` tuples.
//!
//! ## Irreducible encoding
//!
//! Construct a single-member indexed multiset of member $m$ at index $i$ as the
//! polynomial
//!
//! $$
//!   F_{i,m}(X) = (m + (i+1)X)^3 - c
//! $$
//!
//! where $c = 2$ is selected because it is the smallest cubic non-residue.
//!
//! Since $(m + (i+1)X)^3 \neq c$ the encoding is irreducible.
//!
//! ## Product composition
//!
//! Construct a larger indexed multiset as the product of smaller ones.
//!
//! $$
//!   S(X) = \prod_{(i,m) \in S}{F_{i,m}(X)}
//! $$
//!
//! Combined indexed multisets will maintain input multiplicity. The inputs
//! may be contiguous, disjoint, or overlapping.
//!
//! ## Quotient decomposition
//!
//! Since a union is a product of irreducible factors, we may demonstrate
//! correct division to confirm membership.
//!
//! $$
//!   \begin{aligned}
//!
//!   Q \uplus R &= S
//!       &\quad \iff &\quad
//!   &R &= S \setminus Q
//!
//!   \\ \\
//!
//!   Q(X) \cdot R(X) &= S(X)
//!       &\quad \iff &\quad
//!   &R(X) &= \frac{S(X)}{Q(X)}
//!
//!   \end{aligned}
//! $$
//!
//! Sequences $Q$ and $R$ combine to produce $S$, or, subsequence $R$ is
//! extracted from $S$ by complement $Q$. Select a challenge and evaluate.
//!
//! ## Injectivity
//!
//! Single-member encodings collide when the ratio of their linear terms is a
//! cube root of unity.
//!
//! Precisely, if
//!
//! $$
//!   \frac{m_1 + (i_1+1)X}{m_2 + (i_2+1)X} \in \{1, \zeta, \zeta^2\}
//! $$
//!
//! then $(i_1, m_1)$ cannot be distinguished from $(i_2, m_2)$ in an
//! indexed multiset.
//!
//! Specifying $i_\mathsf{max} + 1$ below $\lfloor\sqrt{p/3}\rfloor$ is
//! sufficient to prevent collisions.

#![allow(clippy::min_ident_chars, reason = "just for fun")]

extern crate alloc;

use ff::Field as _;
use pasta_curves::Fp;
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_pasta::fp;

use super::poly_mul;

const NON_RESIDUE: Fp = fp!(0x02);

#[must_use]
fn encode_single(idx: u64, m: Fp) -> Polynomial<Fp, ProductionRank> {
    let i = Fp::from(idx) + Fp::ONE;
    // writing out expanded coefficients for $F(X) = (iX + m)^3 - c$ is
    // cheaper than constructing a linear $f(X) = iX + m$ and then cubing it.
    Polynomial::from_coeffs(
        [
            m.pow([3]) - NON_RESIDUE,
            fp!(3) * i * m.square(),
            fp!(3) * i.square() * m,
            i.pow([3]),
        ]
        .to_vec(),
    )
}

#[must_use]
fn direct_eval_single(idx: u64, m: Fp, x: Fp) -> Fp {
    let i = Fp::from(idx) + Fp::ONE;
    ((i * x) + m).pow([3]) - NON_RESIDUE
}

/// Encode the provided indexed members.
pub(crate) fn encode(
    members: impl IntoIterator<Item = (u64, Fp)>,
) -> Polynomial<Fp, ProductionRank> {
    members.into_iter().fold(
        Polynomial::from_coeffs([Fp::ONE].to_vec()),
        |acc, (idx, m)| poly_mul(&acc, &encode_single(idx, m)),
    )
}

/// Evaluate the indexed multiset without building the polynomial.
pub(crate) fn direct_eval(members: impl IntoIterator<Item = (u64, Fp)>, x: Fp) -> Fp {
    members
        .into_iter()
        .fold(Fp::ONE, |acc, (idx, m)| acc * direct_eval_single(idx, m, x))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use proptest::{collection::vec, prelude::*, sample::Index};
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::testing::check;

    /// Members at the given indices, drawn from `seed`.
    fn members_at(seed: u64, indices: &[u64]) -> Vec<(u64, Fp)> {
        let rng = &mut StdRng::seed_from_u64(seed);
        indices
            .iter()
            .map(|&idx| (idx, Fp::random(&mut *rng)))
            .collect()
    }

    /// The expanded coefficients are $(m + (i+1)X)^3 - c$, built by cubing
    /// the linear factor.
    #[test]
    fn member_encoding_is_the_cubed_linear_factor() {
        check(
            256,
            (any::<u64>(), 0..u64::from(u32::MAX)),
            |(seed, idx)| {
                let rng = &mut StdRng::seed_from_u64(seed);
                let member = Fp::random(&mut *rng);
                let x = Fp::random(&mut *rng);

                let linear = Polynomial::from_coeffs([member, Fp::from(idx) + Fp::ONE].to_vec());
                let mut coeffs = poly_mul(&poly_mul(&linear, &linear), &linear)
                    .iter_coeffs()
                    .collect::<Vec<_>>();
                coeffs[0] -= NON_RESIDUE;
                let cubed = Polynomial::<Fp, ProductionRank>::from_coeffs(coeffs);

                prop_assert_eq!(encode_single(idx, member).eval(x), cubed.eval(x));
                prop_assert_eq!(
                    encode_single(idx, member).eval(x),
                    direct_eval([(idx, member)], x)
                );
                Ok(())
            },
        );
    }

    /// Evaluating without building the polynomial agrees with the encoding,
    /// for any members at any indices, repeats included.
    #[test]
    fn direct_evaluation_matches_the_encoding() {
        let strategy = (any::<u64>(), vec(0..u64::from(u32::MAX), 0..=8));
        check(256, strategy, |(seed, indices)| {
            let members = members_at(seed, &indices);
            let x = Fp::random(&mut StdRng::seed_from_u64(!seed));
            prop_assert_eq!(
                direct_eval(members.iter().copied(), x),
                encode(members).eval(x)
            );
            Ok(())
        });
    }

    /// A larger multiset is the product of any split of its members, in any
    /// order.
    #[test]
    fn encoding_composes_by_product() {
        let strategy = (
            any::<u64>(),
            vec(0..u64::from(u32::MAX), 0..=8),
            any::<Index>(),
        );
        check(256, strategy, |(seed, indices, split)| {
            let mut members = members_at(seed, &indices);
            let x = Fp::random(&mut StdRng::seed_from_u64(!seed));
            let whole = encode(members.iter().copied()).eval(x);

            let right = members.split_off(split.index(members.len() + 1));
            prop_assert_eq!(
                whole,
                encode(right.iter().copied()).eval(x) * encode(members.iter().copied()).eval(x)
            );
            prop_assert_eq!(whole, encode(right.into_iter().chain(members)).eval(x));
            Ok(())
        });
    }
}
