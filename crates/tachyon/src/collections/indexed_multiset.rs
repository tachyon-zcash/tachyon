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
//! Since $(m + (i+1)X)^3 \neq c$ the encoding is irreducible. In full, $Y^3 -
//! c$ is a cubic without a root, and $F_{i,m}$ is its image under the
//! substitution $Y = m + (i+1)X$, which is invertible because $i + 1 \neq 0$.
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
//! $\mathbb{F}_p\[X\]$ factors uniquely, so $S$ determines its irreducible
//! factors up to scalars. Two encodings that differ by a scalar are equal. If
//! $F_{i_1,m_1} = \lambda F_{i_2,m_2}$ then
//!
//! $$
//!   (m_1 + (i_1+1)X)^3 - \lambda \cdot (m_2 + (i_2+1)X)^3 = c \cdot (1 -
//! \lambda) $$
//!
//! is constant. Its derivative vanishes, which makes the two linear terms
//! proportional, and a multiple of a cube is constant only when it is zero.
//! Hence $\lambda = 1$ and the two cubes are equal.
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
//! sufficient to prevent collisions. A ratio $\omega \neq 1$ satisfies
//! $\omega^2 + \omega + 1 = 0$, which for $a_k = i_k + 1$ and $a_1 = \omega
//! a_2$ gives $a_1^2 + a_1 a_2 + a_2^2 \equiv 0 \pmod p$. For integers $1 \leq
//! a_k < \sqrt{p/3}$ the left side is positive and below $p$.
//!
//! Within the bound, $S$ therefore determines the multiset of its $(i, m)$
//! tuples, and a polynomial dividing $S$ is a scalar times the encoding of a
//! sub-multiset. The bound is above $2^{126}$. Every step indexes by an epoch,
//! which is at most `EPOCH_MAX`.

#![allow(clippy::min_ident_chars, reason = "just for fun")]

extern crate alloc;

use alloc::vec;

use ragu::{
    Polynomial, WalletRank,
    udon::{field::Field as _, polynomial::fold_weighted},
};

use crate::pasta::Fp;

pub(crate) const NON_RESIDUE: Fp = Fp::new(ragu::udon::fp_hex!(
    "0x0000000000000000000000000000000000000000000000000000000000000002"
));

/// Encode the provided indexed members.
#[expect(
    clippy::expect_used,
    reason = "the padding supplies all four shifts, each with a weight and room in the output"
)]
pub(crate) fn encode(members: impl IntoIterator<Item = (u64, Fp)>) -> Polynomial<Fp, WalletRank> {
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
