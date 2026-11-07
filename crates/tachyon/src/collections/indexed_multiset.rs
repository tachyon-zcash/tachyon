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

use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use udon::field::Field as _;

use crate::{arithmetic, pasta::Fp};

const NON_RESIDUE: Fp = Fp::new(udon::fp_hex!(
    "0x0000000000000000000000000000000000000000000000000000000000000002"
));

#[must_use]
fn encode_single(idx: u64, m: Fp) -> [Fp; 4] {
    let i = Fp::from(idx) + Fp::ONE;
    // writing out expanded coefficients for $F(X) = (iX + m)^3 - c$ is
    // cheaper than constructing a linear $f(X) = iX + m$ and then cubing it.
    [
        m.pow_u64(3) - NON_RESIDUE,
        Fp::from(3) * i * m.square(),
        Fp::from(3) * i.square() * m,
        i.pow_u64(3),
    ]
}

/// Encode the provided indexed members.
pub(crate) fn encode(
    members: impl IntoIterator<Item = (u64, Fp)>,
) -> Polynomial<Fp, ProductionRank> {
    Polynomial::from_coeffs(
        members
            .into_iter()
            .fold([Fp::ONE].to_vec(), |product, (idx, m)| {
                arithmetic::poly_mul(&product, &encode_single(idx, m))
            }),
    )
}
