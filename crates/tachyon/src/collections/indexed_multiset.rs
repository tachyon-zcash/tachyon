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
//! The rootless cubic $Y^3-c$ remains irreducible under the invertible
//! substitution $Y=m+(i+1)X$, since $i+1\ne0$.
//!
//! ## Product composition
//!
//! Construct a larger indexed multiset as the product of smaller ones.
//!
//! $$
//!   S(X) = \prod_{(i,m) \in S}{F_{i,m}(X)}
//! $$
//!
//! Multiplication adds multiplicities even when the inputs overlap.
//!
//! ## Quotient decomposition
//!
//! To show that $R$ is a sub-multiset of $S$, commit its complement $Q$ and
//! check $Q(X)R(X)=S(X)$ at the challenge.
//!
//! ## Injectivity
//!
//! When $i_\mathsf{max} + 1 < \lfloor\sqrt{p/3}\rfloor$, $S$ determines its
//! multiset of $(i, m)$ tuples, and any divisor of $S$ is a scalar multiple of
//! a sub-multiset's encoding. The bound exceeds $2^{126}$. Every step indexes
//! by an epoch, which is at most `EPOCH_MAX`.
//!
//! Unique factorization fixes each irreducible factor up to a scalar. Write
//! $L_k=m_k+a_kX$, with $a_k=i_k+1$. If $L_1^3-c=\lambda(L_2^3-c)$, then
//! differentiation gives $a_1L_1^2=\lambda a_2L_2^2$. Thus the linear terms
//! have the same root. At that root $-c=-\lambda c$, so $\lambda=1$ and
//! $L_1/L_2$ is a cube root of unity.
//!
//! A nontrivial ratio $\omega=a_1/a_2$ satisfies $\omega^2+\omega+1=0$,
//! so $a_1^2+a_1a_2+a_2^2\equiv0\pmod p$. But $1\le a_k<\sqrt{p/3}$ makes
//! that sum positive and below $p$. Hence $L_1=L_2$ and both tuples agree.

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
