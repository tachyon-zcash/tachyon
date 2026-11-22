//! # Multiset
//!
//! A multiset of field elements is encoded as the monic polynomial whose roots
//! are its members, its *set polynomial*.
//!
//! $$
//!   S(X) = \prod_{m \in S}{(X - m)}
//! $$
//!
//! The empty multiset is the constant one.
//!
//! ## Injectivity
//!
//! $\mathbb{F}_p\[X\]$ factors uniquely and each $X - m$ is monic and
//! irreducible, so a set polynomial determines its members with their
//! multiplicities. The product of two set polynomials is that of the multiset
//! sum, a polynomial that divides one is a scalar times that of a
//! sub-multiset, and $S(x) = 0$ exactly when $x$ is a member.
//!
//! No constraint makes a slot's polynomial a product of linear factors. What
//! a step shows about a slot is about that polynomial's roots and factors,
//! and is about a multiset only once the polynomial is known to be a set
//! polynomial. An identity at the challenge against factors computed from
//! values fixed before the challenge shows that, as does an accumulator that
//! a verifier recomputes from published members.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ragu::{
    Polynomial, WalletRank,
    udon::{field::Field as _, polynomial::vanishing_polynomial},
};

use crate::pasta::Fp;

/// Encode the provided members as roots.
#[expect(
    clippy::expect_used,
    reason = "the buffer fits the roots and leading one"
)]
pub(crate) fn encode(members: impl IntoIterator<Item = Fp>) -> Polynomial<Fp, WalletRank> {
    let roots: Vec<Fp> = members.into_iter().collect();
    let mut coeffs = vec![Fp::ZERO; roots.len() + 1];
    vanishing_polynomial(Fp::as_slice(&roots), Fp::as_slice_mut(&mut coeffs))
        .expect("the buffer fits the roots and leading one");
    Polynomial::from_coeffs(coeffs)
}
