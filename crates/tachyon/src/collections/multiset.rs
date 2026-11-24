//! # Multiset
//!
//! A *set polynomial* encodes a multiset of field elements as the monic
//! polynomial with those members as roots.
//!
//! $$
//!   S(X) = \prod_{m \in S}{(X - m)}
//! $$
//!
//! The constant one encodes the empty multiset.
//!
//! ## Injectivity
//!
//! A set polynomial determines its members and their multiplicities because
//! $\mathbb{F}_p\[X\]$ factors uniquely and each $X - m$ is monic and
//! irreducible. Multiplying two set polynomials gives the set polynomial of the
//! multiset sum. Any divisor of a set polynomial is a scalar multiple of a
//! sub-multiset's set polynomial, and $S(x) = 0$ holds iff $x$ is a member.
//!
//! A slot alone need not hold a product of monic linear factors. Steps can
//! establish that product by checking factors fixed before the challenge;
//! [`AnchorSpanSeed`](crate::stamp::proof::pool::AnchorSpanSeed) gives the
//! separate argument for its unfixed root. A verifier can also recompute the
//! accumulator from published members.

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
