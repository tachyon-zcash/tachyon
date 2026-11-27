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

extern crate alloc;

use alloc::{vec, vec::Vec};

use ragu::{
    Polynomial, Rank as _, WalletRank,
    udon::{field::Field as _, polynomial::vanishing_polynomial},
};

use crate::pasta::Fp;

/// Encode a monic polynomial, reserving one coefficient for its leading one.
pub(crate) fn try_encode(
    members: impl IntoIterator<Item = Fp>,
) -> ragu::Result<Polynomial<Fp, WalletRank>> {
    let capacity = WalletRank::num_coeffs();
    let roots: Vec<Fp> = members.into_iter().take(capacity).collect();
    if roots.len() == capacity {
        return Err(ragu::Error::InvalidWitness(
            "set polynomial exceeds wallet-rank coefficient capacity".into(),
        ));
    }
    let mut coeffs = vec![Fp::ZERO; roots.len() + 1];
    vanishing_polynomial(Fp::as_slice(&roots), Fp::as_slice_mut(&mut coeffs))
        .map_err(|err| ragu::Error::InvalidWitness(err.into()))?;
    Ok(Polynomial::from_coeffs(coeffs))
}

#[cfg(test)]
mod tests {
    use core::iter;

    use super::*;

    #[test]
    fn monic_polynomial_needs_one_more_coefficient_than_roots() {
        let capacity = WalletRank::num_coeffs();
        let max_set = try_encode(iter::repeat_n(Fp::ZERO, capacity - 1)).unwrap();
        assert_eq!(max_set.iter_coeffs().next_back(), Some(Fp::ONE));
        assert!(matches!(
            try_encode(iter::repeat_n(Fp::ZERO, capacity)),
            Err(ragu::Error::InvalidWitness(_))
        ));
    }
}
