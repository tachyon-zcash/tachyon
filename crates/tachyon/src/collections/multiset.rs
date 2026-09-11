//! # Multiset
//!
//! A multiset of members encoded as the roots of a monic polynomial, with
//! multiplicity:
//!
//! $$
//!   S(X) = \prod_{m \in S}{(X - m)^{\mathsf{count}(m)}}
//! $$
//!
//! ## Set form
//!
//! Unique factorization means the member multiset *is* the polynomial, so
//! [`Multiset`] keeps the members as its canonical representation -- a
//! [`BTreeMap`] count-map -- and defers realization into coefficient form
//! until [committed](Multiset::commit). Operating on the set form is much
//! cheaper: a product is a count merge rather than a coefficient
//! convolution, the quotient witness is count subtraction rather than
//! polynomial division, and evaluation streams over members without
//! materializing coefficients.
//!
//! The stamp sets built on this type are non-repeating in practice (a stamp's
//! tachygrams are unique on the wire), but the representation stays a general
//! multiset: a repeated member contributes a repeated factor, which is what
//! lets a commitment to $(X-m)^2$ stay distinguishable from one to $(X-m)$.

extern crate alloc;

use alloc::{
    collections::{BTreeMap, btree_map::Entry},
    vec::Vec,
};
use core::{cell::OnceCell, cmp::Eq as TotalEq, num::NonZero};

use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu_arithmetic::{Cycle as _, poly_with_roots};
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_pasta::Pasta;

/// Encode the provided members as roots, eagerly realized; kept as a
/// test-only reference implementation: production composition happens in set
/// form ([`Multiset`]).
#[cfg(test)]
pub(crate) fn encode(members: impl IntoIterator<Item = Fp>) -> Polynomial<Fp, ProductionRank> {
    let roots: Vec<Fp> = members.into_iter().collect();
    Polynomial::from_coeffs(poly_with_roots(&roots))
}

/// A multiset of members held as polynomial roots, kept in set form.
///
/// The encoded [`Polynomial`] is realized lazily -- at first
/// [`realize`](Self::realize) or [`commit`](Self::commit) -- and memoized
/// until the next mutation. Equality considers the members only, never the
/// memoized realization.
///
/// # Construction
///
/// There is no `new`: collect members from any iterator, or
/// [`insert`](Self::insert)/[`Extend`] into an existing multiset.
#[derive(Clone, Debug, Default)]
pub(crate) struct Multiset {
    /// Member multiplicities, keyed by the member.
    members: BTreeMap<Fp, NonZero<u32>>,
    /// Memoized realization of the encoded polynomial.
    realized: OnceCell<Polynomial<Fp, ProductionRank>>,
    /// Memoized commitment to the realized polynomial.
    commitment: OnceCell<Eq>,
}

impl Multiset {
    /// Insert one member, incrementing its multiplicity.
    ///
    /// # Panics
    ///
    /// If one member's multiplicity exceeds `u32::MAX`, far beyond the
    /// realizable coefficient capacity.
    pub(crate) fn insert(&mut self, member: Fp) {
        self.reset_memo();
        match self.members.entry(member) {
            Entry::Occupied(mut occupied) => {
                #[expect(
                    clippy::expect_used,
                    reason = "a multiplicity beyond u32::MAX cannot be realized anyway"
                )]
                let bumped = occupied
                    .get()
                    .checked_add(1)
                    .expect("multiplicity overflow");
                *occupied.get_mut() = bumped;
            },
            Entry::Vacant(vacant) => {
                vacant.insert(NonZero::<u32>::MIN);
            },
        }
    }

    /// Multiset sum: adds `other`'s multiplicities to this one's, matching
    /// the product of their encoded polynomials.
    ///
    /// # Panics
    ///
    /// If one member's multiplicity exceeds `u32::MAX`, far beyond the
    /// realizable coefficient capacity.
    pub(crate) fn add_factors(&mut self, other: &Self) {
        self.reset_memo();
        for (&key, &count) in &other.members {
            match self.members.entry(key) {
                Entry::Occupied(mut occupied) => {
                    #[expect(
                        clippy::expect_used,
                        reason = "a multiplicity beyond u32::MAX cannot be realized anyway"
                    )]
                    let merged = occupied
                        .get()
                        .checked_add(count.get())
                        .expect("multiplicity overflow");
                    *occupied.get_mut() = merged;
                },
                Entry::Vacant(vacant) => {
                    vacant.insert(count);
                },
            }
        }
    }

    /// Multiset difference: subtracts `other`'s multiplicities from this
    /// one's, the quotient of the encoded polynomials computed by count
    /// subtraction instead of polynomial division.
    ///
    /// Saturating, so a member `other` holds more often than `self` does
    /// leaves at zero. `other` divides `self` exactly when no such member
    /// exists.
    pub(crate) fn rm_factors(&mut self, other: &Self) {
        self.reset_memo();
        for (&key, &removed) in &other.members {
            let Entry::Occupied(mut occupied) = self.members.entry(key) else {
                continue;
            };
            match NonZero::new(occupied.get().get().saturating_sub(removed.get())) {
                Some(count) => *occupied.get_mut() = count,
                None => {
                    occupied.remove();
                },
            }
        }
    }

    /// Evaluate the encoded polynomial at `x` by streaming over the members,
    /// without realizing the coefficients. A repeated member contributes its
    /// factor by square-and-multiply; the (near-universal) multiplicity-one
    /// case pays no exponentiation at all.
    #[must_use]
    pub(crate) fn eval(&self, x: Fp) -> Fp {
        self.members
            .iter()
            .map(|(&member, &count)| {
                let factor = x - member;
                if count.get() == 1 {
                    factor
                } else {
                    factor.pow([NonZero::<u64>::from(count).get()])
                }
            })
            .product()
    }

    /// Realize (and memoize) the encoded polynomial in coefficient form.
    ///
    /// # Panics
    ///
    /// If the realization exceeds the polynomial coefficient cap.
    pub(crate) fn realize(&self) -> &Polynomial<Fp, ProductionRank> {
        self.realized.get_or_init(|| {
            let mut roots = Vec::new();
            for (&member, &count) in &self.members {
                for _ in 0..count.get() {
                    roots.push(member);
                }
            }
            Polynomial::from_coeffs(poly_with_roots(&roots))
        })
    }

    /// Deterministic (untrapdoored) commitment to the realized polynomial,
    /// memoized alongside the realization.
    ///
    /// # Panics
    ///
    /// If the realization exceeds the polynomial coefficient cap.
    #[must_use]
    pub(crate) fn commit(&self) -> Eq {
        *self.commitment.get_or_init(|| {
            self.realize()
                .commit(Pasta::host_generators(Pasta::baked()))
        })
    }

    fn reset_memo(&mut self) {
        self.realized.take();
        self.commitment.take();
    }
}

impl PartialEq for Multiset {
    fn eq(&self, other: &Self) -> bool {
        self.members == other.members
    }
}

impl TotalEq for Multiset {}

impl Extend<Fp> for Multiset {
    fn extend<T: IntoIterator<Item = Fp>>(&mut self, iter: T) {
        for member in iter {
            self.insert(member);
        }
    }
}

impl FromIterator<Fp> for Multiset {
    fn from_iter<T: IntoIterator<Item = Fp>>(iter: T) -> Self {
        let mut set = Self::default();
        set.extend(iter);
        set
    }
}

#[cfg(test)]
mod tests {
    use core::iter;

    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    fn random_set(rng: &mut StdRng, len: usize) -> Multiset {
        iter::repeat_with(|| Fp::random(&mut *rng))
            .take(len)
            .collect()
    }

    #[test]
    fn streaming_evaluation_matches_the_realization() {
        let rng = &mut StdRng::seed_from_u64(12);
        for len in (0..6).chain([32]) {
            let set = random_set(rng, len);
            let x = Fp::random(&mut *rng);
            assert_eq!(set.eval(x), set.realize().eval(x));
        }
    }

    #[test]
    fn empty_multiset_encodes_the_constant_one() {
        let rng = &mut StdRng::seed_from_u64(14);
        let empty = Multiset::default();
        assert_eq!(empty.eval(Fp::random(&mut *rng)), Fp::ONE);
        assert_eq!(empty.realize().eval(Fp::random(rng)), Fp::ONE);
    }

    /// `self.add_factors(other)`, as an expression.
    fn product(left: &Multiset, right: &Multiset) -> Multiset {
        let mut product = left.clone();
        product.add_factors(right);
        product
    }

    /// `self.rm_factors(other)`, as an expression.
    fn quotient(left: &Multiset, right: &Multiset) -> Multiset {
        let mut quotient = left.clone();
        quotient.rm_factors(right);
        quotient
    }

    #[test]
    fn added_factors_match_the_realized_product() {
        let rng = &mut StdRng::seed_from_u64(17);
        let left = random_set(rng, 3);
        // The right operand overlaps the left entirely: shared members'
        // multiplicities add, exactly as the product's factors do.
        let right = product(&random_set(rng, 4), &left);
        let whole = product(&left, &right);
        let x = Fp::random(&mut *rng);
        assert_eq!(whole.eval(x), left.eval(x) * right.eval(x));
        assert_eq!(whole.realize().eval(x), left.eval(x) * right.eval(x));
    }

    #[test]
    fn factor_arithmetic_roundtrips() {
        let rng = &mut StdRng::seed_from_u64(23);
        let set = random_set(rng, 5);
        let complement = random_set(rng, 3);
        let whole = product(&set, &complement);
        assert_eq!(quotient(&whole, &complement), set);
        assert_eq!(quotient(&whole, &set), complement);
        assert_eq!(quotient(&whole, &whole), Multiset::default());
    }

    #[test]
    fn removing_absent_factors_saturates() {
        let rng = &mut StdRng::seed_from_u64(29);
        let set = random_set(rng, 4);
        let disjoint = random_set(rng, 2);
        assert_eq!(
            quotient(&set, &disjoint),
            set,
            "a disjoint divisor takes nothing away"
        );

        // A divisor with excess multiplicity of a present member takes out
        // only what is there.
        let doubled = product(&set, &set);
        assert_eq!(quotient(&set, &doubled), Multiset::default());
        assert_eq!(quotient(&doubled, &set), set);
    }

    #[test]
    fn multiplicity_is_maintained() {
        let rng = &mut StdRng::seed_from_u64(31);
        let member = Fp::random(&mut *rng);
        let x = Fp::random(&mut *rng);

        let mut repeated = Multiset::default();
        repeated.insert(member);
        repeated.insert(member);

        let single_at_x = iter::once(member).collect::<Multiset>().eval(x);
        assert_eq!(repeated.eval(x), single_at_x.square());
        assert_eq!(repeated.realize().eval(x), single_at_x.square());
        assert_ne!(
            repeated.commit(),
            iter::once(member).collect::<Multiset>().commit()
        );

        // Structurally, the realization carries the repeated factor in full:
        // exactly (X - m)^2 = m^2 - 2mX + X^2, degree matching the total
        // multiplicity.
        let coeffs: Vec<Fp> = repeated.realize().iter_coeffs().collect();
        assert_eq!(
            coeffs.iter().rposition(|coeff| coeff != &Fp::ZERO),
            Some(2),
            "degree must equal the total multiplicity"
        );
        assert_eq!(
            coeffs[..3],
            [member.square(), -member.double(), Fp::ONE],
            "realization must be (X - m)^2 exactly"
        );
    }

    #[test]
    fn memoized_realization_resets_on_mutation() {
        let rng = &mut StdRng::seed_from_u64(37);
        let mut members: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
            .take(3)
            .collect();

        let mut set: Multiset = members.iter().copied().collect();
        let stale_commitment = set.commit();

        members.push(Fp::random(&mut *rng));
        set.insert(members[3]);

        assert_ne!(set.commit(), stale_commitment);
        assert_eq!(
            set.commit(),
            members.into_iter().collect::<Multiset>().commit()
        );
    }
}
