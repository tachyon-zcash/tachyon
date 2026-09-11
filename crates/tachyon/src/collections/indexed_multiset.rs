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
//!
//! ## Set form
//!
//! The unique factorization above means the multiset of `(index, member)`
//! tuples *is* the polynomial, so [`IndexedMultiset`] keeps the tuples as its
//! canonical representation and defers realization into coefficient form until
//! [committed](IndexedMultiset::commit). Operating on the set form is much
//! cheaper: a product is a count merge rather than a coefficient
//! convolution, the quotient witness is count subtraction rather than
//! polynomial division, and evaluation streams over members without
//! materializing coefficients.

#![allow(clippy::min_ident_chars, reason = "just for fun")]

extern crate alloc;

use alloc::{
    collections::{BTreeMap, btree_map::Entry},
    vec,
    vec::Vec,
};
use core::{cell::OnceCell, cmp::Eq as TotalEq, mem, num::NonZero};

use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu_arithmetic::{Cycle as _, poly_mul};
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_pasta::{Pasta, fp};

const NON_RESIDUE: Fp = fp!(0x02);

#[must_use]
fn encode_single(idx: u64, m: Fp) -> [Fp; 4] {
    let i = Fp::from(idx) + Fp::ONE;
    // writing out expanded coefficients for $F(X) = (iX + m)^3 - c$ is
    // cheaper than constructing a linear $f(X) = iX + m$ and then cubing it.
    [
        m.pow([3]) - NON_RESIDUE,
        fp!(3) * i * m.square(),
        fp!(3) * i.square() * m,
        i.pow([3]),
    ]
}

#[must_use]
fn direct_eval_single(idx: u64, m: Fp, x: Fp) -> Fp {
    let i = Fp::from(idx) + Fp::ONE;
    ((i * x) + m).pow([3]) - NON_RESIDUE
}

/// An indexed multiset of `(index, member)` tuples, kept in set form.
///
/// The encoded [`Polynomial`] is realized lazily -- at first
/// [`realize`](Self::realize) or [`commit`](Self::commit) -- and memoized
/// until the next mutation. Equality considers the members only, never the
/// memoized realization.
///
/// # Construction
///
/// There is no `new`: collect `(index, member)` tuples from any iterator,
/// or [`insert`](Self::insert)/[`Extend`] into an existing set.
///
/// ```ignore
/// use core::iter;
///
/// // a single member at one index, e.g. one nullifier read at its epoch,
/// // evaluated at a challenge without ever realizing coefficients:
/// let member_at_z = iter::once((epoch.into(), nf.into()))
///     .collect::<IndexedMultiset>()
///     .eval(z);
///
/// // a contiguous run: consecutive indices zipped with their members.
/// let window: IndexedMultiset = (epoch_start..).zip(nullifiers).collect();
///
/// // set-form arithmetic before realization: a product merges
/// // multiplicities, a quotient subtracts them.
/// let mut merged = window.clone();
/// merged.add_factors(&other);
/// merged.rm_factors(&other);
/// assert_eq!(merged, window);
/// ```
#[derive(Clone, Debug, Default)]
pub(crate) struct IndexedMultiset {
    /// Member multiplicities, keyed by `(index, member)`.
    members: BTreeMap<(u64, Fp), NonZero<u32>>,
    /// Memoized realization of the encoded polynomial.
    realized: OnceCell<Polynomial<Fp, ProductionRank>>,
    /// Memoized commitment to the realized polynomial.
    commitment: OnceCell<Eq>,
}

impl IndexedMultiset {
    /// Insert one member at `idx`, incrementing its multiplicity.
    ///
    /// # Panics
    ///
    /// If one member's multiplicity exceeds `u32::MAX`, far beyond the
    /// realizable coefficient capacity.
    pub(crate) fn insert(&mut self, idx: u64, m: Fp) {
        self.reset_memo();
        match self.members.entry((idx, m)) {
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
    /// without realizing the coefficients.
    #[must_use]
    pub(crate) fn eval(&self, x: Fp) -> Fp {
        self.members
            .iter()
            .fold(Fp::ONE, |product, (&(idx, m), &count)| {
                let factor = direct_eval_single(idx, m, x);
                (0..count.get()).fold(product, |subtotal, _| subtotal * factor)
            })
    }

    /// Realize (and memoize) the encoded polynomial in coefficient form.
    ///
    /// # Panics
    ///
    /// If the realization exceeds the polynomial coefficient cap.
    pub(crate) fn realize(&self) -> &Polynomial<Fp, ProductionRank> {
        self.realized.get_or_init(|| {
            let mut coeffs = vec![Fp::ONE];
            let mut scratch = Vec::new();
            for (&(idx, m), &count) in &self.members {
                let factor = encode_single(idx, m);
                for _ in 0..count.get() {
                    poly_mul(&coeffs, &factor, &mut scratch);
                    mem::swap(&mut coeffs, &mut scratch);
                }
            }
            Polynomial::from_coeffs(coeffs)
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

impl PartialEq for IndexedMultiset {
    fn eq(&self, other: &Self) -> bool {
        self.members == other.members
    }
}

impl TotalEq for IndexedMultiset {}

impl Extend<(u64, Fp)> for IndexedMultiset {
    fn extend<T: IntoIterator<Item = (u64, Fp)>>(&mut self, iter: T) {
        for (idx, m) in iter {
            self.insert(idx, m);
        }
    }
}

impl FromIterator<(u64, Fp)> for IndexedMultiset {
    fn from_iter<T: IntoIterator<Item = (u64, Fp)>>(iter: T) -> Self {
        let mut set = Self::default();
        set.extend(iter);
        set
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::iter;

    use rand::{RngExt as _, SeedableRng as _, rngs::StdRng};

    use super::*;

    fn random_set(rng: &mut StdRng, len: u64) -> IndexedMultiset {
        let start_idx = u64::from(rng.random_range(0..u32::MAX));
        (start_idx..start_idx + len)
            .map(|idx| (idx, Fp::random(&mut *rng)))
            .collect()
    }

    #[test]
    fn member_encoding_matches_manual_evaluation() {
        let rng = &mut StdRng::seed_from_u64(3);
        for _ in 0..8 {
            let idx = u64::from(rng.random_range(0..u32::MAX));
            let member = Fp::random(&mut *rng);
            let x = Fp::random(&mut *rng);
            assert_eq!(
                Polynomial::<Fp, ProductionRank>::from_coeffs(encode_single(idx, member).to_vec())
                    .eval(x),
                iter::once((idx, member))
                    .collect::<IndexedMultiset>()
                    .eval(x)
            );
        }
    }

    #[test]
    fn member_encoding_matches_manual_construction() {
        let rng = &mut StdRng::seed_from_u64(6);
        let idx = u64::from(rng.random_range(0..u32::MAX));
        let member = Fp::random(&mut *rng);

        let manual_coeffs = {
            let m_ix = [member, Fp::from(idx) + Fp::ONE];

            let mut m_ix_square = Vec::new();
            poly_mul(&m_ix, &m_ix, &mut m_ix_square);
            let mut m_ix_cube = Vec::new();
            poly_mul(&m_ix_square, &m_ix, &mut m_ix_cube);

            m_ix_cube[0] -= NON_RESIDUE;
            m_ix_cube
        };

        assert_eq!(encode_single(idx, member).to_vec(), manual_coeffs);
    }

    #[test]
    fn streaming_evaluation_matches_the_realization() {
        let rng = &mut StdRng::seed_from_u64(12);
        for len in 0..6u64 {
            let set = random_set(rng, len);
            let x = Fp::random(&mut *rng);
            assert_eq!(set.eval(x), set.realize().eval(x));
        }
    }

    /// `self.add_factors(other)`, as an expression.
    fn product(left: &IndexedMultiset, right: &IndexedMultiset) -> IndexedMultiset {
        let mut product = left.clone();
        product.add_factors(right);
        product
    }

    /// `self.rm_factors(other)`, as an expression.
    fn quotient(left: &IndexedMultiset, right: &IndexedMultiset) -> IndexedMultiset {
        let mut quotient = left.clone();
        quotient.rm_factors(right);
        quotient
    }

    #[test]
    fn added_factors_match_the_realized_product() {
        let rng = &mut StdRng::seed_from_u64(17);
        let left = random_set(rng, 3);
        let right = random_set(rng, 4);
        let product = product(&left, &right);
        let x = Fp::random(&mut *rng);
        assert_eq!(product.eval(x), left.eval(x) * right.eval(x));
        assert_eq!(product.realize().eval(x), left.eval(x) * right.eval(x));
    }

    #[test]
    fn factor_arithmetic_roundtrips() {
        let rng = &mut StdRng::seed_from_u64(23);
        let seq = random_set(rng, 5);
        let complement = random_set(rng, 3);
        let product = product(&seq, &complement);
        assert_eq!(quotient(&product, &complement), seq);
        assert_eq!(quotient(&product, &seq), complement);
        assert_eq!(quotient(&product, &product), IndexedMultiset::default());
    }

    #[test]
    fn removing_absent_factors_saturates() {
        let rng = &mut StdRng::seed_from_u64(29);
        let seq = random_set(rng, 4);
        let disjoint = random_set(rng, 2);
        assert_eq!(
            quotient(&seq, &disjoint),
            seq,
            "a disjoint divisor takes nothing away"
        );

        // a divisor with excess multiplicity of a present member takes out
        // only what is there.
        let doubled = product(&seq, &seq);
        assert_eq!(quotient(&seq, &doubled), IndexedMultiset::default());
        assert_eq!(quotient(&doubled, &seq), seq);
    }

    #[test]
    fn multiplicity_is_maintained() {
        let rng = &mut StdRng::seed_from_u64(31);
        let idx = u64::from(rng.random_range(0..u32::MAX));
        let member = Fp::random(&mut *rng);
        let x = Fp::random(&mut *rng);

        let mut repeated = IndexedMultiset::default();
        repeated.insert(idx, member);
        repeated.insert(idx, member);

        let single_at_x = iter::once((idx, member))
            .collect::<IndexedMultiset>()
            .eval(x);
        assert_eq!(repeated.eval(x), single_at_x.square());
        assert_eq!(repeated.realize().eval(x), single_at_x.square());
        let coeffs: Vec<Fp> = repeated.realize().iter_coeffs().collect();
        assert_eq!(coeffs.iter().rposition(|co| co != &Fp::ZERO), Some(6));
    }

    #[test]
    fn memoized_realization_resets_on_mutation() {
        let rng = &mut StdRng::seed_from_u64(37);
        let mut members: Vec<(u64, Fp)> =
            (0..3u64).map(|idx| (idx, Fp::random(&mut *rng))).collect();

        let mut set: IndexedMultiset = members.iter().copied().collect();
        let stale_commitment = set.commit();

        members.push((3, Fp::random(&mut *rng)));
        set.insert(3, members[3].1);

        assert_ne!(set.commit(), stale_commitment);
        assert_eq!(
            set.commit(),
            members.into_iter().collect::<IndexedMultiset>().commit()
        );
    }
}
