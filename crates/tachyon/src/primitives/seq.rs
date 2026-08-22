extern crate alloc;

use alloc::vec::Vec;
use core::ops::Mul;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu::Polynomial;

use crate::{
    nullifier::{NF_MAX_FUSED_SPAN, Nullifier},
    primitives::EpochIndex,
};

/// The non-cubic residue $c$ in the member encoding: the smallest $c$ with
/// $c^{(p-1)/3} \ne 1$.
///
/// $p \equiv 1 \pmod 3$ for the Pallas base field, so non-cubes exist and
/// $Y^3 - c$ is irreducible for any non-cube $c$. The only property the
/// scheme needs from $c$ is non-cube-ness, which
/// `residue_is_a_non_cube` verifies; any non-cube yields identical
/// binding, so the smallest is the canonical choice.
pub const NF_FACTOR_RESIDUE: Fp = Fp::from_raw([2, 0, 0, 0]);

/// Schoolbook coefficient-vector product.
///
/// Host-side only; ragu's `Polynomial` exposes no multiplication and
/// `poly_with_roots` handles linear roots only.
#[expect(
    clippy::indexing_slicing,
    reason = "the output vector is sized to hold every cross term"
)]
fn poly_mul(lhs: &[Fp], rhs: &[Fp]) -> Vec<Fp> {
    let mut out = alloc::vec![Fp::ZERO; lhs.len() + rhs.len() - 1];
    for (lhs_degree, &lhs_coeff) in lhs.iter().enumerate() {
        for (rhs_degree, &rhs_coeff) in rhs.iter().enumerate() {
            out[lhs_degree + rhs_degree] += lhs_coeff * rhs_coeff;
        }
    }
    out
}

/// The product of the factors of consecutively indexed members, starting
/// from the empty product $1$.
///
/// Each member pair expands to the cubic's coefficients
/// $[b^3 - c,\ 3ab^2,\ 3a^2b,\ a^3]$ for $a = e + 1$, $b = \mathsf{nf}$.
fn run_coeffs(epoch_start: EpochIndex, members: &[Nullifier]) -> Vec<Fp> {
    let mut coeffs = alloc::vec![Fp::ONE];
    for (offset, &nf) in members.iter().enumerate() {
        #[expect(
            clippy::as_conversions,
            reason = "the constructor asserts the run fits the epoch space"
        )]
        let index = Fp::from(u64::from(epoch_start.0) + 1 + offset as u64);
        let member = Fp::from(nf);
        let three = Fp::from(3);
        let factor = [
            member.square() * member - NF_FACTOR_RESIDUE,
            three * index * member.square(),
            three * index.square() * member,
            index.square() * index,
        ];
        coeffs = poly_mul(&coeffs, &factor);
    }
    coeffs
}

/// Pedersen commitment to a nullifier sequence.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfSeqCommit(Eq);

/// Witness polynomial for a nullifier sequence: the factor product
///
/// $$\mathsf{seq}(X) = \prod_{i} F_{e_i,\mathsf{nf}_i}(X), \qquad
/// F_{e,\mathsf{nf}}(X) = ((e+1)X + \mathsf{nf})^3 - c$$
///
/// with one indexed cubic factor per member, positions baked into the
/// factors, and $c$ = [`NF_FACTOR_RESIDUE`]. The $e+1$ offset keeps every
/// leading coefficient nonzero at epoch $0$. Appending a member multiplies
/// a factor in; containment of one sequence in another is divisibility.
///
/// The polynomial is naturally a *multiset* of factors: products carry no
/// positional structure, so stricter claims (contiguity, one member per
/// epoch) are provenance facts of the header fields that carry particular
/// commitments, not properties of this type. The empty product is the
/// constant $1$, which commits to a real curve point.
///
/// # Binding
///
/// The exponent is 3 because $3 \mid p - 1$, which makes $x \mapsto x^3$
/// three-to-one on its image and $Y^3 - c$ irreducible for any non-cube $c$.
/// A permutation exponent cannot serve: $5 \nmid p - 1$, so $x \mapsto x^5$ is
/// a bijection (the Poseidon S-box property) and $Y^5 - c$ has a root for
/// every $c$, leaving the factor reducible and the pair unbound.
///
/// $Y^3 - c$ is irreducible ($c$ is a non-cube), so each factor is
/// irreducible and a product of factors determines its factor multiset
/// (unique factorization). Commitment equality binds a sequence only up to
/// trailing zeros, which costs nothing here: trailing zeros do not change the
/// polynomial, and no step reads a rank, so the encoding needs no degree pin
/// anywhere. Two factors coincide only if their linear parts
/// differ by a cube root of unity: $F_{e_1,\mathsf{nf}_1} =
/// F_{e_2,\mathsf{nf}_2}$ requires $e_1 + 1 = \omega^k (e_2 + 1)$ with
/// $\omega = 2^{(p-1)/3}$, $k \in \{1, 2\}$. Over all $b \in [1, 2^{32}]$,
/// the minimum of $\omega^k b \bmod p$ exceeds $2^{220}$ for both $k$
/// (checked at every continued-fraction best approximation of $\omega^k/p$
/// with denominator at most $2^{32}$, where the minimum is attained), so no
/// two epoch indices are $\omega$-related and the encoding
/// $(e, \mathsf{nf}) \mapsto F_{e,\mathsf{nf}}$ is injective on the whole
/// epoch space. Reproduction:
///
/// ```text
/// p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
/// for w in (pow(2, (p-1)//3, p), pow(2, 2*(p-1)//3, p)):
///     h0, h1, k0, k1, a, b = 1, 0, 0, 1, w, p
///     best = p
///     while b:
///         q = a // b
///         a, b = b, a - q*b
///         h0, h1 = h0*q + h1, h0
///         k0, k1 = k0*q + k1, k0
///         if 1 <= k0 <= 2**32:
///             best = min(best, (w * k0) % p)
///     print(best.bit_length())  # 221 and 224
/// ```
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NfSeqPoly(Polynomial);

impl NfSeqPoly {
    /// Build the sequence polynomial for one contiguous run: the members of
    /// the consecutive epochs starting at `epoch_start`.
    ///
    /// An empty run is the constant $1$. Multisequences (a complement with
    /// an interior gap, say) compose from runs by multiplication.
    ///
    /// # Panics
    ///
    /// If `members` is longer than [`NF_MAX_FUSED_SPAN`] (the span whose
    /// product still fits the polynomial coefficient cap) or extends past
    /// the epoch space.
    #[must_use]
    pub fn new(epoch_start: EpochIndex, members: &[Nullifier]) -> Self {
        assert!(
            members.len() <= NF_MAX_FUSED_SPAN,
            "a nullifier sequence spans at most NF_MAX_FUSED_SPAN epochs"
        );
        assert!(
            members.is_empty()
                || u32::try_from(members.len() - 1)
                    .ok()
                    .and_then(|span| epoch_start.0.checked_add(span))
                    .is_some(),
            "a nullifier sequence stays inside the epoch space"
        );
        Self(Polynomial::from_coeffs(run_coeffs(epoch_start, members)))
    }

    /// Deterministic (untrapdoored) commitment to the sequence polynomial.
    #[must_use]
    pub fn commit(&self) -> NfSeqCommit {
        NfSeqCommit(self.0.commit())
    }

    /// Evaluate the sequence polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl Mul for NfSeqPoly {
    type Output = Self;

    /// Multiset union: the product of two sequences' factor multisets.
    ///
    /// # Panics
    ///
    /// If the product exceeds the polynomial coefficient cap.
    fn mul(self, rhs: Self) -> Self {
        // `iter_coeffs` yields the dense capacity-length form; trim the
        // trailing zeros so the convolution works over actual degrees.
        fn trimmed(poly: &Polynomial) -> Vec<Fp> {
            let mut coeffs: Vec<Fp> = poly.iter_coeffs().collect();
            while coeffs.len() > 1 && coeffs.last() == Some(&Fp::ZERO) {
                coeffs.pop();
            }
            coeffs
        }
        Self(Polynomial::from_coeffs(poly_mul(
            &trimmed(&self.0),
            &trimmed(&rhs.0),
        )))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        reason = "test vectors and windows of known constant size"
    )]

    use core::iter;

    use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

    use super::*;

    /// $(p-1)/3$, little-endian limbs.
    const CUBE_EXP: [u64; 4] = [
        0x330f_104f_0000_0000,
        0x60c2_32fe_adc4_5309,
        0x5555_5555_5555_5555,
        0x1555_5555_5555_5555,
    ];

    /// $\omega = 2^{(p-1)/3}$, the primitive cube root of unity in the
    /// injectivity argument.
    const OMEGA: Fp = Fp::from_raw([
        0x7b7f_d22f_0201_b547,
        0x0527_0d29_d19f_c7d2,
        0xd355_2a23_a855_4e50,
        0x2d33_357c_b532_458e,
    ]);

    fn factor_eval(epoch: EpochIndex, nf: Nullifier, x: Fp) -> Fp {
        let linear = Fp::from(u64::from(epoch.0) + 1) * x + Fp::from(nf);
        linear.square() * linear - NF_FACTOR_RESIDUE
    }

    fn random_members(rng: &mut StdRng, count: usize) -> Vec<Nullifier> {
        iter::repeat_with(|| Nullifier::from(Fp::random(&mut *rng)))
            .take(count)
            .collect()
    }

    /// The residue is a non-cube ($c^{(p-1)/3} \ne 1$), and that power is the
    /// documented cube root of unity, anchoring the injectivity proof's
    /// $\omega$.
    #[test]
    fn residue_is_a_non_cube() {
        let omega = NF_FACTOR_RESIDUE.pow_vartime(CUBE_EXP);
        assert_ne!(omega, Fp::ONE, "residue is a cube");
        assert_eq!(omega * omega * omega, Fp::ONE, "omega is not of order 3");
        assert_eq!(omega, OMEGA, "omega differs from the documented constant");
    }

    /// The product polynomial evaluates as the pointwise product of its
    /// members' factors.
    #[test]
    fn product_matches_pointwise_factor_evals() {
        let rng = &mut StdRng::seed_from_u64(1);
        let epoch_start = EpochIndex(rng.r#gen_range(0..u32::MAX - 8));
        let members = random_members(rng, 5);
        let seq = NfSeqPoly::new(epoch_start, &members);
        let x = Fp::random(&mut *rng);
        let pointwise = members
            .iter()
            .enumerate()
            .map(|(offset, &nf)| factor_eval(EpochIndex(epoch_start.0 + offset as u32), nf, x))
            .product::<Fp>();
        assert_eq!(seq.eval(x), pointwise);
    }

    /// The empty run is the constant $1$, and it commits to a real point.
    #[test]
    fn empty_run_is_one() {
        let empty = NfSeqPoly::new(EpochIndex(7), &[]);
        assert_eq!(empty.eval(Fp::from(1000)), Fp::ONE);
        let _commit: Eq = empty.commit().into();
    }

    /// Multiplication is multiset union: two runs compose into the product
    /// of their factors, gap or no gap.
    #[test]
    fn mul_composes_runs() {
        let rng = &mut StdRng::seed_from_u64(2);
        let older = random_members(rng, 2);
        let newer = random_members(rng, 3);
        let composed =
            NfSeqPoly::new(EpochIndex(10), &older) * NfSeqPoly::new(EpochIndex(20), &newer);
        let x = Fp::random(&mut *rng);
        let expected = NfSeqPoly::new(EpochIndex(10), &older).eval(x)
            * NfSeqPoly::new(EpochIndex(20), &newer).eval(x);
        assert_eq!(composed.eval(x), expected);
    }

    /// The span cap is asserted before any product is built.
    #[test]
    #[should_panic(expected = "at most NF_MAX_FUSED_SPAN")]
    fn oversized_sequence_panics() {
        let members = alloc::vec![Nullifier::from(Fp::ONE); NF_MAX_FUSED_SPAN + 1];
        let _unused = NfSeqPoly::new(EpochIndex(0), &members);
    }
}
