//! Off-circuit native preparation of the trace-based witness quotients.
//!
//! One module for every quotient the proof system opens against the
//! `relations` enforcers, for both cipher families:
//!
//! - the 8192-round **derivation** polynomials (`TachyonP5R8192`): the
//!   masked-quintic round quotient, the boundary quotient, and the arc's
//!   weight/accumulator recurrences, plus the native off-domain nullifier
//!   query.
//! - the 32x256 **expansion** trace (`TachyonP5R32`, `ROUNDS` columns by
//!   `EK_PART_LENGTH` rows): the masked-quintic round quotient, the affine
//!   input column with its recurrence quotient, and the strided-column
//!   quotients binding the trace's first column to the S-boxed inputs and the
//!   key polynomial to its final column.
//!
//! Both families share one generic coset-arithmetic layer (FFT evaluation,
//! vanishing-polynomial division, capacity splitting) defined at the top of the
//! module; no cipher-specific structure lives in those helpers.

#![allow(
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "todo"
)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::array;

use ff::{Field as _, PrimeField as _};
use lazy_static::lazy_static;
use pasta_curves::Fp;
use ragu::{Domain, Polynomial};
use zcash_mimc::spec::tachyon::{TachyonP5R32, TachyonP5R8192};

use super::subgroup_generator;
use crate::{
    constants::{EK_PART_LENGTH, MK_LENGTH, NF_DOMAIN, NF_EMITTERS, POLY_LEN_MAX},
    keys::{ExpansionParams, NoteMasterKey},
    primitives::{ExpansionInputSpectrum, NfEmitterSpectrum},
};

/// Splits per full-length arc polynomial, `NF_DOMAIN / POLY_LEN_MAX`.
///
/// The arc's weight `w_j` and accumulator `A` span the order-`NF_DOMAIN` query
/// coset `c·⟨γ⟩` and so exceed commitment capacity; each is committed as this
/// many capacity-wide splits. Derived from [`NF_DOMAIN`], so the arc scales
/// with the nullifier domain with nothing pinned to a specific split count.
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "safe conversion"
)]
pub(crate) const ARC_SPLITS: usize = NF_DOMAIN / POLY_LEN_MAX;

/// The secret query-coset shift `c`: the coset origin `c·⟨gamma⟩` (with
/// `c ∉ ⟨gamma⟩`), constant across a note's epochs. A randomizer that hides the
/// evaluation locations; not an epoch offset.
#[derive(Clone, Copy, Debug)]
pub struct QueryShift(pub Fp);

/// A per-poly secret geometric weight base `ρ_j`: the nullifier query weights
/// `ρ_j^d`, pinned generic-distinct so the `N·8192` query roots stay distinct.
#[derive(Clone, Copy, Debug)]
pub struct WeightRatios(pub [Fp; NF_EMITTERS]);

/// The per-poly secret salts `mk_s^{(j)}`: the input to each derivation poly's
/// 8192-round cipher, fixing `T_j` via the round-0 boundary `T_j(1) =
/// (mk_s^{(j)} + k_0)^5`.
#[derive(Clone, Copy, Debug)]
pub struct QuerySalts(pub [Fp; NF_EMITTERS]);
impl QuerySalts {
    pub const fn get(&self, idx: usize) -> Fp {
        assert!(idx < NF_EMITTERS, "index out of bounds");
        self.0[idx]
    }
}

/// Round and boundary quotients for one cipher trace: the masked round quotient
/// (as `N` capacity-wide splits) and the boundary quotient `(T − B)/(z − 1)`.
/// Use `EMITTER_ROUND_SPLITS` for derivation polys and `EXPANSION_ROUND_SPLITS`
/// for the expansion trace.
#[derive(Clone, Debug)]
pub struct RoundBoundaryQuotients<const N: usize> {
    pub round: [Polynomial; N],
    pub boundary: Polynomial,
}

// ---------------------------------------------------------------------------
// Shared generic coset arithmetic
// ---------------------------------------------------------------------------

/// Coset shift off the evaluating subgroup, so the subgroup vanisher `Z_D`
/// does not vanish on the evaluation domain.
const COSET_SHIFT: Fp = Fp::MULTIPLICATIVE_GENERATOR;

/// Multiply coefficient `k` by `base^k` in place, mapping `p(X)` to
/// `p(base·X)`.
fn scale_by_powers(coeffs: &mut [Fp], base: Fp) {
    let mut power = Fp::ONE;
    for coeff in coeffs.iter_mut() {
        *coeff *= power;
        power *= base;
    }
}

/// Evaluations of `coeffs` on the coset `shift · ⟨size-th root⟩`.
fn coset_evaluations(coeffs: &[Fp], size: usize, shift: Fp) -> Vec<Fp> {
    assert!(
        coeffs.len() <= size,
        "numerator piece exceeds the coset domain"
    );
    let mut values = vec![Fp::ZERO; size];
    values[..coeffs.len()].copy_from_slice(coeffs);
    scale_by_powers(&mut values[..coeffs.len()], shift);
    Domain::new(size.ilog2()).fft(&mut values);
    values
}

/// Coefficients from coset evaluations on `COSET_SHIFT · ⟨size-th root⟩`
/// (inverse of [`coset_evaluations`] at `shift = COSET_SHIFT`), trailing zeros
/// trimmed. The domain size is the input length.
fn coset_coefficients(values: Vec<Fp>) -> Vec<Fp> {
    let mut coeffs = coset_interpolate(values, COSET_SHIFT);
    while coeffs.last() == Some(&Fp::ZERO) {
        coeffs.pop();
    }
    coeffs
}

/// Coefficients of the polynomial whose evaluations over the coset
/// `shift·⟨omega⟩` (omega the order-`values.len()` root) are `values`: inverse
/// FFT over `⟨omega⟩`, then unscale the coset shift. `values.len()` must be a
/// power of two. Unlike [`coset_coefficients`] (the extended-evaluation
/// inverse, trailing zeros trimmed), this keeps full length so the recurrence
/// numerator preserves its degree.
fn coset_interpolate(mut values: Vec<Fp>, shift: Fp) -> Vec<Fp> {
    Domain::new(values.len().ilog2()).ifft(&mut values);
    scale_by_powers(&mut values, shift.invert().expect("coset shift is nonzero"));
    values
}

/// Exact division by `X^domain − vanishing`, returning `(quotient, remainder)`
/// with `remainder.len() <= domain`. The subgroup vanisher is `vanishing = 1`;
/// the query coset `c·⟨gamma⟩` (order `domain`) has vanisher `vanishing =
/// c^domain` (its `domain` points are the roots of `z^domain − c^domain`).
fn divide_by_coset_vanishing(poly: &[Fp], domain: usize, vanishing: Fp) -> (Vec<Fp>, Vec<Fp>) {
    if poly.len() <= domain {
        return (Vec::new(), poly.to_vec());
    }
    let mut remainder = poly.to_vec();
    let mut quotient = vec![Fp::ZERO; poly.len() - domain];
    for degree in (domain..poly.len()).rev() {
        let coeff = remainder[degree];
        quotient[degree - domain] += coeff;
        remainder[degree - domain] += vanishing * coeff;
        remainder[degree] = Fp::ZERO;
    }
    remainder.truncate(domain);
    (quotient, remainder)
}

/// Exact division by `X^domain − 1` (the subgroup case of
/// [`divide_by_coset_vanishing`]).
fn divide_by_vanishing(poly: &[Fp], domain: usize) -> (Vec<Fp>, Vec<Fp>) {
    divide_by_coset_vanishing(poly, domain, Fp::ONE)
}

/// Carve `coeffs` into `SPLITS` adjacent `width`-wide pieces, the
/// commitment-capacity splits the circuit recombines by Horner in `z^width`. A
/// polynomial spanning more than one commitment's capacity (a round quotient,
/// the arc's weight `w_j` and accumulator `A`) cannot ride one commitment, so
/// it is committed and opened this way. Production passes `POLY_LEN_MAX`;
/// domain-generic callers pass their `DOMAIN`.
fn split_coeffs<const SPLITS: usize>(coeffs: &[Fp], width: usize) -> [Polynomial; SPLITS] {
    array::from_fn(|split| {
        let lo = split * width;
        let hi = ((split + 1) * width).min(coeffs.len());
        Polynomial::from_coeffs(if lo < hi { &coeffs[lo..hi] } else { &[] })
    })
}

/// Polynomial product via FFT (degree-additive), coefficient form in and out.
fn multiply(left: &[Fp], right: &[Fp]) -> Vec<Fp> {
    if left.is_empty() || right.is_empty() {
        return Vec::new();
    }
    let product_len = left.len() + right.len() - 1;
    let size = product_len.next_power_of_two();
    let domain = Domain::new(size.ilog2());
    let mut left_ext = left.to_vec();
    left_ext.resize(size, Fp::ZERO);
    let mut right_ext = right.to_vec();
    right_ext.resize(size, Fp::ZERO);
    domain.fft(&mut left_ext);
    domain.fft(&mut right_ext);
    for (value, factor) in left_ext.iter_mut().zip(&right_ext) {
        *value *= factor;
    }
    domain.ifft(&mut left_ext);
    left_ext.truncate(product_len);
    left_ext
}

/// Add `addend` into `accumulator` coefficient-wise, growing as needed.
fn add_into(accumulator: &mut Vec<Fp>, addend: &[Fp]) {
    if addend.len() > accumulator.len() {
        accumulator.resize(addend.len(), Fp::ZERO);
    }
    for (slot, value) in accumulator.iter_mut().zip(addend) {
        *slot += value;
    }
}

/// Multiply `coeffs` by the linear factor `z − root`, returning the
/// degree-`coeffs.len()` product.
fn multiply_by_linear(coeffs: &[Fp], root: Fp) -> Vec<Fp> {
    let mut product = vec![Fp::ZERO; coeffs.len() + 1];
    for (degree, coeff) in coeffs.iter().enumerate() {
        product[degree + 1] += *coeff;
        product[degree] -= root * *coeff;
    }
    product
}

// ---------------------------------------------------------------------------
// Derivation polynomials (8192-round TachyonP5R8192) and the arc
// ---------------------------------------------------------------------------

/// Committed splits of the derivation poly's masked round quotient. The
/// numerator `mask·(T(omega z) − (T + O)^POW)` has degree `POW·(DOMAIN-1) + 1`
/// (degree-1 row-wrap mask), so over the degree-`DOMAIN` vanisher the quotient
/// spans this many capacity-wide splits. Derived from `POW`; differs from
/// [`EXPANSION_ROUND_SPLITS`] only by the mask degree (1 vs `EK_PART_LENGTH`).
pub(crate) const EMITTER_ROUND_SPLITS: usize = {
    #[expect(clippy::cast_possible_truncation, reason = "constant size")]
    let numerator_len = TachyonP5R8192::POW as usize * (POLY_LEN_MAX - 1) + 1 + 1;
    (numerator_len - POLY_LEN_MAX).div_ceil(POLY_LEN_MAX)
};

/// The per-transition offsets `O(omega^j) = c_{(j+1) mod |D|} +
/// round_keys[(j+1) mod κ]` for `j = 0..DOMAIN`. The single row-wrap entry
/// (`j = DOMAIN-1`) is masked out of the recurrence, so its value is free; the
/// periodic convention (matching the in-circuit committed offset `C(z) + sum_r
/// k_r E_r(z)`) is the cheapest choice, and `c_0 = 0` makes it exactly
/// `round_keys[0]`. Using the same convention as the circuit keeps this
/// quotient consistent with what `enforce_committed_offset_recurrence` checks.
fn offsets(round_keys: &[Fp]) -> [Fp; TachyonP5R8192::ROUNDS] {
    assert!(!round_keys.is_empty(), "key schedule must be non-empty");
    let constants = TachyonP5R8192::CONSTANTS;
    array::from_fn(|source| {
        let next = source + 1;
        constants[next % TachyonP5R8192::ROUNDS] + round_keys[next % round_keys.len()]
    })
}

/// Build the masked-quintic round quotient (production sizes) as
/// [`EMITTER_ROUND_SPLITS`] adjacent splits.
fn round_quotient(trace_coeffs: &[Fp], round_keys: &[Fp]) -> [Polynomial; EMITTER_ROUND_SPLITS] {
    round_quotient_inner::<
        { TachyonP5R8192::ROUNDS },
        { TachyonP5R8192::POW },
        { EMITTER_ROUND_SPLITS },
    >(trace_coeffs, &offsets(round_keys))
}

/// Domain-generic masked round quotient, so the identity is testable on a tiny
/// domain: `mask·(T(omega z) − (T + O)^POW) = Q·(z^DOMAIN − 1)`, with `mask(z)
/// = z − omega^{-1}` (zeroing the row-wrap, degree 1) and `O` the interpolant
/// of `offset_values`. The eval coset is sized from `POW` to cover the
/// degree-`POW·(DOMAIN-1) + 1` numerator exactly.
fn round_quotient_inner<const DOMAIN: usize, const POW: u64, const SPLITS: usize>(
    trace_coeffs: &[Fp],
    offset_values: &[Fp; DOMAIN],
) -> [Polynomial; SPLITS] {
    #[expect(clippy::cast_possible_truncation, reason = "constant size")]
    const {
        assert!(
            SPLITS == (POW as usize * (DOMAIN - 1) + 2 - DOMAIN).div_ceil(DOMAIN),
            "SPLITS must match the degree-POW round-numerator quotient (degree-1 mask)"
        );
    }
    // Round numerator degree = POW·(DOMAIN-1) + 1 (degree-1 row-wrap mask); the
    // eval coset must hold its `degree + 1` coefficients.
    #[expect(clippy::cast_possible_truncation, reason = "constant size")]
    let eval_size = (POW as usize * (DOMAIN - 1) + 2).next_power_of_two();
    let row_step = eval_size / DOMAIN;

    let trace_ext = coset_evaluations(trace_coeffs, eval_size, COSET_SHIFT);
    let offset_ext = {
        let mut offset_coeffs = offset_values.to_vec();
        Domain::new(DOMAIN.ilog2()).ifft(&mut offset_coeffs);
        coset_evaluations(&offset_coeffs, eval_size, COSET_SHIFT)
    };

    // mask(z) = z − omega^{DOMAIN-1}, and omega^{DOMAIN-1} = omega^{-1}.
    let wrap_root = subgroup_generator::<DOMAIN>()
        .invert()
        .expect("a root of unity is nonzero");
    let mask_ext = coset_evaluations(&[-wrap_root, Fp::ONE], eval_size, COSET_SHIFT);

    let numerator: Vec<Fp> = (0..eval_size)
        .map(|point| {
            let cipher_in = trace_ext[point] + offset_ext[point];
            let shifted = trace_ext[(point + row_step) % eval_size];
            mask_ext[point] * (shifted - cipher_in.pow_vartime([POW]))
        })
        .collect();

    let (quotient, remainder) = divide_by_vanishing(&coset_coefficients(numerator), DOMAIN);
    assert!(
        remainder.iter().all(|coeff| *coeff == Fp::ZERO),
        "round numerator must be divisible by the domain vanishing polynomial"
    );
    assert!(
        quotient.len() <= SPLITS * DOMAIN,
        "round quotient exceeds the split budget"
    );
    split_coeffs::<SPLITS>(&quotient, DOMAIN)
}

/// Build the boundary quotient `(T − B)/(z − 1)`, `B = (mk_s + k_0)^5`.
fn boundary_quotient(trace_coeffs: &[Fp], salt: Fp, first_key: Fp) -> Polynomial {
    let alpha = salt + first_key;
    let boundary = alpha.square().square() * alpha;

    let mut shifted = trace_coeffs.to_vec();
    shifted[0] -= boundary;
    let (quotient, remainder) = divide_by_vanishing(&shifted, 1);
    assert!(
        remainder.iter().all(|coeff| *coeff == Fp::ZERO),
        "T(1) must equal the boundary value (mk_s + k_0)^5"
    );
    Polynomial::from_coeffs(&quotient)
}

/// Domain-generic masked affine-recurrence quotient on the coset
/// `shift·⟨gamma⟩` (order `N`), so the identity is testable on a tiny coset.
/// The sequence interpolates the affine orbit `v_{d+1} = scale·v_d + step`
/// from `v_0 = boundary_value`, and `mask(z)·(seq(gammaz) − scale·seq(z) −
/// step) = Q(z)·(z^S − shift^S)` holds with `mask(z) = z − shift·gamma^{S-1}`
/// zeroing the single coset wrap (`gamma·shift·gamma^{S-1} = shift·gamma^S =
/// shift` wraps to the origin, where the recurrence would otherwise have to
/// close the orbit). The pure-geometric case (`step = 0`, `boundary_value =
/// 1`) is the arc weight `w(shift·gamma^d) = scale^d`; the arithmetic case
/// (`scale = 1`, `shift = 1`) is an affine progression over a subgroup.
/// Returns the sequence coefficients and the quotient.
fn affine_recurrence_inner<const N: usize>(
    scale: Fp,
    step: Fp,
    shift: Fp,
    boundary_value: Fp,
) -> (Vec<Fp>, Vec<Fp>) {
    let gamma = subgroup_generator::<N>();

    // seq(shift·gamma^d) = v_d over the coset, by native orbit iteration.
    let mut values = vec![Fp::ZERO; N];
    let mut value = boundary_value;
    for slot in &mut values {
        *slot = value;
        value = scale * value + step;
    }
    let sequence = coset_interpolate(values, shift);

    // diff(z) = seq(gammaz) − scale·seq(z) − step: scaling coeff i of seq by
    // gamma^i gives seq(gammaz); `step` lands on the constant term.
    let mut advanced = sequence.clone();
    scale_by_powers(&mut advanced, gamma);
    let mut diff: Vec<Fp> = advanced
        .iter()
        .zip(&sequence)
        .map(|(shifted, base)| *shifted - scale * *base)
        .collect();
    if let Some(constant) = diff.first_mut() {
        *constant -= step;
    }

    // numerator = (z − shift·gamma^{S-1})·diff, divisible by z^S − shift^S.
    let wrap_point = shift * gamma.pow_vartime([N as u64 - 1]);
    let numerator = multiply_by_linear(&diff, wrap_point);
    let shift_pow = shift.pow_vartime([N as u64]);
    let (quotient, remainder) = divide_by_coset_vanishing(&numerator, N, shift_pow);
    assert!(
        remainder.iter().all(|coeff| *coeff == Fp::ZERO),
        "affine recurrence must vanish on the coset"
    );
    (sequence, quotient)
}

/// Domain-generic masked running-sum accumulator with its recurrence and
/// boundary quotients on the query coset `shift·⟨gamma⟩` (order `N`),
/// testable on a tiny coset with synthetic `t_coeffs` (decoupling the
/// accumulator logic from the full-degree derivation polys).
///
/// `A(shift·gamma^d) = sum_{k<d} β^k·nf_k` (exclusive prefix) with `nf_k =
/// sum_j rho_j^k·T_j(shift·gamma^k)`. The recurrence `A(gammaz) − A(z) = sum_j
/// w_j(z)·T_j(z)` (`w_j(shift·gamma^d) = (rho_j·β)^d`, the right-hand side the
/// term at the old position `d`) holds off the wrap, masked by `z −
/// shift·gamma^{S-1}` and witnessed against `z^S − shift^S`; the boundary
/// `A(shift) = 0` is witnessed against `z − shift`. Returns `(A, Q_recurrence,
/// Q_boundary)`.
fn accumulator_quotient_inner<const N: usize, const POLYS: usize>(
    polys: &[NfEmitterSpectrum; POLYS],
    ratios: &[Fp; POLYS],
    shift: Fp,
    beta: Fp,
) -> (Vec<Fp>, Vec<Fp>, Vec<Fp>) {
    let gamma = subgroup_generator::<N>();

    // nf_k = sum_j rho_j^k · T_j(shift·gamma^k), over the coset.
    let mut nullifiers = vec![Fp::ZERO; N];
    for (&ratio, poly) in ratios.iter().zip(polys) {
        let evaluations = coset_evaluations(poly.0.coefficients(), N, shift);
        for (offset, &evaluation) in evaluations.iter().enumerate() {
            nullifiers[offset] += ratio.pow_vartime([offset as u64]) * evaluation;
        }
    }

    // A(shift·gamma^d) = sum_{k<d} β^k·nf_k (exclusive prefix; A(shift) = 0),
    // then interpolate. Exclusive so a range starting at offset 0 reads its
    // left endpoint at the coset origin (A = 0), never at the wrap.
    let mut accumulator_values = vec![Fp::ZERO; N];
    let mut running = Fp::ZERO;
    for (offset, nullifier) in nullifiers.iter().enumerate() {
        accumulator_values[offset] = running;
        running += beta.pow_vartime([offset as u64]) * nullifier;
    }
    let accumulator = coset_interpolate(accumulator_values, shift);

    // M(z) = sum_j w_j(z)·T_j(z). With the exclusive prefix the recurrence
    // right-hand side is M(z) — the term at the old position d, added going
    // from d to d+1 — not M(gammaz).
    let mut product = Vec::new();
    for (ratio, poly) in ratios.iter().zip(polys) {
        let (weight, _) = affine_recurrence_inner::<N>(*ratio * beta, Fp::ZERO, shift, Fp::ONE);
        add_into(&mut product, &multiply(&weight, poly.0.coefficients()));
    }

    // difference = A(gammaz) − A(z) − M(z).
    let mut difference = accumulator.clone();
    scale_by_powers(&mut difference, gamma);
    for (slot, value) in difference.iter_mut().zip(&accumulator) {
        *slot -= value;
    }
    add_into(
        &mut difference,
        &product.iter().map(Fp::neg).collect::<Vec<_>>(),
    );

    // numerator = (z − shift·gamma^{S-1})·difference, divisible by z^S − shift^S.
    let wrap_point = shift * gamma.pow_vartime([N as u64 - 1]);
    let numerator = multiply_by_linear(&difference, wrap_point);
    let shift_pow = shift.pow_vartime([N as u64]);
    let (recurrence, remainder) = divide_by_coset_vanishing(&numerator, N, shift_pow);
    assert!(
        remainder.iter().all(|coeff| *coeff == Fp::ZERO),
        "accumulator recurrence must vanish on the query coset"
    );

    // boundary: A(shift) = 0 (the exclusive prefix's empty sum at the origin),
    // witnessed against z − shift.
    let (boundary, boundary_remainder) = divide_by_coset_vanishing(&accumulator, 1, shift);
    assert!(
        boundary_remainder.iter().all(|coeff| *coeff == Fp::ZERO),
        "accumulator boundary A(shift) must be zero"
    );

    (accumulator, recurrence, boundary)
}

// ---------------------------------------------------------------------------
// Derivation / arc production wrappers and the native nullifier query
// ---------------------------------------------------------------------------

/// The masked-quintic round quotient, as [`EMITTER_ROUND_SPLITS`] adjacent
/// splits. Satisfies `mask·(T(omegaz) − (T + O)^5) = Q·(z^|D| − 1)` with offset
/// `O(omega^j) = c_{j+1} + round_keys[(j+1) mod κ]` and `mask(z) = z −
/// omega^{|D|-1}` (zeroing the row-wrap) — the identity
/// `enforce_committed_offset_recurrence` checks.
#[must_use]
pub(crate) fn nf_emitter_round_quotient(
    coeffs: &[Fp],
    round_keys: &[Fp],
) -> [Polynomial; EMITTER_ROUND_SPLITS] {
    round_quotient(coeffs, round_keys)
}

/// The boundary quotient `(T(z) − B)/(z − 1)`, `B = (mk_s + k_0)^5`, pinning
/// `T(1)` to the first cipher state — the identity
/// `enforce_first_column_values::<1>` checks.
#[must_use]
pub(crate) fn nf_emitter_boundary_quotient(coeffs: &[Fp], salt: Fp, first_key: Fp) -> Polynomial {
    boundary_quotient(coeffs, salt, first_key)
}

/// Native off-domain nullifier query for one epoch offset `d`.
///
/// `nf_d = sum_{j<N} rho_j^d · T_j(c·gamma^d)`: each derivation poly `T_j` is
/// read at the query point `p_d = c·gamma^d` on the secret coset `c·⟨gamma⟩`,
/// weighted by the per-poly secret geometric `rho_j^d`, and summed. This is the
/// wallet's native nullifier; the in-circuit query relation mirrors it.
#[must_use]
pub(crate) fn nullifier_query(
    polys: &[NfEmitterSpectrum; NF_EMITTERS],
    shift: QueryShift,
    ratios: WeightRatios,
    coset_generator: Fp,
    offset: u64,
) -> Fp {
    // Past the coset order the query points wrap; a note has no safe
    // nullifier there and deriving one is misuse, never silent.
    assert!(
        offset < NF_DOMAIN as u64,
        "nullifier offset exceeds the query coset order"
    );
    let point = shift.0 * coset_generator.pow_vartime([offset]);
    polys
        .iter()
        .zip(ratios.0)
        .fold(Fp::ZERO, |sum, (poly, ratio)| {
            sum + ratio.pow_vartime([offset]) * poly.0.eval(point)
        })
}

/// Native masked weight polynomial (as [`ARC_SPLITS`] capacity-wide splits)
/// and its recurrence quotient for one derivation poly's arc, at the
/// production query-coset order `S = NF_DOMAIN`.
///
/// `ratio = rho_j·β` (the per-poly geometric base scaled by the arc challenge)
/// and `shift = c` (the secret query-coset shift). The weight `w_j`
/// interpolates `[ratio^d]_{d<S}` over `c·⟨gamma⟩`, so `w_j(c·gamma^d) =
/// (rho_j·β)^d`; the quotient witnesses the masked recurrence `w_j(gammaz) =
/// ratio·w_j(z)` (the pure-geometric case of the affine recurrence). The
/// weight spans the order-`S` coset and so exceeds commitment capacity; it is
/// returned as `ARC_SPLITS` splits the circuit recombines by Horner in
/// `z^POLY_LEN_MAX`. The quotient has degree below `POLY_LEN_MAX`, so it is a
/// single polynomial.
#[must_use]
pub(crate) fn weight_recurrence(ratio: Fp, shift: Fp) -> ([Polynomial; ARC_SPLITS], Polynomial) {
    let (weight, quotient) = affine_recurrence_inner::<NF_DOMAIN>(ratio, Fp::ZERO, shift, Fp::ONE);
    (
        split_coeffs::<ARC_SPLITS>(&weight, POLY_LEN_MAX),
        Polynomial::from_coeffs(&quotient),
    )
}

/// Native running-sum accumulator (as [`ARC_SPLITS`] capacity-wide splits)
/// with its recurrence quotient for the arc, at the production query-coset
/// order `S = NF_DOMAIN`.
///
/// `A(c·gamma^d) = sum_{k<d} β^k·nf_k` (exclusive prefix; `A(c) = 0`)
/// accumulates the `β`-weighted nullifiers over the coset, so a range `[start,
/// end)` reads as the endpoint difference `A(p_end) − A(p_start)`. `ratios` are
/// the `rho_j`, `shift` is the secret `c`, `beta` the arc challenge. The
/// accumulator spans the order-`S` coset and exceeds commitment capacity, so it
/// is returned as `ARC_SPLITS` splits; the boundary `A(c) = 0` is a direct
/// circuit open (no boundary quotient). Returns `(A splits, Q_recurrence)`.
#[must_use]
pub(crate) fn accumulator_recurrence(
    polys: &[NfEmitterSpectrum; NF_EMITTERS],
    ratios: &[Fp; NF_EMITTERS],
    shift: Fp,
    beta: Fp,
) -> ([Polynomial; ARC_SPLITS], Polynomial) {
    let (accumulator, recurrence, _boundary) =
        accumulator_quotient_inner::<NF_DOMAIN, NF_EMITTERS>(polys, ratios, shift, beta);
    (
        split_coeffs::<ARC_SPLITS>(&accumulator, POLY_LEN_MAX),
        Polynomial::from_coeffs(&recurrence),
    )
}

// ---------------------------------------------------------------------------
// Expansion trace (32x256 TachyonP5R32)
// ---------------------------------------------------------------------------

/// Committed splits of the expansion trace's masked round quotient. The
/// numerator has degree `POW·(DOMAIN-1) + EK_PART_LENGTH` (the
/// degree-`EK_PART_LENGTH` output-cell mask), so over the degree-`DOMAIN`
/// vanisher the quotient spans this many capacity-wide splits. Derived from
/// `POW`; the larger mask degree (`EK_PART_LENGTH` vs the derivation poly's 1) is
/// what pushes it one split past [`EMITTER_ROUND_SPLITS`].
pub(crate) const EXPANSION_ROUND_SPLITS: usize = {
    #[expect(clippy::cast_possible_truncation, reason = "constant size")]
    let numerator_len = TachyonP5R32::POW as usize * (POLY_LEN_MAX - 1) + EK_PART_LENGTH + 1;
    (numerator_len - POLY_LEN_MAX).div_ceil(POLY_LEN_MAX)
};

/// Round-numerator eval coset (expansion). Sized from `POW` to cover the
/// degree-`POW·(DOMAIN-1) + EK_PART_LENGTH` numerator (the degree-`EK_PART_LENGTH`
/// output-cell mask) exactly. Was the hand-set `ROUND_COSET`.
#[expect(clippy::cast_possible_truncation, reason = "constant size")]
const ROUND_COSET: usize =
    (TachyonP5R32::POW as usize * (POLY_LEN_MAX - 1) + EK_PART_LENGTH + 1).next_power_of_two();

/// Row step: the round-coset-to-trace size ratio. `T(gX)` on the round coset is
/// `trace_ext` rotated by this, since ω_trace = ω_round^ROW_STEP.
const ROW_STEP: usize = ROUND_COSET / POLY_LEN_MAX;

/// Length of a column-stride spread: coefficient `k` of a `TRACE_COLUMNS`-term
/// polynomial lands at degree `k·EK_PART_LENGTH`.
const SPREAD_LEN: usize = (TachyonP5R32::ROUNDS - 1) * EK_PART_LENGTH + 1;

lazy_static! {
    /// Output-cell mask `M(X) = X^ERA − column_root^OUTPUT_CELL` evaluated on
    /// the quintic coset. Keyset-independent, so it is built once.
    static ref MASK_EXT: Vec<Fp> = {
        let column_root = subgroup_generator::<{ TachyonP5R32::ROUNDS }>();
        let mut mask = vec![Fp::ZERO; EK_PART_LENGTH + 1];
        mask[0] = -column_root.pow_vartime([(TachyonP5R32::ROUNDS - 1) as u64]);
        mask[EK_PART_LENGTH] = Fp::ONE;
        coset_evaluations(&mask, ROUND_COSET, COSET_SHIFT)
    };

    /// Quintic-coset evaluations of the round offset's constants part: the
    /// `CONSTANTS[col + 1]` contribution of `offset[col]` alone (the row-wrap
    /// column zeroed), with no key material. The keyset-independent half of the
    /// cached `offset_ext` basis (see `expansion_round_quotient`). Built once.
    static ref OFFSET_CONST_EXT: Vec<Fp> = offset_basis_ext(
        &TachyonP5R32::CONSTANTS
            .iter()
            .skip(1)
            .copied()
            .chain([Fp::ZERO])
            .collect::<Vec<Fp>>(),
    );

    /// Quintic-coset evaluations of the round offset's per-key selector bases,
    /// one per round-key residue class. `OFFSET_KEY_EXT[r]` is `1` at every
    /// column whose offset adds `round_key(r)` (i.e. `(col + 1) % ROUND_KEYS ==
    /// r`) and `0` elsewhere -- pure structure, no key material. The row-wrap
    /// column is masked out of the recurrence, so its value is free; the
    /// periodic convention (`k_0` at the wrap, matching the in-circuit
    /// committed reconstruction `K(ζ·z^{|D|/κ})`) keeps this quotient
    /// consistent with what `enforce_committed_row_recurrence` checks. The
    /// per-call combine scales each by `round_key(r)` (see
    /// `expansion_round_quotient`). Built once.
    static ref OFFSET_KEY_EXT: Vec<Vec<Fp>> = (0..MK_LENGTH)
        .map(|residue| {
            let selector: Vec<Fp> = (0..TachyonP5R32::ROUNDS)
                .map(|col| {
                    if (col + 1) % MK_LENGTH == residue {
                        Fp::ONE
                    } else {
                        Fp::ZERO
                    }
                })
                .collect();
            offset_basis_ext(&selector)
        })
        .collect();
}

/// Apply the keyset-independent offset transform to per-column `values`:
/// interpolate over the column subgroup, spread by the column stride, and
/// evaluate on the quintic coset. Linear, so it builds each cached `offset_ext`
/// basis (see `expansion_round_quotient`).
fn offset_basis_ext(values: &[Fp]) -> Vec<Fp> {
    let mut coeffs = values.to_vec();
    Domain::new(TachyonP5R32::ROUNDS.ilog2()).ifft(&mut coeffs);
    coset_evaluations(&spread_by_stride(&coeffs), ROUND_COSET, COSET_SHIFT)
}

/// Prover-side bundle of the expansion step's witness polynomials, from the
/// coefficient vectors of the trace poly `T` and the eval-form part-key poly
/// `K`. `keyset` is the note's master key `mk` (the expansion cipher's
/// round-key schedule) and `params` its expansion-input parameters
/// `(s, δ, w)`; `base = part · EK_PART_LENGTH` is this part's cipher-input
/// window origin. Returns `(round splits, input column, recurrence quotient,
/// link quotient, decimation quotient)`, matching what [`KeyExpansionStep`]
/// opens: the input column `I` interpolates the round-0 cipher inputs
/// `s + δ·(base + row) + k_0` (built by the same affine-recurrence builder as
/// the arc weights), the link quotient binds `T`'s first column to `I^POW`,
/// and the decimation quotient binds `K` to `T`'s final column plus the
/// whitening `w`.
pub(crate) fn expansion_quotients(
    trace_coeffs: &[Fp],
    keyset: &NoteMasterKey,
    params: &ExpansionParams,
    key_coeffs: &[Fp],
    base: Fp,
) -> (
    [Polynomial; EXPANSION_ROUND_SPLITS],
    ExpansionInputSpectrum,
    Polynomial,
    Polynomial,
    Polynomial,
) {
    let trace_ext = coset_evaluations(trace_coeffs, ROUND_COSET, COSET_SHIFT);
    let round = expansion_round_quotient(&trace_ext, keyset);
    let origin = params.input(base) + keyset.round_key(0);
    let (input_coeffs, recurrence_coeffs) =
        affine_recurrence_inner::<EK_PART_LENGTH>(Fp::ONE, params.stride, Fp::ONE, origin);
    let link = strided_column_quotient(
        trace_coeffs,
        &input_coeffs,
        Fp::ONE,
        Fp::ZERO,
        TachyonP5R32::POW,
    );
    let final_column_stride =
        subgroup_generator::<POLY_LEN_MAX>().pow_vartime([(TachyonP5R32::ROUNDS - 1) as u64]);
    let decimation =
        strided_column_quotient(trace_coeffs, key_coeffs, final_column_stride, params.whitening, 1);
    (
        round,
        ExpansionInputSpectrum(Polynomial::from_coeffs(&input_coeffs)),
        Polynomial::from_coeffs(&recurrence_coeffs),
        link,
        decimation,
    )
}

/// The challenge-free masked-quintic transition quotient `Q_round`, as
/// [`EXPANSION_ROUND_SPLITS`] adjacent splits. Builds the round numerator
/// `mask·(T(gX) − (T + offset)^5)` on the quintic coset and divides by `Z_D`.
pub(crate) fn expansion_round_quotient(
    trace_ext: &[Fp],
    keyset: &NoteMasterKey,
) -> [Polynomial; EXPANSION_ROUND_SPLITS] {
    // Per-column offset `round_key(col + 1) + CONSTANTS[(col + 1) % ROUNDS]`,
    // evaluated on the quintic coset. The transition out of column `col`
    // produces round `col + 1` (cell `col` is round `col`'s output, with the
    // salted input held outside the trace and pinned by the boundary), so
    // column `col` carries round `col + 1`'s offset; the masked row-wrap
    // column carries the periodic `k_0` (`c_0 = 0`), matching the committed
    // reconstruction.
    //
    // The offset is affine in the round keys and ifft/spread/coset_evaluations
    // are linear, so its coset evaluation needs no per-call FFT: it is the
    // cached keyset-independent basis (OFFSET_CONST_EXT, OFFSET_KEY_EXT)
    // combined with the per-call `round_key(r)` scalars, bit-identical by field
    // linearity. The keys enter only in this combine, never the cache.
    let offset_ext: Vec<Fp> = {
        let const_ext: &[Fp] = &OFFSET_CONST_EXT;
        let key_ext: &[Vec<Fp>] = &OFFSET_KEY_EXT;
        (0..ROUND_COSET)
            .map(|point| {
                let mut value = const_ext[point];
                for (residue, basis) in key_ext.iter().enumerate() {
                    value += keyset.0[residue % keyset.0.len()] * basis[point];
                }
                value
            })
            .collect()
    };

    // The output-cell mask is keyset-independent: built once (see MASK_EXT).
    let mask_ext: &[Fp] = &MASK_EXT;

    let quotient = coset_quotient(ROUND_COSET, |point| {
        let cipher_in = trace_ext[point] + offset_ext[point];
        // T(gX) is trace_ext rotated cyclically by ROW_STEP.
        let shifted = trace_ext[(point + ROW_STEP) % ROUND_COSET];
        mask_ext[point] * (shifted - cipher_in.pow_vartime([TachyonP5R32::POW]))
    });
    assert!(
        quotient.len() <= EXPANSION_ROUND_SPLITS * POLY_LEN_MAX,
        "round quotient exceeds the split budget",
    );
    split_coeffs::<EXPANSION_ROUND_SPLITS>(&quotient, POLY_LEN_MAX)
}

/// The strided-column quotient `Q = (C(X)^e − offset − M(σX)) /
/// (X^EK_PART_LENGTH − 1)` binding a low-degree column poly `C` to a strided
/// column of the trace `M` — the identity `enforce_strided_column` checks.
/// The numerator vanishes on the order-`EK_PART_LENGTH` subgroup `⟨ζ⟩` exactly
/// when `C(ζ^r)^e = M(σ·ζ^r) + offset`, so exact division certifies the
/// column. Two callers: the decimation binding (`C = K`, `σ` the final-column
/// stride, `offset = w`, `e = 1`) and the round-0 input link (`C = I`,
/// `σ = 1`, `offset = 0`, `e = POW`).
pub(crate) fn strided_column_quotient(
    trace_coeffs: &[Fp],
    column_coeffs: &[Fp],
    stride: Fp,
    offset: Fp,
    exponent: u64,
) -> Polynomial {
    // C(X)^e by repeated products (the exponent is a tiny S-box degree).
    let mut powered = vec![Fp::ONE];
    for _ in 0..exponent {
        powered = multiply(&powered, column_coeffs);
    }

    // numerator(X) = C(X)^e − offset − M(σX): coefficient `i` of `M(σX)` is
    // `σ^i·trace_coeffs[i]`, with `offset` removed from the constant term.
    let mut numerator = vec![Fp::ZERO; trace_coeffs.len().max(powered.len())];
    let mut stride_power = Fp::ONE;
    for (degree, slot) in numerator.iter_mut().enumerate() {
        let column = powered.get(degree).copied().unwrap_or(Fp::ZERO);
        let trace = trace_coeffs.get(degree).copied().unwrap_or(Fp::ZERO);
        *slot = column - stride_power * trace;
        stride_power *= stride;
    }
    if let Some(constant) = numerator.first_mut() {
        *constant -= offset;
    }

    let (quotient, remainder) = divide_by_vanishing(&numerator, EK_PART_LENGTH);
    assert!(
        remainder.iter().all(|coeff| *coeff == Fp::ZERO),
        "strided-column numerator is not divisible by Z_<zeta>: column poly mismatches the trace",
    );
    Polynomial::from_coeffs(&quotient)
}

/// Spread `coeffs` by the column stride: place coefficient `k` at degree
/// `k·EK_PART_LENGTH`, zero elsewhere. `coeffs.len()` must not exceed
/// `TRACE_COLUMNS`.
fn spread_by_stride(coeffs: &[Fp]) -> Vec<Fp> {
    let mut spread = vec![Fp::ZERO; SPREAD_LEN];
    for (column, &coeff) in coeffs.iter().enumerate() {
        spread[column * EK_PART_LENGTH] = coeff;
    }
    spread
}

/// Build a numerator from its coset evaluations `numerator(point)` over the
/// `size`-point coset domain, then divide by `Z_D` (asserting exact division).
fn coset_quotient(size: usize, numerator: impl Fn(usize) -> Fp) -> Vec<Fp> {
    let evaluations: Vec<Fp> = (0..size).map(numerator).collect();
    expansion_quotient_coeffs(&coset_coefficients(evaluations))
}

/// Divide an expansion numerator by `Z_D` and assert exact divisibility (a
/// nonzero remainder means the trace violates the constraint), returning the
/// quotient coefficients.
fn expansion_quotient_coeffs(numerator: &[Fp]) -> Vec<Fp> {
    let (quotient, remainder) = divide_by_vanishing(numerator, POLY_LEN_MAX);
    assert!(
        remainder.iter().all(|coeff| *coeff == Fp::ZERO),
        "expansion numerator is not divisible by Z_D: the trace violates a constraint",
    );
    quotient
}

#[cfg(test)]
#[expect(
    clippy::as_conversions,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "test code"
)]
mod tests {
    use core::array;

    use pasta_curves::Fp;
    use ragu::{Domain, Polynomial};
    use zcash_mimc::spec::tachyon::TachyonP5R8192;

    use super::*;
    use crate::{
        keys::NoteMasterKey, primitives::NfEmitterSpectrum, relations::subgroup_generator,
    };

    #[test]
    fn expansion_quotients_fit_the_pow_derived_cosets() {
        // Guards the POW-derived ROUND_COSET sizing without proving: building
        // the expansion witness polynomials on a real keyset runs their
        // internal `divide_by_vanishing` divisibility asserts, which fire if a
        // coset is too small for its numerator (coefficients alias). Also pins
        // the derived size, so a cipher/POLY_LEN_MAX change that would
        // under-size it is caught here rather than only in the slow prover.
        assert_eq!(ROUND_COSET, 1 << 16, "round-numerator coset");

        let mk = NoteMasterKey(array::from_fn(|index| Fp::from(index as u64 + 1)));
        let params = mk.expansion_params();
        let (states, part_keys) = mk.derive_schedule_part(0);
        let spectrum = states.spectrum();
        let key_poly = part_keys.key_spectrum();
        let (round, input_column, input_quotient, link, decimation) = expansion_quotients(
            spectrum.0.coefficients(),
            &mk,
            &params,
            key_poly.0.coefficients(),
            Fp::ZERO,
        );

        assert_eq!(round.len(), EXPANSION_ROUND_SPLITS);
        assert!(
            input_column.0.coefficients().len() <= EK_PART_LENGTH,
            "input column is a row-subgroup interpolant"
        );
        assert!(
            link.coefficients().len() <= POLY_LEN_MAX,
            "link quotient fits one split"
        );
        assert!(
            decimation.coefficients().len() <= POLY_LEN_MAX,
            "decimation quotient fits one split"
        );

        // The link identity at an off-domain challenge, production sizes:
        // I(z)^5 − T(z) = Q(z)·(z^EK_PART_LENGTH − 1). This is the identity
        // `enforce_strided_column` checks at the S-box exponent.
        let z = Fp::from(4321u64);
        let input_at_z = input_column.0.eval(z);
        let powered = input_at_z.square().square() * input_at_z;
        assert_eq!(
            powered - spectrum.0.eval(z),
            link.eval(z) * (z.pow_vartime([EK_PART_LENGTH as u64]) - Fp::ONE),
            "link identity must hold at the challenge"
        );

        // The input column's affine-recurrence identity at the same challenge:
        // (z − ζ^{-1})·(I(ζz) − I(z) − δ) = Q(z)·(z^EK_PART_LENGTH − 1), plus
        // the boundary I(1) = s + k_0 (part 0: base = 0).
        let zeta = subgroup_generator::<EK_PART_LENGTH>();
        let wrap = zeta.invert().expect("a root of unity is nonzero");
        assert_eq!(
            (z - wrap) * (input_column.0.eval(zeta * z) - input_at_z - params.stride),
            input_quotient.eval(z) * (z.pow_vartime([EK_PART_LENGTH as u64]) - Fp::ONE),
            "input recurrence identity must hold at the challenge"
        );
        assert_eq!(
            input_column.0.eval(Fp::ONE),
            params.input(Fp::ZERO) + mk.round_key(0),
            "input column origin must be s + k_0"
        );
    }

    #[test]
    fn affine_recurrence_interpolates_the_orbit_on_a_tiny_coset() {
        // The generalized builder on the arithmetic orbit (scale 1, step δ,
        // shift 1): seq(ζ^d) = origin + δ·d over the order-8 subgroup, and the
        // masked identity holds at an off-domain challenge.
        const SMALL_N: usize = 8;
        let step = Fp::from(3u64);
        let origin = Fp::from(11u64);
        let (sequence_vec, quotient_vec) =
            affine_recurrence_inner::<SMALL_N>(Fp::ONE, step, Fp::ONE, origin);

        let zeta = Domain::new(SMALL_N.ilog2()).omega();
        let sequence = Polynomial::from_coeffs(&sequence_vec);
        let quotient = Polynomial::from_coeffs(&quotient_vec);

        for index in 0..SMALL_N {
            assert_eq!(
                sequence.eval(zeta.pow_vartime([index as u64])),
                origin + step * Fp::from(index as u64),
                "seq must interpolate the affine orbit on the subgroup"
            );
        }

        let wrap = zeta.pow_vartime([(SMALL_N - 1) as u64]);
        let z = Fp::from(123u64);
        assert_eq!(
            (z - wrap) * (sequence.eval(zeta * z) - sequence.eval(z) - step),
            quotient.eval(z) * (z.pow_vartime([SMALL_N as u64]) - Fp::ONE),
            "masked affine recurrence must hold at the challenge"
        );
    }

    #[test]
    fn round_quotient_identity_holds_on_a_tiny_domain() {
        // A synthetic degree-5 recurrence on an 8-point domain (the production
        // identity at a tractable size): states[j+1] = (states[j] + O(omega^j))^5,
        // the wrap entry O(omega^7) masked out.
        const DOMAIN: usize = 8;
        const POW: u64 = 5;
        const SPLITS: usize = 4;

        let offsets: [Fp; DOMAIN] = [
            Fp::from(1u64),
            Fp::from(2u64),
            Fp::from(3u64),
            Fp::from(4u64),
            Fp::from(5u64),
            Fp::from(6u64),
            Fp::from(7u64),
            Fp::ZERO,
        ];
        let mut states = [Fp::ZERO; DOMAIN];
        states[0] = Fp::from(9u64);
        for index in 1..DOMAIN {
            let cipher_in = states[index - 1] + offsets[index - 1];
            states[index] = cipher_in.square().square() * cipher_in;
        }

        let mut trace_coeffs = states.to_vec();
        Domain::new(DOMAIN.ilog2()).ifft(&mut trace_coeffs);
        let trace = Polynomial::from_coeffs(&trace_coeffs);
        let splits = round_quotient_inner::<DOMAIN, POW, SPLITS>(&trace_coeffs, &offsets);

        let mut offset_coeffs = offsets.to_vec();
        Domain::new(DOMAIN.ilog2()).ifft(&mut offset_coeffs);
        let offset_poly = Polynomial::from_coeffs(&offset_coeffs);
        let omega = Domain::new(DOMAIN.ilog2()).omega();
        let wrap_root = omega.invert().expect("a root of unity is nonzero");

        let z = Fp::from(13u64);
        let stride = z.pow_vartime([DOMAIN as u64]);
        let mut quotient_at_z = Fp::ZERO;
        let mut shift = Fp::ONE;
        for split in &splits {
            quotient_at_z += shift * split.eval(z);
            shift *= stride;
        }
        let cipher_in = trace.eval(z) + offset_poly.eval(z);
        let residual = trace.eval(omega * z) - cipher_in.square().square() * cipher_in;
        assert_eq!(
            (z - wrap_root) * residual,
            quotient_at_z * (stride - Fp::ONE),
            "round recurrence identity must hold on the tiny domain"
        );
    }

    #[test]
    fn offsets_follow_the_shifted_constant_and_cyclic_key_schedule() {
        let round_keys = [
            Fp::from(11u64),
            Fp::from(22u64),
            Fp::from(33u64),
            Fp::from(44u64),
        ];
        let rk_offsets = offsets(&round_keys);
        let constants = TachyonP5R8192::CONSTANTS;

        // O(omega^j) = c_{(j+1) mod |D|} + round_keys[(j+1) mod 4].
        assert_eq!(
            rk_offsets[0],
            constants[1] + round_keys[1],
            "j=0: c_1 + k_1"
        );
        assert_eq!(
            rk_offsets[5],
            constants[6] + round_keys[2],
            "j=5: c_6 + k_(6 mod 4)"
        );
        // The wrap uses the periodic convention: c_0 + k_0 = 0 + k_0 = k_0.
        assert_eq!(
            rk_offsets[TachyonP5R8192::ROUNDS - 1],
            round_keys[0],
            "the row-wrap offset is the periodic k_0"
        );
    }

    #[test]
    fn boundary_quotient_pins_the_first_state_on_a_tiny_domain() {
        // The boundary pins T(1) = B = (mk_s + k_0)^5; build a tiny T whose first
        // evaluation is B (the rest arbitrary, since the boundary constrains only
        // the first cell).
        const DOMAIN: usize = 8;
        let salt = Fp::from(5u64);
        let first_key = Fp::from(11u64);
        let alpha = salt + first_key;
        let boundary = alpha.square().square() * alpha;

        let states = [
            boundary,
            Fp::from(2u64),
            Fp::from(3u64),
            Fp::from(4u64),
            Fp::from(5u64),
            Fp::from(6u64),
            Fp::from(7u64),
            Fp::from(8u64),
        ];
        let mut trace_coeffs = states.to_vec();
        Domain::new(DOMAIN.ilog2()).ifft(&mut trace_coeffs);
        let trace = Polynomial::from_coeffs(&trace_coeffs);
        let quotient = boundary_quotient(&trace_coeffs, salt, first_key);

        let z = Fp::from(9u64);
        assert_eq!(
            trace.eval(z) - boundary,
            quotient.eval(z) * (z - Fp::ONE),
            "boundary identity must hold at the challenge"
        );
    }

    #[test]
    fn query_coset_has_order_s_and_contains_the_state_domain() {
        // gamma generates the order-S = NF_DOMAIN coset group; the state
        // domain ⟨omega⟩ (order 2^13) sits inside it as omega = gamma^2.
        let gamma = subgroup_generator::<NF_DOMAIN>();
        let order = NF_DOMAIN as u64;
        assert_eq!(gamma.pow_vartime([order]), Fp::ONE, "gamma^S = 1");
        assert_ne!(
            gamma.pow_vartime([order / 2]),
            Fp::ONE,
            "gamma has order exactly S, not S/2"
        );
        let state_omega = Domain::new(TachyonP5R8192::ROUNDS.ilog2()).omega();
        assert_eq!(gamma.square(), state_omega, "omega = gamma^2");
    }

    #[test]
    fn nullifier_query_advances_point_and_weights_independently() {
        // nf_d = sum_j rho_j^d·T_j(c·gamma^d). Build N real cipher polys, then check
        // the query against a reference that advances the point by gamma and
        // the weights by rho_j through repeated multiplication (independent of
        // the fn's pow).
        let polys: [NfEmitterSpectrum; NF_EMITTERS] = array::from_fn(|poly| {
            let base = poly as u64;
            let keys = [
                Fp::from(base + 1),
                Fp::from(base + 2),
                Fp::from(base + 3),
                Fp::from(base + 4),
            ];
            NfEmitterSpectrum(Polynomial::from_coeffs(&zcash_mimc::state_sequence::<
                TachyonP5R8192,
                Fp,
                5,
                8192,
            >(
                &keys, Fp::from(base + 5)
            )))
        });
        let shift = Fp::MULTIPLICATIVE_GENERATOR; // c ∉ ⟨gamma⟩
        let ratios: [Fp; NF_EMITTERS] = [
            Fp::from(2u64),
            Fp::from(3u64),
            Fp::from(5u64),
            Fp::from(7u64),
        ];
        let gamma = subgroup_generator::<NF_DOMAIN>();

        // Offset 0 anchors at the coset origin c with unit weights.
        let origin = polys
            .iter()
            .fold(Fp::ZERO, |sum, poly| sum + poly.0.eval(shift));
        assert_eq!(
            nullifier_query(&polys, QueryShift(shift), WeightRatios(ratios), gamma, 0),
            origin,
            "offset 0 reads sum_j T_j(c) with unit weights"
        );

        // Offset d: independent reference via repeated multiplication.
        let offset = 5u64;
        let mut point = shift;
        let mut weights = [Fp::ONE; NF_EMITTERS];
        for _ in 0..offset {
            point *= gamma;
            for (weight, ratio) in weights.iter_mut().zip(&ratios) {
                *weight *= ratio;
            }
        }
        let reference = polys
            .iter()
            .zip(&weights)
            .fold(Fp::ZERO, |sum, (poly, weight)| {
                sum + *weight * poly.0.eval(point)
            });
        assert_eq!(
            nullifier_query(
                &polys,
                QueryShift(shift),
                WeightRatios(ratios),
                gamma,
                offset,
            ),
            reference,
            "nf_d must read T_j at c*gamma^d with weight rho_j^d"
        );
    }

    #[test]
    fn weight_recurrence_holds_on_a_tiny_coset() {
        // w(c·gamma^d) = ratio^d over the order-8 coset; the masked recurrence
        // w(gammaz) = ratio·w(z) holds off the wrap, with quotient by z^S − c^S.
        const SMALL_N: usize = 8;
        let ratio = Fp::from(6u64); // rho_j·β
        let shift = Fp::MULTIPLICATIVE_GENERATOR; // c ∉ ⟨gamma⟩
        let (weight_vec, quotient_vec) =
            affine_recurrence_inner::<SMALL_N>(ratio, Fp::ZERO, shift, Fp::ONE);

        let gamma = Domain::new(SMALL_N.ilog2()).omega();
        let weight = Polynomial::from_coeffs(&weight_vec);
        let quotient = Polynomial::from_coeffs(&quotient_vec);

        // Interpolation: w(c·gamma^d) = ratio^d.
        for exponent in 0..SMALL_N {
            assert_eq!(
                weight.eval(shift * gamma.pow_vartime([exponent as u64])),
                ratio.pow_vartime([exponent as u64]),
                "w must interpolate ratio^d on the coset"
            );
        }

        // Masked recurrence identity at an off-coset challenge.
        let wrap_point = shift * gamma.pow_vartime([(SMALL_N - 1) as u64]);
        let z = Fp::from(123u64);
        let lhs = (z - wrap_point) * (weight.eval(gamma * z) - ratio * weight.eval(z));
        let rhs = quotient.eval(z)
            * (z.pow_vartime([SMALL_N as u64]) - shift.pow_vartime([SMALL_N as u64]));
        assert_eq!(
            lhs, rhs,
            "masked weight recurrence must hold at the challenge"
        );
    }

    #[test]
    fn accumulator_recurrence_and_range_hold_on_a_tiny_coset() {
        // Synthetic low-degree T_j on an order-8 coset (decoupling the
        // accumulator logic from the full-size derivation polys). Verifies the
        // masked recurrence, the boundary A(c) = nf_0, and that the endpoint
        // difference A(p_{end-1}) − A(p_{start-1}) is the β-weighted nullifier
        // sum over [start, end).
        const SMALL_N: usize = 8;
        const POLYS: usize = 2;
        let t0 = [Fp::from(2u64), Fp::from(3u64), Fp::from(5u64)];
        let t1 = [Fp::from(7u64), Fp::from(11u64)];
        let tc: [&[Fp]; POLYS] = [&t0, &t1];
        let t_coeffs = tc.map(|coeffs| NfEmitterSpectrum(Polynomial::from_coeffs(coeffs)));
        let ratios = [Fp::from(4u64), Fp::from(6u64)];
        let shift = Fp::MULTIPLICATIVE_GENERATOR;
        let beta = Fp::from(9u64);

        let (accumulator, recurrence, boundary) =
            accumulator_quotient_inner::<SMALL_N, POLYS>(&t_coeffs, &ratios, shift, beta);

        let gamma = Domain::new(SMALL_N.ilog2()).omega();
        let acc = Polynomial::from_coeffs(&accumulator);
        let q_recurrence = Polynomial::from_coeffs(&recurrence);
        let q_boundary = Polynomial::from_coeffs(&boundary);
        let two = [Polynomial::from_coeffs(&t0), Polynomial::from_coeffs(&t1)];
        let weights: [Polynomial; POLYS] = array::from_fn(|poly| {
            let (weight, _) =
                affine_recurrence_inner::<SMALL_N>(ratios[poly] * beta, Fp::ZERO, shift, Fp::ONE);
            Polynomial::from_coeffs(&weight)
        });

        // Independent nf_k = sum_j rho_j^k·T_j(c·gamma^k).
        let nullifier = |offset: u64| -> Fp {
            let point = shift * gamma.pow_vartime([offset]);
            (0..POLYS).fold(Fp::ZERO, |sum, poly| {
                sum + ratios[poly].pow_vartime([offset]) * two[poly].eval(point)
            })
        };

        let z = Fp::from(123u64);

        // Boundary: A(c) = 0 (exclusive prefix's empty sum at the origin).
        assert_eq!(
            acc.eval(z),
            q_boundary.eval(z) * (z - shift),
            "boundary A(c) = 0 must hold at the challenge"
        );

        // Masked recurrence: A(gammaz) − A(z) = sum_j w_j(z)·T_j(z) (RHS at z).
        let wrap_point = shift * gamma.pow_vartime([(SMALL_N - 1) as u64]);
        let rhs_at_z = (0..POLYS).fold(Fp::ZERO, |sum, poly| {
            sum + weights[poly].eval(z) * two[poly].eval(z)
        });
        let lhs = (z - wrap_point) * (acc.eval(gamma * z) - acc.eval(z) - rhs_at_z);
        let rhs = q_recurrence.eval(z)
            * (z.pow_vartime([SMALL_N as u64]) - shift.pow_vartime([SMALL_N as u64]));
        assert_eq!(
            lhs, rhs,
            "masked accumulator recurrence must hold at the challenge"
        );

        // Range read [start, end): exclusive-prefix endpoint difference
        // A(p_end) − A(p_start). An origin-rooted arc start = 0 reads its left
        // endpoint at the coset origin (A(c) = 0), never the wrap.
        let range_read = |start: u64, end: u64| {
            acc.eval(shift * gamma.pow_vartime([end]))
                - acc.eval(shift * gamma.pow_vartime([start]))
        };
        let expected = |start: u64, end: u64| {
            (start..end).fold(Fp::ZERO, |sum, offset| {
                sum + beta.pow_vartime([offset]) * nullifier(offset)
            })
        };
        assert_eq!(
            range_read(2, 5),
            expected(2, 5),
            "mid-sequence range [2, 5)"
        );
        assert_eq!(
            range_read(0, 4),
            expected(0, 4),
            "origin-rooted arc [0, 4) reads the origin, not the wrap"
        );
    }
}
