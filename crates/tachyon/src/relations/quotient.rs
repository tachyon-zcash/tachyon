//! Off-circuit native preparation of the trace-based witness quotients.
//!
//! One module for every quotient the proof system opens against the
//! `relations` enforcers, all for one cipher family: the `GGM_TREE_ARITY ×
//! ROUNDS` node-expansion trace (`TachyonP5R128`, `ROUNDS` columns by
//! `GGM_TREE_ARITY` rows), with the masked round quotient, the boundary
//! quotient, and the decimation quotient binding the output polynomial to the
//! trace's final column.
//!
//! The generic coset-arithmetic layer (FFT evaluation, vanishing-polynomial
//! division, capacity splitting) is defined at the top of the module; no
//! cipher-specific structure lives in those helpers.

#![allow(
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "dense constant-size coset arithmetic"
)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::array;

use ff::{Field as _, PrimeField as _};
use lazy_static::lazy_static;
use pasta_curves::Fp;
use ragu::{Domain, Polynomial};
use zcash_mimc::spec::tachyon::TachyonP5R128;

use super::subgroup_generator;
use crate::{
    constants::{MK_LENGTH, POLY_LEN_MAX},
    keys::{ExpansionParams, GGM_TREE_ARITY},
    primitives::CONSTANT_SCHEDULE,
};

/// Round and boundary quotients for one expansion trace: the masked round
/// quotient (as `N = EXPANSION_ROUND_SPLITS` capacity-wide splits) and the
/// boundary quotient.
#[derive(Clone, Debug)]
pub struct RoundBoundaryQuotients<const N: usize> {
    /// The masked round quotient's capacity-wide splits.
    pub round: [Polynomial; N],
    /// The first-column boundary quotient.
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

/// Exact division by `X^domain − 1`, returning `(quotient, remainder)` with
/// `remainder.len() <= domain`.
fn divide_by_vanishing(poly: &[Fp], domain: usize) -> (Vec<Fp>, Vec<Fp>) {
    if poly.len() <= domain {
        return (Vec::new(), poly.to_vec());
    }
    let mut remainder = poly.to_vec();
    let mut quotient = vec![Fp::ZERO; poly.len() - domain];
    for degree in (domain..poly.len()).rev() {
        let coeff = remainder[degree];
        quotient[degree - domain] += coeff;
        remainder[degree - domain] += coeff;
        remainder[degree] = Fp::ZERO;
    }
    remainder.truncate(domain);
    (quotient, remainder)
}

/// Carve `coeffs` into `SPLITS` adjacent `width`-wide pieces, the
/// commitment-capacity splits the circuit recombines by Horner in `z^width`. A
/// polynomial spanning more than one commitment's capacity (a round quotient)
/// cannot ride one commitment, so it is committed and opened this way.
fn split_coeffs<const SPLITS: usize>(coeffs: &[Fp], width: usize) -> [Polynomial; SPLITS] {
    array::from_fn(|split| {
        let lo = split * width;
        let hi = ((split + 1) * width).min(coeffs.len());
        Polynomial::from_coeffs(if lo < hi { &coeffs[lo..hi] } else { &[] })
    })
}

// ---------------------------------------------------------------------------
// Node-expansion trace (GGM_TREE_ARITY x ROUNDS, TachyonP5R128)
// ---------------------------------------------------------------------------

/// Committed splits of the expansion trace's masked round quotient. The
/// numerator has degree `POW·(DOMAIN-1) + GGM_TREE_ARITY` (the
/// degree-`GGM_TREE_ARITY` output-cell mask), so over the degree-`DOMAIN`
/// vanisher the quotient spans this many capacity-wide splits. Derived from
/// `POW`.
pub(crate) const EXPANSION_ROUND_SPLITS: usize = {
    #[expect(clippy::cast_possible_truncation, reason = "constant size")]
    let numerator_len = TachyonP5R128::POW as usize * (POLY_LEN_MAX - 1) + GGM_TREE_ARITY + 1;
    (numerator_len - POLY_LEN_MAX).div_ceil(POLY_LEN_MAX)
};

/// Round-numerator eval coset. Sized from `POW` to cover the
/// degree-`POW·(DOMAIN-1) + GGM_TREE_ARITY` numerator (the
/// degree-`GGM_TREE_ARITY` output-cell mask) exactly.
#[expect(clippy::cast_possible_truncation, reason = "constant size")]
const ROUND_COSET: usize =
    (TachyonP5R128::POW as usize * (POLY_LEN_MAX - 1) + GGM_TREE_ARITY + 1).next_power_of_two();

/// Boundary-numerator eval coset. The boundary numerator is `complement ·
/// (T − target)`: `complement` has degree `(ROUNDS-1)·GGM_TREE_ARITY`, `T`
/// degree `< POLY_LEN_MAX`, `target` degree `< GGM_TREE_ARITY`, so the product
/// has degree `(ROUNDS-1)·GGM_TREE_ARITY + POLY_LEN_MAX − 1`; the coset covers
/// its `degree + 1` coefficients.
const BOUNDARY_COSET: usize =
    ((TachyonP5R128::ROUNDS - 1) * GGM_TREE_ARITY + POLY_LEN_MAX).next_power_of_two();

/// Row step: the round-coset-to-trace size ratio. `T(gX)` on the round coset
/// is `trace_ext` rotated by this, since ω_trace = ω_round^ROW_STEP.
const ROW_STEP: usize = ROUND_COSET / POLY_LEN_MAX;

/// Decimation stride: the round-coset-to-boundary-coset size ratio. The
/// boundary-coset evaluations are every REDUCE_STRIDE-th round-coset one,
/// since ω_boundary = ω_round^REDUCE_STRIDE.
const REDUCE_STRIDE: usize = ROUND_COSET / BOUNDARY_COSET;

/// Length of a column-stride spread: coefficient `k` of a `ROUNDS`-term
/// polynomial lands at degree `k·GGM_TREE_ARITY`.
const SPREAD_LEN: usize = (TachyonP5R128::ROUNDS - 1) * GGM_TREE_ARITY + 1;

lazy_static! {
    /// Output-cell mask `M(X) = X^ROWS − column_root^{ROUNDS-1}` evaluated on
    /// the quintic coset. Schedule-independent, so it is built once.
    static ref MASK_EXT: Vec<Fp> = {
        let column_root = subgroup_generator::<{ TachyonP5R128::ROUNDS }>();
        let mut mask = vec![Fp::ZERO; GGM_TREE_ARITY + 1];
        mask[0] = -column_root.pow_vartime([(TachyonP5R128::ROUNDS - 1) as u64]);
        mask[GGM_TREE_ARITY] = Fp::ONE;
        coset_evaluations(&mask, ROUND_COSET, COSET_SHIFT)
    };

    /// Boundary complement `E(X) = Σ X^(ROWS·m)` evaluated on the reduced
    /// coset. Schedule-independent, so it is built once.
    static ref COMPLEMENT_EXT: Vec<Fp> = coset_evaluations(
        &spread_by_stride(&[Fp::ONE; TachyonP5R128::ROUNDS]),
        BOUNDARY_COSET,
        COSET_SHIFT,
    );

    /// Reduced-coset evaluations of the row-power interpolants, the cached
    /// basis that folds round 0 into the boundary without a per-call FFT.
    /// `ROW_POWER_EXT[j]` is the coset evaluation of the row-subgroup
    /// interpolant of `row^j`. The round-0 target `(alpha + δ·row)^POW` (with
    /// `alpha = s + δ·base + k_0`) expands by the binomial theorem into
    /// `Σ_j C(POW, j) · alpha^{POW−j} · δ^j · row^j`; since ifft and
    /// coset_evaluations are linear, its coset evaluation is this
    /// schedule-independent basis combined with per-call scalars (see
    /// `expansion_boundary_quotient`). Built once.
    static ref ROW_POWER_EXT: Vec<Vec<Fp>> = (0..=TachyonP5R128::POW)
        .map(|power| {
            let mut samples: Vec<Fp> = (0..GGM_TREE_ARITY as u64)
                .map(|row| Fp::from(row).pow_vartime([power]))
                .collect();
            Domain::new(GGM_TREE_ARITY.ilog2()).ifft(&mut samples);
            coset_evaluations(&samples, BOUNDARY_COSET, COSET_SHIFT)
        })
        .collect();

    /// Quintic-coset evaluations of the round offset's constants part: the
    /// public [`struct@CONSTANT_SCHEDULE`] evaluated on the round coset, with
    /// no key material. The schedule-independent half of the cached
    /// `offset_ext` basis (see `expansion_round_quotient`), shared by both
    /// offset conventions: the in-step offsets array zeroes the wrap entry
    /// and the committed `C` is built with the same zeroed wrap. Derived from
    /// the one committed polynomial the circuit opens, so the two sides
    /// cannot drift. Built once.
    static ref OFFSET_CONST_EXT: Vec<Fp> = coset_evaluations(
        CONSTANT_SCHEDULE.coefficients(),
        ROUND_COSET,
        COSET_SHIFT,
    );

    /// Quintic-coset evaluations of the round offset's per-key selector
    /// bases for the root schedule width, one per round-key residue class
    /// mod `MK_LENGTH`. `basis[r]` is `1` at every column whose offset adds
    /// `keys[r]` (i.e. `(col + 1) % MK_LENGTH == r`, the row-wrap column
    /// excepted) and `0` elsewhere — pure structure, no key material. The
    /// per-call combine scales each by `keys[r]` (see
    /// `expansion_round_quotient`). The zeroed wrap matches the in-step
    /// offsets array `enforce_row_recurrence` interpolates, whose wrap entry
    /// is zero. Built once.
    static ref OFFSET_KEY_EXT_ROOT: Vec<Vec<Fp>> = offset_key_basis(MK_LENGTH, false);

    /// The node-schedule counterpart of [`OFFSET_KEY_EXT_ROOT`]: residue
    /// classes mod `GGM_TREE_ARITY`, with the wrap column *included* in its
    /// cyclic residue class (`(col + 1) % GGM_TREE_ARITY = 0`). The cyclic
    /// wrap matches the key interpolant `K(ζ·z^{|D|/κ})` that
    /// `enforce_committed_offset_recurrence` reconstructs — a cyclic
    /// interpolant has no zeroed entry, and the wrap step stays masked either
    /// way. Built once.
    static ref OFFSET_KEY_EXT_NODE: Vec<Vec<Fp>> = offset_key_basis(GGM_TREE_ARITY, true);
}

/// The per-key selector bases for a cyclic schedule of the given width.
/// `cyclic_wrap` selects the wrap-column convention: `false` zeroes it (the
/// scalar-offset pairing), `true` keeps its cyclic residue (the
/// committed-offset pairing).
fn offset_key_basis(schedule_len: usize, cyclic_wrap: bool) -> Vec<Vec<Fp>> {
    (0..schedule_len)
        .map(|residue| {
            let selector: Vec<Fp> = (0..TachyonP5R128::ROUNDS)
                .map(|col| {
                    if (cyclic_wrap || col + 1 < TachyonP5R128::ROUNDS)
                        && (col + 1) % schedule_len == residue
                    {
                        Fp::ONE
                    } else {
                        Fp::ZERO
                    }
                })
                .collect();
            offset_basis_ext(&selector)
        })
        .collect()
}

/// Apply the schedule-independent offset transform to per-column `values`:
/// interpolate over the column subgroup, spread by the column stride, and
/// evaluate on the quintic coset. Linear, so it builds each cached
/// `offset_ext` basis (see `expansion_round_quotient`).
fn offset_basis_ext(values: &[Fp]) -> Vec<Fp> {
    let mut coeffs = values.to_vec();
    Domain::new(TachyonP5R128::ROUNDS.ilog2()).ifft(&mut coeffs);
    coset_evaluations(&spread_by_stride(&coeffs), ROUND_COSET, COSET_SHIFT)
}

/// Prover-side bundle of an expansion step's three witness quotients, from
/// the coefficient vectors of the trace poly `T` and the eval-form output
/// poly `K`. `keys` is the expanding node's cyclic round-key schedule (the
/// root's `MK_LENGTH` keys or a node's `GGM_TREE_ARITY` keys) and `params`
/// its expansion-input parameters `(s, δ, w)`; `base = GGM_TREE_ARITY·chunk`
/// is the child's cipher-input window origin (zero for a leaf).
/// Builds the shared quintic-coset trace evaluation once and returns
/// `(round splits, boundary, decimation)`, matching what the expansion steps
/// open: cipher input `s + δ·(base + row)`, first key `keys[0]`, whitening
/// `w`.
pub(crate) fn expansion_quotients(
    trace_coeffs: &[Fp],
    keys: &[Fp],
    params: &ExpansionParams,
    output_coeffs: &[Fp],
    base: Fp,
) -> ([Polynomial; EXPANSION_ROUND_SPLITS], Polynomial, Polynomial) {
    let trace_ext = coset_evaluations(trace_coeffs, ROUND_COSET, COSET_SHIFT);
    let round = expansion_round_quotient(&trace_ext, keys);
    let boundary =
        expansion_boundary_quotient(&trace_ext, params.input(base) + keys[0], params.stride);
    let decimation = expansion_decimation_quotient(trace_coeffs, output_coeffs, params.whitening);
    (round, boundary, decimation)
}

/// The challenge-free masked-quintic transition quotient `Q_round`, as
/// [`EXPANSION_ROUND_SPLITS`] adjacent splits. Builds the round numerator
/// `mask·(T(gX) − (T + offset)^5)` on the quintic coset and divides by `Z_D`.
#[expect(
    clippy::panic,
    reason = "an unsupported schedule width is a prover-side bug"
)]
pub(crate) fn expansion_round_quotient(
    trace_ext: &[Fp],
    keys: &[Fp],
) -> [Polynomial; EXPANSION_ROUND_SPLITS] {
    // Per-column offset `keys[(col + 1) % len] + CONSTANTS[col + 1]`,
    // evaluated on the quintic coset. The transition out of column `col`
    // produces round `col + 1` (cell `col` is round `col`'s output, with the
    // salted input held outside the trace and pinned by the boundary), so
    // column `col` carries round `col + 1`'s offset; the row-wrap column is
    // zeroed.
    //
    // The offset is affine in the round keys and ifft/spread/coset_evaluations
    // are linear, so its coset evaluation needs no per-call FFT: it is the
    // cached schedule-independent basis (OFFSET_CONST_EXT plus the residue
    // selectors for this schedule width) combined with the per-call `keys[r]`
    // scalars, bit-identical by field linearity. The keys enter only in this
    // combine, never the cache.
    let key_ext: &[Vec<Fp>] = match keys.len() {
        MK_LENGTH => &OFFSET_KEY_EXT_ROOT,
        GGM_TREE_ARITY => &OFFSET_KEY_EXT_NODE,
        len => panic!("no offset-key basis for schedule width {len}"),
    };
    let offset_ext: Vec<Fp> = {
        let const_ext: &[Fp] = &OFFSET_CONST_EXT;
        (0..ROUND_COSET)
            .map(|point| {
                let mut value = const_ext[point];
                for (residue, basis) in key_ext.iter().enumerate() {
                    value += keys[residue % keys.len()] * basis[point];
                }
                value
            })
            .collect()
    };

    // The output-cell mask is schedule-independent: built once (see MASK_EXT).
    let mask_ext: &[Fp] = &MASK_EXT;

    let quotient = coset_quotient(ROUND_COSET, |point| {
        let cipher_in = trace_ext[point] + offset_ext[point];
        // T(gX) is trace_ext rotated cyclically by ROW_STEP.
        let shifted = trace_ext[(point + ROW_STEP) % ROUND_COSET];
        mask_ext[point] * (shifted - cipher_in.pow_vartime([TachyonP5R128::POW]))
    });
    assert!(
        quotient.len() <= EXPANSION_ROUND_SPLITS * POLY_LEN_MAX,
        "round quotient exceeds the split budget",
    );
    split_coeffs::<EXPANSION_ROUND_SPLITS>(&quotient, POLY_LEN_MAX)
}

/// The challenge-free boundary quotient `Q_boundary` (one split): builds
/// `complement·(T − target)` on the reduced coset and divides by `Z_D`, where
/// `target` interpolates each row's round-0 output. Round 0 is folded into
/// the boundary here: `alpha = s + δ·base + k_0` collects the row-independent
/// input terms (with `c_0 = 0`), so round 0's S-box pins each first-column
/// cell to `(alpha + δ·row)^POW`.
///
/// The target's coset evaluation needs no per-call FFT: `(alpha + δ·row)^POW`
/// expands by the binomial theorem to
/// `Σ_j C(POW, j) · alpha^{POW−j} · δ^j · row^j`, so it is the cached
/// row-power basis [`ROW_POWER_EXT`] combined with the per-call scalars
/// `C(POW, j) · alpha^{POW−j} · δ^j`. This matches the values the step pins
/// via `enforce_first_column_values`.
pub(crate) fn expansion_boundary_quotient(trace_ext: &[Fp], alpha: Fp, stride: Fp) -> Polynomial {
    // `C(5, j)` for `j = 0..=5`.
    const BINOMIAL: [u64; 6] = [1, 5, 10, 10, 5, 1];
    const {
        assert!(
            TachyonP5R128::POW == 5,
            "boundary binomial coefficients assume the x^5 S-box"
        );
    }

    // The complement `E(X) = Σ X^(ROWS·m)` and the row-power basis are both
    // schedule-independent: built once (see COMPLEMENT_EXT, ROW_POWER_EXT).
    let complement_ext: &[Fp] = &COMPLEMENT_EXT;
    let row_power_ext: &[Vec<Fp>] = &ROW_POWER_EXT;

    // Per-call scalars `scale[j] = C(5, j) · alpha^{5−j} · δ^j`.
    let mut scale = [Fp::ZERO; BINOMIAL.len()];
    let mut alpha_power = Fp::ONE;
    for (degree, coefficient) in BINOMIAL.iter().enumerate().rev() {
        scale[degree] = Fp::from(*coefficient) * alpha_power;
        alpha_power *= alpha;
    }
    let mut stride_power = Fp::ONE;
    for weight in &mut scale {
        *weight *= stride_power;
        stride_power *= stride;
    }

    let quotient = coset_quotient(BOUNDARY_COSET, |point| {
        let target = scale
            .iter()
            .zip(row_power_ext.iter())
            .fold(Fp::ZERO, |acc, (weight, basis)| {
                acc + *weight * basis[point]
            });
        complement_ext[point] * (trace_ext[point * REDUCE_STRIDE] - target)
    });
    assert!(
        quotient.len() <= POLY_LEN_MAX,
        "boundary quotient exceeds one split"
    );
    Polynomial::from_coeffs(&quotient)
}

/// The decimation quotient `Q` binding the eval-form output poly `K` to the
/// trace's final column: `Q = (K(X) − w − T(σX)) / (X^GGM_TREE_ARITY − 1)`,
/// with the final-column stride `σ = ω^{ROUNDS-1}` (`ω` the
/// order-`POLY_LEN_MAX` root) and the whitening key `w`. The numerator
/// vanishes on the order-`GGM_TREE_ARITY` subgroup `⟨ζ⟩` (`ζ = ω^ROUNDS`)
/// exactly when `K(ζ^r) = (row-r final cell) + w`, so exact division
/// certifies the outputs. `output_coeffs` is the eval-form interpolant's
/// coefficient vector (degree `< GGM_TREE_ARITY`).
pub(crate) fn expansion_decimation_quotient(
    trace_coeffs: &[Fp],
    output_coeffs: &[Fp],
    whitening: Fp,
) -> Polynomial {
    let stride =
        subgroup_generator::<POLY_LEN_MAX>().pow_vartime([(TachyonP5R128::ROUNDS - 1) as u64]);

    // numerator(X) = K(X) − w − T(σX): coefficient `i` is `output_coeffs[i] −
    // σ^i·trace_coeffs[i]`, with `w` removed from the constant term.
    let mut numerator = vec![Fp::ZERO; trace_coeffs.len().max(output_coeffs.len())];
    let mut stride_power = Fp::ONE;
    for (degree, slot) in numerator.iter_mut().enumerate() {
        let key = output_coeffs.get(degree).copied().unwrap_or(Fp::ZERO);
        let trace = trace_coeffs.get(degree).copied().unwrap_or(Fp::ZERO);
        *slot = key - stride_power * trace;
        stride_power *= stride;
    }
    if let Some(constant) = numerator.first_mut() {
        *constant -= whitening;
    }

    let (quotient, remainder) = divide_by_vanishing(&numerator, GGM_TREE_ARITY);
    assert!(
        remainder.iter().all(|coeff| *coeff == Fp::ZERO),
        "decimation numerator is not divisible by Z_<zeta>: output poly mismatches the trace column",
    );
    Polynomial::from_coeffs(&quotient)
}

/// Spread `coeffs` by the column stride: place coefficient `k` at degree
/// `k·GGM_TREE_ARITY`, zero elsewhere. `coeffs.len()` must not exceed
/// `ROUNDS`.
fn spread_by_stride(coeffs: &[Fp]) -> Vec<Fp> {
    let mut spread = vec![Fp::ZERO; SPREAD_LEN];
    for (column, &coeff) in coeffs.iter().enumerate() {
        spread[column * GGM_TREE_ARITY] = coeff;
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

// ---------------------------------------------------------------------------
// Homomorphic eval->coeff bind
// ---------------------------------------------------------------------------

/// The running-sum accumulator `A` and degree-0 quotient `Q` for the
/// homomorphic eval->coeff bind [`enforce_evaluation_sum`]. `values_coeffs` is
/// the eval-form leaf interpolant `B` (degree `< ORDER`) and `weight` the
/// Horner challenge `β`.
///
/// `A` is the inclusive geometric suffix sum
/// `A(ζ^d) = Σ_{k≥d} B(ζ^k)·β^{k-d}` over the order-`ORDER` subgroup `⟨ζ⟩`
/// (reverse Horner), interpolated back to coefficients. `Q` divides the masked
/// recurrence numerator `(X − ζ^{ORDER-1})·(A(X) − β·A(ζX) − B(X))` by
/// `X^ORDER − 1`; the numerator vanishes on `⟨ζ⟩` (the recurrence holds off
/// the wrap node, the mask kills it on it), so the division is exact and `Q`
/// is a single constant. Returns `(A, Q)`.
pub(crate) fn evaluation_sum<const ORDER: usize>(
    values_coeffs: &[Fp],
    weight: Fp,
) -> (Polynomial, Polynomial) {
    let zeta = subgroup_generator::<ORDER>();

    // Eval-form leaf values `nf_p = B(ζ^p)` over the order-`ORDER` subgroup.
    let mut values_evals = vec![Fp::ZERO; ORDER];
    values_evals[..values_coeffs.len()].copy_from_slice(values_coeffs);
    Domain::new(ORDER.ilog2()).fft(&mut values_evals);

    // Inclusive geometric running sum by reverse Horner:
    // `A(ζ^{ORDER-1}) = nf_{ORDER-1}`, `A(ζ^d) = nf_d + β·A(ζ^{d+1})`.
    let mut acc_coeffs = vec![Fp::ZERO; ORDER];
    let mut running = Fp::ZERO;
    for (slot, value) in acc_coeffs.iter_mut().zip(values_evals.iter()).rev() {
        running = *value + weight * running;
        *slot = running;
    }

    // Interpolate `A` to coefficients (degree `< ORDER`).
    Domain::new(ORDER.ilog2()).ifft(&mut acc_coeffs);

    // R(X) = A(X) − β·A(ζX) − B(X); `A(ζX)` scales coefficient `k` by `ζ^k`.
    let mut shifted = acc_coeffs.clone();
    scale_by_powers(&mut shifted, zeta);
    let mut residual = vec![Fp::ZERO; ORDER];
    for (degree, slot) in residual.iter_mut().enumerate() {
        let acc = acc_coeffs.get(degree).copied().unwrap_or(Fp::ZERO);
        let shift = shifted.get(degree).copied().unwrap_or(Fp::ZERO);
        let value = values_coeffs.get(degree).copied().unwrap_or(Fp::ZERO);
        *slot = acc - weight * shift - value;
    }

    // LHS(X) = (X − ζ^{ORDER-1})·R(X).
    let top = zeta.pow_vartime([ORDER as u64 - 1]);
    let mut numerator = vec![Fp::ZERO; ORDER + 1];
    for (degree, &coeff) in residual.iter().enumerate() {
        numerator[degree + 1] += coeff;
        numerator[degree] -= top * coeff;
    }

    let (quotient, remainder) = divide_by_vanishing(&numerator, ORDER);
    assert!(
        remainder.iter().all(|coeff| *coeff == Fp::ZERO),
        "evaluation-sum numerator is not divisible by Z_<zeta>: accumulator mismatches the leaf",
    );

    (
        Polynomial::from_coeffs(&acc_coeffs),
        Polynomial::from_coeffs(&quotient),
    )
}

#[cfg(test)]
#[expect(clippy::as_conversions, reason = "test code")]
mod tests {
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::keys::NoteMasterKey;

    #[test]
    fn expansion_shapes_fit_the_pow_derived_cosets() {
        assert_eq!(
            EXPANSION_ROUND_SPLITS, 5,
            "round quotient splits for the 64x128 trace"
        );
        assert_eq!(ROUND_COSET, 1 << 16, "round-numerator coset");
        assert_eq!(BOUNDARY_COSET, 1 << 14, "boundary-numerator coset");
        assert_eq!(REDUCE_STRIDE, 4, "decimation stride");
    }

    /// The three quotients divide exactly for an honestly derived root
    /// expansion (the divisibility asserts inside the builders are the
    /// checks).
    #[test]
    fn nf_master_step_quotients_divide_exactly() {
        let rng = &mut StdRng::seed_from_u64(0);
        let mk = NoteMasterKey(array::from_fn(|_| Fp::random(&mut *rng)));
        let (states, _child, key_poly) = mk.expand_child_trace(3);
        let spectrum = states.spectrum();

        let (round, boundary, decimation) = expansion_quotients(
            spectrum.0.coefficients(),
            &mk.0,
            &mk.expansion_params(),
            key_poly.0.coefficients(),
            Fp::from(3u64 * GGM_TREE_ARITY as u64),
        );

        assert_eq!(round.len(), EXPANSION_ROUND_SPLITS);
        assert!(
            boundary.coefficients().len() <= POLY_LEN_MAX,
            "boundary fits one split"
        );
        assert!(
            decimation.coefficients().len() <= POLY_LEN_MAX,
            "decimation fits one split"
        );
    }

    /// A node-level expansion (64-key schedule) also divides exactly, through
    /// the node-width offset basis.
    #[test]
    fn nf_prefix_step_quotients_divide_exactly() {
        let rng = &mut StdRng::seed_from_u64(1);
        let mk = NoteMasterKey(array::from_fn(|_| Fp::random(&mut *rng)));
        let node = mk.step(5);
        let (states, _child, key_poly) = node.expand_child_trace(7);
        let spectrum = states.spectrum();

        let (_round, _boundary, _decimation) = expansion_quotients(
            spectrum.0.coefficients(),
            &node.schedule,
            &node.expansion_params(),
            key_poly.0.coefficients(),
            Fp::from(7u64 * GGM_TREE_ARITY as u64),
        );
    }

    /// The leaf expansion (base 0, leaf domain) divides exactly.
    #[test]
    fn leaf_nullifiers_quotients_divide_exactly() {
        let rng = &mut StdRng::seed_from_u64(2);
        let mk = NoteMasterKey(array::from_fn(|_| Fp::random(&mut *rng)));
        let leaf_key = mk.step(1).step(2);
        let (states, _outputs, leaf_poly) = leaf_key.leaf_nullifier_trace();
        let spectrum = states.spectrum();

        let (_round, _boundary, _decimation) = expansion_quotients(
            spectrum.0.coefficients(),
            &leaf_key.schedule,
            &leaf_key.leaf_params(),
            leaf_poly.0.coefficients(),
            Fp::ZERO,
        );
    }
}
