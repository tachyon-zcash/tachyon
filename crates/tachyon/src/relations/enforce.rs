//! Generic committed-polynomial relations for step witnesses.

#![allow(
    clippy::as_conversions,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "todo"
)]

extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu::Polynomial;

use super::subgroup_generator;
use crate::constants::POLY_LEN_MAX;

/// Evaluate at `position` the unique polynomial of degree below `ORDER` that
/// takes `values[i]` at node `i` and is zero at every other `ORDER`-th root of
/// unity.
///
/// The nodes start at `node_start` and step by a primitive `VALUES`-th root
/// (computed internally), the spacing that lands them on the `ORDER`-th roots.
/// A *full* set (`VALUES = ORDER`, `node_start = 1`) covers every root; a
/// *sparse* set covers a sub-coset and is zero elsewhere. `vanishing` is the
/// `position^ORDER - 1` factor of the closed form, taken as an argument so a
/// caller that already holds it (the relation's domain divisor) does not
/// recompute it; callers must pass exactly `position^ORDER - 1`. Closed-form
/// subgroup-Lagrange interpolation, one inversion per node, with `n` = `ORDER`,
/// point `x` = `position`, nodes `a_i`, and values `v_i`:
///
/// $$
///     \sum_i v_i \, \frac{a_i}{x - a_i} \cdot \frac{x^{\,n} - 1}{n}.
/// $$
fn subgroup_interpolate<const ORDER: usize, const VALUES: usize>(
    values: &[Fp; VALUES],
    node_start: Fp,
    position: Fp,
    vanishing: Fp,
) -> Fp {
    const {
        assert!(ORDER != 0, "subgroup order must be nonzero");
    }

    let prefactor = vanishing
        * Fp::from(ORDER as u64)
            .invert()
            .expect("subgroup order must be nonzero");

    let node_step = subgroup_generator::<VALUES>();
    let mut accumulator = Fp::ZERO;
    let mut node = node_start;
    for &value in values {
        let denominator = (position - node)
            .invert()
            .expect("position should not coincide with a node");

        accumulator += value * node * denominator;
        node *= node_step;
    }
    accumulator * prefactor
}

/// Evaluate `position^ORDER - 1`, whose roots are exactly the `ORDER`-th roots
/// of unity: zero on that subgroup, nonzero elsewhere.
fn zeroizer<const ORDER: usize>(position: Fp) -> Fp {
    position.pow_vartime([ORDER as u64]) - Fp::ONE
}

/// Bind the committed `poly` to the unique degree-`<NODES` interpolant of
/// `values` over the order-`NODES` subgroup: derive `z` from the commitment
/// and check `poly(z)` against the closed-form subgroup-Lagrange evaluation of
/// `values` at `z`. A pass at the random `z` forces the polynomial equality
/// (Schwartz-Zippel), pinning every node value *and* the exact degree bound;
/// per-node openings alone would leave the higher-degree slack `Z(X)·R(X)`
/// (any multiple of the subgroup vanishing polynomial) free. Constraint-only:
/// one opening, no prover-built quotient.
///
/// # Caller obligations (soundness)
///
/// - **Binding.** `poly` must be commitment-bound to a statement-fixed value;
///   the commitment feeds `z`.
/// - **Public structure.** `values` must be statement-fixed (derived or
///   pinned in-step), never witness-chosen after `z`.
pub(crate) fn enforce_interpolant<const NODES: usize>(
    ctx: &mut ragu::StepCtx<'_>,
    poly: &Polynomial,
    values: &[Fp; NODES],
) -> ragu::Result<()> {
    let commit = poly.commit();
    let z = ctx.derive_challenge(&[commit])?;

    let poly_at_z = poly.eval(z);
    ctx.enforce_poly_query(commit, z, poly_at_z)?;

    let interpolant_at_z =
        subgroup_interpolate::<NODES, NODES>(values, Fp::ONE, z, zeroizer::<NODES>(z));
    if poly_at_z != interpolant_at_z {
        return Err(ragu::Error::InvalidWitness(
            "interpolant identity fails at challenge".into(),
        ));
    }
    Ok(())
}

/// Prove the flat keyed-cipher recurrence `T(ωz) = (T(z) + O(z))^e` over the
/// whole order-`POLY_LEN_MAX` domain, with the per-step offset carried as a
/// *committed* constant polynomial plus the `FULL`-wide cyclic key schedule
/// reconstructed inline from `PARTS` *committed* part-key polynomials rather
/// than `POLY_LEN_MAX` public offsets. The offset is `O(z) = C(z) +
/// K(ζ·z^{|D|/κ})`, `κ = FULL`: `constants` is the committed `C` (the public
/// constant schedule, opened at `z`), and the order-`κ` key interpolant `K` is
/// the `P = PARTS` part schedules interleaved on the `P` cosets of `⟨ζ⟩`,
///
/// $$ K(x) = \sum_{p=0}^{P-1} s_p(x)\,A_p\!\left(x\,ζ^{-p}\right),\quad
///    s_p(x) = \tfrac{1}{P}\sum_{j=0}^{P-1} ω_P^{-pj}\,\bigl(x^{κ/P}\bigr)^{j},
/// $$
///
/// with `ω_P` a primitive `P`-th root and `A_p` the eval-form part-key poly
/// over the order-`κ/P` subgroup (`A_p(ζ^{P·r}) = k_{P·r+p}`). The `s_p` are
/// the inverse-DFT coset indicators (`s_p(ζ^m) = [m ≡ p mod P]`), so this is an
/// exact degree-`<κ` polynomial identity: reconstructing `K(ζ·z^{|D|/κ})` needs
/// one opening of each `A_p` (at `key_point·ζ^{-p}`) plus the public selectors
/// — no merged key commitment and no quotient. As an identity at the
/// Fiat-Shamir point `z` (`|D|` = `POLY_LEN_MAX`, single-wrap mask $m(z) = z -
/// ω^{-1}$):
///
/// $$
///     m(z) \bigl( T(gz) - (T(z) + O(z))^{\,e} \bigr) = Q(z) \, (z^{|D|} - 1).
/// $$
///
/// The quotient `Q` is carried as `SPLITS` capacity-wide splits. The offset
/// needs no per-node inversion and is independent of `κ`, so a full-length key
/// schedule stays in budget. `PARTS` is the inferred length of `keys`; the
/// per-part domain size `κ/P` is computed here, not threaded.
///
/// # Caller obligations (soundness)
///
/// - **Binding.** `matrix`, `constants`, every `keys[p]`, and every split must
///   be commitment-bound to a statement-fixed value; all feed `z`. In
///   particular `constants` must be pinned (by commit-equality) to the public
///   constant schedule and each `keys[p]` to the certified part-keyset
///   commitments, or the offset is a free witness and the relation is vacuous.
/// - **Public structure.** `exponent` is fixed and not witness-chosen after
///   `z`. Part `p`'s poly is opened at `key_point·ζ^{-p}` (the coset
///   realignment); the `keys` order must match the part indices `0..P`, or the
///   reconstruction is wrong.
pub(crate) fn enforce_committed_offset_recurrence<
    const SPLITS: usize,
    const FULL: usize,
    const PARTS: usize,
>(
    ctx: &mut ragu::StepCtx<'_>,
    matrix: &Polynomial,
    quotient: &[Polynomial; SPLITS],
    constants: &Polynomial,
    keys: &[&Polynomial; PARTS],
    exponent: u64,
) -> ragu::Result<()> {
    let matrix_commit = matrix.commit();
    let constants_commit = constants.commit();
    let key_commits: [Eq; PARTS] = keys.each_ref().map(|key| key.commit());
    let quotient_commits: [Eq; SPLITS] = quotient.each_ref().map(Polynomial::commit);

    let z = ctx.derive_challenge(
        &[
            [matrix_commit, constants_commit].as_slice(),
            key_commits.as_slice(),
            quotient_commits.as_slice(),
        ]
        .concat(),
    )?;
    let vanishing = zeroizer::<POLY_LEN_MAX>(z);

    let matrix_at_z = matrix.eval(z);
    ctx.enforce_poly_query(matrix_commit, z, matrix_at_z)?;
    let constants_at_z = constants.eval(z);
    ctx.enforce_poly_query(constants_commit, z, constants_at_z)?;

    let quotient_at_z = {
        let stride = vanishing + Fp::ONE;
        let mut quotient_at_z = Fp::ZERO;
        let mut shift = Fp::ONE;
        for qt_p in quotient {
            let eval = qt_p.eval(z);
            ctx.enforce_poly_query(qt_p.commit(), z, eval)?;
            quotient_at_z += shift * eval;
            shift *= stride;
        }
        quotient_at_z
    };

    let omega = subgroup_generator::<POLY_LEN_MAX>();
    let znext = omega * z;
    let matrix_at_znext = matrix.eval(znext);
    ctx.enforce_poly_query(matrix_commit, znext, matrix_at_znext)?;

    // O(z) = C(z) + K(ζ·z^{|D|/κ}): committed constant schedule plus the cyclic
    // key value, reconstructed inline from the `PARTS` part-key polys by the
    // interleaved-coset identity `K(x) = Σ_p s_p(x)·A_p(x·ζ^{-p})`. Each `A_p`
    // interpolates part `p` over `⟨ζ^P⟩`; `s_p` is the inverse-DFT indicator of
    // coset `p`. `y = (key_point)^{κ/P}` maps `⟨ζ⟩` onto the `P`-th roots, where
    // `s_p(x) = (1/P)·Σ_j (ω_P^{-p}·y)^j`.
    let zeta = subgroup_generator::<FULL>();
    let key_point = zeta * z.pow_vartime([(POLY_LEN_MAX / FULL) as u64]);
    let zeta_inv = zeta.invert().expect("a root of unity is nonzero");
    let part_root = subgroup_generator::<PARTS>();
    let part_root_inv = part_root.invert().expect("a root of unity is nonzero");
    let parts_inv = Fp::from(PARTS as u64)
        .invert()
        .expect("PARTS is invertible in Fp");
    let y = key_point.pow_vartime([(FULL / PARTS) as u64]);

    // Open each part `p` at `key_point·ζ^{-p}`, weight by `s_p(key_point)`.
    let mut key_at = Fp::ZERO;
    let mut point = key_point; // key_point·ζ^{-p}
    let mut root_negp = Fp::ONE; // ω_P^{-p}
    for (key, key_commit) in keys.iter().zip(key_commits) {
        let a_at = key.eval(point);
        ctx.enforce_poly_query(key_commit, point, a_at)?;
        let base = root_negp * y;
        let mut selector = Fp::ZERO;
        let mut term = Fp::ONE;
        for _ in 0..PARTS {
            selector += term;
            term *= base;
        }
        key_at += selector * parts_inv * a_at;
        point *= zeta_inv;
        root_negp *= part_root_inv;
    }
    let offset = constants_at_z + key_at;

    // Single-wrap mask z − ω^{-1} (= z − ω^{|D|-1}).
    let mask = z - omega.invert().expect("a root of unity is nonzero");

    let residual = matrix_at_znext - (matrix_at_z + offset).pow_vartime([exponent]);

    if mask * residual != quotient_at_z * vanishing {
        return Err(ragu::Error::InvalidWitness(
            "committed-offset recurrence identity fails at challenge".into(),
        ));
    }
    Ok(())
}

/// Prove the row-structured keyed-cipher recurrence `T(gz) = (T(z) + O(z))^e`
/// (rows of `COLUMNS` cells over the order-`POLY_LEN_MAX` domain, the final
/// cell of every row exempt) with the offset's cyclic key schedule
/// reconstructed inline from `PARTS` *committed* part-key polynomials rather
/// than `COLUMNS` public scalars. The schedule runs one full orbit per row
/// (`κ = COLUMNS`), so the offset is `O(z) = C(z^{|D|/κ}) + K(ζ·z^{|D|/κ})`:
/// `constants` are the public rotated round constants (value at column `c` is
/// `c_{(c+1) mod κ}`), interpolated over the column subgroup as a public
/// closed form in `z`, and the order-`κ` key interpolant `K` is the
/// `P = PARTS` part schedules interleaved on the `P` cosets of `⟨ζ⟩`, exactly
/// as in [`enforce_committed_offset_recurrence`]: reconstructing
/// `K(ζ·z^{|D|/κ})` needs one opening of each part poly `A_p` (at
/// `key_point·ζ^{-p}`) plus the public coset selectors, with no merged key
/// commitment and no extra quotient. The `ζ` factor is the keys' `+1` column
/// rotation (the transition out of column `c` consumes key `c + 1`; the
/// row-wrap column reads the periodic `k_0`, and the mask exempts it). As an
/// identity at the Fiat-Shamir point `z` (`|D|` = `POLY_LEN_MAX`, row mask
/// $m(z) = z^{|D|/κ} - ζ^{-1}$ vanishing on every final column):
///
/// $$
///     m(z) \bigl( T(gz) - (T(z) + O(z))^{\,e} \bigr) = Q(z) \, (z^{|D|} - 1).
/// $$
///
/// The quotient `Q` is carried as `SPLITS` capacity-wide splits.
///
/// # Caller obligations (soundness)
///
/// - **Binding.** `matrix`, every `keys[p]`, and every split must be
///   commitment-bound to a statement-fixed value; all feed `z`. In particular
///   each `keys[p]` must be pinned to a certified part commitment, or the
///   offset is a free witness and the relation is vacuous.
/// - **Public structure.** `constants` and `exponent` are not absorbed into
///   `z`; they must be statement-fixed, never witness-chosen after `z`. Part
///   `p`'s poly is opened at `key_point·ζ^{-p}` (the coset realignment); the
///   `keys` order must match the part indices `0..P`, or the reconstruction is
///   wrong.
pub(crate) fn enforce_committed_row_recurrence<
    const COLUMNS: usize,
    const SPLITS: usize,
    const PARTS: usize,
>(
    ctx: &mut ragu::StepCtx<'_>,
    matrix: &Polynomial,
    quotient: &[Polynomial; SPLITS],
    constants: &[Fp; COLUMNS],
    keys: &[&Polynomial; PARTS],
    exponent: u64,
) -> ragu::Result<()> {
    let matrix_commit = matrix.commit();
    let key_commits: [Eq; PARTS] = keys.each_ref().map(|key| key.commit());
    let quotient_commits: [Eq; SPLITS] = quotient.each_ref().map(Polynomial::commit);

    let z = ctx.derive_challenge(
        &[
            [matrix_commit].as_slice(),
            key_commits.as_slice(),
            quotient_commits.as_slice(),
        ]
        .concat(),
    )?;
    let vanishing = zeroizer::<POLY_LEN_MAX>(z);

    let matrix_at_z = matrix.eval(z);
    ctx.enforce_poly_query(matrix_commit, z, matrix_at_z)?;

    let quotient_at_z = {
        let stride = vanishing + Fp::ONE;
        let mut quotient_at_z = Fp::ZERO;
        let mut shift = Fp::ONE;
        for qt_p in quotient {
            let eval = qt_p.eval(z);
            ctx.enforce_poly_query(qt_p.commit(), z, eval)?;
            quotient_at_z += shift * eval;
            shift *= stride;
        }
        quotient_at_z
    };

    let znext = subgroup_generator::<POLY_LEN_MAX>() * z;
    let matrix_at_znext = matrix.eval(znext);
    ctx.enforce_poly_query(matrix_commit, znext, matrix_at_znext)?;

    // The column map `z ↦ z^{|D|/κ}` sends domain position `32·r + c` to
    // `ζ^c`; the constants interpolation, the key reconstruction, and the row
    // mask are all functions of it.
    let period_position = z.pow_vartime([(POLY_LEN_MAX / COLUMNS) as u64]);
    let zeta = subgroup_generator::<COLUMNS>();
    let zeta_inv = zeta.invert().expect("a root of unity is nonzero");

    // Mask end-of-row discontinuity at `ζ^{COLUMNS-1} = ζ^{-1}`.
    let mask = period_position - zeta_inv;

    // The constants interpolation's `position^COLUMNS - 1` factor is
    // `period_position^COLUMNS = z^|D|`, so its vanishing is the shared one.
    let constants_at =
        subgroup_interpolate::<COLUMNS, COLUMNS>(constants, Fp::ONE, period_position, vanishing);

    // K(ζ·period_position): the cyclic key value, reconstructed inline from
    // the `PARTS` part-key polys by the interleaved-coset identity
    // `K(x) = Σ_p s_p(x)·A_p(x·ζ^{-p})`. Each `A_p` interpolates part `p` over
    // `⟨ζ^P⟩`; `s_p` is the inverse-DFT indicator of coset `p`.
    // `y = (key_point)^{κ/P}` maps `⟨ζ⟩` onto the `P`-th roots, where
    // `s_p(x) = (1/P)·Σ_j (ω_P^{-p}·y)^j`.
    let key_point = zeta * period_position;
    let part_root = subgroup_generator::<PARTS>();
    let part_root_inv = part_root.invert().expect("a root of unity is nonzero");
    let parts_inv = Fp::from(PARTS as u64)
        .invert()
        .expect("PARTS is invertible in Fp");
    let y = key_point.pow_vartime([(COLUMNS / PARTS) as u64]);

    // Open each part `p` at `key_point·ζ^{-p}`, weight by `s_p(key_point)`.
    let mut key_at = Fp::ZERO;
    let mut point = key_point; // key_point·ζ^{-p}
    let mut root_negp = Fp::ONE; // ω_P^{-p}
    for (key, key_commit) in keys.iter().zip(key_commits) {
        let a_at = key.eval(point);
        ctx.enforce_poly_query(key_commit, point, a_at)?;
        let base = root_negp * y;
        let mut selector = Fp::ZERO;
        let mut term = Fp::ONE;
        for _ in 0..PARTS {
            selector += term;
            term *= base;
        }
        key_at += selector * parts_inv * a_at;
        point *= zeta_inv;
        root_negp *= part_root_inv;
    }
    let offset = constants_at + key_at;

    let residual = matrix_at_znext - (matrix_at_z + offset).pow_vartime([exponent]);

    if mask * residual != quotient_at_z * vanishing {
        return Err(ragu::Error::InvalidWitness(
            "committed-key row recurrence identity fails at challenge".into(),
        ));
    }
    Ok(())
}

/// Bind a low-degree polynomial `column`, raised to a fixed `exponent`, to a
/// strided column of the committed `matrix`. On the order-`SUB_ORDER` subgroup
/// `⟨ζ⟩` (`ζ = subgroup_generator::<SUB_ORDER>()`) the relation pins
/// `column(ζ^r)^e = matrix(stride·ζ^r) + offset`. At `e = 1`, `column` is the
/// degree-`<SUB_ORDER` interpolant of the `matrix` cells on the coset
/// `stride·⟨ζ⟩` (plus a constant `offset`); at an S-box exponent it pins the
/// `matrix` cells to the S-boxed `column` values. As an identity at the
/// Fiat-Shamir point `z`:
///
/// $$ \mathit{column}(z)^{\,e} - \mathit{offset} - \mathit{matrix}(\sigma z)
///    = Q(z)\,(z^{\mathrm{SUB\_ORDER}} - 1). $$
///
/// The numerator `column(X)^e − offset − matrix(σX)` vanishes on `⟨ζ⟩` exactly
/// when the column equality holds, so a pass at random `z` forces it
/// (Schwartz-Zippel). Off-subgroup slack in `column` (any `Z(X)·R(X)` addend)
/// contributes only vanisher-divisible terms to `column^e`, absorbed by `Q`,
/// so the relation binds exactly the subgroup values. `column` and `matrix`
/// are full polynomials; `Q` is a single committed quotient.
///
/// # Caller obligations (soundness)
///
/// - **Binding.** `matrix`, `column`, and `quotient` must be commitment-bound
///   to statement-fixed values; all feed `z`.
/// - **Public structure.** `stride`, `offset`, and `exponent` are
///   statement-fixed, never witness-chosen after `z`.
pub(crate) fn enforce_strided_column<const SUB_ORDER: usize>(
    ctx: &mut ragu::StepCtx<'_>,
    matrix: &Polynomial,
    column: &Polynomial,
    quotient: &Polynomial,
    stride: Fp,
    offset: Fp,
    exponent: u64,
) -> ragu::Result<()> {
    let matrix_commit = matrix.commit();
    let column_commit = column.commit();
    let quotient_commit = quotient.commit();

    let z = ctx.derive_challenge(&[matrix_commit, column_commit, quotient_commit])?;

    let column_at_z = column.eval(z);
    ctx.enforce_poly_query(column_commit, z, column_at_z)?;
    let strided = stride * z;
    let matrix_at_strided = matrix.eval(strided);
    ctx.enforce_poly_query(matrix_commit, strided, matrix_at_strided)?;
    let quotient_at_z = quotient.eval(z);
    ctx.enforce_poly_query(quotient_commit, z, quotient_at_z)?;

    if column_at_z.pow_vartime([exponent]) - offset - matrix_at_strided
        != quotient_at_z * zeroizer::<SUB_ORDER>(z)
    {
        return Err(ragu::Error::InvalidWitness(
            "strided column identity fails at challenge".into(),
        ));
    }
    Ok(())
}

/// Compute the weighted opening `Σ_j weights[j]·polys[j](point)` in-circuit,
/// binding each polynomial to its statement-fixed `commitment` and opening it
/// at `point`. The shared core of any weighted multi-polynomial query at a
/// common point: the caller supplies the query point and the per-poly weights.
///
/// # Caller obligations (soundness)
///
/// - **Binding.** `commits` must be statement-fixed (public inputs, prior-step
///   outputs, or transcript-absorbed values); the witnessed `polys` are pinned
///   to them by commit-equality before being opened.
/// - **Public structure.** `point` and `weights` must be bound to
///   statement-fixed values, never free witnesses, or the returned value is
///   unconstrained.
pub(crate) fn enforce_weighted_opening<const OPERANDS: usize>(
    ctx: &mut ragu::StepCtx<'_>,
    commits: &[Eq; OPERANDS],
    polys: &[Polynomial; OPERANDS],
    point: Fp,
    weights: &[Fp; OPERANDS],
) -> ragu::Result<Fp> {
    let mut combination = Fp::ZERO;
    for ((commitment, poly), weight) in commits.iter().zip(polys).zip(weights) {
        if poly.commit() != *commitment {
            return Err(ragu::Error::InvalidWitness(
                "weighted opening: polynomial does not match its commitment".into(),
            ));
        }
        let value = poly.eval(point);
        ctx.enforce_poly_query(*commitment, point, value)?;
        combination += *weight * value;
    }
    Ok(combination)
}

/// Compute the pair of weighted openings at consecutive positions `d` and
/// `d+1` of a geometric query family over the order-`COSET_ORDER` coset
/// `shift·⟨γ⟩`: the query points are `p_d = shift·γ^d` and `p_{d+1} = γ·p_d`,
/// the per-poly weights `ratios[j]^d` and `ratios[j]^{d+1}`, and each value is
/// the weighted open `Σ_j ratios[j]^{·}·polys[j](p_·)` via
/// [`enforce_weighted_opening`].
///
/// The offset is rejected at or past `COSET_ORDER` (beyond it the coset
/// wraps); the real circuit decomposes the offset into `log₂(COSET_ORDER)`
/// bits and forms the powers by square-and-multiply, which realizes the same
/// bound structurally.
///
/// # Caller obligations (soundness)
///
/// - **Binding.** `commits` are statement-fixed; the witnessed `polys` are
///   pinned to them inside [`enforce_weighted_opening`]. `shift` and `ratios`
///   must be statement-fixed, never witness-chosen.
/// - **Offset.** `offset` must be statement-fixed (the production caller
///   threads it from bound header values); matching the first returned value
///   against a statement-fixed reference is an additional consistency bind,
///   not the pin.
pub(crate) fn enforce_geometric_opening_pair<const OPERANDS: usize, const COSET_ORDER: usize>(
    ctx: &mut ragu::StepCtx<'_>,
    commits: &[Eq; OPERANDS],
    polys: &[Polynomial; OPERANDS],
    shift: Fp,
    ratios: &[Fp; OPERANDS],
    offset: u64,
) -> ragu::Result<(Fp, Fp)> {
    if offset >= COSET_ORDER as u64 {
        return Err(ragu::Error::InvalidWitness(
            "offset exceeds the query coset order".into(),
        ));
    }
    let coset_gen = subgroup_generator::<COSET_ORDER>();

    // p_d = c·γ^d and the per-poly weights ρ_j^d.
    let point_d = shift * coset_gen.pow_vartime([offset]);
    let mut weights_d = *ratios;
    for weight in &mut weights_d {
        *weight = weight.pow_vartime([offset]);
    }
    let value_d = enforce_weighted_opening(ctx, commits, polys, point_d, &weights_d)?;

    // Advance one position: p_{d+1} = γ·p_d, ρ_j^{d+1} = ρ_j·ρ_j^d.
    let point_next = coset_gen * point_d;
    let mut weights_next = weights_d;
    for (weight, ratio) in weights_next.iter_mut().zip(ratios) {
        *weight *= *ratio;
    }
    let value_next = enforce_weighted_opening(ctx, commits, polys, point_next, &weights_next)?;

    Ok((value_d, value_next))
}

/// Open `SPLITS` capacity-wide splits at `point`, binding each to its
/// commitment, and recombine to the unsplit polynomial's value by Horner in
/// `point^POLY_LEN_MAX`: `Σ_s splits[s](point)·point^{POLY_LEN_MAX·s}`. The
/// arc polynomials (`w_j`, `A`) span the order-`S` coset and exceed capacity,
/// so they are carried this way; `SPLITS` is `⌈S/POLY_LEN_MAX⌉`, derived from
/// `S`.
fn open_splits<const SPLITS: usize>(
    ctx: &mut ragu::StepCtx<'_>,
    splits: &[Polynomial; SPLITS],
    point: Fp,
) -> ragu::Result<Fp> {
    let stride = point.pow_vartime([POLY_LEN_MAX as u64]);
    let mut value = Fp::ZERO;
    let mut shift = Fp::ONE;
    for split in splits {
        let eval = split.eval(point);
        ctx.enforce_poly_query(split.commit(), point, eval)?;
        value += shift * eval;
        shift *= stride;
    }
    Ok(value)
}

/// Prove the committed `sequence` advances by the affine map `v ↦ scale·v +
/// step` along the order-`COSET_ORDER` coset `c·⟨γ⟩` (so `seq(c·γ^d) = v_d`
/// with `v_{d+1} = scale·v_d + step` from `v_0 = boundary_value`). As an
/// identity at the Fiat-Shamir point `z` (`c` = `shift`, `S` = `COSET_ORDER`,
/// single-wrap mask `z − c·γ^{S-1}`):
///
/// $$ (z - c\gamma^{S-1})\,\bigl(\mathit{seq}(\gamma z) -
/// \text{scale}\cdot \mathit{seq}(z) - \text{step}\bigr) =
/// Q(z)\,(z^{S} - c^{S}), $$
///
/// plus the boundary open `seq(c) = boundary_value`. That boundary is
/// load-bearing: the masked recurrence pins only the relation between
/// consecutive values, leaving the orbit's one remaining degree of freedom
/// free (a global scale `α` on the homogeneous part); the boundary pins it.
/// `sequence` is carried as `SPLITS` splits.
///
/// The pure-geometric case (`step = 0`, `boundary_value = 1`) is the arc's
/// per-poly weight; the arithmetic case (`scale = 1`, `shift = 1`) pins an
/// affine progression over a subgroup.
///
/// # Caller obligations (soundness)
///
/// - **Binding.** the `sequence` splits and `quotient` are commitment-bound
///   (all feed `z`).
/// - **Public structure.** `scale`, `step`, `shift`, and `boundary_value` are
///   statement-fixed, never witness-chosen after `z`.
pub(crate) fn enforce_affine_recurrence<const COSET_ORDER: usize, const SPLITS: usize>(
    ctx: &mut ragu::StepCtx<'_>,
    sequence: &[Polynomial; SPLITS],
    quotient: &Polynomial,
    scale: Fp,
    step: Fp,
    shift: Fp,
    boundary_value: Fp,
) -> ragu::Result<()> {
    let sequence_commits: [Eq; SPLITS] = sequence.each_ref().map(Polynomial::commit);
    let quotient_commit = quotient.commit();

    let z = ctx
        .derive_challenge(&[sequence_commits.as_slice(), [quotient_commit].as_slice()].concat())?;
    let gamma = subgroup_generator::<COSET_ORDER>();
    let coset_vanishing =
        z.pow_vartime([COSET_ORDER as u64]) - shift.pow_vartime([COSET_ORDER as u64]);

    let sequence_at_z = open_splits(ctx, sequence, z)?;
    let sequence_at_znext = open_splits(ctx, sequence, gamma * z)?;
    let quotient_at_z = quotient.eval(z);
    ctx.enforce_poly_query(quotient_commit, z, quotient_at_z)?;

    let wrap = shift * gamma.pow_vartime([COSET_ORDER as u64 - 1]);
    if (z - wrap) * (sequence_at_znext - scale * sequence_at_z - step)
        != quotient_at_z * coset_vanishing
    {
        return Err(ragu::Error::InvalidWitness(
            "affine recurrence identity fails at challenge".into(),
        ));
    }

    // Boundary: `seq(c) = v_0`, pinning the orbit's free scale (see above).
    if open_splits(ctx, sequence, shift)? != boundary_value {
        return Err(ragu::Error::InvalidWitness(
            "affine recurrence boundary does not match at the origin".into(),
        ));
    }
    Ok(())
}

/// Prove the committed running-sum accumulator `A` advances by the β-weighted
/// nullifiers over the order-`COSET_ORDER` query coset, so (exclusive prefix)
/// `A(c·γ^d) = Σ_{k<d} β^k·nf_k`. As an identity at the Fiat-Shamir point `z`
/// (`c` = `shift`, weights `w_j`, derivation polys `T_j`, `S` = `COSET_ORDER`,
/// single-wrap mask `z − c·γ^{S-1}`):
///
/// $$ (z - c\gamma^{S-1})\Bigl(A(\gamma z) - A(z) - \sum_j w_j(z)\,T_j(z)\Bigr)
/// = Q(z)\,(z^S - c^S), $$
///
/// plus the boundary open `A(c) = 0`. The exclusive prefix lets a range
/// starting at offset 0 read its left endpoint at the origin (`A(c) = 0`)
/// rather than the wrap. The right-hand side is a scalar sum of challenge-point
/// openings, so no product polynomial is committed. `A` and each `w_j` are
/// carried as `SPLITS` splits; `T_j` are single capacity-wide polys.
///
/// # Caller obligations (soundness)
///
/// - **Binding.** `A`, `quotient`, the `weights`, and `trace_polys` are
///   commitment-bound (all feed `z`). Each `w_j` must independently be proven
///   geometric by [`enforce_affine_recurrence`], and each `T_j` bound to its
///   certified derivation commitment, by the caller.
/// - **Public structure.** `shift` is statement-fixed.
pub(crate) fn enforce_accumulator_recurrence<
    const COSET_ORDER: usize,
    const SPLITS: usize,
    const POLYS: usize,
>(
    ctx: &mut ragu::StepCtx<'_>,
    accumulator: &[Polynomial; SPLITS],
    quotient: &Polynomial,
    weights: &[[Polynomial; SPLITS]; POLYS],
    trace_polys: &[Polynomial; POLYS],
    shift: Fp,
) -> ragu::Result<()> {
    let mut commits: Vec<Eq> = accumulator.each_ref().map(Polynomial::commit).into();
    commits.push(quotient.commit());
    for weight in weights {
        commits.extend(weight.each_ref().map(Polynomial::commit));
    }
    commits.extend(trace_polys.each_ref().map(Polynomial::commit));
    let z = ctx.derive_challenge(&commits)?;

    let gamma = subgroup_generator::<COSET_ORDER>();
    let znext = gamma * z;
    let coset_vanishing =
        z.pow_vartime([COSET_ORDER as u64]) - shift.pow_vartime([COSET_ORDER as u64]);

    let accumulator_at_z = open_splits(ctx, accumulator, z)?;
    let accumulator_at_znext = open_splits(ctx, accumulator, znext)?;
    let quotient_at_z = quotient.eval(z);
    ctx.enforce_poly_query(quotient.commit(), z, quotient_at_z)?;

    // Σ_j w_j(z)·T_j(z): a scalar of challenge-point openings, no product poly.
    // Exclusive recurrence — the RHS is the term at the old position, read at z.
    let mut advance = Fp::ZERO;
    for (weight, trace) in weights.iter().zip(trace_polys) {
        let weight_at_z = open_splits(ctx, weight, z)?;
        let trace_at_z = trace.eval(z);
        ctx.enforce_poly_query(trace.commit(), z, trace_at_z)?;
        advance += weight_at_z * trace_at_z;
    }

    let wrap = shift * gamma.pow_vartime([COSET_ORDER as u64 - 1]);
    if (z - wrap) * (accumulator_at_znext - accumulator_at_z - advance)
        != quotient_at_z * coset_vanishing
    {
        return Err(ragu::Error::InvalidWitness(
            "accumulator recurrence identity fails at challenge".into(),
        ));
    }

    // Boundary: `A(c) = 0` (the exclusive prefix's empty sum at the origin).
    if open_splits(ctx, accumulator, shift)? != Fp::ZERO {
        return Err(ragu::Error::InvalidWitness(
            "accumulator boundary A(c) must be zero".into(),
        ));
    }
    Ok(())
}

/// Discharge the arc match against the tested-value polynomial `q`.
///
/// The exclusive-prefix accumulator gives the `β`-weighted nullifier sum over
/// the offset arc `[start_offset, end_offset)` as the endpoint difference
/// `A(p_{end_offset}) − A(p_{start_offset})`, with `p_d = shift·coset_gen^d`.
/// The sync-tested values `q` pack the same range's nullifiers from
/// `start_offset`, so `q(β)·β^{start_offset}` must equal that difference: each
/// tested value, weighted by its absolute `β^k`, lines up with the
/// accumulator's `β^k·nf_k` term. A passing match plus Schwartz-Zippel forces
/// every tested value to be the genuine `nf_k` at its offset.
///
/// `start_offset`/`end_offset` are `start_epoch − E_0` / `end_epoch − E_0`
/// against the certified creation origin `E_0`; the caller reconciles `E_0`
/// downstream so the arc cannot be shifted. Both offsets are rejected at or
/// past `COSET_ORDER` (an endpoint at the order would wrap the exclusive
/// prefix back to the origin); the real circuit decomposes the offsets into
/// `log₂(COSET_ORDER)` bits, which realizes the same bound structurally.
///
/// # Caller obligations (soundness)
///
/// - **Binding.** `accumulator` must be proven by
///   [`enforce_accumulator_recurrence`] and `range`/`range_commit` bound to the
///   consensus-tested values (the `Unspent` `elapsed ++ tip` reconstruction);
///   `β` must be derived from `range_commit` and the certified derivation
///   digest before this call.
/// - **Public structure.** `shift` and the offsets are statement-fixed, never
///   witness-chosen.
#[expect(clippy::too_many_arguments, reason = "todo")]
pub(crate) fn enforce_arc_match<const SPLITS: usize, const COSET_ORDER: usize>(
    ctx: &mut ragu::StepCtx<'_>,
    accumulator: &[Polynomial; SPLITS],
    range: &Polynomial,
    range_commit: Eq,
    shift: Fp,
    beta: Fp,
    start_offset: u64,
    end_offset: u64,
) -> ragu::Result<()> {
    if start_offset >= COSET_ORDER as u64 || end_offset >= COSET_ORDER as u64 {
        return Err(ragu::Error::InvalidWitness(
            "offset exceeds the query coset order".into(),
        ));
    }
    let coset_gen = subgroup_generator::<COSET_ORDER>();
    let point_start = shift * coset_gen.pow_vartime([start_offset]);
    let point_end = shift * coset_gen.pow_vartime([end_offset]);
    let range_total =
        open_splits(ctx, accumulator, point_end)? - open_splits(ctx, accumulator, point_start)?;

    let q_at_beta = range.eval(beta);
    ctx.enforce_poly_query(range_commit, beta, q_at_beta)?;
    if q_at_beta * beta.pow_vartime([start_offset]) != range_total {
        return Err(ragu::Error::InvalidWitness(
            "arc match fails at the challenge".into(),
        ));
    }
    Ok(())
}

/// Pin the *first column* of the committed `matrix` to prescribed values. Read
/// its domain evaluations as a matrix; the first column is the `ROWS`-th roots
/// of unity (one cell per row), pinned to `base + values[row]`. As an identity
/// at the Fiat-Shamir point `z` (with `|D|` = `POLY_LEN_MAX`, `R` = `ROWS`,
/// `M` = `matrix`, `b` = `base`, selector $s$, and interpolant $v$ of
/// `values`):
///
/// $$
///     s(z) \bigl( M(z) - b - v(z) \bigr) = Q(z) \, (z^{|D|} - 1).
/// $$
///
/// The constraint binds only the first column, so it does not fit the bare
/// $Q \cdot Z_D$ form: the selector $s(z) = (z^{|D|} - 1) / (z^{R} - 1)$
/// carries the $z^{|D|} - 1$ factor the check re-introduces, leaving the column
/// vanisher $z^{R} - 1$ as the effective divisor. The `quotient` has degree
/// below `POLY_LEN_MAX`, so it is one committed polynomial; the relation
/// derives `z` from `matrix` and `quotient`, opens both at `z`, and checks the
/// identity.
///
/// Callers needing a non-affine boundary (such as pinning each cell to an S-box
/// of its row input) precompute the per-row target into `values`; the relation
/// pins the column to whatever interpolant `values` describes.
///
/// # Caller obligations (soundness)
///
/// - **Binding.** `matrix` and `quotient` must be commitment-bound to a
///   statement-fixed value (not a fresh or merely-threaded witness); both feed
///   `z`.
/// - **Public structure.** `base` and `values` are not absorbed into `z`; fix
///   them to statement-fixed values, never witness-chosen after `z`.
pub(crate) fn enforce_first_column_values<const ROWS: usize>(
    ctx: &mut ragu::StepCtx<'_>,
    matrix: &Polynomial,
    quotient: &Polynomial,
    base: Fp,
    values: &[Fp; ROWS],
) -> ragu::Result<()> {
    let matrix_commit = matrix.commit();
    let quotient_commit = quotient.commit();

    let z = ctx.derive_challenge(&[matrix_commit, quotient_commit])?;

    let matrix_at_z = matrix.eval(z);
    ctx.enforce_poly_query(matrix_commit, z, matrix_at_z)?;
    let quotient_at_z = quotient.eval(z);
    ctx.enforce_poly_query(quotient_commit, z, quotient_at_z)?;

    let domain_vanishing = zeroizer::<POLY_LEN_MAX>(z);
    let rows_vanishing = zeroizer::<ROWS>(z);

    let values_at_z = subgroup_interpolate::<ROWS, ROWS>(values, Fp::ONE, z, rows_vanishing);

    let complement = domain_vanishing
        * rows_vanishing
            .invert()
            .expect("random challenge should not be a first-column root of unity");

    if complement * (matrix_at_z - base - values_at_z) != quotient_at_z * domain_vanishing {
        return Err(ragu::Error::InvalidWitness(
            "first column values identity fails at challenge".into(),
        ));
    }
    Ok(())
}

/// Faithful polynomial product: confirm `product = multiplicand · multiplier`
/// among three committed polynomials by opening all three at a Fiat-Shamir
/// challenge.
///
/// `product` is prover-supplied and the relation works only from the three
/// commitments and their openings at `z` -- it does not multiply the inputs.
/// The point-wise identity `product(z) = multiplicand(z)·multiplier(z)` at a
/// random `z` confirms the relation: with every operand committed and absorbed
/// into `z`, the difference `product − multiplicand·multiplier` is a fixed
/// polynomial pinned to zero by Schwartz-Zippel.
///
/// # Caller obligation (soundness)
///
/// Every operand is committed and absorbed into `z`, so the module-level
/// binding obligation -- here applying symmetrically to `multiplicand`,
/// `multiplier`, and `product` -- is the only precondition.
pub(crate) fn enforce_poly_product(
    ctx: &mut ragu::StepCtx<'_>,
    multiplicand: &Polynomial,
    multiplier: &Polynomial,
    product: &Polynomial,
) -> ragu::Result<()> {
    let multiplicand_com = multiplicand.commit();
    let multiplier_com = multiplier.commit();
    let product_com = product.commit();
    let z = ctx.derive_challenge(&[multiplicand_com, multiplier_com, product_com])?;

    if product.eval(z) != multiplicand.eval(z) * multiplier.eval(z) {
        return Err(ragu::Error::InvalidWitness(
            "poly product: product identity fails at challenge".into(),
        ));
    }

    ctx.enforce_poly_query(multiplicand_com, z, multiplicand.eval(z))?;
    ctx.enforce_poly_query(multiplier_com, z, multiplier.eval(z))?;
    ctx.enforce_poly_query(product_com, z, product.eval(z))?;

    Ok(())
}

/// `X^exponent` evaluated at `point`.
#[expect(clippy::as_conversions, reason = "must be in range")]
fn monomial_at(point: Fp, exponent: usize) -> Fp {
    point.pow_vartime([exponent as u64])
}

/// Shifted linear combination of committed polynomials and monomials: confirm
/// `result(X) = Σ_i X^{k_i}·p_i(X) + Σ_j c_j·X^{m_j}` by opening each `p_i`
/// and `result` at a Fiat-Shamir challenge.
///
/// `result` is prover-supplied (built off-circuit). Each `shifted_polys` entry
/// pairs a committed operand `p_i` with its shift exponent `k_i`; each
/// `monomials` entry pairs a raw scalar coefficient `c_j` with its degree
/// `m_j`. The point-wise identity at a random `z` confirms the combination:
/// every polynomial operand is committed and absorbed into `z`, so the
/// difference of the two sides is a fixed polynomial pinned to zero by
/// Schwartz-Zippel.
///
/// # Caller obligations (soundness)
///
/// 1. **Binding.** Subject to the module-level binding obligation for every
///    `shifted_polys` entry and `result`. One nuance: `commit(X^k·p)` lands on
///    shifted generators, so it is not homomorphically recoverable from
///    `commit(p)`; a `result` consumed downstream must have its commitment
///    threaded independently.
/// 2. **Monomial coefficients fixed before the challenge.** The scalars `c_j`
///    are not absorbed into `z`, and the identity is *linear* in each: a prover
///    free to choose one after seeing `z` solves it and passes for any
///    committed `result`. Pin each coefficient independently of `z` -- a
///    public/statement input, a prior-step output, or a value absorbed into the
///    transcript before `z`.
/// 3. **Exponents.** The integer exponents `k_i` and `m_j` may be left free:
///    `z` is fixed by the commitments before any exponent is chosen, an
///    adaptive search over wrong exponents succeeds with probability `<=
///    tries/|F|`, and recovering an exponent from a `z` power is
///    discrete-log-hard. Whether a *specific* exponent is the one the
///    surrounding statement needs (an operand's span, say) is that statement's
///    obligation, as is any structural well-formedness of the operands (a
///    shifted sum proves the sum, not that the addends avoid overlapping).
///
/// The exponent parameters and the `z^k` point-wise factors stand in for
/// positional shifts the commitment scheme does not express directly; a
/// first-class committed `X^k·p` (or a built-in shifted sum) would carry the
/// shift itself and collapse this to a direct check.
pub(crate) fn enforce_shifted_combination<const SHIFTED_POLYS: usize, const MONOMIALS: usize>(
    ctx: &mut ragu::StepCtx<'_>,
    shifted_polys: [(&Polynomial, usize); SHIFTED_POLYS],
    monomials: [(Fp, usize); MONOMIALS],
    result: &Polynomial,
) -> ragu::Result<()> {
    let poly_coms = shifted_polys.map(|(poly, _)| poly.commit());
    let result_com = result.commit();
    let z = ctx.derive_challenge(&[poly_coms.as_slice(), [result_com].as_slice()].concat())?;

    let combination = shifted_polys
        .iter()
        .map(|&(poly, shift)| monomial_at(z, shift) * poly.eval(z))
        .chain(
            monomials
                .iter()
                .map(|&(coeff, degree)| coeff * monomial_at(z, degree)),
        )
        .sum::<Fp>();
    if result.eval(z) != combination {
        return Err(ragu::Error::InvalidWitness(
            "shifted combination: identity fails at challenge".into(),
        ));
    }

    for (&(poly, _), com) in shifted_polys.iter().zip(poly_coms) {
        ctx.enforce_poly_query(com, z, poly.eval(z))?;
    }
    ctx.enforce_poly_query(result_com, z, result.eval(z))?;

    Ok(())
}

#[cfg(test)]
mod tests {

    extern crate alloc;

    use alloc::{vec, vec::Vec};
    use core::{array, iter::repeat_with};

    use ragu::Domain;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    /// The interleaved-coset key reconstruction the offset recurrence relies
    /// on: `K(x) = Σ_p s_p(x)·A_p(x·ζ⁻ᵖ)` (the inverse-DFT coset selectors
    /// `s_p`, `ζ` the order-`FULL` root) equals the direct order-`FULL`
    /// interpolant of the interleaved schedule at any `x`. The reference
    /// `K` is interpolated directly, so the check is not impl-frozen.
    /// `PART_SIZE = FULL / PARTS` is computed, not threaded.
    fn check_interleave_identity<const PARTS: usize, const FULL: usize>(
        schedule: &[Fp; FULL],
        point: Fp,
    ) {
        let part_size = FULL / PARTS;
        let zeta = subgroup_generator::<FULL>();
        let zeta_inv = zeta.invert().expect("a root of unity is nonzero");
        let part_root = subgroup_generator::<PARTS>();
        let part_root_inv = part_root.invert().expect("a root of unity is nonzero");
        let parts_inv = Fp::from(PARTS as u64)
            .invert()
            .expect("PARTS is invertible");
        let y = point.pow_vartime([part_size as u64]);

        // Reconstruct via the P-point coset identity: part p = the schedule
        // values at positions ≡ p (mod PARTS), interpolated over ⟨ζ^P⟩.
        let mut recon = Fp::ZERO;
        let mut coset_point = point;
        let mut root_negp = Fp::ONE;
        for part in 0..PARTS {
            let mut coeffs: Vec<Fp> = (0..part_size)
                .map(|row| schedule[part + PARTS * row])
                .collect();
            Domain::new(part_size.ilog2()).ifft(&mut coeffs);
            let a_p = Polynomial::from_coeffs(&coeffs);
            let base = root_negp * y;
            let mut selector = Fp::ZERO;
            let mut term = Fp::ONE;
            for _ in 0..PARTS {
                selector += term;
                term *= base;
            }
            recon += selector * parts_inv * a_p.eval(coset_point);
            coset_point *= zeta_inv;
            root_negp *= part_root_inv;
        }

        // Independent reference: interpolate the full interleaved schedule directly.
        let mut k_coeffs = schedule.to_vec();
        Domain::new(FULL.ilog2()).ifft(&mut k_coeffs);
        let k_direct = Polynomial::from_coeffs(&k_coeffs);

        assert_eq!(
            k_direct.eval(point),
            recon,
            "interleave identity must match the direct interpolant",
        );
    }

    /// The offset recurrence reconstructs the full key schedule from the
    /// committed parts by the interleaved-coset identity. Checked on the tiny
    /// order-4 (`PARTS = 2`) case per the L=2 habit, a tiny order-8 `PARTS = 4`
    /// case that exercises the P-point generalization beyond binary, and the
    /// production order-256 (`PARTS = 2`), at random points.
    #[test]
    fn interleave_identity_reconstructs_the_full_schedule() {
        let rng = &mut StdRng::seed_from_u64(7);
        for _ in 0..8 {
            let schedule: [Fp; 4] = array::from_fn(|_| Fp::random(&mut *rng));
            check_interleave_identity::<2, 4>(&schedule, Fp::random(&mut *rng));
        }
        for _ in 0..8 {
            let schedule: [Fp; 8] = array::from_fn(|_| Fp::random(&mut *rng));
            check_interleave_identity::<4, 8>(&schedule, Fp::random(&mut *rng));
        }
        for _ in 0..8 {
            let schedule: [Fp; 256] = array::from_fn(|_| Fp::random(&mut *rng));
            check_interleave_identity::<2, 256>(&schedule, Fp::random(&mut *rng));
        }
    }

    /// Constant-term lemma: over the domain `D`, any polynomial `g` of degree
    /// below `|D|` has power sums that vanish except at exponent zero, so
    ///
    /// $$ \sum_{x \in D} g(x) = |D| \cdot g(0). $$
    ///
    /// The converter leans on it to collapse a domain sum to a single opening
    /// of `g` at zero. Checked on a 16-element domain.
    #[test]
    fn constant_term_lemma_on_a_small_domain() {
        const ORDER: usize = 16;
        let rng = &mut StdRng::seed_from_u64(0);

        let coeffs: Vec<Fp> = repeat_with(|| Fp::random(&mut *rng)).take(ORDER).collect();
        let poly = Polynomial::from_coeffs(&coeffs);

        let sum = {
            let root = subgroup_generator::<ORDER>();
            let mut sum = Fp::ZERO;
            let mut pos = Fp::ONE;
            for _ in 0..ORDER {
                sum += poly.eval(pos);
                pos *= root;
            }
            sum
        };

        {
            assert_eq!(
                sum,
                Fp::from(ORDER as u64) * poly.coefficients()[0],
                "sum over D of g must collapse to |D| * g(0)"
            );
        }
    }

    /// `subgroup_interpolate` (full set) reconstructs a polynomial from its
    /// values on the `ORDER`-th roots of unity: sampling a `deg < ORDER`
    /// polynomial on the roots and interpolating returns it at any off-node
    /// position. Checked against direct evaluation, an independent reference.
    #[test]
    fn subgroup_interpolate_reconstructs_a_full_value_set() {
        const ORDER: usize = 4;
        let rng = &mut StdRng::seed_from_u64(0);

        let coeffs: Vec<Fp> = repeat_with(|| Fp::random(&mut *rng)).take(ORDER).collect();
        let poly = Polynomial::from_coeffs(&coeffs);

        // Sample `poly` on the roots of unity.
        let values = {
            let mut values = [Fp::ZERO; ORDER];
            let root = subgroup_generator::<ORDER>();
            let mut node = Fp::ONE;
            for value in &mut values {
                *value = poly.eval(node);
                node *= root;
            }
            values
        };

        // Interpolating the samples reproduces `poly` away from the nodes.
        let challenge = Fp::random(rng);
        assert_eq!(
            subgroup_interpolate::<ORDER, ORDER>(
                &values,
                Fp::ONE,
                challenge,
                zeroizer::<ORDER>(challenge)
            ),
            poly.eval(challenge),
            "full interpolation must reconstruct the sampled polynomial",
        );
    }

    /// The recombination arithmetic `recombine_quotient` relies on: adjacent
    /// splits at the `POLY_LEN_MAX` stride evaluate, via Horner in
    /// `z^POLY_LEN_MAX`, to the unsplit polynomial's direct evaluation.
    #[test]
    fn quotient_splits_recombine_to_the_full_evaluation() {
        let rng = &mut StdRng::seed_from_u64(0);
        // Three capacities long, split adjacently.
        let full: Vec<Fp> = repeat_with(|| Fp::random(&mut *rng))
            .take(3 * POLY_LEN_MAX)
            .collect();
        let z = Fp::random(rng);

        let stride = z.pow_vartime([POLY_LEN_MAX as u64]);
        let mut combined = Fp::ZERO;
        let mut shift = Fp::ONE;
        for chunk in full.chunks(POLY_LEN_MAX) {
            combined += shift * Polynomial::from_coeffs(chunk).eval(z);
            shift *= stride;
        }

        let direct = full
            .iter()
            .rev()
            .fold(Fp::ZERO, |acc, &coeff| acc * z + coeff);
        assert_eq!(
            combined, direct,
            "adjacent splits must recombine to the full evaluation"
        );
    }

    // Native checks of the shifted-combination identity on tiny cases: pure
    // algebra over explicit coefficient vectors. Each case builds the operands
    // with `Polynomial::from_coeffs`, the true combination by coefficient
    // arithmetic (an independent computation in the coefficient basis), and
    // confirms the relation's defining identity point-wise (an exact
    // polynomial identity holds at every point), plus one mismatch per operand
    // kind.

    /// Sample evaluation points (arbitrary, fixed).
    const POINTS: [u64; 3] = [0, 2, 927];

    fn poly(coeffs: &[u64]) -> Polynomial {
        Polynomial::from_coeffs(&coeffs.iter().copied().map(Fp::from).collect::<Vec<_>>())
    }

    /// `x^exponent` by repeated multiplication (exponents here are tiny).
    fn power(x: Fp, exponent: usize) -> Fp {
        (0..exponent).fold(Fp::ONE, |acc, _| acc * x)
    }

    /// The true combination, built in the coefficient basis.
    fn combine(shifted_polys: &[(&Polynomial, usize)], monomials: &[(Fp, usize)]) -> Polynomial {
        let len = shifted_polys
            .iter()
            .map(|&(poly, shift)| shift + poly.coefficients().len())
            .chain(monomials.iter().map(|&(_, degree)| degree + 1))
            .max()
            .unwrap_or(0);
        let mut coeffs = vec![Fp::ZERO; len];
        for &(poly, shift) in shifted_polys {
            for (position, coeff) in poly.coefficients().iter().enumerate() {
                coeffs[shift + position] += coeff;
            }
        }
        for &(coeff, degree) in monomials {
            coeffs[degree] += coeff;
        }
        Polynomial::from_coeffs(&coeffs)
    }

    /// The relation's point-wise check, at every sample point.
    fn identity_holds(
        shifted_polys: &[(&Polynomial, usize)],
        monomials: &[(Fp, usize)],
        result: &Polynomial,
    ) -> bool {
        POINTS.iter().all(|&point| {
            let x = Fp::from(point);
            let combination = shifted_polys
                .iter()
                .map(|&(poly, shift)| power(x, shift) * poly.eval(x))
                .chain(
                    monomials
                        .iter()
                        .map(|&(coeff, degree)| coeff * power(x, degree)),
                )
                .sum::<Fp>();
            result.eval(x) == combination
        })
    }

    #[test]
    fn identity_on_single_unshifted_polynomial() {
        let operand = poly(&[3, 5, 7]);
        let result = combine(&[(&operand, 0)], &[]);
        assert_eq!(result.coefficients(), operand.coefficients());
        assert!(identity_holds(&[(&operand, 0)], &[], &result));
    }

    #[test]
    fn identity_on_overlapping_shifted_polynomials() {
        let low = poly(&[3, 5, 7]);
        let high = poly(&[11, 13]);
        let terms = [(&low, 0), (&high, 1)];
        let result = combine(&terms, &[]);
        assert_eq!(result.coefficients(), poly(&[3, 16, 20]).coefficients());
        assert!(identity_holds(&terms, &[], &result));
    }

    #[test]
    fn identity_on_monomials_alone() {
        let monomials = [(Fp::from(5), 0), (Fp::from(9), 3)];
        let result = combine(&[], &monomials);
        assert_eq!(result.coefficients(), poly(&[5, 0, 0, 9]).coefficients());
        assert!(identity_holds(&[], &monomials, &result));
    }

    #[test]
    fn identity_on_cancelling_monomial() {
        // A negative monomial cancels a known coefficient: `low`'s top
        // coefficient `1` at degree 2 is overwritten by `high`'s first.
        let low = poly(&[3, 5, 1]);
        let high = poly(&[7, 11]);
        let terms = [(&low, 0), (&high, 2)];
        let monomials = [(-Fp::ONE, 2)];
        let result = combine(&terms, &monomials);
        assert_eq!(result.coefficients(), poly(&[3, 5, 7, 11]).coefficients());
        assert!(identity_holds(&terms, &monomials, &result));
    }

    #[test]
    fn identity_rejects_wrong_result() {
        let low = poly(&[3, 5]);
        let high = poly(&[7]);
        let wrong = poly(&[3, 5, 8]);
        assert!(!identity_holds(&[(&low, 0), (&high, 2)], &[], &wrong));
    }

    #[test]
    fn identity_rejects_wrong_monomial_coefficient() {
        let operand = poly(&[3, 5]);
        let result = combine(&[(&operand, 0)], &[(Fp::from(9), 2)]);
        assert!(!identity_holds(
            &[(&operand, 0)],
            &[(Fp::from(8), 2)],
            &result
        ));
    }

    #[test]
    fn identity_rejects_wrong_shift() {
        let low = poly(&[3, 5]);
        let high = poly(&[7]);
        let result = combine(&[(&low, 0), (&high, 2)], &[]);
        assert!(!identity_holds(&[(&low, 0), (&high, 3)], &[], &result));
    }
}
