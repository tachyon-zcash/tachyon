//! Prover-side machinery for the nullifier-derivation trace.
//!
//! Everything specific to the window-derivation cipher (`TachyonP5R64`,
//! `ROUNDS` columns by `NF_DERIVATION_WIDTH` rows) lives here: the public
//! column interpolants the circuit Horner-evaluates (the round-constant
//! schedule and the epoch-offset ramp), the coset-geometry constants the
//! steps consume, and the builders for the quotient and accumulator
//! polynomials the steps open: $Q_A$, $Q_B$, and the fold accumulator $A$.
//! In the math below, $W$ is `NF_DERIVATION_WIDTH` and $|D|$ is
//! `POLY_LEN_MAX`.
//!
//! The generic coset-arithmetic layer (FFT evaluation, vanishing-polynomial
//! division) stays in [`relations::quotient`](crate::relations::quotient); no
//! cipher-specific structure lives in those helpers.

use core::array;

use ff::Field as _;
use lazy_static::lazy_static;
use pasta_curves::Fp;
use ragu::{Domain, Polynomial};
use zcash_mimc::specs::tachyon::TachyonP5R64;

use crate::{
    constants::NF_DERIVATION_WIDTH,
    nullifier::{
        NfFoldAccumulator, NfGridSpectrum, NfWhitenedSpectrum, SboxQuarticSpectrum,
        SboxQuotientSpectrum, SboxSquareSpectrum, WrapQuotientSpectrum, WrapSpectrum,
    },
    relations::quotient::{coset_quotient, spread_argument},
};

lazy_static! {
    /// The per-column round-constant schedule, advanced by one. Cells hold
    /// round *outputs* (column $c$ stores $x_{c+1}$, putting the finished
    /// cipher output on the last column), so the transition out of column $c$
    /// consumes the *next* constant: entry $c$ is `CONSTANTS[c + 1]` off the
    /// wrap column, and $0$ on it (column `ROUNDS - 1`, whose step the wrap
    /// correction exempts; the rotate supplies that zero because $c_0 = 0$ by
    /// construction).
    pub(crate) static ref ROUND_SCHEDULE: [Fp; TachyonP5R64::CONSTANTS.len()] = {
        let mut schedule = *TachyonP5R64::CONSTANTS;
        schedule.rotate_left(1);
        schedule
    };

    /// [`struct@ROUND_SCHEDULE`]'s column interpolant $C_{\mathsf{col}}$ in
    /// spectral (coefficient) form. The full-domain schedule is column-periodic, so
    /// $C(X) = C_{\mathsf{col}}(X^W)$; the step Horner-evaluates these public
    /// coefficients in-circuit at $z^W$ instead of opening a committed
    /// schedule.
    pub(crate) static ref ROUND_SCHEDULE_SPECTRUM: [Fp; TachyonP5R64::CONSTANTS.len()] = {
        let mut coeffs = *ROUND_SCHEDULE;
        Domain::new(TachyonP5R64::ROUNDS.ilog2()).ifft(&mut coeffs);
        coeffs
    };

    /// The within-window epoch-offset interpolant $N_{\mathsf{row}}$ in
    /// spectral (coefficient) form: the unique degree-below-$W$ polynomial with
    /// $N_{\mathsf{row}}(\zeta^r) = r$ on the first-column subgroup. Row $r$
    /// encrypts the epoch $\mathsf{base} + r$, so the boundary target is
    /// $(\mathsf{base} + k + N_{\mathsf{row}}(X))^{\mathsf{POW}}$; the step
    /// Horner-evaluates these public coefficients in-circuit at $z$.
    // TODO: can't expect clippy on "NF_DERIVATION_WIDTH as usize" in type signature
    pub(crate) static ref EPOCH_OFFSET_SPECTRUM: [Fp; 128] = {
        #[expect(clippy::as_conversions, reason = "constant widths fit u64")]
        let mut coeffs: [Fp; NF_DERIVATION_WIDTH as usize] = array::from_fn(|i| Fp::from(i as u64));
        Domain::new(NF_DERIVATION_WIDTH.ilog2()).ifft(&mut coeffs);
        coeffs
    };

    /// $\zeta = \omega^{\mathsf{ROUNDS}}$: the order-$W$ row-subgroup
    /// generator, the one-epoch step. Multiplying a nullifier point by
    /// $\zeta$ advances one row, so one epoch. Built once.
    pub(crate) static ref NF_EPOCH_STEP: Fp = Domain::new(NF_DERIVATION_WIDTH.ilog2()).omega();

    /// $\omega$: the generator of the full evaluation domain (size
    /// `POLY_LEN_MAX`), the grid's per-cell step. A round transition advances
    /// the trace argument by $\omega$; $\omega^{\mathsf{ROUNDS}} = \zeta$ and
    /// $\omega^{\mathsf{ROUNDS}-1} = \sigma$. Built once.
    pub(crate) static ref DOMAIN_GENERATOR: Fp = Domain::new(Polynomial::R).omega();

    /// $\sigma = \omega^{\mathsf{ROUNDS}-1}$: the shift onto the nullifier
    /// coset (the grid's last column), where the nullifiers live: $W(\sigma
    /// \zeta^j) = \mathsf{nf}_{\mathsf{base}+j}$. Built once.
    pub(crate) static ref NF_COSET_SHIFT: Fp =
        DOMAIN_GENERATOR.pow_vartime([TachyonP5R64::ROUNDS - 1]);

    /// $\sigma^W = g_{\mathsf{ROUNDS}}^{\mathsf{ROUNDS}-1}$: the common
    /// $W$-th power of every nullifier point, identifying the nullifier
    /// coset. The constant of the last-column vanisher $X^W - \sigma^W$ and
    /// the target of coset-membership checks $\ell^W = \sigma^W$. Built once.
    pub(crate) static ref NF_COSET_ID: Fp = Domain::new(TachyonP5R64::ROUNDS.ilog2())
        .omega()
        .pow_vartime([TachyonP5R64::ROUNDS - 1]);

    /// The wrap mask's inverse on the nullifier coset: the mask
    /// $Z_{H \setminus C}$ is constant there, so its inverse is the single
    /// constant $(|D|/W)^{-1} \cdot \sigma^W$. Built once.
    pub(crate) static ref WRAP_MASK_INV: Fp = {
        Fp::from(TachyonP5R64::ROUNDS).invert().expect(
            "the domain-to-width ratio is
    nonzero",
        ) * *NF_COSET_ID
    };

    /// The round offset's constants part on the grid, the epoch-repeated
    /// spread of [`struct@ROUND_SCHEDULE_SPECTRUM`] (no key material): the
    /// schedule-independent half of the per-point offset
    /// $\mathsf{off} = C + k$, derived from the same public column
    /// coefficients the circuit Horner-evaluates, so the two sides cannot
    /// drift. Built once.
    static ref ROUND_SCHEDULE_GRID: Polynomial = spread_argument(
        &Polynomial::from_coeffs(ROUND_SCHEDULE_SPECTRUM.to_vec()),
        NF_DERIVATION_WIDTH,
    );

    /// [`struct@EPOCH_OFFSET_SPECTRUM`]'s interpolant $N_{\mathsf{row}}$ as a
    /// polynomial operand. Built once.
    static ref EPOCH_OFFSET: Polynomial =
        Polynomial::from_coeffs(EPOCH_OFFSET_SPECTRUM.to_vec());

    /// The wrap mask
    ///
    /// $$
    /// Z_{H \setminus C}(X) = \frac{X^{|D|} - 1}{X^W - \sigma^W}
    ///     = \sum_m (\sigma^W)^{\mathsf{ROUNDS}-1-m} X^{Wm},
    /// $$
    ///
    /// which vanishes everywhere but the nullifier column: it confines the
    /// wrap correction to the wrap column. Built once.
    static ref WRAP_MASK: Polynomial = {
        let mut power = Fp::ONE;
        let mut coeffs = TachyonP5R64::CONSTANTS.map(|_| {
            let coeff = power;
            power *= *NF_COSET_ID;
            coeff
        });
        coeffs.reverse();
        spread_argument(&Polynomial::from_coeffs(coeffs.to_vec()), NF_DERIVATION_WIDTH)
    };

    /// The boundary mask
    /// $Z_{H \setminus C_0}(X) = (X^{|D|} - 1)/(X^W - 1) = \sum_m X^{Wm}$,
    /// which vanishes everywhere but the first column: it confines the
    /// boundary identity to the epoch-input column. Built once.
    static ref BOUNDARY_MASK: Polynomial = spread_argument(
        &Polynomial::from_coeffs(TachyonP5R64::CONSTANTS.map(|_| Fp::ONE).to_vec()),
        NF_DERIVATION_WIDTH,
    );
}

/// The S-box/boundary quotient $Q_A$ (one commitment): builds the
/// $\chi_A$-combined numerator $I_1 + \chi_A I_2 + \chi_A^2 I_4$ on the coset
/// and divides by $Z_D$, where, with $\mathsf{off} = C + k$ the public
/// schedule plus round key and $B = (\mathsf{base} + k +
/// N_{\mathsf{row}})^{\mathsf{POW}}$ the boundary target:
///
/// $$
/// I_1 = \mathsf{square} - (T + \mathsf{off})^2, \qquad
/// I_2 = \mathsf{quartic} - \mathsf{square}^2, \qquad
/// I_4 = (T - B) \, Z_{H \setminus C_0}.
/// $$
///
/// Every identity has degree at most $2(|D| - 1)$, so the quotient fits one
/// commitment. `challenge` must be $\chi_A$, derived after the trace and
/// S-box intermediate commitments. $\chi_A$ binds those commitments only,
/// not `key`/`base`; the soundness discussion lives on `SboxStep`.
pub(crate) fn sbox_quotient(
    trace: &NfGridSpectrum,
    square: &SboxSquareSpectrum,
    quartic: &SboxQuarticSpectrum,
    key: Fp,
    base: Fp,
    challenge: Fp,
) -> SboxQuotientSpectrum {
    let origin = base + key;

    let quotient = coset_quotient(
        [
            trace.as_ref(),
            square.as_ref(),
            quartic.as_ref(),
            &ROUND_SCHEDULE_GRID,
            &EPOCH_OFFSET,
            &BOUNDARY_MASK,
        ],
        |[
            trace_eval,
            square_eval,
            quartic_eval,
            schedule_eval,
            offset_eval,
            boundary_eval,
        ]| {
            let input = trace_eval + schedule_eval + key;
            let bound = (origin + offset_eval).pow_vartime([TachyonP5R64::POW]);

            let i1 = square_eval - input.square();
            let i2 = quartic_eval - square_eval.square();
            let i4 = (trace_eval - bound) * boundary_eval;
            i1 + challenge * (i2 + challenge * i4)
        },
    );
    SboxQuotientSpectrum::from(quotient)
}

/// The round quotient $Q_B$ (one commitment): the single round-transition
/// identity divided by $Z_D$, with the last-column wrap exemption:
///
/// $$
/// I_3 = T(\omega X) - \mathsf{quartic} \cdot (T + \mathsf{off})
///     - Z_{H \setminus C} \, \mathsf{wrap}.
/// $$
///
/// A single identity, so no combination challenge. Degree at most
/// $2(|D| - 1)$, so the quotient fits one commitment.
pub(crate) fn wrap_quotient(
    trace: &NfGridSpectrum,
    quartic: &SboxQuarticSpectrum,
    wrap: &WrapSpectrum,
    key: Fp,
) -> WrapQuotientSpectrum {
    let mut advanced = trace.as_ref().clone();
    advanced.dilate(*DOMAIN_GENERATOR);

    let quotient = coset_quotient(
        [
            &advanced,
            trace.as_ref(),
            quartic.as_ref(),
            wrap.as_ref(),
            &ROUND_SCHEDULE_GRID,
            &WRAP_MASK,
        ],
        |[
            next_eval,
            trace_eval,
            quartic_eval,
            wrap_eval,
            schedule_eval,
            mask_eval,
        ]| {
            let input = trace_eval + schedule_eval + key;
            next_eval - quartic_eval * input - mask_eval * wrap_eval
        },
    );
    WrapQuotientSpectrum::from(quotient)
}

/// Build the nullifier-fold accumulator $A$ for the trace at fold weight
/// `challenge`.
///
/// $A$ satisfies $A(X) - \chi A(\zeta X) = T(\sigma X)$ with $\chi$ =
/// `challenge`: its coefficient $a_j = t_j \sigma^j (1 - \chi \zeta^{j
/// \bmod W})^{-1}$ ($\sigma$ the column stride, $\zeta$ the row subgroup
/// generator, $t_j$ the trace coefficients). The identity telescopes over
/// $\langle \zeta \rangle$ to
///
/// $$
/// A(1) \, (1 - \chi^W) = \sum_r \chi^r \, T(\sigma \zeta^r),
/// $$
///
/// folding the trace's final column at $\chi$ in $O(1)$ openings.
pub(crate) fn nf_fold_accumulator(nf: &NfWhitenedSpectrum, challenge: Fp) -> NfFoldAccumulator {
    // Per-row fold denominators $(1 - \chi \zeta^r)^{-1}$, $\zeta$ the order-$W$
    // row generator, cycling with period $W$ over the columns.
    let mut zeta_power = Fp::ONE;
    #[expect(clippy::as_conversions, reason = "NF_DERIVATION_WIDTH fits usize")]
    let denominator_invs: [Fp; NF_DERIVATION_WIDTH as usize] = array::from_fn(|_| {
        let denominator = Fp::ONE - challenge * zeta_power;
        zeta_power *= *NF_EPOCH_STEP;
        denominator
            .invert()
            .expect("challenge is not an inverse root of the row subgroup")
    });

    // $a_j = t_j \sigma^j (1 - \chi \zeta^{j \bmod W})^{-1}$: dilate by the
    // column stride $\sigma$, then scale each coefficient by its row denominator.
    let mut accumulator = nf.as_ref().clone();
    accumulator.dilate(*NF_COSET_SHIFT);
    let coeffs = accumulator
        .iter_coeffs()
        .zip(denominator_invs.iter().cycle())
        .map(|(coeff, &inv)| coeff * inv)
        .collect();
    NfFoldAccumulator::from(Polynomial::from_coeffs(coeffs))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::too_many_arguments,
        reason = "test code"
    )]

    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        keys::NoteMasterKey,
        nullifier::{NfGridSpectrum, NfTraceGrid, Nullifier},
        primitives::EpochIndex,
    };

    fn honest_parts(
        base: EpochIndex,
    ) -> (
        NoteMasterKey,
        NfGridSpectrum,
        (SboxSquareSpectrum, SboxQuarticSpectrum, WrapSpectrum),
    ) {
        let rng = &mut StdRng::seed_from_u64(0);
        let mk = NoteMasterKey(Fp::random(&mut *rng), Fp::random(&mut *rng));
        let grid: NfTraceGrid = (0..NF_DERIVATION_WIDTH)
            .map(|row| mk.derive_nullifier_trace(EpochIndex(base.0 + row)).0)
            .collect();
        let trace = grid.spectrum();
        let binding = grid.round_binding_spectra(&mk);
        (mk, trace, binding)
    }

    /// The two identity residuals $I - Q \cdot Z_D$ at `z` for the
    /// S-box/boundary and round identities, recomputed exactly as the two
    /// cert steps do. Zero iff each quotient satisfies its identity.
    fn identity_residuals(
        base: u32,
        mk: &NoteMasterKey,
        trace: &NfGridSpectrum,
        square: &SboxSquareSpectrum,
        quartic: &SboxQuarticSpectrum,
        wrap: &WrapSpectrum,
        challenge: Fp,
        z: Fp,
    ) -> (Fp, Fp) {
        let q_a = sbox_quotient(
            trace,
            square,
            quartic,
            mk.0,
            Fp::from(u64::from(base)),
            challenge,
        );
        let q_b = wrap_quotient(trace, quartic, wrap, mk.0);

        let z_width = z.pow_vartime([u64::from(NF_DERIVATION_WIDTH)]);
        let vanishing = z.pow_vartime([1 << Polynomial::R]) - Fp::ONE;
        let round_schedule_at_z = ROUND_SCHEDULE_SPECTRUM
            .iter()
            .rev()
            .fold(Fp::ZERO, |acc, &coeff| acc * z_width + coeff);
        let epoch_offset_at_z = EPOCH_OFFSET_SPECTRUM
            .iter()
            .rev()
            .fold(Fp::ZERO, |acc, &coeff| acc * z + coeff);
        let last_complement = vanishing * (z_width - *NF_COSET_ID).invert().unwrap();
        let first_complement = vanishing * (z_width - Fp::ONE).invert().unwrap();

        let input = trace.as_ref().eval(z) + round_schedule_at_z + mk.0;
        let bound =
            (Fp::from(u64::from(base)) + mk.0 + epoch_offset_at_z).pow_vartime([TachyonP5R64::POW]);
        let i1 = square.as_ref().eval(z) - input.square();
        let i2 = quartic.as_ref().eval(z) - square.as_ref().eval(z).square();
        let i4 = (trace.as_ref().eval(z) - bound) * first_complement;
        let sbox = i1 + challenge * (i2 + challenge * i4) - q_a.as_ref().eval(z) * vanishing;

        let i3 = trace.as_ref().eval(*DOMAIN_GENERATOR * z)
            - quartic.as_ref().eval(z) * input
            - last_complement * wrap.as_ref().eval(z);
        let round = i3 - q_b.as_ref().eval(z) * vanishing;

        (sbox, round)
    }

    /// A tampered trace cell throws the S-box/boundary quotient off its
    /// identity. With no divisibility check inside the builder, detection is
    /// the identity opening the cert step performs.
    #[test]
    fn sbox_boundary_quotient_rejects_tampered_trace() {
        let base = 130u32;
        let (mk, trace, (square, quartic, wrap)) = honest_parts(EpochIndex(base));
        let rng = &mut StdRng::seed_from_u64(1);

        let mut bump = [Fp::ZERO; 8];
        bump[7] = Fp::ONE;
        let mut poly = trace.as_ref().clone();
        poly += &Polynomial::from_coeffs(bump.to_vec());
        let tampered = NfGridSpectrum::from(poly);

        let (sbox, _round) = identity_residuals(
            base,
            &mk,
            &tampered,
            &square,
            &quartic,
            &wrap,
            Fp::from(0x00C0_FFEE),
            Fp::random(&mut *rng),
        );
        assert_ne!(
            sbox,
            Fp::ZERO,
            "tampered trace must break the S-box/boundary identity"
        );
    }

    /// A tampered trace cell throws the round quotient off its identity.
    #[test]
    fn wrap_quotient_rejects_tampered_trace() {
        let base = 130u32;
        let (mk, trace, (square, quartic, wrap)) = honest_parts(EpochIndex(base));
        let rng = &mut StdRng::seed_from_u64(1);

        let mut bump = [Fp::ZERO; 8];
        bump[7] = Fp::ONE;
        let mut poly = trace.as_ref().clone();
        poly += &Polynomial::from_coeffs(bump.to_vec());
        let tampered = NfGridSpectrum::from(poly);

        let (_sbox, round) = identity_residuals(
            base,
            &mk,
            &tampered,
            &square,
            &quartic,
            &wrap,
            Fp::from(0x00C0_FFEE),
            Fp::random(&mut *rng),
        );
        assert_ne!(
            round,
            Fp::ZERO,
            "tampered trace must break the round identity"
        );
    }

    /// Both identities hold for real witness polynomials against the real
    /// public columns, checked directly (bypassing `StepCtx`) at a random
    /// challenge point, exactly as the two cert steps recompute them.
    #[test]
    fn real_quotients_match_identities() {
        let base = 130u32;
        let (mk, trace, (square, quartic, wrap)) = honest_parts(EpochIndex(base));
        let rng = &mut StdRng::seed_from_u64(1);

        let (sbox, round) = identity_residuals(
            base,
            &mk,
            &trace,
            &square,
            &quartic,
            &wrap,
            Fp::random(&mut *rng),
            Fp::random(&mut *rng),
        );
        assert_eq!(
            sbox,
            Fp::ZERO,
            "real sbox/boundary quotient does not satisfy the identity"
        );
        assert_eq!(
            round,
            Fp::ZERO,
            "real round quotient does not satisfy the identity"
        );
    }

    /// The trace's nullifier-point evaluations recover the window's nullifiers:
    /// $T(\sigma \zeta^r) + w$ equals `derive_nullifier`'s output for every
    /// row.
    #[test]
    fn nf_reads_match_derived_nullifiers() {
        let base = 130u32;
        let (mk, trace, _binding) = honest_parts(EpochIndex(base));

        let mut node = *NF_COSET_SHIFT;
        for row in 0..NF_DERIVATION_WIDTH {
            let nf = mk.derive_nullifier(EpochIndex(base + row));
            assert_eq!(
                Nullifier::from(trace.as_ref().eval(node) + mk.1),
                nf,
                "whitened coset read does not match the derived nullifier"
            );
            node *= *NF_EPOCH_STEP;
        }
    }
}
