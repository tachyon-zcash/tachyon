//! Prove a fusable range of a note's per-epoch nullifiers.
//!
//! Four steps. [`NfSboxStep`] and [`NfWrapStep`] are parallel, note-free
//! seeds over the same witnessed cipher trace: one proves the S-box
//! decomposition and window boundary, the other the round transition. Both
//! take their key operand as a free witness carried on their header.
//! [`NfDerive`] joins the two certs: it witnesses the note once, pins both
//! certs' free keys to the note's real master key, stitches the certs by
//! commit equality, and crosses the certified evaluation-form window into
//! the bare-Horner coefficient form every consumer reads, exporting one
//! canonical window per proof as a [`NullifierDerivation`].
//! [`NullifierFuse`] concatenates adjacent ranges, so a span of any length
//! is a chain of windows. All
//! headers are wallet-only, and no key material rides the exported
//! [`NullifierDerivation`].

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Polynomial, Step, Suffix,
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};
use zcash_mimc::specs::tachyon::TachyonP5R64;

use crate::{
    digest::poseidon,
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::{self, Note},
    nullifier::{
        NF_BASE_MAX, NF_DERIVATION_WIDTH, NfFoldAccumulator, NfGridSpectrum, NfGridSpectrumCommit,
        NfWindowSpectrum, NfWindowSpectrumCommit, Nullifier, SboxQuarticSpectrum,
        SboxQuarticSpectrumCommit, SboxQuotientSpectrum, SboxSquareSpectrum, WrapQuotientSpectrum,
        WrapSpectrum,
        derivation::{
            DOMAIN_GENERATOR, EPOCH_OFFSET_SPECTRUM, NF_COSET_ID, NF_COSET_SHIFT,
            NF_EPOCH_STEP_INV, ROUND_SCHEDULE_SPECTRUM,
        },
    },
    primitives::{EpochIndex, NfSeqCommit, NfSeqPoly},
    relations::enforce::enforce_shifted_combination,
};

/// A certified S-box/boundary slice of a window's trace (wallet-only).
///
/// Carries the trace, whitened, and quartic commitments, the master key `mk`
/// (a free witness at the seed; a bare cert is sound only once [`NfDerive`]
/// pins it), and the window `base`. Attests $\mathsf{square} = (T +
/// \mathsf{off})^2$ and $\mathsf{quartic} = \mathsf{square}^2$ (off the wrap
/// column), the arithmetic-progression boundary for this `base`, and the
/// homomorphic whitening $\mathsf{nf\_commit} = \mathsf{trace\_commit} +
/// \lbrack w \rbrack\,\mathcal{G}_0$.
#[derive(Clone, Debug)]
pub struct Sbox;

impl Header for Sbox {
    /// `(trace_commit, nf_commit, quartic_commit, mk, base)`.
    type Data = (
        NfGridSpectrumCommit,
        NfWindowSpectrumCommit,
        SboxQuarticSpectrumCommit,
        NoteMasterKey,
        EpochIndex,
    );

    const SUFFIX: Suffix = Suffix::new(13);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (trace_commit, nf_commit, quartic_commit, mk, base) = *data;
        (
            vec![mk.0, mk.1, Fp::from(base)],
            Vec::new(),
            Vec::new(),
            vec![
                Eq::from(trace_commit),
                Eq::from(nf_commit),
                Eq::from(quartic_commit),
            ],
        )
    }
}

/// A certified round-transition slice of a window's trace (wallet-only).
///
/// Carries the trace and quartic commitments and the master key `mk` (a free
/// witness at the seed; a bare cert is sound only once [`NfDerive`] pins it).
/// Attests the round transition $T(\omega X) = \mathsf{quartic} \cdot (T +
/// \mathsf{off}) + Z_{H \setminus C}\,\mathsf{wrap}$ over the same trace the
/// S-box cert constrains, which [`NfDerive`] confirms by commit equality.
#[derive(Clone, Debug)]
pub struct Wrap;

impl Header for Wrap {
    /// `(trace_commit, quartic_commit, mk)`.
    type Data = (
        NfGridSpectrumCommit,
        SboxQuarticSpectrumCommit,
        NoteMasterKey,
    );

    const SUFFIX: Suffix = Suffix::new(15);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (trace_commit, quartic_commit, mk) = *data;
        (
            vec![mk.0, mk.1],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(trace_commit), Eq::from(quartic_commit)],
        )
    }
}

/// A proven contiguous range of derived nullifiers (wallet-only).
///
/// `(cm, (epoch_start, nf_start), nf_commit, (epoch_end, nf_last))`: covers
/// epochs `[epoch_start, epoch_end)`; `nf_commit` commits the range's
/// nullifier sequence $g$ in bare Horner order (see
/// [`NfSeqPoly`]), one coefficient per covered
/// epoch, the newest at degree $0$. `cm` binds the range to the real note.
///
/// No consumer reads either boundary nullifier as data; every read selects
/// its own window out of the sequence. `nf_start` is the **rank pin**: it is
/// $g$'s top coefficient, nonzero by the leaf's guards and threaded by the
/// fuse, and that induction is what places every covering read's bands.
/// `nf_last` is pinned by the fuse's degree-0 query.
///
/// The header carries a range and a commitment, nothing about who will read
/// it or where: masking is the consuming step's responsibility.
#[derive(Clone, Debug)]
pub struct NullifierDerivation;

impl Header for NullifierDerivation {
    /// `(cm, (epoch_start, nf_start), nf_commit, (epoch_end, nf_last))`.
    /// `epoch_end` is exclusive and names no item; `nf_last` is the member at
    /// `epoch_end - 1`.
    type Data = (
        note::Commitment,
        (EpochIndex, Nullifier),
        NfSeqCommit,
        (EpochIndex, Nullifier),
    );

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, (epoch_start, nf_start), nf_commit, (epoch_end, nf_last)) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(epoch_start),
                Fp::from(nf_start),
                Fp::from(epoch_end),
                Fp::from(nf_last),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(nf_commit)],
        )
    }
}

/// Certify the S-box decomposition and the boundary of a window's trace, and
/// whiten its commitment.
///
/// Seed step. Witnesses the trace $T$, the S-box intermediates
/// `square`/`quartic`, the combined quotient $Q_A$, the master key `mk` (free
/// here; [`NfDerive`] pins it to the note's real one), and the window `base`.
/// Derives $\chi_A$ over $(T, \mathsf{square}, \mathsf{quartic})$ and
/// proves, combined at a free $z_A$, the S-box decomposition
///
/// $$
/// \mathsf{square} = (T + \mathsf{off})^2, \qquad
/// \mathsf{quartic} = \mathsf{square}^2
/// $$
///
/// (with $\mathsf{off}$ the public schedule plus round key $k$), and the
/// boundary $(T - (\mathsf{base} + k + N_{\mathsf{row}})^5) \, Z_{H \setminus
/// C_0}$ pinning each row's first cell to round $0$ of its
/// arithmetic-progression input $\mathsf{base} + r$. Range-checks `base` and
/// computes $\mathsf{nf\_commit} = \mathsf{trace\_commit} +
/// \lbrack w \rbrack\,\mathcal{G}_0$, the commitment of the whitened trace
/// $W = T + w$,
/// in-circuit, so a valid export's `nf_commit` is a pinned function of the
/// certified trace and the pinned `mk`. The whitening is computed here and
/// sounded by [`NfDerive`]'s `mk` pin.
///
/// # Soundness
///
/// $\chi_A$ binds only the three column commitments; the scalar identity
/// operands $k$ and $\mathsf{base}$ ride the header unabsorbed. The
/// combination argument
/// alone therefore does not force $I_1$/$I_2$/$I_4$ individually against a
/// prover choosing $k$/$\mathsf{base}$ after $\chi_A$: a bare cert attests
/// the identities for *some* $(k, \mathsf{base})$ only. [`NfDerive`], the
/// cert's sole consumer, pins `mk` to the note's Poseidon-derived key, so
/// choosing $k$ as a function of $\chi_A$ requires inverting that
/// derivation; with $k$ pinned, $\mathsf{base}$ is one scalar against the
/// boundary column's full set of equations. Any new consumer of [`Sbox`]
/// certs must preserve the `mk` pin before trusting the identities.
///
/// # Gate budget
///
/// | item | gates |
/// |---|---|
/// | $\chi_A$ sponge (absorb 7, squeeze 1: two permutations) | ~590 |
/// | $N_{\mathsf{row}}(z)$ Horner + schedule Horner | ~190 |
/// | power chains, inverse, identity | ~30 |
/// | base range check | ~10 |
/// | whitening scalar multiplication | ~512 |
/// | total | ~1332 |
#[derive(Debug)]
pub struct NfSboxStep;

impl Step for NfSboxStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = Sbox;
    type Right = ();
    /// `(trace, square, quartic, quotient, mk, base)`.
    type Witness<'source> = (
        NfGridSpectrum,
        SboxSquareSpectrum,
        SboxQuarticSpectrum,
        SboxQuotientSpectrum,
        NoteMasterKey,
        EpochIndex, // base in 0..=NF_BASE_MAX
    );

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (trace, square, quartic, quotient, mk, base): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Native stand-in for the base range check.
        if base.0 > NF_BASE_MAX {
            return Err(ragu::Error::InvalidWitness(
                "Sbox: base exceeds epoch space".into(),
            ));
        }

        let NoteMasterKey(key, whitening) = mk;

        // $\chi_A$: the Poseidon combination challenge over the three column
        // commitments; $k$ and `base` are deliberately unabsorbed (see the
        // step's soundness section).
        let chi = poseidon::derivation_challenge(
            trace.commit().into(),
            square.commit().into(),
            quartic.commit().into(),
        );

        // $z_A$: a fresh transcript challenge over all four commitments.
        let z = ctx.derive_challenge(&[
            trace.commit().into(),
            square.commit().into(),
            quartic.commit().into(),
            quotient.commit().into(),
        ])?;

        let trace_at_z = trace.as_ref().eval(z);
        ctx.enforce_poly_query(trace.commit().into(), z, trace_at_z)?;
        let square_at_z = square.as_ref().eval(z);
        ctx.enforce_poly_query(square.commit().into(), z, square_at_z)?;
        let quartic_at_z = quartic.as_ref().eval(z);
        ctx.enforce_poly_query(quartic.commit().into(), z, quartic_at_z)?;
        let quotient_at_z = quotient.as_ref().eval(z);
        ctx.enforce_poly_query(quotient.commit().into(), z, quotient_at_z)?;

        #[expect(
            clippy::as_conversions,
            reason = "the window width is a small constant"
        )]
        let z_width = z.pow_vartime([NF_DERIVATION_WIDTH as u64]);
        let vanishing = z.pow_vartime([1 << Polynomial::R]) - Fp::ONE;
        let round_schedule_at_z = ROUND_SCHEDULE_SPECTRUM
            .iter()
            .rev()
            .fold(Fp::ZERO, |acc, &coeff| acc * z_width + coeff);
        let epoch_offset_at_z = EPOCH_OFFSET_SPECTRUM
            .iter()
            .rev()
            .fold(Fp::ZERO, |acc, &coeff| acc * z + coeff);
        #[expect(
            clippy::expect_used,
            reason = "a derived challenge lands on a column with negligible probability"
        )]
        let first_complement = vanishing
            * (z_width - Fp::ONE)
                .invert()
                .into_option()
                .expect("random challenge does not land on the first column");

        // Combined identity: $I_1 + \chi_A I_2 + \chi_A^2 I_4 = Q_A Z_D$
        // at $z$.
        let input = trace_at_z + round_schedule_at_z + key;
        let bound = (Fp::from(base) + key + epoch_offset_at_z).pow_vartime([TachyonP5R64::POW]);
        let i1 = square_at_z - input.square();
        let i2 = quartic_at_z - square_at_z.square();
        let i4 = (trace_at_z - bound) * first_complement;
        if i1 + chi * (i2 + chi * i4) != quotient_at_z * vanishing {
            return Err(ragu::Error::InvalidWitness(
                "Sbox: sbox/boundary identity fails at challenge".into(),
            ));
        }

        // Whitening: $\mathsf{nf\_commit} = \mathsf{trace\_commit} +
        // [w]\,\mathcal{G}_0$ is the commitment of $W = T + w$ (the
        // whitening lands on the constant coefficient's generator), computed
        // in-circuit so `nf_commit` is pinned by the trace commitment and
        // `mk`.
        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let nf_commit = NfWindowSpectrumCommit::from(Eq::from(trace.commit()) + g0 * whitening);

        Ok(((trace.commit(), nf_commit, quartic.commit(), mk, base), ()))
    }
}

/// Certify the round transition of a window's trace.
///
/// Seed step, the pure-cipher sibling of [`NfSboxStep`] over the same
/// witnessed trace: no note, no sponges. Witnesses the trace $T$, the
/// `quartic` intermediate, the wrap correction `wrap`, the round quotient
/// $Q_B$, and the master key `mk` (free here; [`NfDerive`] pins it), proving
/// the single round-transition identity
///
/// $$
/// T(\omega X) = \mathsf{quartic} \cdot (T + \mathsf{off})
///     + Z_{H \setminus C} \, \mathsf{wrap}
/// $$
///
/// at a free $z_B$. That the trace and `quartic` are the same polynomials the
/// S-box cert constrained is [`NfDerive`]'s stitch, by commit equality.
///
/// # Gate budget
///
/// | item | gates |
/// |---|---|
/// | schedule Horner | ~63 |
/// | power chains, inverse, identity | ~30 |
/// | total | ~93 |
#[derive(Debug)]
pub struct NfWrapStep;

impl Step for NfWrapStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = Wrap;
    type Right = ();
    /// `(trace, quartic, wrap, quotient, mk)`.
    type Witness<'source> = (
        NfGridSpectrum,
        SboxQuarticSpectrum,
        WrapSpectrum,
        WrapQuotientSpectrum,
        NoteMasterKey,
    );

    const INDEX: Index = Index::new(24);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (trace, quartic, wrap, quotient, mk): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let NoteMasterKey(key, _whitening) = mk;

        // $z_B$: a fresh transcript challenge over the four commitments. No
        // combination challenge: a single identity is its own quotient.
        let z = ctx.derive_challenge(&[
            trace.commit().into(),
            quartic.commit().into(),
            wrap.commit().into(),
            quotient.commit().into(),
        ])?;

        let trace_at_z = trace.as_ref().eval(z);
        ctx.enforce_poly_query(trace.commit().into(), z, trace_at_z)?;
        let trace_advanced = trace.as_ref().eval(*DOMAIN_GENERATOR * z);
        ctx.enforce_poly_query(trace.commit().into(), *DOMAIN_GENERATOR * z, trace_advanced)?;
        let quartic_at_z = quartic.as_ref().eval(z);
        ctx.enforce_poly_query(quartic.commit().into(), z, quartic_at_z)?;
        let wrap_at_z = wrap.as_ref().eval(z);
        ctx.enforce_poly_query(wrap.commit().into(), z, wrap_at_z)?;
        let quotient_at_z = quotient.as_ref().eval(z);
        ctx.enforce_poly_query(quotient.commit().into(), z, quotient_at_z)?;

        #[expect(
            clippy::as_conversions,
            reason = "the window width is a small constant"
        )]
        let z_width = z.pow_vartime([NF_DERIVATION_WIDTH as u64]);
        let vanishing = z.pow_vartime([1 << Polynomial::R]) - Fp::ONE;
        let round_schedule_at_z = ROUND_SCHEDULE_SPECTRUM
            .iter()
            .rev()
            .fold(Fp::ZERO, |acc, &coeff| acc * z_width + coeff);
        #[expect(
            clippy::expect_used,
            reason = "a derived challenge lands on a column with negligible probability"
        )]
        let last_complement = vanishing
            * (z_width - *NF_COSET_ID)
                .invert()
                .into_option()
                .expect("random challenge does not land on the last column");

        // Round identity $I_3 = Q_B Z_D$ at $z$.
        let input = trace_at_z + round_schedule_at_z + key;
        let i3 = trace_advanced - quartic_at_z * input - last_complement * wrap_at_z;
        if i3 != quotient_at_z * vanishing {
            return Err(ragu::Error::InvalidWitness(
                "Wrap: round identity fails at challenge".into(),
            ));
        }

        Ok(((trace.commit(), quartic.commit(), mk), ()))
    }
}

/// Join the two cipher certs, bind the note, and export the window in
/// coefficient form as a certified [`NullifierDerivation`].
///
/// `Left = Sbox`, `Right = Wrap`: the two-input join, the single
/// note-semantics site, and the format crossing. Stitches the certs (trace
/// and quartic commit equalities), derives the note's real master key
/// (`note.pk == pak.derive_payment_key()` pins `nk`; `mk =
/// derive_note_private(psi, nk)`) and pins both certs' free-witness keys to
/// it, completing both combination arguments; `cm` is computed here where
/// the note is witnessed, and `nk` never leaves the step.
///
/// The crossing is a format translation: the cipher identities exist only on
/// an evaluation domain, and the fusable sequence is coefficient form, so one
/// whole trace window becomes one bare-Horner sequence; selection belongs to
/// the consumers' covering reads. The fold accumulator $A$ satisfies $A(X) -
/// \chi A(\zeta^{-1} X) = W(\sigma X)$ exactly as polynomials (checked at a
/// free $z$), and the full-window telescope collapses to a single opening,
/// since $\zeta^{W-1} = \zeta^{-1}$:
///
/// $$
/// g(\chi) = A(\zeta^{W-1}) - \chi^{W} A(\zeta^{-1})
///         = A(\zeta^{-1})\,(1 - \chi^{W}).
/// $$
///
/// $\chi$ is Poseidon-bound to the whitened window's and $g$'s commitments
/// (see `poseidon::fold_challenge`), so the single-point discharge forces
/// every coefficient of $g$ to the genuine nullifiers.
///
/// # Committed polynomials
///
/// | polynomial | role |
/// |---|---|
/// | `window` | the whitened trace $W$, bound to the sbox cert's `nf_commit` |
/// | `accumulator` | the fold accumulator $A$, built for $\chi$ |
/// | `seq` | the exported bare-Horner sequence $g$ |
///
/// # Gate budget
///
/// | item | gates |
/// |---|---|
/// | payment-key sponge (one permutation) | ~293 |
/// | master-key sponge (absorb 3, squeeze 2: one permutation) | ~293 |
/// | note-commitment sponge (two permutations) | ~586 |
/// | $\chi$ sponge (absorb 5, squeeze 1: two permutations) | ~590 |
/// | commit-equality binds and key pins | ~10 |
/// | fold and telescope algebra | ~30 |
/// | total | ~1802 |
#[derive(Debug)]
pub struct NfDerive;

impl Step for NfDerive {
    type Aux<'source> = ();
    type Left = Sbox;
    type Output = NullifierDerivation;
    type Right = Wrap;
    /// `(note, pak, window, accumulator, seq)`.
    type Witness<'source> = (
        Note,
        ProofAuthorizingKey,
        NfWindowSpectrum,
        NfFoldAccumulator,
        NfSeqPoly,
    );

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (note, pak, window, accumulator, seq): Self::Witness<'source>,
        (sbox_trace, sbox_nf_commit, sbox_quartic, sbox_mk, base): <Self::Left as Header>::Data,
        (wrap_trace, wrap_quartic, wrap_mk): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Stitch: both certs constrained the same trace and quartic.
        enforce_equal_point(
            Eq::from(sbox_trace),
            Eq::from(wrap_trace),
            "NfDerive: certs disagree on the trace",
        )?;
        enforce_equal_point(
            Eq::from(sbox_quartic),
            Eq::from(wrap_quartic),
            "NfDerive: certs disagree on the quartic",
        )?;

        // Master: derive the note's real `mk` at its master secrets and pin
        // both certs' free witnesses to it. `nk` never leaves the step (only
        // the payment key `pk` does, and it preimage-hides `nk`).
        enforce_zero(
            Fp::from(note.pk) - Fp::from(pak.derive_payment_key()),
            "NfDerive: pak not related to note",
        )?;
        let mk = pak.nk.derive_note_private(note.psi);
        enforce_zero(
            mk.0 - sbox_mk.0,
            "NfDerive: sbox round key does not match the note",
        )?;
        enforce_zero(
            mk.1 - sbox_mk.1,
            "NfDerive: sbox whitening key does not match the note",
        )?;
        enforce_zero(
            mk.0 - wrap_mk.0,
            "NfDerive: wrap round key does not match the note",
        )?;
        enforce_zero(
            mk.1 - wrap_mk.1,
            "NfDerive: wrap whitening key does not match the note",
        )?;
        let cm = note.commitment();

        // The whitened window: the sbox cert computed `nf_commit` from its
        // certified trace and the now-pinned `mk`, so binding the witness to
        // it makes $W$ the genuine whitened trace.
        enforce_equal_point(
            Eq::from(window.commit()),
            Eq::from(sbox_nf_commit),
            "NfDerive: whitened window does not match the cert",
        )?;

        // $\chi$: the fold weight, Poseidon over the whitened window's and
        // the sequence's commitments; $A$ is built for it, and the
        // single-point discharge below is sound only because $\chi$ binds
        // $g$'s commitment.
        let chi = poseidon::fold_challenge(sbox_nf_commit.into(), seq.commit().into());

        // `z`: a fresh transcript challenge over the three commitments, so
        // the fold identity's operands are fixed before it (Schwartz-Zippel).
        let z = ctx.derive_challenge(&[
            window.commit().into(),
            accumulator.commit().into(),
            seq.commit().into(),
        ])?;

        // Fold identity: $A(X) - \chi A(\zeta^{-1} X) = W(\sigma X)$, exact
        // as polynomials (both sides have degree below `|D|`), so the point
        // check forces it coefficient-wise and the telescope below is sound.
        let zeta_inv = *NF_EPOCH_STEP_INV;
        let window_at_coset = window.as_ref().eval(*NF_COSET_SHIFT * z);
        ctx.enforce_poly_query(window.commit().into(), *NF_COSET_SHIFT * z, window_at_coset)?;
        let accumulator_at_z = accumulator.as_ref().eval(z);
        ctx.enforce_poly_query(accumulator.commit().into(), z, accumulator_at_z)?;
        let accumulator_folded = accumulator.as_ref().eval(zeta_inv * z);
        ctx.enforce_poly_query(
            accumulator.commit().into(),
            zeta_inv * z,
            accumulator_folded,
        )?;
        if accumulator_at_z - chi * accumulator_folded != window_at_coset {
            return Err(ragu::Error::InvalidWitness(
                "NfDerive: fold accumulator identity fails at challenge".into(),
            ));
        }

        // Full-window telescope: head $A(\zeta^{W-1})$ and tail
        // $A(\zeta^{-1})$ coincide, since $\zeta$ has order $W$.
        let boundary = accumulator.as_ref().eval(zeta_inv);
        ctx.enforce_poly_query(accumulator.commit().into(), zeta_inv, boundary)?;
        #[expect(
            clippy::as_conversions,
            reason = "the window width is a small constant"
        )]
        let chi_window = chi.pow_vartime([NF_DERIVATION_WIDTH as u64]);
        let seq_at_chi = seq.eval(chi);
        ctx.enforce_poly_query(seq.commit().into(), chi, seq_at_chi)?;
        if seq_at_chi != boundary * (Fp::ONE - chi_window) {
            return Err(ragu::Error::InvalidWitness(
                "NfDerive: sequence does not match the folded window".into(),
            ));
        }

        // Boundary nullifiers: repeat reads on the already-opened window at
        // the coset's endpoints. The nonzero start is the rank pin: $g$'s
        // top coefficient cannot be zero, so the announced range is $g$'s
        // actual rank. `nf_last` is additionally $g$'s own degree 0.
        let window_at_start = window.as_ref().eval(*NF_COSET_SHIFT);
        ctx.enforce_poly_query(window.commit().into(), *NF_COSET_SHIFT, window_at_start)?;
        let last_point = *NF_COSET_SHIFT * zeta_inv;
        let window_at_last = window.as_ref().eval(last_point);
        ctx.enforce_poly_query(window.commit().into(), last_point, window_at_last)?;
        enforce_nonzero(window_at_start, "NfDerive: starting nullifier is zero")?;
        enforce_nonzero(window_at_last, "NfDerive: final nullifier is zero")?;
        ctx.enforce_poly_query(seq.commit().into(), Fp::ZERO, window_at_last)?;

        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "the window width is a small constant"
        )]
        let end = EpochIndex(base.0 + NF_DERIVATION_WIDTH as u32);
        Ok((
            (
                cm,
                (base, Nullifier::from(window_at_start)),
                seq.commit(),
                (end, Nullifier::from(window_at_last)),
            ),
            (),
        ))
    }
}

/// Concatenate two adjacent derived ranges into one.
///
/// The halves must share `cm` and be contiguous (`right.start == left.end`).
/// Each witnessed sequence is bound to its header commitment, and the merged
/// sequence is the left half shifted past the right half's span plus the
/// right half: $g = X^{\mathsf{right\_span}}\,g_L + g_R$, enforced as a
/// shifted combination at a transcript challenge.
///
/// The degree-0 queries pin the **end** nullifiers, the one coefficient a
/// single opening isolates under Horner order: `merged` opens to
/// `right.nf_last` (also right's own degree 0) and `left` opens to
/// `left.nf_last`. `nf_start` is the
/// non-extractable top coefficient; it threads from the left header, and its
/// nonzero-ness (the rank pin) is inductive from the leaf's guard.
///
/// # Committed polynomials
///
/// | polynomial | role |
/// |---|---|
/// | `left_seq` | left half, bound to `left.nf_commit` |
/// | `right_seq` | right half, bound to `right.nf_commit` |
/// | `merged_seq` | the concatenation, bound by the shifted combination |
#[derive(Debug)]
pub struct NullifierFuse;

impl Step for NullifierFuse {
    type Aux<'source> = ();
    type Left = NullifierDerivation;
    type Output = NullifierDerivation;
    type Right = NullifierDerivation;
    /// `(left_seq, merged_seq, right_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(16);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_seq, merged_seq, right_seq): Self::Witness<'source>,
        (
            left_cm,
            (left_epoch_start, left_nf_start),
            left_nf_commit,
            (left_epoch_end, left_nf_last),
        ): <Self::Left as Header>::Data,
        (
            right_cm,
            (right_epoch_start, _right_nf_start),
            right_nf_commit,
            (right_epoch_end, right_nf_last),
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_cm) - Fp::from(right_cm),
            "NullifierFuse: note commitments differ",
        )?;
        enforce_zero(
            Fp::from(right_epoch_start) - Fp::from(left_epoch_end),
            "NullifierFuse: ranges not contiguous",
        )?;
        enforce_equal_point(
            Eq::from(left_seq.commit()),
            Eq::from(left_nf_commit),
            "NullifierFuse: left polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(right_seq.commit()),
            Eq::from(right_nf_commit),
            "NullifierFuse: right polynomial does not match header",
        )?;
        let merged_nf_commit = merged_seq.commit();
        let right_span = right_epoch_end - right_epoch_start;
        enforce_shifted_combination(
            ctx,
            [
                (left_seq.as_ref(), right_span.into()),
                (right_seq.as_ref(), 0),
            ],
            [],
            merged_seq.as_ref(),
            "NullifierFuse: merged is not the concat of the halves",
        )?;
        ctx.enforce_poly_query(merged_nf_commit.into(), Fp::ZERO, Fp::from(right_nf_last))?;
        ctx.enforce_poly_query(left_seq.commit().into(), Fp::ZERO, Fp::from(left_nf_last))?;
        Ok((
            (
                left_cm,
                (left_epoch_start, left_nf_start),
                merged_nf_commit,
                (right_epoch_end, right_nf_last),
            ),
            (),
        ))
    }
}
