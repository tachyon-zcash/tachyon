//! Prove a trace of nullifier derivations.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Polynomial, Step, Suffix,
    constraint::{enforce_equal_point, enforce_zero},
};
use zcash_mimc::specs::tachyon::TachyonP5R64;

use crate::{
    constants::{EPOCH_MAX, NF_DERIVATION_WIDTH},
    digest::poseidon,
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::{self, Note},
    nullifier::{
        NfGridSpectrum, NfGridSpectrumCommit, NfWhitenedSpectrumCommit, SboxQuarticSpectrum,
        SboxQuarticSpectrumCommit, SboxQuotientSpectrum, SboxSquareSpectrum, WrapQuotientSpectrum,
        WrapSpectrum,
        derivation::{
            DOMAIN_GENERATOR, EPOCH_OFFSET_SPECTRUM, NF_COSET_ID, ROUND_SCHEDULE_SPECTRUM,
        },
    },
    primitives::EpochIndex,
};

/// A certified S-box/boundary slice of a window's trace (wallet-only).
///
/// Carries the trace, whitened, and quartic commitments, the master key `mk`
/// (a free witness at the seed; a bare cert is sound only once [`WrapStep`]
/// pins it), and the window `base`. Attests $\mathsf{square} = (T +
/// \mathsf{off})^2$ and $\mathsf{quartic} = \mathsf{square}^2$ (off the wrap
/// column), the arithmetic-progression boundary for this `base`, and the
/// homomorphic whitening $\mathsf{nf\_commit} = \mathsf{trace\_commit} +
/// [w]\,\mathcal{G}_0$.
#[derive(Clone, Debug)]
pub struct Sbox;

impl Header for Sbox {
    /// `(trace_commit, nf_commit, quartic_commit, mk, base)`.
    type Data = (
        NfGridSpectrumCommit,
        NfWhitenedSpectrumCommit,
        SboxQuarticSpectrumCommit,
        NoteMasterKey,
        EpochIndex,
    );

    const SUFFIX: Suffix = Suffix::new(12);

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

/// A certified, point-queryable window of derived nullifiers (wallet-only).
///
/// `(cm, epoch_start, epoch_end, nf_commit)`: covers epochs `[epoch_start,
/// epoch_end)`, always one `NF_DERIVATION_WIDTH`-wide window; `nf_commit`
/// commits the whitened trace $W = T + w$, whose last-column cells are the
/// genuine nullifiers, $\mathsf{nf}_{\mathsf{epoch\_start}+j} = W(\sigma
/// \zeta^j)$ ($\sigma$ the column stride, $\zeta$ the row-subgroup
/// generator). `cm` binds the window to the real note.
/// Consumers re-witness `W`, bind it by commit-equality, and read covered
/// nullifiers as single openings at pinned points. No key material rides the
/// header.
#[derive(Clone, Debug)]
pub struct NullifierDerivation;

impl Header for NullifierDerivation {
    /// `(cm, epoch_start, epoch_end, nf_commit)`.
    type Data = (
        note::Commitment,
        EpochIndex,
        EpochIndex,
        NfWhitenedSpectrumCommit,
    );

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, epoch_start, epoch_end, nf_commit) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(u64::from(epoch_start.0)),
                Fp::from(u64::from(epoch_end.0)),
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
/// here; [`WrapStep`] pins it to the note's real one), and the window `base`.
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
/// [w]\,\mathcal{G}_0$, the commitment of the whitened trace $W = T + w$,
/// in-circuit, so a valid export's `nf_commit` is a pinned function of the
/// certified trace and the pinned `mk`.
///
/// # Soundness
///
/// $\chi_A$ binds only the three column commitments; the scalar identity
/// operands $k$ and $\mathsf{base}$ ride the header unabsorbed (absorbing
/// them would cost a third sponge permutation). The combination argument
/// alone therefore does not force $I_1$/$I_2$/$I_4$ individually against a
/// prover choosing $k$/$\mathsf{base}$ after $\chi_A$: a bare cert attests
/// the identities for *some* $(k, \mathsf{base})$ only. [`WrapStep`], the
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
pub struct SboxStep;

impl Step for SboxStep {
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
        EpochIndex, // base in 0..=(EPOCH_MAX - (NF_DERIVATION_WIDTH - 1))
    );

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (trace, square, quartic, quotient, mk, base): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Native mock stand-in for the base range check: in real ragu this is
        // a bit decomposition against the epoch space's width.
        if base.0 > (EPOCH_MAX - (NF_DERIVATION_WIDTH - 1)) {
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
        let first_complement = vanishing
            * (z_width - Fp::ONE)
                .invert()
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
        let nf_commit = NfWhitenedSpectrumCommit::from(Eq::from(trace.commit()) + g0 * whitening);

        Ok(((trace.commit(), nf_commit, quartic.commit(), mk, base), ()))
    }
}

/// Certify the round transition, pin the master key, and export the window as
/// a certified [`NullifierDerivation`].
///
/// `Left = Sbox`. Witnesses the trace $T$, the `quartic` intermediate, the
/// wrap correction `wrap`, the round quotient $Q_B$, and the note with its
/// proof authorizing key `pak`. Binds $T$ and `quartic` by commit-equality
/// to the cert's header, proving the single round-transition identity
///
/// $$
/// T(\omega X) = \mathsf{quartic} \cdot (T + \mathsf{off})
///     + Z_{H \setminus C} \, \mathsf{wrap}
/// $$
///
/// at a free $z_B$ against the same trace the cert constrained. Derives the
/// note's real master key (`note.pk == pak.derive_payment_key()` pins `nk`;
/// `mk = derive_note_private(psi, nk)`) and pins the cert's free-witness
/// `mk` to it, computing `cm` here where the note is witnessed; `nk` never
/// leaves the step. The pin fixes the scalar operands of the cert's $\chi_A$
/// combination, completing the seed's soundness argument. The cert's
/// `nf_commit`, now a pinned function of certified trace and real `mk`, is
/// published.
///
/// # Gate budget
///
/// | item | gates |
/// |---|---|
/// | payment-key sponge (one permutation) | ~293 |
/// | master-key sponge (absorb 3, squeeze 2: one permutation) | ~293 |
/// | note-commitment sponge (two permutations) | ~586 |
/// | schedule Horner | ~63 |
/// | power chains, inverse, identity | ~30 |
/// | commit-equality binds (two point equalities) | ~4 |
/// | total | ~1269 |
#[derive(Debug)]
pub struct WrapStep;

impl Step for WrapStep {
    type Aux<'source> = ();
    type Left = Sbox;
    type Output = NullifierDerivation;
    type Right = ();
    /// `(trace, quartic, wrap, quotient, note, pak)`.
    type Witness<'source> = (
        NfGridSpectrum,
        SboxQuarticSpectrum,
        WrapSpectrum,
        WrapQuotientSpectrum,
        Note,
        ProofAuthorizingKey,
    );

    const INDEX: Index = Index::new(16);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (trace, quartic, wrap, quotient, note, pak): Self::Witness<'source>,
        (left_trace, left_nf_commit, left_quartic, left_mk, base): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Stitch: this step's identity runs against the same trace and
        // `quartic` the cert constrained.
        enforce_equal_point(
            Eq::from(trace.commit()),
            Eq::from(left_trace),
            "Wrap: trace does not match the cert",
        )?;
        enforce_equal_point(
            Eq::from(quartic.commit()),
            Eq::from(left_quartic),
            "Wrap: quartic does not match the cert",
        )?;

        // Master: derive the note's real `mk` at its master secrets and pin
        // the cert's free witness to it. `nk` never leaves the step (only the
        // payment key `pk` does, and it preimage-hides `nk`).
        enforce_zero(
            note.pk.0 - pak.derive_payment_key().0,
            "Wrap: pak not related to note",
        )?;
        let mk = pak.nk.derive_note_private(note.psi);
        enforce_zero(mk.0 - left_mk.0, "Wrap: round key does not match the note")?;
        enforce_zero(
            mk.1 - left_mk.1,
            "Wrap: whitening key does not match the note",
        )?;
        let cm = note.commitment();

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

        let z_width = z.pow_vartime([u64::from(NF_DERIVATION_WIDTH)]);
        let vanishing = z.pow_vartime([1 << Polynomial::R]) - Fp::ONE;
        let round_schedule_at_z = ROUND_SCHEDULE_SPECTRUM
            .iter()
            .rev()
            .fold(Fp::ZERO, |acc, &coeff| acc * z_width + coeff);
        let last_complement = vanishing
            * (z_width - *NF_COSET_ID)
                .invert()
                .expect("random challenge does not land on the last column");

        // Round identity $I_3 = Q_B Z_D$ at $z$.
        let input = trace_at_z + round_schedule_at_z + key;
        let i3 = trace_advanced - quartic_at_z * input - last_complement * wrap_at_z;
        if i3 != quotient_at_z * vanishing {
            return Err(ragu::Error::InvalidWitness(
                "Wrap: round identity fails at challenge".into(),
            ));
        }

        let end = EpochIndex(base.0 + NF_DERIVATION_WIDTH);
        Ok(((cm, base, end, left_nf_commit), ()))
    }
}
