//! Nullifier-derivation trace polynomials.
//!
//! One window derivation carries two commitments over the same grid, and the
//! newtypes keep their polynomials apart:
//!
//! - [`NfGridSpectrum`] is the trace interpolant $T$, bound as `trace_commit`.
//!   Its cells are raw cipher round states; the whitening key appears nowhere
//!   in it. The cert steps witness $T$ and prove the round identities over it.
//! - [`NfWhitenedSpectrum`] is the whitened trace $W = T + w$, bound as
//!   `nf_commit`. Its nullifier-coset evaluations are the genuine nullifiers,
//!   so consumer steps read $\mathsf{nf}_{\mathsf{base}+j} = W(\sigma \zeta^j)$
//!   as single openings, with no key material in the step.
//!
//! [`SboxStep`](crate::stamp::proof::delegation::SboxStep) links the two
//! in-circuit, $\mathsf{nf\_commit} = \mathsf{trace\_commit} +
//! [w]\,\mathcal{G}_0$: one scalar multiplication, once per window, so no
//! consumer pays for whitening.

use alloc::vec::Vec;
use core::array;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu::{Domain, Polynomial};
use zcash_mimc::specs::tachyon::TachyonP5R64;

use crate::{
    constants::NF_DERIVATION_WIDTH,
    keys::NoteMasterKey,
    nullifier::derivation::{NF_COSET_SHIFT, ROUND_SCHEDULE, WRAP_MASK_INV},
    primitives::EpochIndex,
    relations::quotient::coset_interpolate,
};

extern crate alloc;

/// One epoch's cipher round-state sequence: the `ROUNDS` cells of a single
/// grid row.
///
/// Wallet-only secret material.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NullifierTrace(#[debug(skip)] [Fp; TachyonP5R64::CONSTANTS.len()]);

/// A window's round-state grid in evaluation form: `NF_DERIVATION_WIDTH` rows
/// of `ROUNDS` cells, row-major over the trace domain. Pre-fft: the spectra
/// the derivation steps witness are produced from it.
///
/// Only constructible row-by-row, so it always holds exactly `POLY_LEN_MAX`
/// cells.
///
/// Wallet-only secret material.
#[derive(AsRef, Clone, Debug)]
pub struct NfTraceGrid(#[debug(skip)] Polynomial);

impl FromIterator<NullifierTrace> for NfTraceGrid {
    fn from_iter<I: IntoIterator<Item = NullifierTrace>>(iter: I) -> Self {
        // todo
        let cells: Vec<Fp> = iter.into_iter().flat_map(|row| row.0).collect();
        assert_eq!(
            cells.len(),
            1 << Polynomial::R,
            "a grid is exactly NF_DERIVATION_WIDTH rows"
        );
        Self(Polynomial::from_coeffs(cells))
    }
}

impl NfTraceGrid {
    /// Derive the window of `NF_DERIVATION_WIDTH` epochs starting at `base`.
    #[must_use]
    pub fn derive(mk: &NoteMasterKey, base: EpochIndex) -> Self {
        (0..NF_DERIVATION_WIDTH)
            .map(|row| mk.derive_nullifier_trace(EpochIndex(base.0 + row)).0)
            .collect()
    }

    /// The grid's trace interpolant $T$.
    #[must_use]
    pub fn spectrum(&self) -> NfGridSpectrum {
        let mut coeffs: Vec<Fp> = self.0.iter_coeffs().collect();
        Domain::new(Polynomial::R).ifft(&mut coeffs);
        NfGridSpectrum(Polynomial::from_coeffs(coeffs))
    }

    /// Prover-side builder of the grid's challenge-independent binding
    /// polynomials `(square, quartic, wrap)` (only the round key $k$ of `mk`
    /// enters), with the per-column round offset $\mathsf{off}(c) = k +
    /// c_{c+1}$ ($c_0 = 0$ on the wrap column, whose step the wrap correction
    /// exempts).
    ///
    /// - `square`: the low-degree extension of $(T + \mathsf{off})^2$ on the
    ///   domain,
    /// - `quartic`: the low-degree extension of $\mathsf{square}^2$ on the
    ///   domain,
    /// - `wrap`: the $W$-coefficient correction interpolated over the nullifier
    ///   coset, absorbing each row seam's mismatch $T(\omega x) -
    ///   \mathsf{quartic} \cdot (T + \mathsf{off})$ scaled by $Z_{H \setminus
    ///   C}(x)^{-1}$ (constant $(|D|/W) \cdot (\sigma^W)^{-1}$ on the coset).
    #[must_use]
    #[expect(
        clippy::indexing_slicing,
        clippy::integer_division_remainder_used,
        reason = "dense constant-size coset arithmetic"
    )]
    pub fn round_binding_spectra(
        &self,
        mk: &NoteMasterKey,
    ) -> (SboxSquareSpectrum, SboxQuarticSpectrum, WrapSpectrum) {
        let trace_evals: Vec<Fp> = self.0.iter_coeffs().collect();
        let inputs: Vec<Fp> = trace_evals
            .as_chunks::<{ TachyonP5R64::CONSTANTS.len() }>()
            .0
            .iter()
            .flat_map(|row| {
                row.iter()
                    .zip(&*ROUND_SCHEDULE)
                    .map(|(&state, &offset)| state + mk.0 + offset)
            })
            .collect();

        let square_evals: Vec<Fp> = inputs.iter().map(Fp::square).collect();
        let quartic_evals: Vec<Fp> = square_evals.iter().map(Fp::square).collect();

        #[expect(clippy::as_conversions, reason = "NF_DERIVATION_WIDTH fits usize")]
        let wrap_values: [Fp; NF_DERIVATION_WIDTH as usize] = array::from_fn(|row| {
            let seam = TachyonP5R64::CONSTANTS.len() * (row + 1);
            let next_first = trace_evals[seam % (1 << Polynomial::R)];
            let seam_step = inputs[seam - 1].pow_vartime([TachyonP5R64::POW]);
            (next_first - seam_step) * *WRAP_MASK_INV
        });

        let mut square = square_evals;
        Domain::new(Polynomial::R).ifft(&mut square);
        let mut quartic = quartic_evals;
        Domain::new(Polynomial::R).ifft(&mut quartic);

        (
            SboxSquareSpectrum::from(Polynomial::from_coeffs(square)),
            SboxQuarticSpectrum::from(Polynomial::from_coeffs(quartic)),
            WrapSpectrum::from(coset_interpolate::<{ NF_DERIVATION_WIDTH.ilog2() }>(
                &Polynomial::from_coeffs(wrap_values.to_vec()),
                *NF_COSET_SHIFT,
            )),
        )
    }
}

/// One window derivation's trace interpolant $T$ over
/// $\langle \omega \rangle$, bound as `trace_commit`.
///
/// Raw round states, no whitening: the cert steps' identity object. Its
/// last-column cells are final round states, not nullifiers.
///
/// Wallet-only secret material.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NfGridSpectrum(#[debug(skip)] Polynomial);

impl NfGridSpectrum {
    /// Deterministic (untrapdoored) commitment to the trace polynomial.
    #[must_use]
    pub fn commit(&self) -> NfGridSpectrumCommit {
        NfGridSpectrumCommit(self.0.commit())
    }

    /// The whitened trace $W = T + w$: `whitening` folded into the constant
    /// coefficient, so $\mathsf{nf}_{\mathsf{base}+j} = W(\sigma \zeta^j)$.
    #[must_use]
    pub fn whiten(&self, whitening: Fp) -> NfWhitenedSpectrum {
        let mut whitened = self.0.clone();
        whitened += &Polynomial::from_coeffs(Vec::from([whitening]));
        NfWhitenedSpectrum(whitened)
    }
}

/// Commitment to a [`NfGridSpectrum`].
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfGridSpectrumCommit(Eq);

/// The S-box square intermediate: the low-degree extension of
/// $(T + \mathsf{off})^2$ on the domain, for a trace $T$ with round offset
/// $\mathsf{off}$.
///
/// Wallet-only secret material.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct SboxSquareSpectrum(#[debug(skip)] Polynomial);

impl SboxSquareSpectrum {
    /// Deterministic (untrapdoored) commitment to the polynomial.
    #[must_use]
    pub fn commit(&self) -> SboxSquareSpectrumCommit {
        SboxSquareSpectrumCommit(self.0.commit())
    }
}

/// Commitment to a [`SboxSquareSpectrum`].
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct SboxSquareSpectrumCommit(Eq);

/// The S-box quartic intermediate: the low-degree extension of the
/// [`SboxSquareSpectrum`]'s square on the domain.
///
/// Wallet-only secret material.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct SboxQuarticSpectrum(#[debug(skip)] Polynomial);

impl SboxQuarticSpectrum {
    /// Deterministic (untrapdoored) commitment to the polynomial.
    #[must_use]
    pub fn commit(&self) -> SboxQuarticSpectrumCommit {
        SboxQuarticSpectrumCommit(self.0.commit())
    }
}

/// Commitment to a [`SboxQuarticSpectrum`].
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct SboxQuarticSpectrumCommit(Eq);

/// The last-column wrap correction: one coefficient per row seam,
/// interpolated over the last-column coset, absorbing the row-transition
/// mismatches the round identity exempts.
///
/// Wallet-only secret material.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct WrapSpectrum(#[debug(skip)] Polynomial);

impl WrapSpectrum {
    /// Deterministic (untrapdoored) commitment to the polynomial.
    #[must_use]
    pub fn commit(&self) -> WrapSpectrumCommit {
        WrapSpectrumCommit(self.0.commit())
    }
}

/// Commitment to a [`WrapSpectrum`].
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct WrapSpectrumCommit(Eq);

/// The S-box/boundary quotient `Q_A`.
///
/// The $\chi_A$-combined numerator of the S-box decomposition identities
/// $I_1, I_2$ and the boundary identity $I_4$, divided by the domain
/// vanisher. One commitment; challenge-dependent (built after $\chi_A$).
///
/// Wallet-only secret material.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct SboxQuotientSpectrum(#[debug(skip)] Polynomial);

impl SboxQuotientSpectrum {
    /// Deterministic (untrapdoored) commitment to the polynomial.
    #[must_use]
    pub fn commit(&self) -> SboxQuotientSpectrumCommit {
        SboxQuotientSpectrumCommit(self.0.commit())
    }
}

/// Commitment to a [`SboxQuotientSpectrum`].
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct SboxQuotientSpectrumCommit(Eq);

/// The round quotient `Q_B`.
///
/// The single round-transition identity `I3` (with its last-column wrap
/// exemption) divided by the domain vanisher. One commitment;
/// challenge-independent (a plain quotient, no combination challenge).
///
/// Wallet-only secret material.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct WrapQuotientSpectrum(#[debug(skip)] Polynomial);

impl WrapQuotientSpectrum {
    /// Deterministic (untrapdoored) commitment to the polynomial.
    #[must_use]
    pub fn commit(&self) -> WrapQuotientSpectrumCommit {
        WrapQuotientSpectrumCommit(self.0.commit())
    }
}

/// Commitment to a [`WrapQuotientSpectrum`].
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct WrapQuotientSpectrumCommit(Eq);

/// The nullifier-fold accumulator `A` binding the sequence to the trace's final
/// column.
///
/// Satisfies $A(X) - \chi A(\zeta X) = T(\sigma X)$ ($\sigma$ the column
/// stride, $\zeta$ the row subgroup generator), telescoping over
/// $\langle \zeta \rangle$ to $A(1) \, (1 - \chi^W) = \sum_r \chi^r \,
/// T(\sigma \zeta^r)$: the trace's final column folded at the weight $\chi$.
/// One commitment; challenge-dependent (built after $\chi$).
///
/// Wallet-only secret material.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NfFoldAccumulator(#[debug(skip)] Polynomial);

impl NfFoldAccumulator {
    /// Deterministic (untrapdoored) commitment to the polynomial.
    #[must_use]
    pub fn commit(&self) -> NfFoldAccumulatorCommit {
        NfFoldAccumulatorCommit(self.0.commit())
    }
}

/// Commitment to a [`NfFoldAccumulator`].
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfFoldAccumulatorCommit(Eq);

/// One window derivation's whitened trace $W = T + w$, bound as `nf_commit`.
///
/// The trace interpolant with the whitening key folded into its constant
/// coefficient, so every last-column cell evaluates to a genuine nullifier,
/// $\mathsf{nf}_{\mathsf{base}+j} = W(\sigma \zeta^j)$.
///
/// Consumers re-witness `W` against `nf_commit` and read covered nullifiers
/// as single openings; no key material is involved.
///
/// Wallet-only secret material.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NfWhitenedSpectrum(#[debug(skip)] Polynomial);

impl NfWhitenedSpectrum {
    /// Deterministic (untrapdoored) commitment to the polynomial.
    #[must_use]
    pub fn commit(&self) -> NfWhitenedSpectrumCommit {
        NfWhitenedSpectrumCommit(self.0.commit())
    }
}

/// Commitment to a [`NfWhitenedSpectrum`].
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfWhitenedSpectrumCommit(Eq);
