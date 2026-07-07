//! MiMC key expansion and nullifier derivation. Wallet-only; every header
//! carries the note so the deferred `cm` binds at the derivation.
//!
//! [`MasterSeed`] derives one `mk` part at the note's master secrets, pinning
//! `nk` through the payment-key check and certifying the part as a committed
//! spectrum (the raw keys never ride a header). [`KeyExpansionStep`] proves
//! one part of a note's keyset expansion -- the `EK_PART_LENGTH` keyed-cipher
//! outputs of that part, keyed by the schedule reconstructed homomorphically
//! from the `MK_PARTS` certified spectra -- in a single trace-based step,
//! emitting a one-slot [`ExpandedKeyDerivation`]; `EK_PARTS` invocations make the full
//! interleaved schedule. [`ExpandedKeyFuse`] merges disjoint keysets
//! slot-wise, in any tree shape, until one keyset covers every part. The
//! single-input [`NullifierDerivationStep`] then certifies the note's
//! derivation polynomials against the covered slots, reconstructing the
//! schedule inline and computing the deferred `cm`.

#![allow(
    clippy::as_conversions,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "todo"
)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::array;

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Polynomial, Step, Suffix,
    constraint::{enforce_equal_point, enforce_zero},
};
use zcash_mimc::spec::tachyon::TachyonP5R32;

use crate::{
    CONSTANT_SCHEDULE, ExpandedKeyPartSpectrum, NfEmitterCommit, NfEmitterSpectrum,
    NfEmittersDigest, NoteMasterKeyPartCommit, NoteMasterKeyPartSpectrum, PartKeyCommit,
    constants::{
        EK_LENGTH, EK_PART_LENGTH, EK_PARTS, MK_LENGTH, MK_PART_LEN, MK_PARTS, NF_EMITTERS,
        POLY_LEN_MAX,
    },
    digest::poseidon,
    keys::{ExpansionParams, NoteMasterKeyPart, ProofAuthorizingKey},
    note::{Commitment as NoteCommitment, Note},
    primitives::{ExpandedKeyTraceSpectrum, ExpansionInputSpectrum},
    relations::{
        enforce::{
            enforce_affine_recurrence, enforce_committed_offset_recurrence,
            enforce_committed_row_recurrence, enforce_first_column_values, enforce_interpolant,
            enforce_strided_column,
        },
        quotient::{
            EMITTER_ROUND_SPLITS, EXPANSION_ROUND_SPLITS, QuerySalts, QueryShift,
            RoundBoundaryQuotients, WeightRatios,
        },
        subgroup_generator,
    },
};

/// One certified `mk` part and its originating note, emitted by
/// [`MasterSeed`].
///
/// Carries the commitment to this part's spectrum (the eval-form interpolant
/// of its `MK_PART_LEN` round keys), its part index, and the whole note (kept
/// collected so the deferred `cm` can be computed downstream). The raw keys
/// never ride a header: downstream steps re-witness the spectrum against this
/// commitment and open it where key material is needed. Wallet-only: the
/// per-note secrets ride a header that never leaves the wallet's own proof
/// tree and is never published.
#[derive(Clone, Debug)]
pub struct MasterKeyDerivation;

impl Header for MasterKeyDerivation {
    /// `(mk_part_commit, part, note)`.
    type Data = (NoteMasterKeyPartCommit, Fp, Note);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (mk_part_commit, part, note) = *data;
        let fps: Vec<Fp> = vec![
            part,
            Fp::from(note.pk),
            Fp::from(note.value),
            Fp::from(note.psi),
            Fp::from(note.rcm),
        ];
        // The commitment of a nonzero spectrum (the part keys are Poseidon
        // squeezes), so the header never witnesses the identity.
        (fps, Vec::new(), Vec::new(), vec![mk_part_commit.0])
    }
}

/// Derive one `mk` part at the note's master secrets.
///
/// Witnesses the note, its proof authorizing key `pak`, the part index, and
/// the part's eval-form spectrum `M_p`. Proves `note.pk ==
/// pak.derive_payment_key()` (pinning the nullifier key `nk`), range-checks
/// `part ∈ 0..MK_PARTS`, derives `mk_part = nf_master_part(psi, nk, part)`,
/// and confirms the witnessed spectrum against the derivation with one
/// interpolant identity ([`enforce_interpolant`]: an opening at a
/// commitment-derived challenge against the closed-form Lagrange evaluation
/// of the derived keys, forcing the polynomial equality). Emits
/// `(commit(M_p), part, note)`. The note rides the header so the deferred
/// `cm` binds downstream; `nk` is discarded and never leaves the seed (only
/// the payment key `pk` does, and it preimage-hides `nk`).
#[derive(Debug)]
pub struct MasterSeed;

impl Step for MasterSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = MasterKeyDerivation;
    type Right = ();
    /// `(note, pak, part, mk_part_spectrum)`.
    type Witness<'source> = (Note, ProofAuthorizingKey, u64, NoteMasterKeyPartSpectrum);

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (note, pak, part, mk_part_spectrum): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            note.pk.0 - pak.derive_payment_key().0,
            "MasterSeed: pak not related to note",
        )?;

        let part_fp = Fp::from(part);
        let part_in_range = (0..MK_PARTS).fold(Fp::ONE, |product, index| {
            product * (part_fp - Fp::from(index as u64))
        });
        enforce_zero(part_in_range, "MasterSeed: part out of range 0..MK_PARTS")?;

        let mk_part = NoteMasterKeyPart(pak.nk.derive_note_part(&note.psi, part));

        // Confirm the witnessed spectrum IS this part's interpolant: one
        // opening at a commitment-derived challenge against the closed-form
        // Lagrange evaluation of the derived keys. Schwartz-Zippel forces the
        // polynomial equality, so the commitment stands for exactly this part
        // (every node value and the degree bound, with no vanishing-multiple
        // slack).
        enforce_interpolant::<MK_PART_LEN>(ctx, &mk_part_spectrum.0, &mk_part.0)?;

        Ok((
            (
                NoteMasterKeyPartCommit(mk_part_spectrum.0.commit()),
                part_fp,
                note,
            ),
            (),
        ))
    }
}

/// Prove one part of a note's keyset expansion in one trace-based step.
///
/// The `EK_PART_LENGTH` keyed-cipher outputs of this part, committed as
/// the eval-form part-key polynomial `A_p`
/// (`A_p(ζ^r) = E_mk(s + δ·(base + r))` over the order-`EK_PART_LENGTH`
/// subgroup `⟨ζ⟩`) into slot `part ∈ 0..EK_PARTS` of a one-slot
/// [`ExpandedKeyDerivation`]. `base = part · EK_PART_LENGTH` selects the cipher-input
/// window; the `EK_PARTS` parts interleave (over the cosets of `⟨ζ⟩`) into
/// the full schedule, reconstructed at [`NullifierDerivationStep`]. The
/// expansion-input parameters `(s, δ, w)` are derived in-step from the `mk`
/// prefix pinned to the certified part spectra
/// ([`ExpansionParams::from_prefix`]), so the cipher inputs are note secrets
/// and the schedule stays a deterministic function of `mk`.
///
/// The witness is the prover-built trace `T`, the round quotient
/// ([`EXPANSION_ROUND_SPLITS`] splits), the round-0 input column `I` with its
/// recurrence and link quotients, the part-key poly `A_p`, the decimation
/// quotient, `part`, and the re-witnessed `mk` part spectra (bound to the
/// seeds' certified commitments); the body is pure orchestration over generic
/// vanishing relations plus a range check.
///
/// - `enforce_affine_recurrence` pins the witnessed input column `I` to the
///   round-0 cipher inputs (`I(ζ^r) = s + δ·(base + r) + k_0`): two scalars,
///   the origin and the stride `δ`, fix all `EK_PART_LENGTH` nodes.
/// - `enforce_strided_column` at the S-box exponent links `I` into the trace,
///   pinning each row-start cell to `I(ζ^r)^5` (round 0, applied outside the
///   trace).
/// - `enforce_committed_row_recurrence` pins the remaining cipher rounds 1..
///   of `T` against the schedule reconstructed inline from the `MK_PARTS`
///   committed part spectra (the interleaved-coset key term) and the public
///   rotated round constants.
/// - `enforce_strided_column` (exponent 1) binds `K` to `T`'s final column
///   plus the whitening key `w`, so `commit(K)` is exactly the expansion
///   outputs.
///
/// # Gate budget
///
/// Rule-of-thumb ledger against the 2048-gate step ceiling (constant
/// multiplications and additions free, witnessed inverse ≈ 2, Poseidon
/// permutation ≈ 1/7, polynomial openings and commitments ≈ free):
///
/// | item | gates |
/// |---|---|
/// | expansion-parameter sponge (one permutation) | ~293 |
/// | `enforce_committed_row_recurrence` (`ROUNDS`-node interpolation) | ~130 |
/// | input column (affine recurrence + S-box link) | ~15 |
/// | `enforce_strided_column`, range check, reconciliation, slots | ~30 |
/// | total | ~470 |
///
/// The parameter sponge must stay single-permutation: the domain tag plus the
/// `MK_PARTS`-element `mk` prefix absorbs at most `RATE` elements and squeezes
/// three; a second permutation does not fit.
#[derive(Debug)]
pub struct KeyExpansionStep;

impl Step for KeyExpansionStep {
    type Aux<'source> = ();
    type Left = MasterKeyDerivation;
    type Output = ExpandedKeyDerivation;
    type Right = MasterKeyDerivation;
    /// `(expansion_trace, round_quotients, input_column, input_quotient,
    /// link_quotient, key_spec, decimation_quotient, part, mk_parts)`.
    type Witness<'source> = (
        ExpandedKeyTraceSpectrum,
        [Polynomial; EXPANSION_ROUND_SPLITS], // masked round-quotient splits
        ExpansionInputSpectrum,
        Polynomial, // input-recurrence quotient pinning the affine input column
        Polynomial, // link quotient binding T's first column to I^5
        ExpandedKeyPartSpectrum,
        Polynomial, // decimation quotient binding K to T's final column
        Fp,         // part ∈ 0..EK_PARTS
        [NoteMasterKeyPartSpectrum; MK_PARTS], // re-witnessed certified mk parts
    );

    const INDEX: Index = Index::new(1);

    #[expect(
        clippy::too_many_lines,
        reason = "one pass orchestrates the reconciliation, binding, and cipher relations"
    )]
    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (
            expansion_trace,
            round_quotients,
            input_column,
            input_quotient,
            link_quotient,
            key_spec,
            decimation_quotient,
            part,
            mk_parts,
        ): Self::Witness<'source>,
        left: <Self::Left as Header>::Data,
        right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // This invocation computes one part of the schedule. `part` is
        // range-checked to `0..EK_PARTS` (the product Π_i (part − i) vanishes
        // only there) and fixes the cipher-input window origin
        // `base = part · EK_PART_LENGTH`, so part `p` runs inputs
        // `p·EK_PART_LENGTH..(p+1)·EK_PART_LENGTH`. The header carries `part` so the
        // derivation step pins one of each.
        let part_in_range = (0..EK_PARTS).fold(Fp::ONE, |product, index| {
            product * (part - Fp::from(index as u64))
        });
        enforce_zero(
            part_in_range,
            "KeyExpansionStep: part out of range 0..EK_PARTS",
        )?;
        let base = part * Fp::from(EK_PART_LENGTH as u64);

        // The certified `mk` transport: the two seeds' part commitments
        // (pinned to indices 0 and 1) of the same note. The note is reconciled
        // across both seeds and forwarded so the deferred `cm` binds
        // downstream.
        let (mk_commits, note) = {
            let (left_commit, left_index, left_note) = left;
            let (right_commit, right_index, right_note) = right;
            enforce_zero(left_index, "KeyExpansionStep: left input is not mk part 0")?;
            enforce_zero(
                right_index - Fp::ONE,
                "KeyExpansionStep: right input is not mk part 1",
            )?;
            enforce_zero(
                Fp::from(left_note.pk) - Fp::from(right_note.pk),
                "KeyExpansionStep: note pk mismatch across mk parts",
            )?;
            enforce_zero(
                Fp::from(left_note.value) - Fp::from(right_note.value),
                "KeyExpansionStep: note value mismatch across mk parts",
            )?;
            enforce_zero(
                Fp::from(left_note.psi) - Fp::from(right_note.psi),
                "KeyExpansionStep: note psi mismatch across mk parts",
            )?;
            enforce_zero(
                Fp::from(left_note.rcm) - Fp::from(right_note.rcm),
                "KeyExpansionStep: note rcm mismatch across mk parts",
            )?;
            ([left_commit, right_commit], left_note)
        };

        // Bind the re-witnessed part spectra to the seeds' certified
        // commitments: every key the recurrence and the prefix openings read
        // below is the proven derivation of this note's `mk`.
        for (mk_part, mk_commit) in mk_parts.iter().zip(&mk_commits) {
            enforce_equal_point(
                mk_part.0.commit(),
                mk_commit.0,
                "KeyExpansionStep: mk part does not match its certified commitment",
            )?;
        }

        // The `mk` prefix, one element of every interleaved part:
        // `mk[p] = part_p[0] = M_p(1)`, each pinned by an opening of its
        // certified spectrum.
        let prefix: [Fp; MK_PARTS] = mk_parts.each_ref().map(|mk_part| mk_part.0.eval(Fp::ONE));
        for (mk_part, &element) in mk_parts.iter().zip(&prefix) {
            ctx.enforce_poly_query(mk_part.0.commit(), Fp::ONE, element)?;
        }

        // The expansion-input parameters `(s, δ, w)`: one domain-separated
        // Poseidon permutation over the pinned `mk` prefix, derived in-step so
        // the schedule stays a deterministic function of `mk` (a freely
        // witnessed salt would let one note carry many valid schedules, hence
        // many nullifier sequences). Every part's step derives the same values
        // from the certified prefix.
        let params = ExpansionParams::from_prefix(&prefix);

        // Round 0, the input step. The cipher input for row `row` is the
        // secret affine `s + δ·(base + row)`, not stored in the trace, so it
        // is witnessed as the committed input column `I` (round-0 key folded
        // in: `I(ζ^r) = s + δ·(base + r) + k_0`, with `c_0 = 0`) and pinned by
        // two scalars: the affine recurrence fixes every node from the origin
        // and `δ`, and the S-box link pins each row-start cell of `T` to
        // `I(ζ^r)^5` (round 0's output). Every operand is pinned: `base` from
        // the range-checked `part`, `k_0 = mk[0] = prefix[0]` and the params
        // from the certified prefix openings.
        {
            let origin = params.input(base) + prefix[0];
            enforce_affine_recurrence::<{ EK_PART_LENGTH }, 1>(
                ctx,
                array::from_ref(&input_column.0),
                &input_quotient,
                Fp::ONE,
                params.stride,
                Fp::ONE,
                origin,
            )?;
            enforce_strided_column::<{ EK_PART_LENGTH }>(
                ctx,
                &expansion_trace.0,
                &input_column.0,
                &link_quotient,
                Fp::ONE,
                Fp::ZERO,
                TachyonP5R32::POW,
            )?;
        }

        // Rounds 1..: advance each row through the rest of the cipher. The
        // recurrence enforces every in-row step `T[cell + 1] = (T[cell] +
        // key + constant)^5` as one round, the same per-column layout for all
        // rows. Cell `cell` holds round `cell`'s output, so the step out of it
        // is round `cell + 1` (round 0 is pinned above, not a step); the last
        // cell's successor is the next row, and the relation's row mask exempts
        // that wrap. The constants are the public rotated schedule
        // (`c_{(cell+1) mod ROUNDS}`, with `c_0 = 0` at the wrap); the keys are
        // reconstructed inline from the `MK_PARTS` certified part spectra --
        // the schedule cycles `mk` once per row (`MK_LENGTH = ROUNDS`), so the
        // committed-key row recurrence opens each spectrum once.
        {
            const {
                assert!(
                    MK_LENGTH == TachyonP5R32::ROUNDS,
                    "the expansion cipher cycles mk exactly once per row"
                );
            }
            #[expect(clippy::indexing_slicing, reason = "index < ROUNDS by modulus")]
            let constants: [Fp; TachyonP5R32::ROUNDS] = array::from_fn(|cell| {
                TachyonP5R32::CONSTANTS[(cell + 1) % TachyonP5R32::ROUNDS]
            });

            enforce_committed_row_recurrence::<
                { TachyonP5R32::ROUNDS },
                { EXPANSION_ROUND_SPLITS },
                { MK_PARTS },
            >(
                ctx,
                &expansion_trace.0,
                &round_quotients,
                &constants,
                &mk_parts.each_ref().map(|mk_part| &mk_part.0),
                TachyonP5R32::POW,
            )?;
        }

        // Bind the eval-form part-key poly `A_p` to the trace's final column. On
        // the order-`EK_PART_LENGTH` subgroup `⟨ζ⟩` (`ζ = ω^{TRACE_COLUMNS}`),
        // `A_p(ζ^r) = (row-r final cell) + w = E_mk(s + δ·(base + r))`, so
        // `A_p` commits this part's `EK_PART_LENGTH` expansion outputs. `σ =
        // ω^{TRACE_COLUMNS-1}` is the final-column stride within a row; the
        // whitening key is the dedicated `w`, not a reused round key.
        #[expect(clippy::as_conversions, reason = "constant column index")]
        let stride =
            subgroup_generator::<POLY_LEN_MAX>().pow_vartime([(TachyonP5R32::ROUNDS - 1) as u64]);
        enforce_strided_column::<{ EK_PART_LENGTH }>(
            ctx,
            &expansion_trace.0,
            &key_spec.0,
            &decimation_quotient,
            stride,
            params.whitening,
            1,
        )?;

        // Emit a one-slot keyset: this part's commitment in its slot, the
        // non-identity filler `g0` elsewhere, with matching boolean coverage.
        // `part` is range-checked above, so the slot selector places exactly one
        // part at its schedule position. The additive fuse accumulates one
        // filler per uncovered contribution; at full coverage every slot carries
        // exactly `EK_PARTS - 1` fillers, which the derivation step compensates.
        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let filler = PartKeyCommit(g0 * Fp::ONE);
        let commit = PartKeyCommit(key_spec.0.commit());
        let slots: [PartKeyCommit; EK_PARTS] = array::from_fn(|slot| {
            if Fp::from(slot as u64) == part {
                commit
            } else {
                filler
            }
        });
        let coverage: [Fp; EK_PARTS] = array::from_fn(|slot| {
            if Fp::from(slot as u64) == part {
                Fp::ONE
            } else {
                Fp::ZERO
            }
        });
        Ok(((slots, coverage, mk_commits, note), ()))
    }
}

/// The expansion keyset `(slots, coverage, mk_commits, note)`: per-part
/// commitment slots and coverage flags. Wallet-only.
///
/// `slots[p]` holds `commit(A_p)`, the [`PartKeyCommit`] to part `p`'s
/// eval-form part-key polynomial (that window's `EK_PART_LENGTH` keyed-cipher
/// expansion outputs, proven by [`KeyExpansionStep`]), plus one non-identity
/// filler `g0` per uncovered contribution folded in; `coverage[p]` is the
/// matching boolean flag and is the authoritative occupancy signal.
/// [`KeyExpansionStep`] emits a one-slot keyset and [`ExpandedKeyFuse`]
/// merges disjoint keysets, so any fuse order covers the schedule; slot
/// position pins each part's schedule index without a fold or per-part
/// ordering. `mk_commits` carries the certified `mk` part commitments for the
/// downstream query parameters (opened at `1`, the prefix nodes) and `note`
/// the per-note fields for the deferred `cm`; both are reconciled across
/// every merge. The header is private to the wallet's own proof tree and is
/// never published.
#[derive(Clone, Debug)]
pub struct ExpandedKeyDerivation;

impl Header for ExpandedKeyDerivation {
    /// `(slots, coverage, mk_commits, note)`.
    type Data = (
        [PartKeyCommit; EK_PARTS],
        [Fp; EK_PARTS],
        [NoteMasterKeyPartCommit; MK_PARTS],
        Note,
    );

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (slots, coverage, mk_commits, note) = *data;
        let mut fps: Vec<Fp> = coverage.to_vec();
        fps.push(Fp::from(note.pk));
        fps.push(Fp::from(note.value));
        fps.push(Fp::from(note.psi));
        fps.push(Fp::from(note.rcm));
        // Every slot is a non-identity point (a real commitment plus filler
        // `g0` terms), and the mk part commitments commit nonzero spectra, so
        // the header never witnesses the identity.
        let mut eqs: Vec<Eq> = slots.iter().map(|slot| slot.0).collect();
        eqs.extend(mk_commits.iter().map(|commit| commit.0));
        (fps, Vec::new(), Vec::new(), eqs)
    }
}

/// Merge two disjoint [`ExpandedKeyDerivation`]s slot-wise.
///
/// Reconciles the two keysets' `mk` part commitments and note (so every
/// covered part belongs to one note), enforces disjoint coverage (no part
/// certified twice), and emits the slot-wise point sum. Slots carry a real commitment plus non-identity
/// filler `g0` terms, so the sum stays off the identity; because addition is
/// associative and commutative, a slot's total is fold-shape-independent and at
/// full coverage is exactly `commit(A_p) + (EK_PARTS - 1)·g0`.
/// `EK_PARTS - 1` invocations, in any tree shape, cover the whole schedule;
/// changing `EK_PARTS` changes the invocation count, not the circuit.
/// Completeness is enforced downstream: [`NullifierDerivationStep`] requires
/// full coverage and matches every witnessed part (offset by the fillers)
/// against its slot.
#[derive(Debug)]
pub struct ExpandedKeyFuse;

impl Step for ExpandedKeyFuse {
    type Aux<'source> = ();
    type Left = ExpandedKeyDerivation;
    type Output = ExpandedKeyDerivation;
    type Right = ExpandedKeyDerivation;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (left_slots, left_coverage, left_mk, left_note): <Self::Left as Header>::Data,
        (right_slots, right_coverage, right_mk, right_note): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Reconcile: every covered part belongs to the same note (shared mk
        // part commitments and note fields), so the forwarded commitments key
        // the genuine derivation and the deferred cm pins the genuine value.
        for (left_commit, right_commit) in left_mk.iter().zip(right_mk.iter()) {
            enforce_equal_point(
                left_commit.0,
                right_commit.0,
                "ExpandedKeyFuse: master key mismatch across parts",
            )?;
        }
        enforce_zero(
            Fp::from(left_note.pk) - Fp::from(right_note.pk),
            "ExpandedKeyFuse: note pk mismatch across parts",
        )?;
        enforce_zero(
            Fp::from(left_note.value) - Fp::from(right_note.value),
            "ExpandedKeyFuse: note value mismatch across parts",
        )?;
        enforce_zero(
            Fp::from(left_note.psi) - Fp::from(right_note.psi),
            "ExpandedKeyFuse: note psi mismatch across parts",
        )?;
        enforce_zero(
            Fp::from(left_note.rcm) - Fp::from(right_note.rcm),
            "ExpandedKeyFuse: note rcm mismatch across parts",
        )?;

        #[expect(clippy::indexing_slicing, reason = "constant size")]
        let (coverage, slots) = {
            // Disjoint coverage: flags are boolean by construction upstream, so a
            // zero product per slot means no part is certified twice.
            for slot in 0..EK_PARTS {
                enforce_zero(
                    left_coverage[slot] * right_coverage[slot],
                    "ExpandedKeyFuse: overlapping part coverage",
                )?;
            }

            (
                array::from_fn(|slot| left_coverage[slot] + right_coverage[slot]),
                array::from_fn(|slot| PartKeyCommit(left_slots[slot].0 + right_slots[slot].0)),
            )
        };
        Ok(((slots, coverage, left_mk, left_note), ()))
    }
}

/// The certify-once nullifier derivation `([commit(T_j)], digest, cm, E_0, c,
/// [ρ_j])`. Wallet-only.
///
/// Holds the `N` derivation-poly commitments (for opening), a transcript
/// challenge over them (so the arc challenge absorbs one element, not `N`),
/// the note commitment, and the secret shift `c` and ratios `ρ_j` forwarded
/// from the keyset for the query and arc match. Secret material rides this
/// wallet-only header without leaking; the public consumer emits only the
/// resulting `nf`.
///
/// The offset origin `E_0` is deliberately absent: the derivation is
/// epoch-independent (a function of the note alone), so it does not fix an
/// epoch. Each consumer that needs the origin witnesses it locally --
/// `SpendableInit` binds it to the creation anchor, `UnspentBind` indexes the
/// arc with it -- and `SpendableLift` reconciles the two branches' origins.
#[derive(Clone, Debug)]
pub struct NullifierDerivation;

impl Header for NullifierDerivation {
    type Data = (
        [NfEmitterCommit; NF_EMITTERS],
        NfEmittersDigest,
        NoteCommitment,
        QueryShift,
        WeightRatios,
    );

    const SUFFIX: Suffix = Suffix::new(13);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (commits, digest, cm, shift, ratios) = *data;
        let mut fps: Vec<Fp> = vec![digest.0, Fp::from(cm), shift.0];
        fps.extend(ratios.0);
        let eqs: Vec<Eq> = commits.iter().map(|commit| commit.0).collect();
        (fps, Vec::new(), Vec::new(), eqs)
    }
}

/// Certify the note's `N` derivation polynomials in one single-input step.
///
/// Consumes the fused [`ExpandedKeyDerivation`] and witnesses the note's
/// `EK_PARTS` part-key polynomials `A_p`, the `N` polynomials `T_j`, and their
/// round- and boundary-quotients. It requires full coverage (every slot
/// certified) and matches each witnessed `A_p.commit()` against its slot, so
/// per-slot equality binds the full ordered set of part commitments to the
/// certified expansion -- every key it reads is the proven interleaved
/// schedule, no part substituted or reordered. The per-poly salts, weight
/// bases `ρ_j`, and shift `c` are derived from the witnessed `mk` prefix,
/// each element pinned by an opening of its fused part commitment at `1`; the
/// deferred `cm` is computed from the fused note here, pinning the note's
/// value and `ψ`.
///
/// Per poly, two relations certify `T_j` is the genuine keyed-cipher
/// interpolant: [`enforce_first_column_values`] pins
/// `T_j(1) = (mk_s^{(j)} + k_0)^5` (round 0 from the salt, `k_0 = A_0(1)`), and
/// [`enforce_committed_offset_recurrence`] pins the remaining rounds against
/// the schedule reconstructed inline from the `A_p` (the interleaved-coset
/// offset key term) and the committed `C`. Then it binds the commitments into
/// one transcript challenge and emits the derivation, forwarding `c`/`ρ_j` for
/// the downstream query and arc match.
///
/// The derivation is epoch-independent: no `E_0` enters here. The offset origin
/// is witnessed by each downstream consumer that needs it (`SpendableInit`,
/// `UnspentBind`) and reconciled at `SpendableLift`.
#[derive(Debug)]
pub struct NullifierDerivationStep;

impl Step for NullifierDerivationStep {
    type Aux<'source> = ();
    type Left = ExpandedKeyDerivation;
    type Output = NullifierDerivation;
    type Right = ();
    /// `(parts, emitters, quotients, mk_prefix)`.
    type Witness<'source> = (
        [ExpandedKeyPartSpectrum; EK_PARTS],
        [NfEmitterSpectrum; NF_EMITTERS],
        [RoundBoundaryQuotients<EMITTER_ROUND_SPLITS>; NF_EMITTERS],
        [Fp; MK_PARTS], // mk prefix, pinned to the fused part commitments
    );

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (parts, emitters, quotients, mk_prefix): Self::Witness<'source>,
        (slots, coverage, mk_commits, note): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Bind the witnessed parts to the certified expansion: every slot must
        // be covered, and each witnessed part-key poly must commit to its
        // slot. A substituted, reordered, or missing part fails its slot
        // equality, so every key the recurrence reads below is the proven
        // interleaved schedule.
        for flag in coverage {
            enforce_zero(
                flag - Fp::ONE,
                "NullifierDerivationStep: incomplete part coverage",
            )?;
        }
        // Full coverage means every slot summed one real commitment and
        // `EK_PARTS - 1` fillers `g0`, so each certified slot is
        // `commit(A_position) + (EK_PARTS - 1)·g0`. Add that constant offset to
        // the witnessed part before matching.
        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let filler_offset = g0 * Fp::from((EK_PARTS - 1) as u64);
        for (slot, part) in slots.iter().zip(parts.iter()) {
            enforce_equal_point(
                part.0.commit() + filler_offset,
                slot.0,
                "NullifierDerivationStep: part does not match its certified slot",
            )?;
        }

        // The deferred `cm`, computed from the fused note: pins the note's
        // value and `ψ` into the published derivation.
        let cm = note.commitment();

        // The `mk` prefix, one element of every interleaved part: each
        // witnessed element is pinned by an opening of its fused certified
        // part commitment at `1` (`mk[p] = part_p[0] = M_p(1)`).
        for (mk_commit, &element) in mk_commits.iter().zip(&mk_prefix) {
            ctx.enforce_poly_query(mk_commit.0, Fp::ONE, element)?;
        }

        // Query parameters derived from the pinned prefix. `salts` fix the
        // per-poly boundaries; `shift`/`ratios` are forwarded for the downstream
        // query and arc match.
        let salts = QuerySalts(poseidon::nf_query_salts(&mk_prefix));
        let (ratios, shift) = {
            let (ratios, shift) = poseidon::nf_query_weights(&mk_prefix);
            (WeightRatios(ratios), QueryShift(shift))
        };

        // Round-0 boundary key `k_0 = K(1) = A_0(1)` (part 0's coset selector is
        // 1 and all others are 0 at `x = 1`), shared across all polys.
        let first_key = parts[0].0.eval(Fp::ONE);
        ctx.enforce_poly_query(parts[0].0.commit(), Fp::ONE, first_key)?;

        for (idx, (emitter, emitter_quot)) in emitters.iter().zip(&quotients).enumerate() {
            // Boundary: round 0 from the salt, `T_j(1) = (mk_s^{(j)} + k_0)^5`.
            let alpha = salts.get(idx) + first_key;
            let boundary = alpha.square().square() * alpha;
            enforce_first_column_values::<1>(
                ctx,
                &emitter.0,
                &emitter_quot.boundary,
                Fp::ZERO,
                &[boundary],
            )?;

            // Rounds 1..: the committed-offset quintic recurrence (x^5 S-box),
            // the full interleaved schedule reconstructed inline from the
            // `EK_PARTS` committed part-key polys.
            enforce_committed_offset_recurrence::<
                { EMITTER_ROUND_SPLITS },
                { EK_LENGTH },
                { EK_PARTS },
            >(
                ctx,
                &emitter.0,
                &emitter_quot.round,
                &CONSTANT_SCHEDULE,
                &parts.each_ref().map(|part| &part.0),
                5,
            )?;
        }

        let commits: [NfEmitterCommit; NF_EMITTERS] =
            emitters.map(|em| NfEmitterCommit(em.0.commit()));

        // Bind all `N` commitments into one transcript challenge, so the
        // downstream arc challenge `β` absorbs a single element rather than the
        // whole set. The native prover reads this scalar off the header.
        let digest = NfEmittersDigest(ctx.derive_challenge(&commits.map(|commit| commit.0))?);

        Ok(((commits, digest, cm, shift, ratios), ()))
    }
}
