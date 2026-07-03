//! MiMC key expansion and nullifier derivation. Wallet-only; every header
//! carries the note so the deferred `cm` binds at the derivation.
//!
//! [`MasterSeed`] derives one `mk` part at the note's master secrets, pinning
//! `nk` through the payment-key check. [`KeyExpansionStep`] proves one part of
//! a note's keyset expansion -- the `EK_PART_SIZE` keyed-cipher outputs of that
//! part -- in a single trace-based step, emitting a one-slot
//! [`EmitterKeyset`]; `EK_PARTS` invocations make the full interleaved
//! schedule. [`EmitterKeysetFuse`] merges disjoint keysets slot-wise, in any
//! tree shape, until one keyset covers every part. The single-input
//! [`NullifierDerivationStep`] then certifies the note's derivation
//! polynomials against the covered slots, reconstructing the schedule inline
//! and computing the deferred `cm`.

#![allow(
    clippy::as_conversions,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "todo"
)]

extern crate alloc;

use alloc::vec::Vec;
use core::array;

use ff::{Field as _, PrimeField as _};
use group::{Curve as _, Group as _, GroupEncoding as _};
use pasta_curves::{Eq, Fp};
use ragu::{
    Header, Index, Polynomial, Step, Suffix,
    constraint::{enforce_equal_point, enforce_zero},
};
use zcash_mimc::spec::tachyon::TachyonP5R32;

use crate::{
    CONSTANT_SCHEDULE, NfEmitterCommit, NfEmitterPoly, NfEmittersDigest, PartKeyCommit,
    PartKeyPoly,
    constants::{
        EK_FULL_SIZE, EK_PART_SIZE, EK_PARTS, MK_PART_LEN, MK_PARTS, NF_EMITTERS, POLY_LEN_MAX,
    },
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::{Commitment as NoteCommitment, Note},
    primitives::PartKeySpectrumPoly,
    relations::{
        enforce::{
            enforce_committed_offset_recurrence, enforce_first_column_values,
            enforce_row_recurrence, enforce_strided_column,
        },
        quotient::{
            EMITTER_ROUND_SPLITS, EXPANSION_ROUND_SPLITS, QueryShift, RoundBoundaryQuotients,
            WeightRatios,
        },
        subgroup_generator,
    },
};

/// One `mk` part and its originating note, emitted by [`MasterSeed`].
///
/// Carries this part's `MK_PART_LEN` round keys, its part index, and the whole
/// note (kept collected so the deferred `cm` can be computed downstream).
/// Wallet-only: the per-note secrets ride a header that never leaves the
/// wallet's own proof tree and is never published.
#[derive(Clone, Debug)]
pub struct MasterKeyPart;

impl Header for MasterKeyPart {
    /// `(mk_part, part, note)`.
    type Data = ([Fp; MK_PART_LEN], Fp, Note);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let (mk_part, part, note) = *data;
        let mut out = Vec::with_capacity(32 * (MK_PART_LEN + 1 + 4));
        for key in mk_part {
            out.extend_from_slice(&key.to_repr());
        }
        out.extend_from_slice(&part.to_repr());
        out.extend_from_slice(&Fp::from(note.pk).to_repr());
        out.extend_from_slice(&Fp::from(note.value).to_repr());
        out.extend_from_slice(&Fp::from(note.psi).to_repr());
        out.extend_from_slice(&Fp::from(note.rcm).to_repr());
        out
    }
}

/// Derive one `mk` part at the note's master secrets.
///
/// Witnesses the note, its proof authorizing key `pak`, and the part index.
/// Proves `note.pk == pak.derive_payment_key()` (pinning the nullifier key
/// `nk`), range-checks `part ∈ 0..MK_PARTS`, derives `mk_part =
/// nf_master_part(psi, nk, part)`, and emits `(mk_part, part, note)`. The note
/// rides the header so the deferred `cm` binds downstream; `nk` is discarded
/// and never leaves the seed (only the payment key `pk` does, and it
/// preimage-hides `nk`).
#[derive(Debug)]
pub struct MasterSeed;

impl Step for MasterSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = MasterKeyPart;
    type Right = ();
    /// `(note, pak, part)`.
    type Witness<'source> = (Note, ProofAuthorizingKey, u64);

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note, pak, part): Self::Witness<'source>,
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

        let mk_part = pak.nk.derive_note_part(&note.psi, part);

        Ok(((mk_part, part_fp, note), ()))
    }
}

/// Prove one part of a note's keyset expansion in one trace-based step.
///
/// The `EK_PART_SIZE` keyed-cipher outputs of this part, committed as
/// the eval-form part-key polynomial `A_p`
/// (`A_p(ζ^r) = E_mk(s + δ·(base + r))` over the order-`EK_PART_SIZE`
/// subgroup `⟨ζ⟩`) into slot `part ∈ 0..EK_PARTS` of a one-slot
/// [`EmitterKeyset`]. `base = part · EK_PART_SIZE` selects the cipher-input
/// window; the `EK_PARTS` parts interleave (over the cosets of `⟨ζ⟩`) into
/// the full schedule, reconstructed at [`NullifierDerivationStep`]. The
/// expansion-input parameters `(s, δ, w)` are derived in-step from the
/// reconciled `mk` ([`NoteMasterKey::expansion_params`]), so the cipher
/// inputs are note secrets and the schedule stays a deterministic function of
/// `mk`.
///
/// The witness is the prover-built trace `T`, the round quotient
/// ([`EXPANSION_ROUND_SPLITS`] splits), the boundary quotient, the part-key
/// poly `A_p`, the decimation quotient `Q`, and `part`; the body is pure
/// orchestration over three generic vanishing relations plus a range check.
///
/// - `enforce_first_column_values` applies round 0 (the input step) outside the
///   trace, pinning each row-start cell to `(s + δ·(base + row) + k_0)^5`.
/// - `enforce_row_recurrence` pins the remaining cipher rounds 1.. of `T`.
/// - `enforce_strided_column` binds `K` to `T`'s final column plus the
///   whitening key `w`, so `commit(K)` is exactly the expansion outputs.
///
/// # Gate budget
///
/// Rule-of-thumb ledger against the 2048-gate step ceiling (constant
/// multiplications and additions free, witnessed inverse ≈ 2, Poseidon
/// permutation ≈ 1/7):
///
/// | item | gates |
/// |---|---|
/// | expansion-parameter sponge (one permutation) | ~293 |
/// | boundary targets (`EK_PART_SIZE` rows × pow5) | ~768 |
/// | `enforce_first_column_values` (`EK_PART_SIZE`-node interpolation) | ~795 |
/// | `enforce_row_recurrence` (`ROUNDS`-node interpolation) | ~130 |
/// | `enforce_strided_column`, range check, reconciliation, slots | ~30 |
/// | total | ~2015 |
///
/// The parameter sponge must stay single-permutation: the domain tag plus the
/// [`NF_EXPANSION_MK_PREFIX`]-element `mk` prefix absorbs exactly `RATE`
/// elements and squeezes three; a second permutation does not fit.
///
/// [`NF_EXPANSION_MK_PREFIX`]: crate::constants::NF_EXPANSION_MK_PREFIX
#[derive(Debug)]
pub struct KeyExpansionStep;

impl Step for KeyExpansionStep {
    type Aux<'source> = ();
    type Left = MasterKeyPart;
    type Output = EmitterKeyset;
    type Right = MasterKeyPart;
    /// `(expansion_trace, quotients, key_poly, decimation_quotient, part)`.
    type Witness<'source> = (
        PartKeySpectrumPoly,
        RoundBoundaryQuotients<EXPANSION_ROUND_SPLITS>,
        PartKeyPoly,
        Polynomial, // decimation quotient binding K to T's final column
        Fp,         // part ∈ 0..EK_PARTS
    );

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (expansion_trace, quotients, key_poly, decimation_quotient, part): Self::Witness<'source>,
        left: <Self::Left as Header>::Data,
        right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // This invocation computes one part of the schedule. `part` is
        // range-checked to `0..EK_PARTS` (the product Π_i (part − i) vanishes
        // only there) and fixes the cipher-input window origin
        // `base = part · EK_PART_SIZE`, so part `p` runs inputs
        // `p·EK_PART_SIZE..(p+1)·EK_PART_SIZE`. The header carries `part` so the
        // derivation step pins one of each.
        let part_in_range = (0..EK_PARTS).fold(Fp::ONE, |product, index| {
            product * (part - Fp::from(index as u64))
        });
        enforce_zero(
            part_in_range,
            "KeyExpansionStep: part out of range 0..EK_PARTS",
        )?;
        let base = part * Fp::from(EK_PART_SIZE as u64);

        // Assemble the 32-key `mk` from the two `mk parts` (pinned to indices 0
        // and 1) of the same note, concatenated -- not the old complementary-sum
        // fuse. The note is reconciled across both seeds and forwarded so the
        // deferred `cm` binds downstream.
        let (mk, note) = {
            let (left_mk_part, left_index, left_note) = left;
            let (right_mk_part, right_index, right_note) = right;
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
            (
                NoteMasterKey::from_parts(&[left_mk_part, right_mk_part]),
                left_note,
            )
        };

        // The expansion-input parameters `(s, δ, w)`: one domain-separated
        // Poseidon permutation over the `mk` prefix, derived in-step so the
        // schedule stays a deterministic function of `mk` (a freely witnessed
        // salt would let one note carry many valid schedules, hence many
        // nullifier sequences). Every part's step derives the same values
        // from the reconciled `mk`.
        let params = mk.expansion_params();

        // Round 0, the input step. The cipher input for row `row` is the
        // secret affine `s + δ·(base + row)`. The input is not stored in the
        // trace, so round 0 is applied here rather than by the recurrence:
        // each row's first cell is pinned to round 0's output
        // `(s + δ·(base + row) + k_0)^5` (with `c_0 = 0`). The targets are
        // S-boxed here so the relation stays a generic first-column pinning;
        // the prover's boundary quotient pins the same values. Every operand
        // is pinned: `base` from the range-checked `part`, `k_0` and the
        // params from the reconciled `mk`.
        {
            let origin = params.input(base) + mk.round_key(0);
            let boundary: [Fp; EK_PART_SIZE] = array::from_fn(|row| {
                #[expect(clippy::as_conversions, reason = "row index conversion")]
                let cipher_in = origin + params.stride * Fp::from(row as u64);
                cipher_in.square().square() * cipher_in
            });
            enforce_first_column_values(
                ctx,
                &expansion_trace.0,
                &quotients.boundary,
                Fp::ZERO,
                &boundary,
            )?;
        }

        // Rounds 1..: advance each row through the rest of the cipher. The
        // recurrence enforces every in-row step `T[cell + 1] = (T[cell] +
        // schedule[cell])^5` as one round; `schedule[cell]` is that round's
        // additive `key + constant`, the same per-column layout for all rows.
        // Cell `cell` holds round `cell`'s output, so the step out of it is
        // round `cell + 1` (round 0 is pinned above, not a step). The last
        // cell's successor is the next row, so its offset is unused:
        // `get(ROUNDS)` is `None` -> `Fp::ZERO`, and the recurrence masks that
        // row-wrap step.
        {
            let schedule: [Fp; TachyonP5R32::ROUNDS] = array::from_fn(|cell| {
                TachyonP5R32::CONSTANTS
                    .get(cell + 1)
                    .map_or(Fp::ZERO, |round_const| mk.round_key(cell + 1) + round_const)
            });

            enforce_row_recurrence(
                ctx,
                &expansion_trace.0,
                &quotients.round,
                &schedule,
                TachyonP5R32::POW,
            )?;
        }

        // Bind the eval-form part-key poly `A_p` to the trace's final column. On
        // the order-`EK_PART_SIZE` subgroup `⟨ζ⟩` (`ζ = ω^{TRACE_COLUMNS}`),
        // `A_p(ζ^r) = (row-r final cell) + w = E_mk(s + δ·(base + r))`, so
        // `A_p` commits this part's `EK_PART_SIZE` expansion outputs. `σ =
        // ω^{TRACE_COLUMNS-1}` is the final-column stride within a row; the
        // whitening key is the dedicated `w`, not a reused round key.
        #[expect(clippy::as_conversions, reason = "constant column index")]
        let stride =
            subgroup_generator::<POLY_LEN_MAX>().pow_vartime([(TachyonP5R32::ROUNDS - 1) as u64]);
        enforce_strided_column::<{ EK_PART_SIZE }>(
            ctx,
            &expansion_trace.0,
            &key_poly.0,
            &decimation_quotient,
            stride,
            params.whitening,
        )?;

        // Emit a one-slot keyset: this part's commitment in its slot, the
        // identity point elsewhere, with matching boolean coverage. `part` is
        // range-checked above, so the slot selector places exactly one part at
        // its schedule position.
        let commit = PartKeyCommit(key_poly.0.commit());
        let slots: [PartKeyCommit; EK_PARTS] = array::from_fn(|slot| {
            if Fp::from(slot as u64) == part {
                commit
            } else {
                PartKeyCommit(Eq::identity())
            }
        });
        let coverage: [Fp; EK_PARTS] = array::from_fn(|slot| {
            if Fp::from(slot as u64) == part {
                Fp::ONE
            } else {
                Fp::ZERO
            }
        });
        Ok(((slots, coverage, mk, note), ()))
    }
}

/// The expansion keyset `(slots, coverage, mk, note)`: per-part commitment
/// slots and coverage flags. Wallet-only.
///
/// `slots[p]` holds `commit(A_p)`, the [`PartKeyCommit`] to part `p`'s
/// eval-form part-key polynomial (that window's `EK_PART_SIZE` keyed-cipher
/// expansion outputs, proven by [`KeyExpansionStep`]), or the identity point
/// while part `p` is uncovered; `coverage[p]` is the matching boolean flag.
/// [`KeyExpansionStep`] emits a one-slot keyset and [`EmitterKeysetFuse`]
/// merges disjoint keysets, so any fuse order covers the schedule; slot
/// position pins each part's schedule index without a fold or per-part
/// ordering. `mk` carries the master key for the downstream query parameters
/// and `note` the per-note fields for the deferred `cm`; both are reconciled
/// across every merge. The header is private to the wallet's own proof tree and
/// is never published.
#[derive(Clone, Debug)]
pub struct EmitterKeyset;

impl Header for EmitterKeyset {
    /// `(slots, coverage, mk, note)`.
    type Data = (
        [PartKeyCommit; EK_PARTS],
        [Fp; EK_PARTS],
        NoteMasterKey,
        Note,
    );

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let (slots, coverage, mk, note) = *data;
        let mut out = Vec::with_capacity(
            (EK_PARTS * 32) + (EK_PARTS * 32) + (NoteMasterKey::MK_LENGTH * 32) + (4 * 32),
        );
        for slot in slots {
            let slot_bytes: [u8; 32] = slot.0.to_affine().to_bytes();
            out.extend_from_slice(&slot_bytes);
        }
        for flag in coverage {
            out.extend_from_slice(&flag.to_repr());
        }
        for key in mk.0 {
            out.extend_from_slice(&key.to_repr());
        }
        out.extend_from_slice(&Fp::from(note.pk).to_repr());
        out.extend_from_slice(&Fp::from(note.value).to_repr());
        out.extend_from_slice(&Fp::from(note.psi).to_repr());
        out.extend_from_slice(&Fp::from(note.rcm).to_repr());
        out
    }
}

/// Merge two disjoint [`EmitterKeyset`]s slot-wise.
///
/// Reconciles the two keysets' `mk` and note (so every covered part belongs to
/// one note), enforces disjoint coverage (no part certified twice), and emits
/// the slot-wise point sum: a covered slot carries its part commitment
/// unchanged (identity plus commitment), an uncovered slot stays the identity.
/// `EK_PARTS - 1` invocations, in any tree shape, cover the whole schedule;
/// changing `EK_PARTS` changes the invocation count, not the circuit.
/// Completeness is enforced downstream: [`NullifierDerivationStep`] requires
/// full coverage and matches every witnessed part against its slot.
#[derive(Debug)]
pub struct EmitterKeysetFuse;

impl Step for EmitterKeysetFuse {
    type Aux<'source> = ();
    type Left = EmitterKeyset;
    type Output = EmitterKeyset;
    type Right = EmitterKeyset;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (left_slots, left_coverage, left_mk, left_note): <Self::Left as Header>::Data,
        (right_slots, right_coverage, right_mk, right_note): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Reconcile: every covered part belongs to the same note (shared mk and
        // note fields), so the forwarded mk keys the genuine derivation and the
        // deferred cm pins the genuine value.
        for (left_key, right_key) in left_mk.0.iter().zip(right_mk.0.iter()) {
            enforce_zero(
                *left_key - *right_key,
                "EmitterKeysetFuse: master key mismatch across parts",
            )?;
        }
        enforce_zero(
            Fp::from(left_note.pk) - Fp::from(right_note.pk),
            "EmitterKeysetFuse: note pk mismatch across parts",
        )?;
        enforce_zero(
            Fp::from(left_note.value) - Fp::from(right_note.value),
            "EmitterKeysetFuse: note value mismatch across parts",
        )?;
        enforce_zero(
            Fp::from(left_note.psi) - Fp::from(right_note.psi),
            "EmitterKeysetFuse: note psi mismatch across parts",
        )?;
        enforce_zero(
            Fp::from(left_note.rcm) - Fp::from(right_note.rcm),
            "EmitterKeysetFuse: note rcm mismatch across parts",
        )?;

        // Disjoint coverage: flags are boolean by construction upstream, so a
        // zero product per slot means no part is certified twice.
        for slot in 0..EK_PARTS {
            enforce_zero(
                left_coverage[slot] * right_coverage[slot],
                "EmitterKeysetFuse: overlapping part coverage",
            )?;
        }

        let slots: [PartKeyCommit; EK_PARTS] =
            array::from_fn(|slot| PartKeyCommit(left_slots[slot].0 + right_slots[slot].0));
        let coverage: [Fp; EK_PARTS] =
            array::from_fn(|slot| left_coverage[slot] + right_coverage[slot]);
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

    fn encode(data: &Self::Data) -> Vec<u8> {
        let (commits, digest, cm, shift, ratios) = *data;
        let mut out = Vec::new();
        for commit in commits {
            let commit_bytes: [u8; 32] = commit.0.to_affine().to_bytes();
            out.extend_from_slice(&commit_bytes);
        }
        out.extend_from_slice(&digest.0.to_repr());
        out.extend_from_slice(&Fp::from(cm).to_repr());
        out.extend_from_slice(&shift.0.to_repr());
        for ratio in ratios.0 {
            out.extend_from_slice(&ratio.to_repr());
        }
        out
    }
}

/// Certify the note's `N` derivation polynomials in one single-input step.
///
/// Consumes the fused [`EmitterKeyset`] and witnesses the note's
/// `EK_PARTS` part-key polynomials `A_p`, the `N` polynomials `T_j`, and their
/// round- and boundary-quotients. It requires full coverage (every slot
/// certified) and matches each witnessed `A_p.commit()` against its slot, so
/// per-slot equality binds the full ordered set of part commitments to the
/// certified expansion -- every key it reads is the proven interleaved
/// schedule, no part substituted or reordered. The per-poly salts, weight
/// bases `ρ_j`, and shift `c` are derived from the fused `mk`; the deferred
/// `cm` is computed from the fused note here, pinning the note's value and
/// `ψ`.
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
    type Left = EmitterKeyset;
    type Output = NullifierDerivation;
    type Right = ();
    /// `(parts, polys, quotients)`.
    type Witness<'source> = (
        [PartKeyPoly; EK_PARTS],
        [NfEmitterPoly; NF_EMITTERS],
        [RoundBoundaryQuotients<EMITTER_ROUND_SPLITS>; NF_EMITTERS],
    );

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (parts, polys, quotients): Self::Witness<'source>,
        (slots, coverage, mk, note): <Self::Left as Header>::Data,
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
        for (position, part) in parts.iter().enumerate() {
            enforce_equal_point(
                part.0.commit(),
                slots[position].0,
                "NullifierDerivationStep: part does not match its certified slot",
            )?;
        }
        let key_polys: [&Polynomial; EK_PARTS] = parts.each_ref().map(|part| &part.0);

        // The deferred `cm`, computed from the fused note: pins the note's
        // value and `ψ` into the published derivation.
        let cm = note.commitment();

        // Query parameters derived from the fused `mk`. `salts` fix the
        // per-poly boundaries; `shift`/`ratios` are forwarded for the downstream
        // query and arc match.
        let salts = mk.query_salts();
        let (ratios, shift) = mk.query_weights();

        // Round-0 boundary key `k_0 = K(1) = A_0(1)` (part 0's coset selector is
        // 1 and all others are 0 at `x = 1`), shared across all polys.
        let first_key = parts[0].0.eval(Fp::ONE);
        ctx.enforce_poly_query(parts[0].0.commit(), Fp::ONE, first_key)?;

        for (poly_index, (poly, poly_quotients)) in polys.iter().zip(&quotients).enumerate() {
            // Boundary: round 0 from the salt, `T_j(1) = (mk_s^{(j)} + k_0)^5`.
            let alpha = salts.0[poly_index] + first_key;
            let boundary = alpha.square().square() * alpha;
            enforce_first_column_values::<1>(
                ctx,
                &poly.0,
                &poly_quotients.boundary,
                Fp::ZERO,
                &[boundary],
            )?;

            // Rounds 1..: the committed-offset quintic recurrence (x^5 S-box),
            // the full interleaved schedule reconstructed inline from the
            // `EK_PARTS` committed part-key polys.
            enforce_committed_offset_recurrence::<
                { EMITTER_ROUND_SPLITS },
                { EK_FULL_SIZE },
                { EK_PARTS },
            >(
                ctx,
                &poly.0,
                &poly_quotients.round,
                &CONSTANT_SCHEDULE,
                &key_polys,
                5,
            )?;
        }

        let commits: [NfEmitterCommit; NF_EMITTERS] =
            array::from_fn(|poly_index| NfEmitterCommit(polys[poly_index].0.commit()));

        // Bind all `N` commitments into one transcript challenge, so the
        // downstream arc challenge `β` absorbs a single element rather than the
        // whole set. The native prover reads this scalar off the header.
        let digest = NfEmittersDigest(ctx.derive_challenge(&commits.map(|commit| commit.0))?);

        Ok(((commits, digest, cm, shift, ratios), ()))
    }
}
