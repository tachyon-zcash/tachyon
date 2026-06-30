//! MiMC key expansion and nullifier derivation. Wallet-only; every header
//! carries `cm` for its consumers.
//!
//! [`NfMasterExpand`] proves one part of a note's keyset expansion -- the
//! `EK_PART_SIZE` keyed-cipher outputs of that part -- in a single
//! trace-based step, committing them on the [`NfPartKeyset`] header. `EK_PARTS`
//! invocations make the full interleaved schedule.
//! [`NullifierDerivationStep`] then certifies the note's derivation polynomials
//! against the parts, reconstructing the schedule inline.

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
use group::{Curve as _, GroupEncoding as _};
use pasta_curves::Fp;
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
    primitives::{EpochIndex, PartKeySpectrumPoly},
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
        let (mk_part, part, note) = data;
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
/// the eval-form part-key polynomial `A_p` (`A_p(ζ^r) = E_mk(base + r)` over
/// the order-`EK_PART_SIZE` subgroup `⟨ζ⟩`) on the [`NfPartKeyset`]
/// header, tagged with `part ∈ 0..EK_PARTS`. `base = part · EK_PART_SIZE`
/// selects the cipher-input window; the `EK_PARTS` parts interleave (over the
/// cosets of `⟨ζ⟩`) into the full schedule, reconstructed at
/// [`NullifierDerivationStep`].
///
/// The witness is the prover-built trace `T`, the round quotient
/// ([`EXPANSION_ROUND_SPLITS`] splits), the boundary quotient, the part-key
/// poly `A_p`, the decimation quotient `Q`, and `part`; the body is pure
/// orchestration over three generic vanishing relations plus a range check.
///
/// - `enforce_first_column_values` applies round 0 (the salt step) outside the
///   trace, pinning each row-start cell to `(mk_s + row + k_0)^5`.
/// - `enforce_row_recurrence` pins the remaining cipher rounds 1.. of `T`.
/// - `enforce_strided_column` binds `K` to `T`'s final column plus the
///   whitening key, so `commit(K)` is exactly the expansion outputs.
#[derive(Debug)]
pub struct ExpandedKeyStep;

impl Step for ExpandedKeyStep {
    type Aux<'source> = ();
    type Left = MasterKeyPart;
    type Output = ExpandedKeyPart;
    type Right = MasterKeyPart;
    /// `(trace T, round/boundary quotients, part-key poly A_p, decimation
    /// quotient, part)`. `part ∈ 0..EK_PARTS` selects this invocation's window.
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
        enforce_zero(part_in_range, "ExpandedKeyStep: part out of range 0..EK_PARTS")?;
        let base = part * Fp::from(EK_PART_SIZE as u64);

        // Assemble the 32-key `mk` from the two `mk parts` (pinned to indices 0
        // and 1) of the same note, concatenated -- not the old complementary-sum
        // fuse. The note is reconciled across both seeds and forwarded so the
        // deferred `cm` binds downstream.
        let (mk, note) = {
            let (left_mk_part, left_index, left_note) = left;
            let (right_mk_part, right_index, right_note) = right;
            enforce_zero(left_index, "ExpandedKeyStep: left input is not mk part 0")?;
            enforce_zero(
                right_index - Fp::ONE,
                "ExpandedKeyStep: right input is not mk part 1",
            )?;
            enforce_zero(
                Fp::from(left_note.pk) - Fp::from(right_note.pk),
                "ExpandedKeyStep: note pk mismatch across mk parts",
            )?;
            enforce_zero(
                Fp::from(left_note.value) - Fp::from(right_note.value),
                "ExpandedKeyStep: note value mismatch across mk parts",
            )?;
            enforce_zero(
                Fp::from(left_note.psi) - Fp::from(right_note.psi),
                "ExpandedKeyStep: note psi mismatch across mk parts",
            )?;
            enforce_zero(
                Fp::from(left_note.rcm) - Fp::from(right_note.rcm),
                "ExpandedKeyStep: note rcm mismatch across mk parts",
            )?;
            (
                NoteMasterKey::from_parts(&[left_mk_part, right_mk_part]),
                left_note,
            )
        };

        // Round 0, the salt step. The expansion runs from index 0, so the
        // cipher input for row `row` is `mk_s + row`. The input is not stored
        // in the trace, so round 0 is applied here rather than by the
        // recurrence: each row's first cell is pinned to round 0's output
        // `(mk_s + row + k_0)^5` (with `c_0 = 0`). The targets are S-boxed here
        // so the relation stays a generic first-column pinning; the prover's
        // boundary quotient pins the same values.
        {
            let first_key = mk.round_key(0);
            let boundary: [Fp; EK_PART_SIZE] = array::from_fn(|row| {
                #[expect(clippy::as_conversions, reason = "row index conversion")]
                let cipher_in = base + Fp::from(row as u64) + first_key;
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

        // Rounds 1..63: advance each row through the rest of the cipher. The
        // recurrence enforces every in-row step `T[cell + 1] = (T[cell] +
        // schedule[cell])^5` as one round; `schedule[cell]` is that round's
        // additive `key + constant`, the same per-column layout for all rows.
        // Cell `cell` holds round `cell`'s output, so the step out of it is
        // round `cell + 1` (round 0 is pinned above, not a step). The last
        // cell's successor is the next row, so its offset is unused: `get(64)`
        // is `None` -> `Fp::ZERO`, and the recurrence masks that row-wrap step.
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
        // `A_p(ζ^r) = (row-r final cell) + whitening = E_mk(base + r)`, so `A_p`
        // commits this part's `EK_PART_SIZE` expansion outputs. `σ =
        // ω^{TRACE_COLUMNS-1}` is the final-column stride within a row.
        #[expect(clippy::as_conversions, reason = "constant column index")]
        let stride =
            subgroup_generator::<POLY_LEN_MAX>().pow_vartime([(TachyonP5R32::ROUNDS - 1) as u64]);
        let whitening = mk.round_key(TachyonP5R32::ROUNDS);
        enforce_strided_column::<{ EK_PART_SIZE }>(
            ctx,
            &expansion_trace.0,
            &key_poly.0,
            &decimation_quotient,
            stride,
            whitening,
        )?;

        Ok(((PartKeyCommit(key_poly.0.commit()), part, mk, note), ()))
    }
}

/// One `ExpandedKey` part: its key-poly commitment, window index, the full
/// `mk`, and the originating note `(keyset_commit, part, mk, note)`. Wallet-only.
///
/// Carries the [`PartKeyCommit`] to the eval-form part-key polynomial (this
/// window's `EK_PART_SIZE` keyed-cipher expansion outputs), proven by
/// [`ExpandedKeyStep`], the `part` index `0..EK_PARTS` so the funnel pins one of
/// each, the full `mk` (for the downstream query parameters), and the note (so
/// the deferred `cm` binds at the funnel root). The header is private to the
/// wallet's own proof tree and is never published.
#[derive(Clone, Debug)]
pub struct ExpandedKeyPart;

impl Header for ExpandedKeyPart {
    type Data = (PartKeyCommit, Fp, NoteMasterKey, Note);

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let (keyset_commit, part, mk, note) = data;
        let mut out = Vec::with_capacity(32 + 32 + (NoteMasterKey::MK_LENGTH * 32) + (4 * 32));
        let commit_bytes: [u8; 32] = keyset_commit.0.to_affine().to_bytes();
        out.extend_from_slice(&commit_bytes);
        out.extend_from_slice(&part.to_repr());
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

/// The certify-once nullifier derivation `([commit(T_j)], digest, cm, E_0, c,
/// [ρ_j])`. Wallet-only.
///
/// Holds the `N` derivation-poly commitments (for opening), a transcript
/// challenge over them (so the lift's challenge absorbs one element, not `N`),
/// the note commitment, the creation
/// epoch `E_0` (the offset origin, bound downstream at `SpendableInit`), and
/// the secret shift `c` and ratios `ρ_j` forwarded from the keyset for the
/// query and lift. Secret material rides this wallet-only header without
/// leaking; the public consumer emits only the resulting `nf`.
#[derive(Clone, Debug)]
pub struct NullifierDerivation;

impl Header for NullifierDerivation {
    type Data = (
        [NfEmitterCommit; NF_EMITTERS],
        NfEmittersDigest,
        NoteCommitment,
        EpochIndex,
        QueryShift,
        WeightRatios,
    );

    const SUFFIX: Suffix = Suffix::new(13);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let (commits, digest, cm, creation_epoch, shift, ratios) = *data;
        let mut out = Vec::new();
        for commit in commits {
            let commit_bytes: [u8; 32] = commit.0.to_affine().to_bytes();
            out.extend_from_slice(&commit_bytes);
        }
        out.extend_from_slice(&digest.0.to_repr());
        out.extend_from_slice(&Fp::from(cm).to_repr());
        out.extend_from_slice(&creation_epoch.0.to_le_bytes());
        out.extend_from_slice(&shift.0.to_repr());
        for ratio in ratios.0 {
            out.extend_from_slice(&ratio.to_repr());
        }
        out
    }
}

/// Certify the note's `N` derivation polynomials in one step.
///
/// Witnesses the note's `EK_PARTS` part-key polynomials `A_p`, the `N`
/// polynomials `T_j`, their round- and boundary-quotients, the public constant
/// schedule `C`, and the creation epoch `E_0`. It first checks the seam (the
/// inputs carry one `mk`/`cm`, and they are parts `0..EK_PARTS` in order), then
/// binds each `A_p` to the threaded [`PartKeyCommit`] by commit-equality, so
/// every key it reads is the proven interleaved schedule; the per-poly salts,
/// weight bases `ρ_j`, and shift `c` arrive on the keyset header, derived from
/// the bound `mk` by [`NfMasterExpand`].
///
/// Per poly, two relations certify `T_j` is the genuine keyed-cipher
/// interpolant: [`enforce_first_column_values`] pins
/// `T_j(1) = (mk_s^{(j)} + k_0)^5` (round 0 from the salt, `k_0 = A_0(1)`), and
/// [`enforce_committed_offset_recurrence`] pins the remaining rounds against
/// the schedule reconstructed inline from the `A_p` (the interleaved-coset
/// offset key term) and the committed `C`. Then it binds the commitments into
/// one transcript challenge and emits the derivation, forwarding `c`/`ρ_j` for
/// the downstream query and lift.
///
/// `E_0` is a free witness here, carrying no claim until `SpendableInit` (its
/// sole gatekeeper) binds it to the creation anchor.
#[derive(Debug)]
pub struct NullifierDerivationStep;

impl Step for NullifierDerivationStep {
    type Aux<'source> = ();
    type Left = NfPartKeyset;
    type Output = NullifierDerivation;
    type Right = NfPartKeyset;
    /// `([A_p; EK_PARTS], T_j, quotients_j, E_0)`: the part-key polys, the `N`
    /// derivation polys, their quotients, and the creation epoch.
    type Witness<'source> = (
        [PartKeyPoly; EK_PARTS],
        [NfEmitterPoly; NF_EMITTERS],
        [RoundBoundaryQuotients<EMITTER_ROUND_SPLITS>; NF_EMITTERS],
        EpochIndex,
    );

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (parts, polys, quotients, creation_epoch): Self::Witness<'source>,
        (commit_left, mk, cm, part_left): <Self::Left as Header>::Data,
        (commit_right, mk_right, cm_right, part_right): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        const { assert!(EK_PARTS == 2, "EK_PARTS > 2 needs a merge tree") };

        // Seam: both inputs belong to the same note (shared `cm`/`mk`)
        enforce_zero(
            Fp::from(cm) - Fp::from(cm_right),
            "NullifierDerivationStep: part commitments do not match",
        )?;
        for (left_part, right_part) in mk.0.iter().zip(mk_right.0.iter()) {
            enforce_zero(
                *left_part - *right_part,
                "NullifierDerivationStep: part master keys do not match",
            )?;
        }

        // The inputs are parts `0..EK_PARTS` in order: bind each part-key poly to
        // its threaded commitment and pin its index, so every key read below is
        // the proven interleaved schedule and no part is supplied twice.
        let part_commits = [commit_left, commit_right];
        let part_indices = [part_left, part_right];
        for part in 0..EK_PARTS {
            enforce_equal_point(
                parts[part].0.commit(),
                part_commits[part].0,
                "NullifierDerivationStep: part-key poly does not match its commitment",
            )?;
            enforce_zero(
                part_indices[part] - Fp::from(part as u64),
                "NullifierDerivationStep: part index mismatch",
            )?;
        }
        let key_polys: [&Polynomial; EK_PARTS] = parts.each_ref().map(|part| &part.0);

        // Query parameters derived from `mk` forwarded on the keyset header.
        // `salts` fix the per-poly boundaries; `shift`/`ratios` are forwarded
        // for the downstream query and lift.
        let salts = mk.query_salts();
        let (ratios, shift) = mk.query_weights();

        // Round-0 boundary key `k_0 = K(1) = A_0(1)` (part 0's coset selector is
        // 1 and all others are 0 at `x = 1`), shared across all polys.
        let first_key = parts[0].0.eval(Fp::ONE);
        ctx.enforce_poly_query(part_commits[0].0, Fp::ONE, first_key)?;

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
        // downstream lift challenge `β` absorbs a single element rather than the
        // whole set. The native prover reads this scalar off the header.
        let digest = NfEmittersDigest(ctx.derive_challenge(&commits.map(|commit| commit.0))?);

        Ok(((commits, digest, cm, creation_epoch, shift, ratios), ()))
    }
}
