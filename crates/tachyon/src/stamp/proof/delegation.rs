//! MiMC key expansion and nullifier derivation. Wallet-only; every header
//! carries `cm` for its consumers.
//!
//! [`NfMasterExpand`] proves one half of a note's keyset expansion -- the
//! `ExpandedKey::EK_HALF` keyed-cipher outputs of that half -- in a single
//! trace-based step, committing them on the [`NfExpandedKeyset`] header. Two
//! invocations (even/odd halves) make the full 256-key interleaved schedule.
//! [`NullifierDerivationStep`] then certifies the note's derivation polynomials
//! against the two halves, reconstructing the schedule inline.

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
use zcash_mimc::spec::tachyon::TachyonP5R64;

use crate::{
    CONSTANT_SCHEDULE, ExpandedKeyCommit, ExpandedKeyPoly, NfEmitterCommit, NfEmitterPoly,
    NfEmittersDigest,
    constants::{NF_EMITTERS, POLY_LEN_MAX},
    keys::{ExpandedKey, NoteMasterKey, ProofAuthorizingKey},
    note::{Commitment as NoteCommitment, Note},
    primitives::{EpochIndex, ExpKeySpectrumPoly},
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

/// The note's keyset, input salt, and commitment `([mk_0..mk_{κ-1}], mk_s,
/// cm)`. Wallet-only.
///
/// Carrying the raw keyset and `mk_s` is required: they are the witness
/// anchors every derivation step proves against. The header is private to
/// the wallet's own proof tree and is never published.
#[derive(Clone, Debug)]
pub struct NfMasterHeader;

impl Header for NfMasterHeader {
    type Data = (NoteCommitment, [Fp; NoteMasterKey::MK_LENGTH]);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(&(cm, mk_parts): &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + (32 * mk_parts.len()));
        out.extend_from_slice(&Fp::from(cm).to_repr());
        for part in mk_parts {
            out.extend_from_slice(&<[u8; 32]>::from(part));
        }
        out
    }
}

/// Seed the derivation chain at the note's master secrets.
///
/// Witnesses the note and `pak`, proves the keyset and `mk_s` are the
/// note's master secrets (`note.pk == pak.derive_payment_key()` pins `nk`,
/// and the keyset and `mk_s` are Poseidon outputs of `(psi, nk)`), and
/// emits `([mk_0..mk_{κ-1}], mk_s, cm)`.
#[derive(Debug)]
pub struct NfMasterSeed;

impl Step for NfMasterSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = NfMasterHeader;
    type Right = ();
    type Witness<'source> = (
        Note,
        ProofAuthorizingKey,
        [u64; 3], // MK_LENGTH / 2
    );

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note, pak, part_idx): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            note.pk.0 - pak.derive_payment_key().0,
            "NfMasterSeed: pak not related to note",
        )?;

        let cm = note.commitment();

        let mut mk_parts: [Fp; NoteMasterKey::MK_LENGTH] = [Fp::ZERO; NoteMasterKey::MK_LENGTH];
        for index in part_idx {
            if index >= (NoteMasterKey::MK_LENGTH as u64) {
                return Err(ragu::Error::InvalidWitness(
                    "NfMasterSeed: key index out of bounds".into(),
                ));
            }
            mk_parts[index as usize] = pak.nk.derive_note_private(&note.psi, index);
        }

        Ok(((cm, mk_parts), ()))
    }
}

/// Prove one half of a note's keyset expansion in one trace-based step.
///
/// The `ExpandedKey::EK_HALF` keyed-cipher outputs of this half, committed as
/// the eval-form half-key polynomial `A` (`A(ζ^r) = E_mk(base + r)` over the
/// order-`ExpandedKey::EK_HALF` subgroup `⟨ζ⟩`) on the [`NfExpandedKeyset`]
/// header, tagged with `half ∈ {0,1}`. `base = half · EK_HALF` selects the
/// cipher-input window; the two halves interleave (even/odd cosets) into the
/// full 256-key schedule, reconstructed at [`NullifierDerivationStep`].
///
/// The witness is the prover-built trace `T`, the round quotient
/// ([`EXPANSION_ROUND_SPLITS`] splits), the boundary quotient, the half-key
/// poly `A`, the decimation quotient `Q`, and `half`; the body is pure
/// orchestration over three generic vanishing relations plus a boolean check.
///
/// - `enforce_first_column_values` applies round 0 (the salt step) outside the
///   trace, pinning each row-start cell to `(mk_s + row + k_0)^5`.
/// - `enforce_row_recurrence` pins the remaining cipher rounds 1.. of `T`.
/// - `enforce_strided_column` binds `K` to `T`'s final column plus the
///   whitening key, so `commit(K)` is exactly the expansion outputs.
#[derive(Debug)]
pub struct NfMasterExpand;

/// TODO: add more tests
impl Step for NfMasterExpand {
    type Aux<'source> = ();
    type Left = NfMasterHeader;
    type Output = NfExpandedKeyset;
    type Right = NfMasterHeader;
    /// `(trace T, round/boundary quotients, half-key poly A/B, decimation
    /// quotient, half)`. `half ∈ {0,1}` selects this invocation's window.
    type Witness<'source> = (
        ExpKeySpectrumPoly,
        RoundBoundaryQuotients<EXPANSION_ROUND_SPLITS>,
        ExpandedKeyPoly,
        Polynomial, // decimation quotient binding K to T's final column
        Fp,         // half ∈ {0,1}
    );

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (expansion_trace, quotients, key_poly, decimation_quotient, half): Self::Witness<'source>,
        left: <Self::Left as Header>::Data,
        right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // This invocation computes one half of the schedule. `half ∈ {0,1}` is
        // range-checked and fixes the cipher-input window origin
        // `base = half · EK_HALF`, so half 0 runs inputs 0..EK_HALF (the even
        // schedule positions) and half 1 runs EK_HALF..2·EK_HALF (odd). The
        // header carries `half` so the derivation step pins one of each.
        enforce_zero(
            half * (half - Fp::ONE),
            "NfMasterExpand: half must be 0 or 1",
        )?;
        #[expect(clippy::as_conversions, reason = "constant size")]
        let base = half * Fp::from(ExpandedKey::EK_HALF as u64);
        let (cm, mk) = {
            let (left_cm, left_parts) = left;
            let (right_cm, right_parts) = right;

            let all_parts: [Fp; NoteMasterKey::MK_LENGTH] = left_parts
                .into_iter()
                .zip(right_parts)
                .map(|(left_key, right_key)| {
                    if bool::from(left_key.is_zero()) == bool::from(right_key.is_zero()) {
                        return Err(ragu::Error::InvalidWitness(
                            "NfMasterExpand: left and right keys are not complementary".into(),
                        ));
                    }
                    Ok(left_key + right_key)
                })
                .collect::<Result<Vec<Fp>, ragu::Error>>()?
                .try_into()
                .map_err(|_err| {
                    ragu::Error::InvalidWitness("NfMasterExpand: unreachable, constant size".into())
                })?;

            enforce_zero(
                Fp::from(left_cm) - Fp::from(right_cm),
                "NfMasterExpand: left and right commitments do not match",
            )?;

            Ok((left_cm, NoteMasterKey(all_parts)))
        }?;

        // Round 0, the salt step. The expansion runs from index 0, so the
        // cipher input for row `row` is `mk_s + row`. The input is not stored
        // in the trace, so round 0 is applied here rather than by the
        // recurrence: each row's first cell is pinned to round 0's output
        // `(mk_s + row + k_0)^5` (with `c_0 = 0`). The targets are S-boxed here
        // so the relation stays a generic first-column pinning; the prover's
        // boundary quotient pins the same values.
        {
            let first_key = mk.round_key(0);
            let boundary: [Fp; ExpandedKey::EK_HALF] = array::from_fn(|row| {
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
            let schedule: [Fp; TachyonP5R64::ROUNDS] = array::from_fn(|cell| {
                TachyonP5R64::CONSTANTS
                    .get(cell + 1)
                    .map_or(Fp::ZERO, |round_const| mk.round_key(cell + 1) + round_const)
            });

            enforce_row_recurrence(
                ctx,
                &expansion_trace.0,
                &quotients.round,
                &schedule,
                TachyonP5R64::POW,
            )?;
        }

        // Bind the eval-form half-key poly `A` to the trace's final column. On
        // the order-`ExpandedKey::EK_HALF` subgroup `⟨ζ⟩` (`ζ = ω^{TRACE_COLUMNS}`),
        // `A(ζ^r) = (row-r final cell) + whitening = E_mk(base + r)`, so `A`
        // commits this half's `ExpandedKey::EK_HALF` expansion outputs. `σ =
        // ω^{TRACE_COLUMNS-1}` is the final-column stride within a row.
        #[expect(clippy::as_conversions, reason = "constant column index")]
        let stride =
            subgroup_generator::<POLY_LEN_MAX>().pow_vartime([(TachyonP5R64::ROUNDS - 1) as u64]);
        let whitening = mk.round_key(TachyonP5R64::ROUNDS);
        enforce_strided_column::<{ ExpandedKey::EK_HALF }>(
            ctx,
            &expansion_trace.0,
            &key_poly.0,
            &decimation_quotient,
            stride,
            whitening,
        )?;

        Ok(((ExpandedKeyCommit(key_poly.0.commit()), mk, cm, half), ()))
    }
}

/// One expansion half's keyset commitment, master key, note commitment, and
/// half tag `(keyset_commit, mk, cm, half)`. Wallet-only.
///
/// Carries the [`ExpandedKeyCommit`] to the eval-form half-key polynomial (this
/// half's `ExpandedKey::EK_HALF` keyed-cipher expansion outputs), proven by
/// [`NfMasterExpand`], plus the raw `mk` forwarded for
/// [`NullifierDerivationStep`] to derive its query parameters (per-poly salts,
/// weight bases `ρ_j`, and shift `c`), and `half ∈ {0,1}` so the derivation
/// step pins one even and one odd half. The header is private to the wallet's
/// own proof tree and is never published.
#[derive(Clone, Debug)]
pub struct NfExpandedKeyset;

impl Header for NfExpandedKeyset {
    type Data = (ExpandedKeyCommit, NoteMasterKey, NoteCommitment, Fp);

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let (keyset_commit, mk, cm, half) = *data;
        let mut out = Vec::with_capacity(32 + (NoteMasterKey::MK_LENGTH * 32) + 32 + 32);
        let commit_bytes: [u8; 32] = keyset_commit.0.to_affine().to_bytes();
        out.extend_from_slice(&commit_bytes);
        for part in mk.0 {
            out.extend_from_slice(&part.to_repr());
        }
        out.extend_from_slice(&Fp::from(cm).to_repr());
        out.extend_from_slice(&half.to_repr());
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
/// Witnesses the note's two half-key polynomials `A`/`B`, the `N` polynomials
/// `T_j`, their round- and boundary-quotients, the public constant schedule
/// `C`, and the creation epoch `E_0`. It first checks the seam (both halves
/// carry one `mk`/`cm`, and they are the even half `0` and odd half `1`), then
/// binds `A`/`B` to the threaded [`ExpandedKeyCommit`]s by commit-equality, so
/// every key it reads is the proven 256-key interleaved schedule; the per-poly
/// salts, weight bases `ρ_j`, and shift `c` arrive on the keyset header,
/// derived from the bound `mk` by [`NfMasterExpand`].
///
/// Per poly, two relations certify `T_j` is the genuine keyed-cipher
/// interpolant: [`enforce_first_column_values`] pins
/// `T_j(1) = (mk_s^{(j)} + k_0)^5` (round 0 from the salt, `k_0 = A(1)`), and
/// [`enforce_committed_offset_recurrence`] pins the remaining rounds against
/// the schedule reconstructed inline from `A`/`B` (the interleaved-coset offset
/// key term) and the committed `C`. Then it binds the commitments into one
/// transcript challenge and emits the derivation, forwarding `c`/`ρ_j` for the
/// downstream query and lift.
///
/// `E_0` is a free witness here, carrying no claim until `SpendableInit` (its
/// sole gatekeeper) binds it to the creation anchor.
#[derive(Debug)]
pub struct NullifierDerivationStep;

impl Step for NullifierDerivationStep {
    type Aux<'source> = ();
    type Left = NfExpandedKeyset;
    type Output = NullifierDerivation;
    type Right = NfExpandedKeyset;
    /// `(A, B, T_j, quotients_j, E_0)`: the even/odd half-key polys, the `N`
    /// derivation polys, their quotients, and the creation epoch.
    type Witness<'source> = (
        ExpandedKeyPoly,
        ExpandedKeyPoly,
        [NfEmitterPoly; NF_EMITTERS],
        [RoundBoundaryQuotients<EMITTER_ROUND_SPLITS>; NF_EMITTERS],
        EpochIndex,
    );

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (key_a, key_b, polys, quotients, creation_epoch): Self::Witness<'source>,
        (keyset_commit_even, mk, cm, half_even): <Self::Left as Header>::Data,
        (keyset_commit_odd, mk_odd, cm_odd, half_odd): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Seam: both halves belong to the same note and share one master key,
        // and they are complementary (left is the even half `0`, right the odd
        // half `1`). Without the half pins a prover could supply the same half
        // twice and forge the schedule.
        enforce_zero(
            Fp::from(cm) - Fp::from(cm_odd),
            "NullifierDerivationStep: half commitments do not match",
        )?;
        for (left_part, right_part) in mk.0.iter().zip(mk_odd.0.iter()) {
            enforce_zero(
                *left_part - *right_part,
                "NullifierDerivationStep: half master keys do not match",
            )?;
        }
        enforce_zero(half_even, "NullifierDerivationStep: left half must be 0")?;
        enforce_zero(
            half_odd - Fp::ONE,
            "NullifierDerivationStep: right half must be 1",
        )?;

        // Bind the witnessed half-key polys to the threaded half commitments, so
        // every key read below is the proven 256-key interleaved schedule.
        enforce_equal_point(
            key_a.0.commit(),
            keyset_commit_even.0,
            "NullifierDerivationStep: even half-key poly does not match its commitment",
        )?;
        enforce_equal_point(
            key_b.0.commit(),
            keyset_commit_odd.0,
            "NullifierDerivationStep: odd half-key poly does not match its commitment",
        )?;

        // Query parameters derived from `mk` forwarded on the keyset header.
        // `salts` fix the per-poly boundaries; `shift`/`ratios` are forwarded
        // for the downstream query and lift.
        let salts = mk.query_salts();
        let (ratios, shift) = mk.query_weights();

        // Round-0 boundary key `k_0 = K(1) = A(1)` (the even-coset selector is 1
        // and the odd-coset selector is 0 at `x = 1`), shared across all polys.
        let first_key = key_a.0.eval(Fp::ONE);
        ctx.enforce_poly_query(keyset_commit_even.0, Fp::ONE, first_key)?;

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
            // the full 256-key interleaved schedule reconstructed inline from
            // the two committed half-key polys.
            enforce_committed_offset_recurrence::<
                { EMITTER_ROUND_SPLITS },
                { ExpandedKey::EK_LENGTH },
            >(
                ctx,
                &poly.0,
                &poly_quotients.round,
                &CONSTANT_SCHEDULE,
                &key_a.0,
                &key_b.0,
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
