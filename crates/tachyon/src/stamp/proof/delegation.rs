//! MiMC key expansion and nullifier derivation. Wallet-only; every header
//! carries `cm` for its consumers.
//!
//! [`NfMasterExpand`] proves a note's keyset expansion -- the
//! `ExpandedKey::EK_LENGTH` keyed-cipher outputs `E_mk(mk_s + i)` -- in a
//! single trace-based step, committing them on the [`NfExpandedKeyset`] header.
//! [`NullifierDerivationStep`] then certifies the note's derivation polynomials
//! against that keyset.

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
    CONSTANT_SCHEDULE_COMMIT, ExpandedKeyCommit, NfEmitterCommit, NfEmitterPoly, NfEmittersDigest,
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
            EMITTER_ROUND_SPLITS, EXPANSION_ROUND_SPLITS, QuerySalts, QueryShift, WeightRatios,
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

/// Prove a note's keyset expansion in one trace-based step.
///
/// The `ExpandedKey::EK_LENGTH` keyed-cipher outputs `E_mk(mk_s + i)`, `i =
/// 0..ExpandedKey::EK_LENGTH`, committed as the eval-form key polynomial `K`
/// (`K(ζ^r) = E_mk(mk_s + r)` over the order-`ExpandedKey::EK_LENGTH` subgroup
/// `⟨ζ⟩`) on the [`NfExpandedKeyset`] header.
///
/// The witness is the prover-built trace `T`, the round quotient
/// ([`EXPANSION_ROUND_SPLITS`] splits), the boundary quotient, the key poly
/// `K`, and the decimation quotient `Q`. The expansion runs from index `0`, so
/// the cipher input for row `i` is `mk_s + i`; the body is pure orchestration
/// over three generic vanishing relations.
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
    /// `(trace, Q_round splits, Q_boundary, key poly K, decimation Q)`.
    type Witness<'source> = (
        ExpKeySpectrumPoly,                   // expansion trace T
        [Polynomial; EXPANSION_ROUND_SPLITS], // round quotient splits
        Polynomial,                           // boundary quotient
        Polynomial,                           // eval-form key poly K
        Polynomial,                           // decimation quotient Q
    );

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (expansion_trace, round_quotient, boundary_quotient, key_poly, decimation_quotient): Self::Witness<
            'source,
        >,
        left: <Self::Left as Header>::Data,
        right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let (cm, mk) = {
            let (left_cm, left_parts) = left;
            let (right_cm, right_parts) = right;

            let all_parts: [Fp; NoteMasterKey::MK_LENGTH] = left_parts
                .into_iter()
                .zip(right_parts.into_iter())
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
            let base = Fp::ZERO; // salt used in key expansion
            let first_key = mk.round_key(0);
            let boundary: [Fp; ExpandedKey::EK_LENGTH] = array::from_fn(|row| {
                #[expect(clippy::as_conversions, reason = "row index conversion")]
                let cipher_in = base + Fp::from(row as u64) + first_key;
                cipher_in.square().square() * cipher_in
            });
            enforce_first_column_values(
                ctx,
                &expansion_trace.0,
                &boundary_quotient,
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
                &round_quotient,
                &schedule,
                TachyonP5R64::POW,
            )?;
        }

        // Bind the eval-form key poly `K` to the trace's final column. On the
        // order-`ExpandedKey::EK_LENGTH` subgroup `⟨ζ⟩` (`ζ = ω^{TRACE_COLUMNS}`),
        // `K(ζ^r) = (row-r final cell) + whitening = E_mk(mk_s + r)`, so `K`
        // commits the `ExpandedKey::EK_LENGTH` expansion outputs. `σ =
        // ω^{TRACE_COLUMNS-1}` is the final-column stride within a row.
        #[expect(clippy::as_conversions, reason = "constant column index")]
        let stride =
            subgroup_generator::<POLY_LEN_MAX>().pow_vartime([(TachyonP5R64::ROUNDS - 1) as u64]);
        let whitening = mk.round_key(TachyonP5R64::ROUNDS);
        enforce_strided_column::<{ ExpandedKey::EK_LENGTH }>(
            ctx,
            &expansion_trace.0,
            &key_poly,
            &decimation_quotient,
            stride,
            whitening,
        )?;

        // Derive the note's query parameters from the bound `mk`
        let salts = mk.query_salts();
        let (ratios, shift) = mk.query_weights();

        Ok((
            (
                ExpandedKeyCommit(key_poly.commit()),
                QuerySalts(salts),
                WeightRatios(ratios),
                QueryShift(shift),
                cm,
            ),
            (),
        ))
    }
}

/// The note's derivation keyset commitment, query parameters, and note
/// commitment `(keyset_commit, salts, ratios, shift, cm)`. Wallet-only.
///
/// Carries the [`ExpandedKeyCommit`] to the eval-form key polynomial `K` (the
/// `ExpandedKey::EK_LENGTH` keyed-cipher expansion outputs), proven by
/// [`NfMasterExpand`], plus the note's query parameters derived from `mk` by
/// the same step: the per-poly salts `mk_s^{(j)}`, weight bases `ρ_j`, and
/// shift `c`. The raw `mk` is not forwarded; `keyset_commit` already binds the
/// schedule, and the parameters are the only `mk`-derived values the consumer
/// needs. [`NullifierDerivationStep`] re-witnesses `K`, binds it to
/// `keyset_commit`, reads the keys through `K` openings, and reads the
/// parameters directly. The header is private to the wallet's own proof tree
/// and is never published.
#[derive(Clone, Debug)]
pub struct NfExpandedKeyset;

impl Header for NfExpandedKeyset {
    type Data = (
        ExpandedKeyCommit,
        QuerySalts,
        WeightRatios,
        QueryShift,
        NoteCommitment,
    );

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let (keyset_commit, salts, ratios, shift, cm) = *data;
        let mut out = Vec::with_capacity(32 + ((2 * NF_EMITTERS + 1) * 32) + 32);
        let commit_bytes: [u8; 32] = keyset_commit.0.to_affine().to_bytes();
        out.extend_from_slice(&commit_bytes);
        for salt in salts.0 {
            out.extend_from_slice(&salt.to_repr());
        }
        for ratio in ratios.0 {
            out.extend_from_slice(&ratio.to_repr());
        }
        out.extend_from_slice(&shift.0.to_repr());
        out.extend_from_slice(&Fp::from(cm).to_repr());
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
/// Witnesses the note's key polynomial `K`, the `N` polynomials `T_j`, their
/// round- and boundary-quotients, the public constant schedule `C`, and the
/// creation epoch `E_0`. It first binds `K` to the threaded
/// [`ExpandedKeyCommit`] by commit-equality, so every key it reads is the
/// proven 128-key schedule; the per-poly salts, weight bases `ρ_j`, and shift
/// `c` arrive on the keyset header, derived from the bound `mk` by
/// [`NfMasterExpand`].
///
/// Per poly, two relations certify `T_j` is the genuine keyed-cipher
/// interpolant: [`enforce_first_column_values`] pins
/// `T_j(1) = (mk_s^{(j)} + k_0)^5` (round 0 from the salt, `k_0 = K(1)`), and
/// [`enforce_committed_offset_recurrence`] pins the remaining rounds against
/// the committed `K` (offset key term `K(ζ·z^{|D|/κ})`) and the committed `C`.
/// Then it binds the commitments into one transcript challenge and emits the
/// derivation, forwarding `c`/`ρ_j` for the downstream query and lift.
///
/// `E_0` is a free witness here, carrying no claim until `SpendableInit` (its
/// sole gatekeeper) binds it to the creation anchor.
#[derive(Debug)]
pub struct NullifierDerivationStep;

impl Step for NullifierDerivationStep {
    type Aux<'source> = ();
    type Left = NfExpandedKeyset;
    type Output = NullifierDerivation;
    type Right = ();
    /// `(K, T_j, round_quotients_j, boundary_quotients_j, C, E_0)`.
    type Witness<'source> = (
        Polynomial,
        [NfEmitterPoly; NF_EMITTERS],
        [[Polynomial; EMITTER_ROUND_SPLITS]; NF_EMITTERS],
        [Polynomial; NF_EMITTERS],
        Polynomial,
        EpochIndex,
    );

    const INDEX: Index = Index::new(2);

    #[expect(
        clippy::indexing_slicing,
        reason = "poly index is bounded by the fixed-size witness arrays"
    )]
    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (key_poly, polys, round_quotients, boundary_quotients, constants, creation_epoch): Self::Witness<
            'source,
        >,
        (keyset_commit, salts, ratios, shift, cm): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Bind the witnessed key poly `K` to the threaded keyset commitment, so
        // every key read below is the proven 128-key schedule.
        let keyset_commitment = keyset_commit.0;
        enforce_equal_point(
            key_poly.commit(),
            keyset_commitment,
            "NullifierDerivationStep: key poly does not match the committed keyset",
        )?;

        // Query parameters, derived from the bound `mk` by `NfMasterExpand` and
        // threaded on the keyset header. `salts` fix the per-poly boundaries;
        // `shift`/`ratios` are forwarded for the downstream query and lift.

        // Round-0 boundary key `k_0 = K(1)`, shared across all polys.
        let first_key = key_poly.eval(Fp::ONE);
        ctx.enforce_poly_query(keyset_commitment, Fp::ONE, first_key)?;

        // Bind the witnessed constant schedule to the public commitment, so the
        // committed offset cannot use a forged `C`.
        enforce_equal_point(
            constants.commit(),
            *CONSTANT_SCHEDULE_COMMIT,
            "NullifierDerivationStep: constant schedule does not match the public commitment",
        )?;

        for (poly_index, ((poly, round_quotient), boundary_quotient)) in polys
            .iter()
            .zip(&round_quotients)
            .zip(&boundary_quotients)
            .enumerate()
        {
            // Boundary: round 0 from the salt, `T_j(1) = (mk_s^{(j)} + k_0)^5`.
            let alpha = salts.0[poly_index] + first_key;
            let boundary = alpha.square().square() * alpha;
            enforce_first_column_values::<1>(
                ctx,
                &poly.0,
                boundary_quotient,
                Fp::ZERO,
                &[boundary],
            )?;

            // Rounds 1..: the committed-offset quintic recurrence (x^5 S-box),
            // the full 128-key schedule read through one opening of `K`.
            enforce_committed_offset_recurrence::<
                { EMITTER_ROUND_SPLITS },
                { ExpandedKey::EK_LENGTH },
            >(ctx, &poly.0, round_quotient, &constants, &key_poly, 5)?;
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
