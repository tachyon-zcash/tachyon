//! GGM nullifier-derivation chain: prove a contiguous range of a note's
//! per-epoch nullifiers `GGM(mk, ·)`.
//!
//! The chain descends the tree by whole-node trace expansions: one step
//! proves one `GGM_TREE_ARITY × ROUNDS` keyed-cipher trace (exactly one
//! committed polynomial), whose whitened final column is the chunk-selected
//! child's key schedule — or, at the deepest level, the node's 64-epoch
//! leaf. Wallet-only; every published-range header carries `cm`
//! for its consumers.

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::array;

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Header, Index, Polynomial, Step, Suffix,
    constraint::{enforce_equal_point, enforce_zero},
};
use zcash_mimc::spec::tachyon::TachyonP5R128;

use crate::{
    constants::{MK_PART_LEN, MK_PARTS, NF_EXPANSION_KEY_PREFIX, POLY_LEN_MAX},
    digest::poseidon,
    keys::{GGM_CHUNK_SIZE, GGM_TREE_ARITY, GGM_TREE_DEPTH, NoteMasterKey, ProofAuthorizingKey},
    note::{self, Note},
    primitives::{
        CONSTANT_SCHEDULE, EpochIndex, NfLeafPoly, NfPrefixCommit, NfPrefixPoly, NfPrefixTracePoly,
        NfSeqCommit, NfSeqPoly,
    },
    relations::{
        enforce::{
            enforce_committed_offset_recurrence, enforce_evaluation_sum,
            enforce_first_column_values, enforce_row_recurrence, enforce_shifted_combination,
            enforce_strided_column,
        },
        quotient::{EXPANSION_ROUND_SPLITS, RoundBoundaryQuotients},
        subgroup_generator,
    },
};

/// One `mk` part and its originating note, emitted by [`NfMasterSeed`].
///
/// Carries this part's `MK_PART_LEN` round keys, its part index, and the whole
/// note (kept collected so the deferred `cm` can be computed downstream).
/// Wallet-only: the per-note secrets ride a header that never leaves the
/// wallet's own proof tree and is never published.
#[derive(Clone, Debug)]
pub struct NfMasterHeader;

impl Header for NfMasterHeader {
    /// `(mk_part, part, note)`.
    type Data = ([Fp; MK_PART_LEN], Fp, Note);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (mk_part, part, note) = *data;
        let mut scalars = Vec::with_capacity(MK_PART_LEN + 5);
        scalars.extend_from_slice(&mk_part);
        scalars.push(part);
        scalars.push(note.pk.0);
        scalars.push(Fp::from(u64::from(note.value)));
        scalars.push(Fp::from(note.psi));
        scalars.push(Fp::from(note.rcm));
        (scalars, Vec::new(), Vec::new(), Vec::new())
    }
}

/// In-progress GGM walk position `(node, depth, index, note)`. Wallet-only.
///
/// The committed key schedule of the current tree `node`, levels descended
/// `depth`, the node `index` at that depth, and the whole note (kept
/// collected so the deferred `cm` can be computed at the leaf).
#[derive(Clone, Debug)]
pub struct NfPrefixHeader;

impl Header for NfPrefixHeader {
    /// `(node_commit, depth, index, note)`.
    type Data = (NfPrefixCommit, u8, EpochIndex, Note);

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (node_commit, depth, index, note) = *data;
        (
            vec![
                Fp::from(u64::from(depth)),
                Fp::from(u64::from(index.0)),
                note.pk.0,
                Fp::from(u64::from(note.value)),
                Fp::from(note.psi),
                Fp::from(note.rcm),
            ],
            Vec::new(),
            Vec::new(),
            vec![node_commit.0],
        )
    }
}

/// A certified, coverage-queryable range of derived nullifiers (wallet-only).
///
/// `(cm, epoch_start, epoch_end, seq_commit)`: covers epochs `[epoch_start,
/// epoch_end)`; `seq_commit` is the coeff-form, sentinel-terminated sequence
/// `q` with `coeff[e - epoch_start] = nf_e` (`N_e = GGM(mk, e)`), sentinel
/// (see [`NfSeqPoly`](crate::primitives::NfSeqPoly)) so the commitment is never
/// the identity point. `cm` binds the range to the real note. Consumers read
/// any single covered nullifier or a covered sub-range by *coverage* (never
/// alignment); adjacent derivations fuse by shift-concat into a wider one.
#[derive(Clone, Debug)]
pub struct NullifierDerivation;

impl Header for NullifierDerivation {
    /// `(cm, epoch_start, epoch_end, seq_commit)`.
    type Data = (note::Commitment, EpochIndex, EpochIndex, NfSeqCommit);

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, epoch_start, epoch_end, seq_commit) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(u64::from(epoch_start.0)),
                Fp::from(u64::from(epoch_end.0)),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(seq_commit)],
        )
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
///
/// # Gate budget
///
/// Rule-of-thumb ledger against the 2048-gate step ceiling (Poseidon
/// permutation ≈ 1/7):
///
/// | item | gates |
/// |---|---|
/// | payment-key sponge (one permutation) | ~293 |
/// | master-part sponge (absorb 4, squeeze 16: five permutations) | ~1465 |
/// | part range check | ~2 |
/// | total | ~1760 |
#[derive(Debug)]
pub struct NfMasterSeed;

impl Step for NfMasterSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = NfMasterHeader;
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
            "NfMasterSeed: pak not related to note",
        )?;

        let part_fp = Fp::from(part);
        let part_in_range = (0..MK_PARTS).fold(Fp::ONE, |product, index| {
            #[expect(clippy::as_conversions, reason = "part index fits u64")]
            let root = Fp::from(index as u64);
            product * (part_fp - root)
        });
        enforce_zero(part_in_range, "NfMasterSeed: part out of range 0..MK_PARTS")?;

        let mk_part = pak.nk.derive_note_part(&note.psi, part);

        Ok(((mk_part, part_fp, note), ()))
    }
}

/// Expand the root: prove child `chunk`'s key schedule out of `mk` in one
/// trace-based step.
///
/// The `GGM_TREE_ARITY` keyed-cipher outputs of the chunk's input window,
/// committed as the eval-form schedule polynomial `K`
/// (`K(ζ^r) = E_mk(s + δ·(64·chunk + r)) + w` over the order-`GGM_TREE_ARITY`
/// subgroup `⟨ζ⟩`). The expansion-input parameters `(s, δ, w)` are derived
/// in-step from the reconciled `mk` ([`NoteMasterKey::expansion_params`]), so
/// the cipher inputs are note secrets and the children stay a deterministic
/// function of `mk` (a freely witnessed salt would let one note carry many
/// child sets, hence many nullifier sequences).
///
/// The witness is the prover-built trace `T`, the round quotient
/// ([`EXPANSION_ROUND_SPLITS`] splits), the boundary quotient, the child
/// schedule poly `K`, the decimation quotient, and the free 6-bit `chunk`,
/// pinned by its accumulation into the header index; the body is pure
/// orchestration over three generic vanishing relations plus the chunk check.
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
/// | boundary targets (`GGM_TREE_ARITY` rows × pow5) | ~192 |
/// | `enforce_first_column_values` (64-node interpolation) | ~200 |
/// | `enforce_row_recurrence` (128-node interpolation) | ~400 |
/// | `enforce_strided_column`, chunk decomposition, reconciliation | ~50 |
/// | total | ~1135 |
///
/// The parameter sponge must stay single-permutation: the domain tag plus the
/// [`NF_EXPANSION_KEY_PREFIX`]-element schedule prefix absorbs exactly `RATE`
/// elements and squeezes three; a second permutation does not fit.
///
/// [`NF_EXPANSION_KEY_PREFIX`]: crate::constants::NF_EXPANSION_KEY_PREFIX
#[derive(Debug)]
pub struct NfMasterStep;

impl Step for NfMasterStep {
    type Aux<'source> = ();
    type Left = NfMasterHeader;
    type Output = NfPrefixHeader;
    type Right = NfMasterHeader;
    /// `(trace, quotients, child_poly, decimation_quotient, chunk)`.
    type Witness<'source> = (
        NfPrefixTracePoly,
        RoundBoundaryQuotients<EXPANSION_ROUND_SPLITS>,
        NfPrefixPoly,
        Polynomial, // decimation quotient binding K to T's final column
        u8,         // chunk ∈ 0..GGM_TREE_ARITY
    );

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (trace, quotients, child_poly, decimation_quotient, chunk): Self::Witness<'source>,
        left: <Self::Left as Header>::Data,
        right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Native mock stand-in for the chunk range check: in real ragu the
        // chunk is a `GGM_CHUNK_SIZE`-bit decomposition (booleanity plus
        // recomposition), so `chunk ∈ 0..GGM_TREE_ARITY` holds by
        // construction.
        if usize::from(chunk) >= GGM_TREE_ARITY {
            return Err(ragu::Error::InvalidWitness(
                "NfMasterStep: chunk exceeds GGM arity".into(),
            ));
        }

        // Assemble the 32-key `mk` from the two `mk` parts (pinned to indices
        // 0 and 1) of the same note, concatenated. The note is reconciled
        // across both seeds and forwarded so the deferred `cm` binds at the
        // leaf.
        let (mk, note) = {
            let (left_mk_part, left_index, left_note) = left;
            let (right_mk_part, right_index, right_note) = right;
            enforce_zero(left_index, "NfMasterStep: left input is not mk part 0")?;
            enforce_zero(
                right_index - Fp::ONE,
                "NfMasterStep: right input is not mk part 1",
            )?;
            enforce_zero(
                left_note.pk.0 - right_note.pk.0,
                "NfMasterStep: note pk mismatch across mk parts",
            )?;
            enforce_zero(
                Fp::from(u64::from(left_note.value)) - Fp::from(u64::from(right_note.value)),
                "NfMasterStep: note value mismatch across mk parts",
            )?;
            enforce_zero(
                Fp::from(left_note.psi) - Fp::from(right_note.psi),
                "NfMasterStep: note psi mismatch across mk parts",
            )?;
            enforce_zero(
                Fp::from(left_note.rcm) - Fp::from(right_note.rcm),
                "NfMasterStep: note rcm mismatch across mk parts",
            )?;
            (
                NoteMasterKey::from_parts(&[left_mk_part, right_mk_part]),
                left_note,
            )
        };

        // The expansion-input parameters `(s, δ, w)`: one domain-separated
        // Poseidon permutation over the mk schedule prefix, computed in-step
        // so the children stay a deterministic function of the header-bound
        // parts (a witnessed tuple would be the free-witness trap).
        let params = mk.expansion_params();

        // Round 0, the input step. The cipher input for row `row` of chunk
        // `chunk` is the secret affine `s + δ·(base + row)`. The input is not
        // stored in the trace, so round 0 is applied here rather than by the
        // recurrence: each row's first cell is pinned to round 0's output
        // `(s + δ·(base + row) + k_0)^5` (with `c_0 = 0`). The targets are
        // S-boxed here so the relation stays a generic first-column pinning;
        // the prover's boundary quotient pins the same values.
        let base = Fp::from(u64::from(chunk) << GGM_CHUNK_SIZE);
        let origin = params.input(base) + mk.round_key(0);
        let boundary: [Fp; GGM_TREE_ARITY] = array::from_fn(|row| {
            #[expect(clippy::as_conversions, reason = "row index conversion")]
            let cipher_in = origin + params.stride * Fp::from(row as u64);
            cipher_in.square().square() * cipher_in
        });
        enforce_first_column_values(ctx, &trace.0, &quotients.boundary, Fp::ZERO, &boundary)?;

        // Rounds 1..: advance each row through the rest of the cipher. The
        // recurrence enforces every in-row step `T[cell + 1] = (T[cell] +
        // offsets[cell])^5` as one round; `offsets[cell]` is that round's
        // additive `key + constant`, the same per-column layout for all rows,
        // built from the raw cyclic mk keys the headers carry. Cell `cell`
        // holds round `cell`'s output, so the step out of it is round
        // `cell + 1` (round 0 is pinned above, not a step). The last cell's
        // successor is the next row, so its offset is unused: `get(ROUNDS)`
        // is `None` -> `Fp::ZERO`, and the recurrence masks that row-wrap
        // step.
        let offsets: [Fp; TachyonP5R128::ROUNDS] = array::from_fn(|cell| {
            TachyonP5R128::CONSTANTS
                .get(cell + 1)
                .map_or(Fp::ZERO, |round_const| mk.round_key(cell + 1) + round_const)
        });
        enforce_row_recurrence(
            ctx,
            &trace.0,
            &quotients.round,
            &offsets,
            TachyonP5R128::POW,
        )?;

        // Bind the eval-form child schedule `K` to the trace's final column.
        // On the order-`GGM_TREE_ARITY` subgroup `⟨ζ⟩` (`ζ = ω^ROUNDS`),
        // `K(ζ^r) = (row-r final cell) + w = E_mk(s + δ·(base + r))`, so `K`
        // commits this expansion's outputs. `σ = ω^{ROUNDS-1}` is the
        // final-column stride within a row; the whitening key is the
        // dedicated `w`, not a reused round key.
        #[expect(clippy::as_conversions, reason = "constant column index")]
        let column_stride =
            subgroup_generator::<POLY_LEN_MAX>().pow_vartime([(TachyonP5R128::ROUNDS - 1) as u64]);
        enforce_strided_column::<{ GGM_TREE_ARITY }>(
            ctx,
            &trace.0,
            &child_poly.0,
            &decimation_quotient,
            column_stride,
            params.whitening,
        )?;

        let child_commit = NfPrefixCommit(child_poly.0.commit());
        Ok(((child_commit, 1, EpochIndex(u32::from(chunk)), note), ()))
    }
}

/// Expand an internal node: prove child `chunk`'s key schedule out of a
/// commitment-carried node schedule in one trace-based step.
///
/// The input node's schedule is witnessed as its eval-form polynomial and
/// bound to the header commitment by commit-equality BEFORE use — its prefix
/// openings feed the parameter sponge and its commitment keys the recurrence
/// challenge, so an unbound witness here would be the free-witness trap (one
/// node, many child sets). Where [`NfMasterStep`] interpolates its raw
/// header-carried keys into public per-column offsets, the schedule here
/// stays behind its commitment: the recurrence offset is the committed
/// constant schedule plus the cyclic key interpolant, each read by a single
/// opening ([`enforce_committed_offset_recurrence`]), never materialized as
/// scalars.
///
/// # Gate budget
///
/// Rule-of-thumb ledger against the 2048-gate step ceiling (constant
/// multiplications and additions free, witnessed inverse ≈ 2, Poseidon
/// permutation ≈ 1/7):
///
/// | item | gates |
/// |---|---|
/// | schedule bind and prefix openings (one equality, three claims) | ~10 |
/// | expansion-parameter sponge (one permutation) | ~293 |
/// | boundary targets (`GGM_TREE_ARITY` rows × pow5) | ~192 |
/// | `enforce_first_column_values` (64-node interpolation) | ~200 |
/// | `enforce_committed_offset_recurrence` (openings, no interpolation) | ~40 |
/// | `enforce_strided_column`, chunk decomposition, depth guard | ~50 |
/// | total | ~785 |
#[derive(Debug)]
pub struct NfPrefixStep;

impl Step for NfPrefixStep {
    type Aux<'source> = ();
    type Left = NfPrefixHeader;
    type Output = NfPrefixHeader;
    type Right = ();
    /// `(node_poly, trace, quotients, child_poly, decimation_quotient, chunk)`.
    type Witness<'source> = (
        NfPrefixPoly, // the input node's schedule, bound to the header commit
        NfPrefixTracePoly,
        RoundBoundaryQuotients<EXPANSION_ROUND_SPLITS>,
        NfPrefixPoly,
        Polynomial, // decimation quotient binding K to T's final column
        u8,         // chunk ∈ 0..GGM_TREE_ARITY
    );

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (node_poly, trace, quotients, child_poly, decimation_quotient, chunk): Self::Witness<
            'source,
        >,
        (node_commit, depth, index, note): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if depth == 0 || depth >= GGM_TREE_DEPTH - 1 {
            return Err(ragu::Error::InvalidWitness(
                "NfPrefixStep: input is not an internal schedule level".into(),
            ));
        }
        // Native mock stand-in for the chunk range check: in real ragu the
        // chunk is a `GGM_CHUNK_SIZE`-bit decomposition (booleanity plus
        // recomposition), so `chunk ∈ 0..GGM_TREE_ARITY` holds by
        // construction.
        if usize::from(chunk) >= GGM_TREE_ARITY {
            return Err(ragu::Error::InvalidWitness(
                "NfPrefixStep: chunk exceeds GGM arity".into(),
            ));
        }

        // Bind the witnessed schedule to the header commitment BEFORE any
        // use: its openings feed the parameter sponge and its commitment
        // keys the recurrence challenge.
        enforce_equal_point(
            node_poly.0.commit(),
            node_commit.0,
            "NfPrefixStep: witnessed schedule does not match the node commitment",
        )?;

        // The expansion-input parameters `(s, δ, w)`: one domain-separated
        // Poseidon permutation over the schedule prefix, read off the bound
        // polynomial by one opening claim per prefix key (`k_r = K(ζ^r)`),
        // computed in-step so the children stay a deterministic function of
        // the certified schedule.
        let zeta = subgroup_generator::<{ GGM_TREE_ARITY }>();
        let mut prefix = [Fp::ZERO; NF_EXPANSION_KEY_PREFIX];
        let mut point = Fp::ONE;
        for key in &mut prefix {
            *key = node_poly.0.eval(point);
            ctx.enforce_poly_query(node_commit.0, point, *key)?;
            point *= zeta;
        }
        let (salt, stride, whitening) = poseidon::nf_expansion_params(prefix);

        // Round 0, the input step: each row's first cell is pinned to round
        // 0's output `(s + δ·(base + row) + k_0)^5` (with `c_0 = 0`); `k_0`
        // is the schedule's first key, the `ζ^0` prefix opening.
        let base = Fp::from(u64::from(chunk) << GGM_CHUNK_SIZE);
        let [first_key, ..] = prefix;
        let origin = salt + stride * base + first_key;
        let boundary: [Fp; GGM_TREE_ARITY] = array::from_fn(|row| {
            #[expect(clippy::as_conversions, reason = "row index conversion")]
            let cipher_in = origin + stride * Fp::from(row as u64);
            cipher_in.square().square() * cipher_in
        });
        enforce_first_column_values(ctx, &trace.0, &quotients.boundary, Fp::ZERO, &boundary)?;

        // Rounds 1..: the committed-offset recurrence. The per-column offset
        // is the public constant schedule plus the node's cyclic key
        // interpolant, each read by a single opening of a committed operand
        // — the schedule is never materialized as scalars.
        enforce_committed_offset_recurrence::<
            { TachyonP5R128::ROUNDS },
            { EXPANSION_ROUND_SPLITS },
            { GGM_TREE_ARITY },
            1,
        >(
            ctx,
            &trace.0,
            &quotients.round,
            &CONSTANT_SCHEDULE,
            &[&node_poly.0],
            TachyonP5R128::POW,
        )?;

        // Bind the eval-form child schedule `K` to the trace's final column.
        // On the order-`GGM_TREE_ARITY` subgroup `⟨ζ⟩` (`ζ = ω^ROUNDS`),
        // `K(ζ^r) = (row-r final cell) + w`, so `K` commits this expansion's
        // outputs. `σ = ω^{ROUNDS-1}` is the final-column stride within a
        // row; the whitening key is the dedicated `w`, not a reused round
        // key.
        #[expect(clippy::as_conversions, reason = "constant column index")]
        let column_stride =
            subgroup_generator::<POLY_LEN_MAX>().pow_vartime([(TachyonP5R128::ROUNDS - 1) as u64]);
        enforce_strided_column::<{ GGM_TREE_ARITY }>(
            ctx,
            &trace.0,
            &child_poly.0,
            &decimation_quotient,
            column_stride,
            whitening,
        )?;

        let child_commit = NfPrefixCommit(child_poly.0.commit());
        let child_index = EpochIndex((index.0 << GGM_CHUNK_SIZE) | u32::from(chunk));
        Ok(((child_commit, depth + 1, child_index, note), ()))
    }
}

/// Expand a depth-2 node into its certified [`NullifierDerivation`].
///
/// The node's single base-0 expansion under the leaf domain
/// (`Tachyon-NfLeaf__` parameters) produces its `GGM_TREE_ARITY` whitened
/// outputs, which ARE the nullifiers for epochs `[base, base + GGM_TREE_ARITY)`
/// (`base = GGM_TREE_ARITY·index`). The eval-form trace decimates onto the
/// internal leaf polynomial `B` (`B(ζ^p) = nf_{base+p}`); `B` is then bound to
/// the coeff-form, sentinel-terminated sequence `q` (`coeff[p] = nf_{base+p}`)
/// homomorphically (a running-sum accumulator over `B`'s subgroup values, no
/// per-leaf read loop; see [`enforce_evaluation_sum`]), and only `q`'s
/// commitment is published as the coverage-queryable [`NullifierDerivation`].
/// The deferred `cm` binds the range to the real note.
///
/// # Gate budget
///
/// As [`NfPrefixStep`] (~785, no chunk), plus the note-commitment sponge
/// (~586), the leaf-sequence sponge (~586), and the homomorphic bind (one
/// accumulator plus a degree-0 quotient, ~8 openings across two challenges,
/// ~20): ~2000 total.
#[derive(Debug)]
pub struct NullifierDerivationStep;

impl Step for NullifierDerivationStep {
    type Aux<'source> = ();
    type Left = NfPrefixHeader;
    type Output = NullifierDerivation;
    type Right = ();
    /// `(node_poly, trace, quotients, decimation_quotient, leaf_poly, seq_poly,
    /// accumulator, evaluation_quotient)`.
    type Witness<'source> = (
        NfPrefixPoly, // the input node's schedule, bound to the header commit
        NfPrefixTracePoly,
        RoundBoundaryQuotients<EXPANSION_ROUND_SPLITS>,
        Polynomial, // decimation quotient binding B to T's final column
        NfLeafPoly, // eval-form leaf values `B`, internal to this step
        NfSeqPoly,  // coeff-form sentinel sequence `q`, published as `seq_commit`
        Polynomial, // running-sum accumulator `A` binding `q` to `B`
        Polynomial, // degree-0 quotient of the accumulator's masked recurrence
    );

    const INDEX: Index = Index::new(3);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (
            node_poly,
            trace,
            quotients,
            decimation_quotient,
            leaf_poly,
            seq_poly,
            accumulator,
            evaluation_quotient,
        ): Self::Witness<'source>,
        (node_commit, depth, index, note): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(u64::from(depth)) - Fp::from(u64::from(GGM_TREE_DEPTH - 1)),
            "NullifierDerivationStep: input is not at the deepest schedule level",
        )?;

        // Bind the witnessed schedule to the header commitment BEFORE any
        // use: its openings feed the parameter sponge and its commitment
        // keys the recurrence challenge.
        enforce_equal_point(
            node_poly.0.commit(),
            node_commit.0,
            "NullifierDerivationStep: witnessed schedule does not match the node commitment",
        )?;

        // The keyed-cipher parameters `(s, δ, w)`: one domain-separated
        // Poseidon permutation over the schedule prefix, read off the bound
        // polynomial by one opening claim per prefix key (`k_r = K(ζ^r)`).
        // The leaf domain separates the leaf from any child schedule: a
        // depth-2 node's expansion can never read as key material.
        let zeta = subgroup_generator::<{ GGM_TREE_ARITY }>();
        let mut prefix = [Fp::ZERO; NF_EXPANSION_KEY_PREFIX];
        let mut point = Fp::ONE;
        for key in &mut prefix {
            *key = node_poly.0.eval(point);
            ctx.enforce_poly_query(node_commit.0, point, *key)?;
            point *= zeta;
        }
        let (salt, stride, whitening) = poseidon::nf_leaf_params(prefix);

        // Round 0, the input step: each row's first cell is pinned to round
        // 0's output `(s + δ·row + k_0)^5` (base 0: the leaf is the node's
        // own single expansion, not a chunk window); `k_0` is the schedule's
        // first key, the `ζ^0` prefix opening.
        let [first_key, ..] = prefix;
        let origin = salt + first_key;
        let boundary: [Fp; GGM_TREE_ARITY] = array::from_fn(|row| {
            #[expect(clippy::as_conversions, reason = "row index conversion")]
            let cipher_in = origin + stride * Fp::from(row as u64);
            cipher_in.square().square() * cipher_in
        });
        enforce_first_column_values(ctx, &trace.0, &quotients.boundary, Fp::ZERO, &boundary)?;

        // Rounds 1..: the committed-offset recurrence. The per-column offset
        // is the public constant schedule plus the node's cyclic key
        // interpolant, each read by a single opening of a committed operand
        // — the schedule is never materialized as scalars.
        enforce_committed_offset_recurrence::<
            { TachyonP5R128::ROUNDS },
            { EXPANSION_ROUND_SPLITS },
            { GGM_TREE_ARITY },
            1,
        >(
            ctx,
            &trace.0,
            &quotients.round,
            &CONSTANT_SCHEDULE,
            &[&node_poly.0],
            TachyonP5R128::POW,
        )?;

        // Bind the eval-form leaf `B` to the trace's final column. On the
        // order-`GGM_TREE_ARITY` subgroup `⟨ζ⟩` (`ζ = ω^ROUNDS`),
        // `B(ζ^p) = (row-p final cell) + w = nf_{base+p}`, so `B` commits
        // exactly this node's 64 epoch nullifiers. `σ = ω^{ROUNDS-1}` is the
        // final-column stride within a row; the whitening key is the
        // dedicated `w`, not a reused round key.
        #[expect(clippy::as_conversions, reason = "constant column index")]
        let column_stride =
            subgroup_generator::<POLY_LEN_MAX>().pow_vartime([(TachyonP5R128::ROUNDS - 1) as u64]);
        enforce_strided_column::<{ GGM_TREE_ARITY }>(
            ctx,
            &trace.0,
            &leaf_poly.0,
            &decimation_quotient,
            column_stride,
            whitening,
        )?;

        let cm = note.commitment();
        let base = EpochIndex(index.0 << GGM_CHUNK_SIZE);

        // Bind the coeff-form sentinel sequence `q` to the bound eval-form leaf
        // `B` homomorphically. `β` is a Poseidon challenge over both
        // commitments (so `q` and `B` are fixed before it, and the native
        // builder reproduces it to construct the accumulator). The running-sum
        // accumulator `A` yields the β-weighted total `Σ_p nf_p·β^p` of `B`'s
        // leaf evaluations; discharging `q`'s sentinel, `q(β) − β^ARITY` must
        // equal that total, which at a random `β` forces every coefficient of
        // `q` to be the genuine nullifier (Schwartz-Zippel). No per-leaf read
        // loop.
        let seq_commit = seq_poly.commit();
        let beta = poseidon::leaf_sequence_challenge(leaf_poly.0.commit(), Eq::from(seq_commit));
        let total = enforce_evaluation_sum::<{ GGM_TREE_ARITY }>(
            ctx,
            &leaf_poly.0,
            &accumulator,
            &evaluation_quotient,
            beta,
        )?;

        let sequence = Polynomial::from(seq_poly);
        let sequence_at_beta = sequence.eval(beta);
        #[expect(clippy::as_conversions, reason = "leaf width fits u64")]
        let sentinel = beta.pow_vartime([GGM_TREE_ARITY as u64]);
        if sequence_at_beta - sentinel != total {
            return Err(ragu::Error::InvalidWitness(
                "NullifierDerivationStep: sequence does not match the leaf".into(),
            ));
        }
        ctx.enforce_poly_query(Eq::from(seq_commit), beta, sequence_at_beta)?;

        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "leaf width fits u32"
        )]
        let end = EpochIndex(base.0 + GGM_TREE_ARITY as u32);
        Ok(((cm, base, end, seq_commit), ()))
    }
}

/// Merge two adjacent derived ranges into one (`left ++ right`).
///
/// Requires the same `cm` and contiguity (`right.start == left.end`). Witnesses
/// the two range polynomials and their concatenation, binds each by
/// commit-equality, and proves the concat at `offset = left.end - left.start`
/// via the faithful opening relation.
///
/// # Gate budget
///
/// Rule-of-thumb ledger against the 2048-gate step ceiling (commitments and
/// challenge derivation free):
///
/// | item | gates |
/// |---|---|
/// | commit-equality binds (three point equalities) | ~6 |
/// | concat faithful opening (three queries at a challenge) | ~24 |
/// | boundary and contiguity equalities | ~0 |
/// | total | ~30 |
#[derive(Debug)]
pub struct NullifierFuse;

impl Step for NullifierFuse {
    type Aux<'source> = ();
    type Left = NullifierDerivation;
    type Output = NullifierDerivation;
    type Right = NullifierDerivation;
    /// `(left_seq, merged_seq, right_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(4);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_seq, merged_seq, right_seq): Self::Witness<'source>,
        (left_cm, left_epoch_start, left_epoch_end, left_seq_commit): <Self::Left as Header>::Data,
        (right_cm, right_epoch_start, right_epoch_end, right_seq_commit): <Self::Right as Header>::Data,
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
            Eq::from(left_seq_commit),
            "NullifierFuse: left polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(right_seq.commit()),
            Eq::from(right_seq_commit),
            "NullifierFuse: right polynomial does not match header",
        )?;
        let merged_seq_commit = merged_seq.commit();
        let offset =
            usize::try_from(left_epoch_end.0 - left_epoch_start.0).map_err(|_too_long| {
                ragu::Error::InvalidWitness("NullifierFuse: range length exceeds usize".into())
            })?;
        // Sentinel concat: a sequence of `k` members is `Σ n_i·X^i + X^k`, so
        // `merged = left ++ right` is the shifted combination
        // `merged(X) = left(X) + X^offset·right(X) - X^offset`. The `-X^offset`
        // monomial cancels left's sentinel, right's first leaf lands in the
        // vacated slot, and right's own sentinel re-terminates `merged`. The
        // monomial's constant coefficient is challenge-independent, and `offset`
        // is left's header-fixed span. Any two contiguous derivations fuse this
        // way, up to the poly-size budget.
        enforce_shifted_combination(
            ctx,
            [
                (&Polynomial::from(left_seq), 0),
                (&Polynomial::from(right_seq), offset),
            ],
            [(-Fp::ONE, offset)],
            &Polynomial::from(merged_seq),
        )
        .map_err(|_relation_err| {
            ragu::Error::InvalidWitness(
                "NullifierFuse: merged is not the concat of the halves".into(),
            )
        })?;
        Ok((
            (
                left_cm,
                left_epoch_start,
                right_epoch_end,
                merged_seq_commit,
            ),
            (),
        ))
    }
}
