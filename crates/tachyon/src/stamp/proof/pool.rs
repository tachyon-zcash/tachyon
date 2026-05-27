//! Anchor-bound primitives over consensus state.
//!
//! Hosts the nf-free anchor segment ([`AnchorChain`]) used by
//! [`super::stamp::StampLift`] to advance a stamp's anchor, and the
//! multi-stamp / multi-epoch exclusion proof ([`Unspent`]) used by
//! [`super::spendable::SpendableLift`] to advance a spendable.
//!
//! An [`Unspent`] carries an `elapsed` polynomial: one coefficient per epoch
//! boundary its anchor span *crosses*, forward-chronological. Per-stamp seeds
//! cross nothing, so they emit the identity commitment with `elapsed_size = 0`
//! and record the checked nf as the in-progress tip `present_nf`; intra-epoch
//! fuses keep `elapsed`/`present_nf` unchanged; only the cross-epoch fuse
//! splices the completing tip into `elapsed` and advances `elapsed_size`. The
//! [`Unspent`] is unaware of any note, `M`, or `psi` — `elapsed` is just a
//! commitment to the nf sequence it claims happened, and `present_nf` the tip
//! it is still proving absent.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use ragu::{Commitment, Header, Index, Polynomial, Step, StepCtx, Suffix, enforce_poly_splice};

use crate::{
    note::Nullifier,
    primitives::{
        Anchor, EpochIndex, NfSeqCommit, NfSeqPoly, TachygramSetCommit, TachygramSetPoly,
    },
};

/// Anchor segment between two endpoints. Composable via [`AnchorFuse`].
///
/// Direction-agnostic: `start` and `end` are both anchors. Consumed only
/// by [`super::stamp::StampLift`] — extending a spendable's anchor must
/// instead go through [`Unspent`] so each step proves nf-exclusion.
///
/// Structurally intra-epoch because only intra-epoch [`Anchor::next_stamp`]
/// is invoked anywhere in the [`AnchorChain`] builders.
///
/// `start` at the seed steps ([`AnchorSeed`] / [`EmptyBlockSeed`]) has
/// PCD lineage rooted in an unbound `start: Anchor` witness, so a
/// standalone segment proves nothing about real coverage. Final binding
/// closes when [`super::stamp::StampLift`] consumes the segment and the
/// resulting stamp is accepted by consensus (anchor membership).
#[derive(Clone, Debug)]
pub struct AnchorChain;

impl Header for AnchorChain {
    /// `(start, end)`. `start` roots in an unbound witness at [`AnchorSeed`] or
    /// [`EmptyBlockSeed`] and flows to [`super::stamp::StampLift`] which must
    /// ultimately be checked by consensus. `end` is always computed in-circuit
    /// as `start.next_stamp(...)` or `start.next_empty()`.
    type Data = (Anchor, Anchor);

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Multi-stamp / multi-epoch exclusion proof carrying an `elapsed` polynomial
/// of per-crossing nullifiers plus an in-progress tip.
///
/// `elapsed` commits to one nullifier per epoch boundary the anchor span
/// crosses, forward-chronological; `elapsed_size` is the crossing count (=
/// `elapsed`'s slot count). A zero-crossing segment has the identity commitment
/// and `elapsed_size = 0`. `present_nf` is the in-progress (tip) epoch's
/// nullifier, *not* in `elapsed` — it is spliced in only when its epoch
/// completes at a crossing. The span may be partial at both ends: the first
/// crossed sub-range begins at `prev_anchor` (front-stitched to the lineage),
/// and the tail after the last crossing is the `present_nf` tip. `elapsed` and
/// `present_nf` (past, present) counterpose the spendable's `future`.
///
/// The [`Unspent`] never references any note, `M`, or `psi` — `elapsed` is just
/// a commitment to the sequence of nfs it threaded through non-membership
/// checks. Its relation to `M` is established at
/// [`super::spendable::SpendableLift`], which strips it as a prefix off the
/// spendable's `future`.
#[derive(Clone, Debug)]
pub struct Unspent;

impl Header for Unspent {
    /// `((elapsed, elapsed_size), prev_anchor, end_anchor, present_nf)`.
    /// `elapsed_size` is the number of epoch-boundary crossings in the span (=
    /// `elapsed`'s slot count); it pins the splice offset at
    /// [`UnspentEpochFuse`] and the shrink offset at
    /// [`super::spendable::SpendableLift`] without reading a polynomial
    /// length. `present_nf` is the tip nf, tied into the lineage at lift.
    type Data = ((NfSeqCommit, u32), Anchor, Anchor, Nullifier);

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 32 + 32 + 32);
        let elapsed_bytes: [u8; 32] = Commitment::from(data.0.0).into();
        out.extend_from_slice(&elapsed_bytes);
        out.extend_from_slice(&data.0.1.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out.extend_from_slice(&Fp::from(data.3).to_repr());
        out
    }
}

/// Single-stamp [`AnchorChain`] seed. Witness `(start, stamp_commit)`;
/// emit `(start, start.next_stamp(&stamp_commit))`.
#[derive(Debug)]
pub struct AnchorSeed;

impl Step for AnchorSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorChain;
    type Right = ();
    /// `(start, stamp_commit)`.
    type Witness<'source> = (Anchor, TachygramSetCommit);

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        (start, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let end = start.next_stamp(&stamp_commit);
        Ok(((start, end), ()))
    }
}

/// One-empty-block [`AnchorChain`] seed. Witness `(start,)`; emit
/// `(start, start.next_empty())`.
#[derive(Debug)]
pub struct EmptyBlockSeed;

impl Step for EmptyBlockSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorChain;
    type Right = ();
    /// `(start,)`.
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        (start,): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok(((start, start.next_empty()), ()))
    }
}

/// Compose two adjacent [`AnchorChain`] segments — `left.end == right.start`.
#[derive(Debug)]
pub struct AnchorFuse;

impl Step for AnchorFuse {
    type Aux<'source> = ();
    type Left = AnchorChain;
    type Output = AnchorChain;
    type Right = AnchorChain;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (left_start, left_end): <Self::Left as Header>::Data,
        (right_start, right_end): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if left_end != right_start {
            return Err(ragu::Error("AnchorFuse: segments not adjacent"));
        }
        Ok(((left_start, right_end), ()))
    }
}

/// Per-stamp exclusion seed: verify `nf ∉ stamp_tg_set` and absorb the
/// stamp's commit at `start`.
///
/// Crosses no epoch boundary: identity `elapsed`, `elapsed_size = 0`, and the
/// checked `nf` as the in-progress tip `present_nf`.
///
/// `present_nf` is the very value just checked absent, so per-stamp soundness
/// binds the tip nf to its non-membership check.
#[derive(Debug)]
pub struct UnspentSeed;

impl Step for UnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Unspent;
    type Right = ();
    /// `(start, tg_set, nf)`.
    type Witness<'source> = (Anchor, TachygramSetPoly, Nullifier);

    const INDEX: Index = Index::new(3);

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        (start, tg_set, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if tg_set.eval(Fp::from(nf)) == Fp::ZERO {
            return Err(ragu::Error("UnspentSeed: found nullifier in set"));
        }
        let stamp_commit = tg_set.commit();
        let end = start.next_stamp(&stamp_commit);
        // Crosses no boundary: empty `elapsed` (identity), `elapsed_size = 0`,
        // and the checked nf is the in-progress tip `present_nf`.
        Ok((((NfSeqCommit::identity(), 0), start, end, nf), ()))
    }
}

/// One-empty-block [`Unspent`] seed: emit a one-block segment that crosses no
/// epoch boundary (an empty block trivially excludes any nf, so no set check).
///
/// Identity `elapsed`, `elapsed_size = 0`, `present_nf = nf`. Same tip-binding
/// role as [`UnspentSeed`].
#[derive(Debug)]
pub struct EmptyBlockUnspentSeed;

impl Step for EmptyBlockUnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Unspent;
    type Right = ();
    /// `(start, nf)`.
    type Witness<'source> = (Anchor, Nullifier);

    const INDEX: Index = Index::new(4);

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        (start, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((
            ((NfSeqCommit::identity(), 0), start, start.next_empty(), nf),
            (),
        ))
    }
}

/// Extend an [`Unspent`] within its tip epoch (intra-epoch fuse, incl. tip
/// extension of a multi-epoch `left`).
///
/// The forwards half must cross no boundary (`right.elapsed_size == 0`, with
/// the matching empty `right.elapsed`), and both halves must share the
/// in-progress tip (`left.present_nf == right.present_nf`) at adjacent anchors
/// (`left.end == right.start`). The output keeps `left`'s
/// `elapsed`/`elapsed_size`/`present_nf` and only extends the anchor; no epoch
/// completes. `left` may be multi-epoch.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step for UnspentFuse {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = Unspent;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(5);

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        _witness: Self::Witness<'source>,
        ((left_elapsed, left_size), left_start, left_end, left_pnf): <Self::Left as Header>::Data,
        ((right_elapsed, right_size), right_start, right_end, right_pnf): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if right_size != 0 {
            return Err(ragu::Error(
                "UnspentFuse: forwards half must stay within one epoch",
            ));
        }
        if right_elapsed != NfSeqCommit::identity() {
            return Err(ragu::Error(
                "UnspentFuse: zero-crossing forwards half must have empty elapsed",
            ));
        }
        if left_pnf != right_pnf {
            return Err(ragu::Error(
                "UnspentFuse: halves must share the present nullifier",
            ));
        }
        if left_end != right_start {
            return Err(ragu::Error("UnspentFuse: left.end must equal right.start"));
        }
        Ok((
            ((left_elapsed, left_size), left_start, right_end, left_pnf),
            (),
        ))
    }
}

/// Cross-epoch [`Unspent`] composition (epoch advance + symmetric composition).
///
/// At the boundary `left.end.next_epoch(new_epoch) == right.start`, left's tip
/// epoch *completes* and is spliced between the two halves: `combined = left ++
/// [left.present_nf] ++ right`. The new tip is `right.present_nf`. This is the
/// only [`Unspent`] step that invokes [`Anchor::next_epoch`], the only one that
/// grows `elapsed`/`elapsed_size`, and the only one that changes `present_nf`.
///
/// Witness the new epoch index and the `left`/`right`/`combined` polynomials.
/// The bindings (`commit() == header.elapsed`) force the splice inputs to be
/// the polynomials the halves attested to; `present_nf` enters the splice as
/// the *left header's* scalar (not a witness), and `combined`'s commit is the
/// output `elapsed`.
///
/// The splice's soundness rests on `present_nf` being the left header's scalar:
/// it is serialized into the left PCD header hash (`Unspent::encode`) and so is
/// fixed by the recursive verification of the Left proof *before* this step's
/// splice challenge. The splice identity is linear in that scalar and would be
/// forgeable if it were a free witness, but a bound `present_nf` (together with
/// the committed `left`/`right`/`combined`) pins `combined` to the splice by
/// Schwartz-Zippel (see [`NfSeqPoly::enforce_splice`]).
#[derive(Debug)]
pub struct UnspentEpochFuse;

impl Step for UnspentEpochFuse {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = Unspent;
    type Right = Unspent;
    /// `(new_epoch, left_poly, right_poly, combined)`. `combined` is the
    /// prover-supplied splice, bound below by the opening relation.
    type Witness<'source> = (EpochIndex, NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(6);

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        (new_epoch, left_poly, right_poly, combined): Self::Witness<'source>,
        ((left_elapsed, left_size), left_start, left_end, left_pnf): <Self::Left as Header>::Data,
        ((right_elapsed, right_size), right_start, right_end, right_pnf): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if left_poly.commit() != left_elapsed {
            return Err(ragu::Error(
                "UnspentEpochFuse: left polynomial does not match header",
            ));
        }
        if right_poly.commit() != right_elapsed {
            return Err(ragu::Error(
                "UnspentEpochFuse: right polynomial does not match header",
            ));
        }
        if left_end.next_epoch(new_epoch) != right_start {
            return Err(ragu::Error(
                "UnspentEpochFuse: boundary anchor does not match right.prev_anchor",
            ));
        }
        // Splice the completing tip epoch in via the faithful relation: prove the
        // witnessed `combined` is `left ++ [left_pnf] ++ right` at `offset =
        // left_size` (the threaded crossing count, never a read length).
        // `left_pnf` enters as a scalar coefficient at degree `left_size`, so the
        // appended epoch lands in place and `combined`'s slot count equals
        // `left_size + 1 + right_size`.
        let combined_commit = combined.commit();
        let offset = usize::try_from(left_size).map_err(|_too_many_epochs| {
            ragu::Error("UnspentEpochFuse: crossing count exceeds usize")
        })?;
        enforce_poly_splice(
            ctx,
            &Polynomial::from(left_poly),
            Fp::from(left_pnf),
            &Polynomial::from(right_poly),
            offset,
            &Polynomial::from(combined),
        )
        .map_err(|_relation_err| {
            ragu::Error("UnspentEpochFuse: combined is not the splice of the halves")
        })?;
        Ok((
            (
                (combined_commit, left_size + 1 + right_size),
                left_start,
                right_end,
                right_pnf,
            ),
            (),
        ))
    }
}
