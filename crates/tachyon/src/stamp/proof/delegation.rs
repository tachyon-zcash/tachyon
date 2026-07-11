//! GGM nullifier-derivation chain: prove a contiguous range of a note's
//! per-epoch nullifiers `GGM(mk, ·)`. Wallet-only; every range header carries
//! `cm` for its consumers.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Polynomial, Step, Suffix,
    constraint::{enforce_equal_point, enforce_zero},
};

use crate::{
    digest::poseidon,
    keys::{GGM_TREE_ARITY, GGM_TREE_DEPTH, ProofAuthorizingKey},
    note::{self, Note, Nullifier},
    primitives::{EpochIndex, NfSeqCommit, NfSeqPoly},
    relations::enforce::enforce_shifted_combination,
};

/// In-progress GGM walk position `(cm, node, depth, index)`: the note
/// commitment `cm` carried for the final binding, the current tree `node`,
/// levels descended `depth`, and leaf `index`. Wallet-only.
#[derive(Clone, Debug)]
pub struct NfPrefixHeader;

impl Header for NfPrefixHeader {
    type Data = (note::Commitment, Fp, u8, EpochIndex);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm0, cm1): (Fp, Fp) = data.0.into();
        (
            vec![
                cm0,
                cm1,
                data.1,
                Fp::from(u64::from(data.2)),
                Fp::from(u64::from(data.3.0)),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// A proven contiguous range of derived nullifiers (wallet-only).
///
/// `(cm, (epoch_start, nf_start), nf_seq_commit, (epoch_end, nf_end))`: `cm`
/// lets every consumer bind the range to the real note; `nf_seq_commit` (the
/// nullifier sequence) sits between its boundary `(epoch, nullifier)` pairs and
/// commits to the half-open range `[nf_start, .., nf_end]` (`N_e = GGM(mk, e)`)
/// at degree 0, sentinel-terminated (see
/// [`NfSeqPoly`](crate::primitives::NfSeqPoly)) so the commitment is never the
/// identity point. `nf_start`/`nf_end` are the genuine boundary leaves, so a
/// consumer can bind them without opening the sequence.
#[derive(Clone, Debug)]
pub struct NullifierHeader;

impl Header for NullifierHeader {
    type Data = (
        note::Commitment,
        (EpochIndex, Nullifier),
        NfSeqCommit,
        (EpochIndex, Nullifier),
    );

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, (epoch_start, nf_start), nf_seq_commit, (epoch_end, nf_end)) = *data;
        let (cm0, cm1): (Fp, Fp) = cm.into();
        (
            vec![
                cm0,
                cm1,
                Fp::from(u64::from(epoch_start.0)),
                Fp::from(nf_start),
                Fp::from(u64::from(epoch_end.0)),
                Fp::from(nf_end),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(nf_seq_commit)],
        )
    }
}

/// Seed the GGM walk at the master root.
///
/// Witnesses the note and `pak`, proves `mk` is the note's master key
/// (`note.pk == pak.derive_payment_key()`), and emits the depth-0 node carrying
/// the note's `cm`.
#[derive(Debug)]
pub struct NfMasterSeed;

impl Step for NfMasterSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = NfPrefixHeader;
    type Right = ();
    /// `(note, pak)`.
    type Witness<'source> = (Note, ProofAuthorizingKey);

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note, pak): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            note.pk.0 - pak.derive_payment_key().0,
            "NfMasterSeed: pak not related to note",
        )?;
        let mk = pak.nk.derive_note_private(&note.psi);
        let cm = note.commitment();
        Ok(((cm, mk.0, 0, EpochIndex(0)), ()))
    }
}

/// Descend one level of the GGM tree.
///
/// Witnesses a free `chunk`; `node' = nf_prefix(node, chunk)`, `index' =
/// index*ARITY + chunk`, `depth' = depth + 1`.
#[derive(Debug)]
pub struct NfPrefixStep;

impl Step for NfPrefixStep {
    type Aux<'source> = ();
    type Left = NfPrefixHeader;
    type Output = NfPrefixHeader;
    type Right = ();
    /// `(chunk,)`.
    type Witness<'source> = (u8,);

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (chunk,): Self::Witness<'source>,
        (cm, node, depth, index): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if depth >= GGM_TREE_DEPTH {
            return Err(ragu::Error::InvalidWitness(
                "NfPrefixStep: already at maximum depth".into(),
            ));
        }
        if chunk >= GGM_TREE_ARITY {
            return Err(ragu::Error::InvalidWitness(
                "NfPrefixStep: chunk exceeds GGM arity".into(),
            ));
        }
        let child = poseidon::nf_prefix(node, chunk);
        let child_index = EpochIndex(index.0 * u32::from(GGM_TREE_ARITY) + u32::from(chunk));
        Ok(((cm, child, depth + 1, child_index), ()))
    }
}

/// Turn a leaf node into a single-leaf [`NullifierHeader`].
///
/// Requires the walk to be at a leaf (`depth == GGM_TREE_DEPTH`); the nullifier
/// is `Poseidon(node)` and the range commits to it alone at degree 0 (sentinel
/// above), spanning the single epoch `[index, index + 1)`.
#[derive(Debug)]
pub struct NullifierStep;

impl Step for NullifierStep {
    type Aux<'source> = ();
    type Left = NfPrefixHeader;
    type Output = NullifierHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (cm, node, depth, index): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        #[expect(clippy::expect_used, reason = "constant size")]
        let &[g0, g1] = Pasta::host_generators(Pasta::baked())
            .g()
            .split_first_chunk::<2>()
            .expect("at least two generators")
            .0;

        enforce_zero(
            Fp::from(u64::from(depth)) - Fp::from(u64::from(GGM_TREE_DEPTH)),
            "NullifierStep: not at maximum depth",
        )?;
        let nf = Nullifier::from(poseidon::nullifier(node));

        // Single-leaf sentinel sequence `nf + X`: `g1` carries the sentinel.
        let nf_seq_commit = NfSeqCommit::from(g0 * Fp::from(nf) + g1);
        Ok(((cm, (index, nf), nf_seq_commit, (index.next(), nf)), ()))
    }
}

/// Merge two adjacent derived ranges into one (`left ++ right`).
///
/// Requires the same `cm` and contiguity (`right.start == left.end`). Witnesses
/// the two range polynomials and their concatenation, binds each by
/// commit-equality, and proves the concat at `offset = left.end - left.start`
/// via the faithful opening relation.
#[derive(Debug)]
pub struct NullifierFuse;

impl Step for NullifierFuse {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = NullifierHeader;
    type Right = NullifierHeader;
    /// `(left_seq, merged_seq, right_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(3);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_seq, merged_seq, right_seq): Self::Witness<'source>,
        (
            left_cm,
            (left_epoch_start, left_nf_start),
            left_nf_seq_commit,
            (left_epoch_end, _left_nf_end),
        ): <Self::Left as Header>::Data,
        (
            right_cm,
            (right_epoch_start, right_nf_start),
            right_nf_seq_commit,
            (right_epoch_end, right_nf_end),
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let (left_cm0, left_cm1): (Fp, Fp) = left_cm.into();
        let (right_cm0, right_cm1): (Fp, Fp) = right_cm.into();
        enforce_zero(
            left_cm0 - right_cm0,
            "NullifierFuse: note commitments differ",
        )?;
        enforce_zero(
            left_cm1 - right_cm1,
            "NullifierFuse: note commitments' second element differs",
        )?;
        enforce_zero(
            Fp::from(right_epoch_start) - Fp::from(left_epoch_end),
            "NullifierFuse: ranges not contiguous",
        )?;
        enforce_equal_point(
            Eq::from(left_seq.commit()),
            Eq::from(left_nf_seq_commit),
            "NullifierFuse: left polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(right_seq.commit()),
            Eq::from(right_nf_seq_commit),
            "NullifierFuse: right polynomial does not match header",
        )?;
        let merged_nf_seq_commit = merged_seq.commit();
        let offset =
            usize::try_from(left_epoch_end.0 - left_epoch_start.0).map_err(|_too_long| {
                ragu::Error::InvalidWitness("NullifierFuse: range length exceeds usize".into())
            })?;
        // Sentinel concat: a sequence of `k` members is `Σ n_i·X^i + X^k`, so
        // `merged = left ++ right` is the shifted combination
        // `merged(X) = left(X) + X^offset·right(X) - X^offset`. The `-X^offset`
        // monomial cancels left's sentinel, right's first member lands in the
        // vacated slot, and right's own sentinel re-terminates `merged`. The
        // monomial's constant coefficient is trivially challenge-independent,
        // and `offset` is left's header-fixed span.
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
        // Pin the boundary nullifiers that sit at a queryable degree-0 position:
        // the merged sequence opens to `left_nf_start` (its first leaf), and the
        // right half opens to `right_nf_start`. Each ties a witnessed sequence to
        // the header value its seed proved by construction. (`left_nf_end` is the
        // left half's top coefficient, not extractable by a single opening.)
        ctx.enforce_poly_query(
            merged_nf_seq_commit.into(),
            Fp::ZERO,
            Fp::from(left_nf_start),
        )?;
        ctx.enforce_poly_query(
            right_nf_seq_commit.into(),
            Fp::ZERO,
            Fp::from(right_nf_start),
        )?;
        Ok((
            (
                left_cm,
                (left_epoch_start, left_nf_start),
                merged_nf_seq_commit,
                (right_epoch_end, right_nf_end),
            ),
            (),
        ))
    }
}
