//! GGM nullifier-derivation chain: prove a contiguous range of a note's
//! per-epoch nullifiers `GGM(mk, ·)`. Wallet-only; every range header carries
//! `cm` for its consumers.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use group::{Curve as _, GroupEncoding as _};
use pasta_curves::{Eq, Fp};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Polynomial, Step, Suffix,
    enforce_poly_concat,
};

use crate::{
    digest::poseidon,
    keys::{GGM_TREE_ARITY, GGM_TREE_DEPTH, ProofAuthorizingKey},
    note::{self, Note, Nullifier},
    primitives::{EpochIndex, NfSeqCommit, NfSeqPoly},
};

/// In-progress GGM walk position `(node, depth, index, cm)`: the current tree
/// `node`, levels descended `depth`, leaf `index`, and the note commitment `cm`
/// carried for the final binding. Wallet-only.
#[derive(Clone, Debug)]
pub struct NfPrefixHeader;

impl Header for NfPrefixHeader {
    type Data = (Fp, u8, EpochIndex, note::Commitment);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 1 + 4 + 32);
        out.extend_from_slice(&data.0.to_repr());
        out.extend_from_slice(&data.1.to_le_bytes());
        out.extend_from_slice(&data.2.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.3).to_repr());
        out
    }
}

/// A proven contiguous range of derived nullifiers (wallet-only).
///
/// `(range_commit, start_epoch, end_epoch, cm)`: `range_commit` commits to the
/// half-open range `[N_start, .., N_{end-1}]` (`N_e = GGM(mk, e)`) at degree 0;
/// `cm` lets every consumer bind the range to the real note.
#[derive(Clone, Debug)]
pub struct NullifierHeader;

impl Header for NullifierHeader {
    type Data = (NfSeqCommit, EpochIndex, EpochIndex, note::Commitment);

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 4 + 32);
        let commit_bytes: [u8; 32] = Eq::from(data.0).to_affine().to_bytes();
        out.extend_from_slice(&commit_bytes);
        out.extend_from_slice(&data.1.0.to_le_bytes());
        out.extend_from_slice(&data.2.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.3).to_repr());
        out
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
    type Witness<'source> = (Note, ProofAuthorizingKey);

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note, pak): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if note.pk.0 != pak.derive_payment_key().0 {
            return Err(ragu::Error("NfMasterSeed: pak not related to note"));
        }
        let mk = pak.nk.derive_note_private(&note.psi);
        let cm = note.commitment();
        Ok(((mk.0, 0, EpochIndex(0), cm), ()))
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
    type Witness<'source> = (u8,);

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (chunk,): Self::Witness<'source>,
        (node, depth, index, cm): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if depth >= GGM_TREE_DEPTH {
            return Err(ragu::Error("NfPrefixStep: already at maximum depth"));
        }
        if chunk >= GGM_TREE_ARITY {
            return Err(ragu::Error("NfPrefixStep: chunk exceeds GGM arity"));
        }
        let child = poseidon::nf_prefix(node, chunk);
        let child_index = EpochIndex(index.0 * u32::from(GGM_TREE_ARITY) + u32::from(chunk));
        Ok(((child, depth + 1, child_index, cm), ()))
    }
}

/// Turn a leaf node into a single-leaf [`NullifierHeader`].
///
/// Requires the walk to be at a leaf (`depth == GGM_TREE_DEPTH`); the nullifier
/// is `Poseidon(node)` and the range commits to it alone at degree 0, spanning
/// the single epoch `[index, index + 1)`.
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
        (node, depth, index, cm): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if depth != GGM_TREE_DEPTH {
            return Err(ragu::Error("NullifierStep: not at maximum depth"));
        }
        let nf = Nullifier::from(poseidon::nullifier(node));
        let generators = Pasta::host_generators(Pasta::baked()).g();
        let Some(g0) = generators.first() else {
            return Err(ragu::Error("NullifierStep: insufficient generators"));
        };
        let range_commit = NfSeqCommit::from(*g0 * Fp::from(nf));
        Ok(((range_commit, index, index.next(), cm), ()))
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
    /// `(left_poly, right_poly, merged)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(3);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_poly, right_poly, merged): Self::Witness<'source>,
        (left_commit, left_start, left_end, left_cm): <Self::Left as Header>::Data,
        (right_commit, right_start, right_end, right_cm): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if left_cm != right_cm {
            return Err(ragu::Error("NullifierFuse: note commitments differ"));
        }
        if right_start != left_end {
            return Err(ragu::Error("NullifierFuse: ranges not contiguous"));
        }
        if left_poly.commit() != left_commit {
            return Err(ragu::Error(
                "NullifierFuse: left polynomial does not match header",
            ));
        }
        if right_poly.commit() != right_commit {
            return Err(ragu::Error(
                "NullifierFuse: right polynomial does not match header",
            ));
        }
        let merged_commit = merged.commit();
        let offset = usize::try_from(left_end.0 - left_start.0)
            .map_err(|_too_long| ragu::Error("NullifierFuse: range length exceeds usize"))?;
        enforce_poly_concat(
            ctx,
            &Polynomial::from(left_poly),
            &Polynomial::from(right_poly),
            offset,
            &Polynomial::from(merged),
        )
        .map_err(|_relation_err| {
            ragu::Error("NullifierFuse: merged is not the concat of the halves")
        })?;
        Ok(((merged_commit, left_start, right_end, left_cm), ()))
    }
}
