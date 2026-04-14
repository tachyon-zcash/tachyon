//! Prefix-partitioned coverage PCD primitives.
//!
//! One merge tree family serves both inclusion and exclusion proofs. Each
//! leaf declares a bit-prefix discriminant identifying which slice of the
//! tachygram space it covers. Sibling leaves have complementary prefixes
//! (differ in one bit at the common depth); [`CoverageFuse`] merges them
//! into a shorter prefix. At the root, the prefix is empty and the commit
//! equals the whole (e.g. one block's `block_commit`).
//!
//! Three leaf variants share [`CoverageHeader`]:
//! - [`CoverageLeaf<N>`]: bare — commit only, no claim.
//! - [`InclusionLeaf<N>`]: commit + "cm is at a specific index".
//! - [`ExclusionLeaf<N>`]: commit + "nf ∉ this leaf's tachygrams". nf's prefix
//!   must match the leaf's prefix — sibling sub-blocks can't contain nf by
//!   construction, so no evaluation is needed elsewhere in the tree.
//!
//! Terminal steps consume a root-prefix [`CoverageHeader`]:
//! - [`InclusionFinalize`] + `PoolHeader` + `NullifierHeader` →
//!   [`SpendableHeader`](super::spendable::SpendableHeader)
//! - [`ExclusionFinalize`] →
//!   [`ExclusionHeader`](super::exclusion::ExclusionHeader)
//!
//! Cross-block aggregation of exclusion proofs (for multi-block pool deltas)
//! uses the existing [`ExclusionFuse`](super::exclusion::ExclusionFuse) to
//! sum per-block [`ExclusionHeader`]s.
//!
//! Soundness: consensus attests `block_commit = Σ pedersen(poly_from_roots(
//! tachygrams_at_prefix_P))` over all prefixes P at the canonical partition
//! depth. Each leaf verifies its witnessed tachygrams match its declared
//! prefix. Pedersen binding prevents forging sub-block commits.

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::{EqAffine, Fp};

use super::{
    delegation::NullifierHeader, exclusion::ExclusionHeader, pool::PoolHeader,
    spendable::SpendableHeader,
};
use crate::{
    SetCommit,
    keys::NullifierKey,
    note::{Note, Nullifier},
    primitives::{Anchor, NoteId, Tachygram, polynomial},
};

// ---------------------------------------------------------------------------
// Prefix — bit-prefix discriminant
// ---------------------------------------------------------------------------

/// A bit prefix: `bits` are the low `depth` bits of a partition key.
///
/// `depth == 0` is the empty prefix (matches everything). Depth is bounded
/// by 64 for simplicity; real deployments fix a protocol-level maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prefix {
    /// The prefix bits, stored in the low `depth` positions.
    pub bits: u64,
    /// Number of significant bits (0..=64).
    pub depth: u8,
}

impl Prefix {
    /// The empty prefix — matches all tachygrams.
    pub const EMPTY: Self = Self { bits: 0, depth: 0 };

    /// Create a new prefix. Verifies `bits` fits within `depth` bits.
    #[must_use]
    pub const fn new(bits: u64, depth: u8) -> Option<Self> {
        if depth > 64 {
            return None;
        }
        let mask = Self::mask(depth);
        if bits & !mask != 0 {
            return None;
        }
        Some(Self { bits, depth })
    }

    /// Bitmask covering `depth` low bits.
    const fn mask(depth: u8) -> u64 {
        if depth == 0 {
            0
        } else if depth >= 64 {
            u64::MAX
        } else {
            (1u64 << depth) - 1
        }
    }

    /// Returns `true` if `value`'s low `depth` bits equal `self.bits`.
    #[must_use]
    pub const fn matches(&self, value: u64) -> bool {
        value & Self::mask(self.depth) == self.bits
    }

    /// Merge two sibling prefixes into their parent.
    ///
    /// Siblings have equal depth and differ in exactly one bit at
    /// position `depth - 1`. Returns the parent (depth - 1, common bits).
    #[must_use]
    pub const fn sibling_merge(left: Self, right: Self) -> Option<Self> {
        if left.depth != right.depth || left.depth == 0 {
            return None;
        }
        let differ_bit = 1u64 << (left.depth - 1);
        if left.bits ^ right.bits != differ_bit {
            return None;
        }
        let common = left.bits & (differ_bit - 1);
        Some(Self {
            bits: common,
            depth: left.depth - 1,
        })
    }

    /// Encode as 8 bytes of bits (little-endian) + 1 byte of depth.
    #[must_use]
    pub fn encode(&self) -> [u8; 9] {
        let mut out = [0u8; 9];
        #[expect(clippy::little_endian_bytes, reason = "specified encoding")]
        out[0..8].copy_from_slice(&self.bits.to_le_bytes());
        out[8] = self.depth;
        out
    }
}

/// Extract the low `depth` bits of a tachygram (or nullifier) field element.
fn low_bits(fp: Fp, depth: u8) -> u64 {
    let bytes = fp.to_repr();
    let mut eight = [0u8; 8];
    eight.copy_from_slice(&bytes[0..8]);
    #[expect(clippy::little_endian_bytes, reason = "specified encoding")]
    let as_u64 = u64::from_le_bytes(eight);
    as_u64 & Prefix::mask(depth)
}

// ---------------------------------------------------------------------------
// Claim — what a CoverageHeader additionally asserts
// ---------------------------------------------------------------------------

/// Optional per-tree claim attached to a [`CoverageHeader`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Claim {
    /// No claim — bare coverage.
    None,
    /// A specific commitment is one of the covered tachygrams.
    Inclusion {
        /// The note commitment.
        cm: Fp,
        /// The note identity `H(mk, cm)` that must match the consuming
        /// `NullifierHeader` at finalize time.
        note_id: NoteId,
    },
    /// A specific nullifier is not one of the covered tachygrams.
    Exclusion {
        /// The excluded nullifier.
        nf: Nullifier,
    },
}

impl Claim {
    fn encode(&self) -> Vec<u8> {
        match *self {
            | Self::None => alloc::vec![0u8],
            | Self::Inclusion { cm, note_id } => {
                let mut out = Vec::with_capacity(1 + 32 + 32);
                out.push(1u8);
                out.extend_from_slice(&cm.to_repr());
                out.extend_from_slice(&Fp::from(note_id).to_repr());
                out
            },
            | Self::Exclusion { nf } => {
                let mut out = Vec::with_capacity(1 + 32);
                out.push(2u8);
                out.extend_from_slice(&Fp::from(nf).to_repr());
                out
            },
        }
    }
}

/// Merge two claims from sibling subtrees being fused. Returns `None` if
/// the combination is invalid.
fn merge_claims(left: Claim, right: Claim) -> Option<Claim> {
    match (left, right) {
        | (Claim::None, Claim::None) => Some(Claim::None),
        | (Claim::None, other) | (other, Claim::None) => Some(other),
        | (Claim::Exclusion { nf: nf_l }, Claim::Exclusion { nf: nf_r }) if nf_l == nf_r => {
            Some(Claim::Exclusion { nf: nf_l })
        },
        | _ => None,
    }
}

// ---------------------------------------------------------------------------
// CoverageHeader — shared output of all three leaves and the fuse
// ---------------------------------------------------------------------------

/// Coverage PCD header: a Pedersen-additive commit over some prefix-identified
/// portion of the tachygram space, optionally with an attached claim.
#[derive(Debug)]
pub struct CoverageHeader;

impl Header for CoverageHeader {
    /// `(commit, prefix, claim)`
    type Data<'source> = (SetCommit, Prefix, Claim);

    const SUFFIX: Suffix = Suffix::new(15);

    fn encode(&(commit, prefix, claim): &Self::Data<'_>) -> Vec<u8> {
        use pasta_curves::group::GroupEncoding as _;
        let claim_bytes = claim.encode();
        let mut out = Vec::with_capacity(32 + 9 + claim_bytes.len());
        out.extend_from_slice(&EqAffine::from(commit).to_bytes());
        out.extend_from_slice(&prefix.encode());
        out.extend_from_slice(&claim_bytes);
        out
    }
}

// ---------------------------------------------------------------------------
// CoverageLeaf<N> — bare commit of one prefix-identified sub-block
// ---------------------------------------------------------------------------

/// Seeds a `CoverageHeader` for one sub-block with no claim.
///
/// Witness: `(prefix, [Tachygram; N])`. Verifies every tachygram matches
/// the declared prefix, commits the polynomial, outputs `(commit, prefix,
/// None)`.
#[derive(Debug)]
pub struct CoverageLeaf<const N: usize>;

impl<const N: usize> Step for CoverageLeaf<N> {
    type Aux<'source> = ();
    type Left = ();
    type Output = CoverageHeader;
    type Right = ();
    type Witness<'source> = (Prefix, &'source [Tachygram; N]);

    const INDEX: Index = Index::new(29);

    fn witness<'source>(
        &self,
        (prefix, tachygrams): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if !all_match_prefix(tachygrams, prefix) {
            return Err(mock_ragu::Error);
        }
        let commit = subset_commit(tachygrams);
        Ok(((commit, prefix, Claim::None), ()))
    }
}

// ---------------------------------------------------------------------------
// InclusionLeaf<N> — commit + cm-at-index claim
// ---------------------------------------------------------------------------

/// Seeds a `CoverageHeader` for one sub-block and claims `cm` is at
/// `cm_index`.
///
/// Witness: `(prefix, [Tachygram; N], cm_index, Note, NullifierKey)`.
/// Verifies:
/// - Every tachygram matches the declared prefix.
/// - `sub_block[cm_index] == Tachygram::from(note.commitment())`.
/// - cm's low-bits prefix equals the leaf's prefix (so cm belongs here).
///
/// Output claim carries `note_id = note.id(&nk)` for the finalizer to
/// match against `NullifierHeader`.
#[derive(Debug)]
pub struct InclusionLeaf<const N: usize>;

impl<const N: usize> Step for InclusionLeaf<N> {
    type Aux<'source> = ();
    type Left = ();
    type Output = CoverageHeader;
    type Right = ();
    type Witness<'source> = (Prefix, &'source [Tachygram; N], usize, Note, NullifierKey);

    const INDEX: Index = Index::new(14);

    fn witness<'source>(
        &self,
        (prefix, tachygrams, cm_index, note, nk): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if !all_match_prefix(tachygrams, prefix) {
            return Err(mock_ragu::Error);
        }
        let cm = note.commitment();
        let cm_fp = Fp::from(cm);
        if !prefix.matches(low_bits(cm_fp, prefix.depth)) {
            return Err(mock_ragu::Error);
        }
        let cm_tg = Tachygram::from(cm_fp);
        if tachygrams.get(cm_index).is_none_or(|tg| *tg != cm_tg) {
            return Err(mock_ragu::Error);
        }
        let note_id = note.id(&nk);
        let commit = subset_commit(tachygrams);
        Ok((
            (commit, prefix, Claim::Inclusion { cm: cm_fp, note_id }),
            (),
        ))
    }
}

// ---------------------------------------------------------------------------
// ExclusionLeaf<N> — commit + nf-excluded claim
// ---------------------------------------------------------------------------

/// Seeds a `CoverageHeader` for one sub-block and claims nf ∉ tachygrams.
///
/// Witness: `(prefix, [Tachygram; N], nf)`. Verifies:
/// - Every tachygram matches the declared prefix.
/// - nf's low-bits prefix equals the leaf's prefix (so evaluating here is
///   meaningful — sibling leaves can't contain nf by prefix mismatch).
/// - `poly_eval(coeffs, nf) != 0` (nf is not a root of the sub-block
///   polynomial).
#[derive(Debug)]
pub struct ExclusionLeaf<const N: usize>;

impl<const N: usize> Step for ExclusionLeaf<N> {
    type Aux<'source> = ();
    type Left = ();
    type Output = CoverageHeader;
    type Right = ();
    type Witness<'source> = (Prefix, &'source [Tachygram; N], Nullifier);

    const INDEX: Index = Index::new(22);

    fn witness<'source>(
        &self,
        (prefix, tachygrams, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if !all_match_prefix(tachygrams, prefix) {
            return Err(mock_ragu::Error);
        }
        let nf_fp = Fp::from(nf);
        if !prefix.matches(low_bits(nf_fp, prefix.depth)) {
            return Err(mock_ragu::Error);
        }
        let roots: Vec<Fp> = tachygrams.iter().map(|tg| Fp::from(*tg)).collect();
        let coeffs = polynomial::poly_from_roots(&roots);
        let eval = polynomial::poly_eval(&coeffs, nf_fp);
        if eval.is_zero().into() {
            return Err(mock_ragu::Error);
        }
        let commit = SetCommit::from(polynomial::pedersen_commit(&coeffs));
        Ok(((commit, prefix, Claim::Exclusion { nf }), ()))
    }
}

// ---------------------------------------------------------------------------
// CoverageFuse — merge two sibling CoverageHeaders
// ---------------------------------------------------------------------------

/// Merge two sibling-prefix `CoverageHeader`s.
///
/// Witness-free. Requires prefixes to be siblings (equal depth, differing in
/// exactly one bit at position `depth - 1`). Sums commits via `SetCommit`
/// additivity. Merges claims: `None + X → X`; `Exclusion(nf) + Exclusion(nf)
/// → Exclusion(nf)`; `Inclusion + Inclusion` or conflicting claims → reject.
#[derive(Debug)]
pub struct CoverageFuse;

impl Step for CoverageFuse {
    type Aux<'source> = ();
    type Left = CoverageHeader;
    type Output = CoverageHeader;
    type Right = CoverageHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(30);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_commit, left_prefix, left_claim): <Self::Left as Header>::Data<'source>,
        (right_commit, right_prefix, right_claim): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let Some(merged_prefix) = Prefix::sibling_merge(left_prefix, right_prefix) else {
            return Err(mock_ragu::Error);
        };
        let Some(merged_claim) = merge_claims(left_claim, right_claim) else {
            return Err(mock_ragu::Error);
        };
        Ok((
            (left_commit + right_commit, merged_prefix, merged_claim),
            (),
        ))
    }
}

// ---------------------------------------------------------------------------
// CoverageEmpty — jump-start an empty subtree at any prefix depth
// ---------------------------------------------------------------------------

/// Seeds a `CoverageHeader` carrying the identity commit at any prefix.
///
/// Lets the prover assert "this subtree at prefix P is empty" in one step,
/// avoiding the need to build real leaves for unpopulated partition elements.
/// Soundness is preserved: the terminal commit-equality check
/// (`InclusionFinalize` / pool-delta checks) still forces the tree's root
/// to equal the consensus-attested total.
#[derive(Debug)]
pub struct CoverageEmpty;

impl Step for CoverageEmpty {
    type Aux<'source> = ();
    type Left = ();
    type Output = CoverageHeader;
    type Right = ();
    type Witness<'source> = Prefix;

    const INDEX: Index = Index::new(32);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let prefix = witness;
        Ok(((SetCommit::identity(), prefix, Claim::None), ()))
    }
}

// ---------------------------------------------------------------------------
// InclusionFinalize — turn a fully-covered inclusion tree into SpendableHeader
// ---------------------------------------------------------------------------

/// Consumes a root-prefix `CoverageHeader` bearing an `Inclusion` claim
/// together with a `PoolHeader` (for the block's anchor) and binds them
/// into a [`SpendableHeader`].
///
/// Witness-free. Verifies:
/// - The coverage header's prefix is empty (whole block covered).
/// - `coverage.commit == pool.block_commit`.
/// - `coverage.claim` is `Inclusion`.
/// - `pool.block_height`'s epoch matches (checked at consuming step via the
///   nullifier header join below).
///
/// The nullifier and epoch are joined later via a separate step that
/// consumes this header and a `NullifierHeader`. Keeping `InclusionFinalize`
/// binary-input keeps it ragu-compatible; see [`InclusionBindNullifier`].
#[derive(Debug)]
pub struct InclusionFinalize;

/// Intermediate header carrying `(note_id, cm, anchor)` before the
/// nullifier binding.
#[derive(Debug)]
pub struct InclusionBoundHeader;

impl Header for InclusionBoundHeader {
    /// `(note_id, cm, anchor)`
    type Data<'source> = (NoteId, Fp, Anchor);

    const SUFFIX: Suffix = Suffix::new(17);

    fn encode(&(note_id, cm, anchor): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 4 + 32 * 4);
        out.extend_from_slice(&Fp::from(note_id).to_repr());
        out.extend_from_slice(&cm.to_repr());
        out.extend_from_slice(&anchor.encode_for_header());
        out
    }
}

impl Step for InclusionFinalize {
    type Aux<'source> = ();
    type Left = CoverageHeader;
    type Output = InclusionBoundHeader;
    type Right = PoolHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(31);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (commit, prefix, claim): <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let anchor = right;
        if prefix != Prefix::EMPTY {
            return Err(mock_ragu::Error);
        }
        if commit != anchor.block_commit.0 {
            return Err(mock_ragu::Error);
        }
        let Claim::Inclusion { cm, note_id } = claim else {
            return Err(mock_ragu::Error);
        };
        Ok(((note_id, cm, anchor), ()))
    }
}

// ---------------------------------------------------------------------------
// InclusionBindNullifier — attach nf from delegation chain
// ---------------------------------------------------------------------------

/// Joins an `InclusionBoundHeader` with a `NullifierHeader` from the
/// delegation chain, producing `SpendableHeader`.
///
/// Witness-free. Verifies note_id and epoch agree.
#[derive(Debug)]
pub struct InclusionBindNullifier;

impl Step for InclusionBindNullifier {
    type Aux<'source> = ();
    type Left = InclusionBoundHeader;
    type Output = SpendableHeader;
    type Right = NullifierHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(33);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_note_id, _cm, anchor): <Self::Left as Header>::Data<'source>,
        (nf, epoch, right_note_id): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_note_id != right_note_id {
            return Err(mock_ragu::Error);
        }
        if epoch != anchor.block_height.epoch() {
            return Err(mock_ragu::Error);
        }
        Ok(((left_note_id, nf, anchor), ()))
    }
}

// ---------------------------------------------------------------------------
// ExclusionFinalize — turn an exclusion tree root into ExclusionHeader
// ---------------------------------------------------------------------------

/// Consumes a root-prefix `CoverageHeader` bearing an `Exclusion` claim
/// and outputs the canonical [`ExclusionHeader`] downstream exclusion
/// fuses expect.
///
/// Witness-free. Verifies:
/// - The coverage header's prefix is empty (whole block or sub-pool covered).
/// - `coverage.claim` is `Exclusion`.
///
/// Cross-block aggregation (summing multiple block-level `ExclusionHeader`s
/// into a pool-delta `ExclusionHeader`) uses the existing
/// [`ExclusionFuse`](super::exclusion::ExclusionFuse).
#[derive(Debug)]
pub struct ExclusionFinalize;

impl Step for ExclusionFinalize {
    type Aux<'source> = ();
    type Left = CoverageHeader;
    type Output = ExclusionHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(32);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (commit, prefix, claim): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if prefix != Prefix::EMPTY {
            return Err(mock_ragu::Error);
        }
        let Claim::Exclusion { nf } = claim else {
            return Err(mock_ragu::Error);
        };
        Ok(((nf, SetCommit::from(EqAffine::from(commit))), ()))
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn all_match_prefix<const N: usize>(tachygrams: &[Tachygram; N], prefix: Prefix) -> bool {
    tachygrams
        .iter()
        .all(|tg| prefix.matches(low_bits(Fp::from(*tg), prefix.depth)))
}

fn subset_commit<const N: usize>(tachygrams: &[Tachygram; N]) -> SetCommit {
    let roots: Vec<Fp> = tachygrams.iter().map(|tg| Fp::from(*tg)).collect();
    let coeffs = polynomial::poly_from_roots(&roots);
    SetCommit::from(polynomial::pedersen_commit(&coeffs))
}
