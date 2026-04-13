//! Exclusion proof PCD steps.
//!
//! Two paths produce [`ExclusionHeader`]:
//!
//! - **Single-nullifier**: [`ExclusionLeaf`] + [`ExclusionFuse`]. One tree per
//!   nullifier. Used by the user for local creation-hiding.
//! - **Multi-nullifier**: [`ExclusionSetLeaf`] + [`ExclusionSetFuse`] +
//!   [`ExclusionSetExtract`]. Amortizes the MSM across M nullifiers per
//!   circuit. Used by the sync service.
//!
//! Both paths produce the same [`ExclusionHeader`], consumed by the
//! binding fuse steps ([`NullifierExclusionFuse`], [`SpendableExclusionFuse`])
//! which connect exclusion proofs to the spendable path.
//!
//! The prover freely partitions tachygrams into subsets (≤ N per leaf
//! circuit). No consensus-level discriminant — the only binding is that
//! fused `scope` must equal the PCD-attested pool delta at the consuming
//! spendable step.

extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::{EqAffine, Fp};

use super::{delegation::NullifierHeader, spendable::SpendableHeader};
use crate::{
    SetCommit,
    note::Nullifier,
    primitives::{Anchor, Epoch, NoteId, Tachygram, polynomial},
};

// ---------------------------------------------------------------------------
// ExclusionHeader — proves nf ∉ a set of tachygrams
// ---------------------------------------------------------------------------

/// PCD header proving a nullifier is absent from tachygrams identified by
/// their polynomial commitment `scope`.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct ExclusionHeader;

impl Header for ExclusionHeader {
    /// `(nf, scope)`
    type Data<'source> = (Nullifier, SetCommit);

    const SUFFIX: Suffix = Suffix::new(11);

    fn encode(&(nf, scope): &Self::Data<'_>) -> Vec<u8> {
        use ff::PrimeField as _;
        use pasta_curves::group::GroupEncoding as _;
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(nf).to_repr());
        out.extend_from_slice(&EqAffine::from(scope).to_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// ExclusionLeaf<N> — single-nullifier seed
// ---------------------------------------------------------------------------

/// Proves nf ∉ a prover-chosen subset of tachygrams.
///
/// Pure seed (no PCD inputs). Builds the polynomial from witness
/// tachygrams, computes the Pedersen commitment, evaluates at nf via
/// Horner. Checks evaluation ≠ 0.
///
/// The prover freely chooses which tachygrams to place in each leaf.
/// Binding comes from the downstream sum check: fused `scope` must equal
/// the PCD-attested pool delta.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct ExclusionLeaf<const N: usize>;

impl<const N: usize> Step for ExclusionLeaf<N> {
    type Aux<'source> = ();
    type Left = ();
    type Output = ExclusionHeader;
    type Right = ();
    type Witness<'source> = (Nullifier, &'source [Tachygram; N]);

    const INDEX: Index = Index::new(22);

    fn witness<'source>(
        &self,
        (nf, tachygrams): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let nf_fp = Fp::from(nf);

        let roots: Vec<Fp> = tachygrams.iter().map(|tg| Fp::from(*tg)).collect();
        let coeffs = polynomial::poly_from_roots(&roots);

        // Evaluate: must be nonzero for exclusion.
        let eval = polynomial::poly_eval(&coeffs, nf_fp);
        if eval.is_zero().into() {
            return Err(mock_ragu::Error);
        }

        let scope = SetCommit::from(polynomial::pedersen_commit(&coeffs));
        Ok(((nf, scope), ()))
    }
}

// ---------------------------------------------------------------------------
// ExclusionFuse — merge two single-nullifier exclusion proofs
// ---------------------------------------------------------------------------

/// Merges two exclusion proofs for the same nullifier across disjoint
/// subsets. `scope_merged = left.scope + right.scope`. Witness-free.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct ExclusionFuse;

impl Step for ExclusionFuse {
    type Aux<'source> = ();
    type Left = ExclusionHeader;
    type Output = ExclusionHeader;
    type Right = ExclusionHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(23);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_nf, left_scope): <Self::Left as Header>::Data<'source>,
        (right_nf, right_scope): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_nf != right_nf {
            return Err(mock_ragu::Error);
        }
        let scope = left_scope + right_scope;
        Ok(((left_nf, scope), ()))
    }
}

// ---------------------------------------------------------------------------
// ExclusionSetHeader<M> — multi-nullifier batch
// ---------------------------------------------------------------------------

/// PCD header carrying committed exclusion products for M nullifiers
/// across accumulated subsets.
///
/// - `nullifier_set`: `pedersen_commit` of the M-element nullifier vector.
/// - `product_set`: `pedersen_commit` of the M-element product vector
///   (per-nullifier accumulated `∏(nf_i - tg_j)` across covered subsets).
/// - `scope`: sum of subset polynomial commitments. Same generator basis as
///   `pool_commit`.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct ExclusionSetHeader<const M: usize>;

impl<const M: usize> Header for ExclusionSetHeader<M> {
    /// `(nullifier_set, product_set, scope)`
    type Data<'source> = (EqAffine, EqAffine, SetCommit);

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode(&(nullifier_set, product_set, scope): &Self::Data<'_>) -> Vec<u8> {
        use pasta_curves::group::GroupEncoding as _;
        let mut out = Vec::with_capacity(32 * 3);
        out.extend_from_slice(&nullifier_set.to_bytes());
        out.extend_from_slice(&product_set.to_bytes());
        out.extend_from_slice(&EqAffine::from(scope).to_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// ExclusionSetLeaf<N, M> — amortized multi-nullifier seed
// ---------------------------------------------------------------------------

/// Evaluates one subset's polynomial at M nullifiers. Pure seed.
///
/// One MSM (expensive, amortized M-fold), M Horner evaluations (cheap).
/// Witness budget: N + M ≤ 512.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct ExclusionSetLeaf<const N: usize, const M: usize>;

impl<const N: usize, const M: usize> Step for ExclusionSetLeaf<N, M> {
    type Aux<'source> = ();
    type Left = ();
    type Output = ExclusionSetHeader<M>;
    type Right = ();
    type Witness<'source> = (&'source [Tachygram; N], &'source [Fp; M]);

    const INDEX: Index = Index::new(26);

    fn witness<'source>(
        &self,
        (tachygrams, nullifiers): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let roots: Vec<Fp> = tachygrams.iter().map(|tg| Fp::from(*tg)).collect();
        let coeffs = polynomial::poly_from_roots(&roots);
        let scope = SetCommit::from(polynomial::pedersen_commit(&coeffs));

        let products: Vec<Fp> = nullifiers
            .iter()
            .map(|&nf| polynomial::poly_eval(&coeffs, nf))
            .collect();

        let nullifier_set = polynomial::pedersen_commit(nullifiers.as_slice());
        let product_set = polynomial::pedersen_commit(&products);

        Ok(((nullifier_set, product_set, scope), ()))
    }
}

// ---------------------------------------------------------------------------
// ExclusionSetFuse<M> — merge subset batches
// ---------------------------------------------------------------------------

/// Merges two subset-level batch headers for the same nullifier set.
///
/// Witness: both product vectors. Verifies commitments, multiplies
/// component-wise (Fp has no zero divisors), sums scope.
/// Witness budget: 2M ≤ 512.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct ExclusionSetFuse<const M: usize>;

impl<const M: usize> Step for ExclusionSetFuse<M> {
    type Aux<'source> = ();
    type Left = ExclusionSetHeader<M>;
    type Output = ExclusionSetHeader<M>;
    type Right = ExclusionSetHeader<M>;
    type Witness<'source> = (&'source [Fp; M], &'source [Fp; M]);

    const INDEX: Index = Index::new(27);

    fn witness<'source>(
        &self,
        (left_products, right_products): Self::Witness<'source>,
        (left_nf_set, left_prod_set, left_scope): <Self::Left as Header>::Data<'source>,
        (right_nf_set, right_prod_set, right_scope): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // Same nullifier set.
        if left_nf_set != right_nf_set {
            return Err(mock_ragu::Error);
        }

        // Verify product vectors against header commitments.
        if polynomial::pedersen_commit(left_products.as_slice()) != left_prod_set {
            return Err(mock_ragu::Error);
        }
        if polynomial::pedersen_commit(right_products.as_slice()) != right_prod_set {
            return Err(mock_ragu::Error);
        }

        // Component-wise field multiplication.
        let merged: Vec<Fp> = left_products
            .iter()
            .zip(right_products.iter())
            .map(|(&lp, &rp)| lp * rp)
            .collect();
        let merged_prod_set = polynomial::pedersen_commit(&merged);

        let merged_scope = left_scope + right_scope;

        Ok(((left_nf_set, merged_prod_set, merged_scope), ()))
    }
}

// ---------------------------------------------------------------------------
// ExclusionSetExtract<M> — narrow batch to single-nullifier ExclusionHeader
// ---------------------------------------------------------------------------

/// Extracts one nullifier's exclusion proof from a batch.
///
/// Witness: both vectors + index. Verifies vector commitments, picks the
/// slot, checks product nonzero. Outputs `ExclusionHeader(nf, scope)`.
/// Witness budget: 2M + 1 ≤ 512.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct ExclusionSetExtract<const M: usize>;

impl<const M: usize> Step for ExclusionSetExtract<M> {
    type Aux<'source> = ();
    type Left = ExclusionSetHeader<M>;
    type Output = ExclusionHeader;
    type Right = ();
    type Witness<'source> = (&'source [Fp; M], &'source [Fp; M], usize);

    const INDEX: Index = Index::new(28);

    fn witness<'source>(
        &self,
        (nullifiers, products, index): Self::Witness<'source>,
        (nullifier_set, product_set, scope): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // Verify vector commitments.
        if polynomial::pedersen_commit(nullifiers.as_slice()) != nullifier_set {
            return Err(mock_ragu::Error);
        }
        if polynomial::pedersen_commit(products.as_slice()) != product_set {
            return Err(mock_ragu::Error);
        }

        // Pick the slot.
        let nf_fp = nullifiers.get(index).ok_or(mock_ragu::Error)?;
        let product = products.get(index).ok_or(mock_ragu::Error)?;

        // Non-membership: product must be nonzero.
        if bool::from(product.is_zero()) {
            return Err(mock_ragu::Error);
        }

        let nf = Nullifier::from(*nf_fp);
        Ok(((nf, scope), ()))
    }
}

// ---------------------------------------------------------------------------
// NullifierExclusionHeader / NullifierExclusionFuse
// ---------------------------------------------------------------------------

/// Binds a nullifier (from delegation chain) to its exclusion scope.
/// Consumed by `SpendableRollover`.
#[derive(Debug)]
pub struct NullifierExclusionHeader;

impl Header for NullifierExclusionHeader {
    /// `(nf, epoch, note_id, scope)`
    type Data<'source> = (Nullifier, Epoch, NoteId, SetCommit);

    const SUFFIX: Suffix = Suffix::new(13);

    fn encode(&(nf, epoch, note_id, scope): &Self::Data<'_>) -> Vec<u8> {
        use ff::PrimeField as _;
        use pasta_curves::group::GroupEncoding as _;
        let mut out = Vec::with_capacity(32 + 4 + 32 + 32);
        out.extend_from_slice(&Fp::from(nf).to_repr());
        #[expect(clippy::little_endian_bytes, reason = "specified encoding")]
        out.extend_from_slice(&epoch.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(note_id).to_repr());
        out.extend_from_slice(&EqAffine::from(scope).to_bytes());
        out
    }
}

/// Fuses NullifierHeader with ExclusionHeader. Witness-free.
#[derive(Debug)]
pub struct NullifierExclusionFuse;

impl Step for NullifierExclusionFuse {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = NullifierExclusionHeader;
    type Right = ExclusionHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(24);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_nf, left_epoch, left_note_id): <Self::Left as Header>::Data<'source>,
        (right_nf, right_scope): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_nf != right_nf {
            return Err(mock_ragu::Error);
        }
        Ok(((left_nf, left_epoch, left_note_id, right_scope), ()))
    }
}

// ---------------------------------------------------------------------------
// SpendableExclusionHeader / SpendableExclusionFuse
// ---------------------------------------------------------------------------

/// Binds spendable state to its exclusion scope.
/// Consumed by `SpendableLift`.
#[derive(Debug)]
pub struct SpendableExclusionHeader;

impl Header for SpendableExclusionHeader {
    /// `(note_id, nf, anchor, scope)`
    type Data<'source> = (NoteId, Nullifier, Anchor, SetCommit);

    const SUFFIX: Suffix = Suffix::new(14);

    fn encode(&(note_id, nf, anchor, scope): &Self::Data<'_>) -> Vec<u8> {
        use ff::PrimeField as _;
        use pasta_curves::group::GroupEncoding as _;
        let mut out = Vec::with_capacity(32 + 32 + 4 + 32 * 4 + 32);
        out.extend_from_slice(&Fp::from(note_id).to_repr());
        out.extend_from_slice(&Fp::from(nf).to_repr());
        out.extend_from_slice(&anchor.encode_for_header());
        out.extend_from_slice(&EqAffine::from(scope).to_bytes());
        out
    }
}

/// Fuses SpendableHeader with ExclusionHeader. Witness-free.
#[derive(Debug)]
pub struct SpendableExclusionFuse;

impl Step for SpendableExclusionFuse {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableExclusionHeader;
    type Right = ExclusionHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(25);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_note_id, left_nf, left_anchor): <Self::Left as Header>::Data<'source>,
        (right_nf, right_scope): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_nf != right_nf {
            return Err(mock_ragu::Error);
        }
        Ok(((left_note_id, left_nf, left_anchor, right_scope), ()))
    }
}
