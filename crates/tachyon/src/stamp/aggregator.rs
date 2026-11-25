//! Full aggregator-rank transactions decompressed from wallet publications.
//!
//! An [`AggregatorProof`] holds the roots of both its set polynomials, which
//! [`Bundle::decompress`](crate::Bundle::decompress) authenticates once from
//! the published bodies. Merging concatenates them and unmerging removes one
//! occurrence per divisor occurrence, so no later operation takes descriptors.

use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};

use derive_more::{Debug, Display, Error};
use polynomials::AggregatorRank;
use ragu::{
    AcceleratedProver, Application, Pcd, Rank as _, WalletRank,
    circuits::polynomials,
    pasta::Pasta,
    pcd::profile::{Aggregator, Profiled},
};
use rand_core::CryptoRng;

use super::{
    Compressed, Stamp,
    proof::{
        HEADER_SIZE, pool,
        transaction::{
            Transaction, TransactionConvert, TransactionLift, TransactionMerge, TransactionUnmerge,
        },
    },
};
use crate::{
    ActionDigest, ActionSetPoly, Anchor, AnchorSetPoly, Tachygram, TachygramSetBridge,
    TachygramSetCommit, TachygramSetPoly, witness,
};

/// A full aggregator-rank transaction proof, its adjunct list and the roots
/// of its action and tachygram set polynomials.
///
/// The roots are multisets: the set polynomials record multiplicity.
#[derive(Clone, Debug)]
pub struct AggregatorProof {
    #[debug(skip)]
    pub(crate) pcd: Pcd<Profiled<Pasta, Aggregator<HEADER_SIZE>>, AggregatorRank, Transaction>,
    pub(crate) adjuncts: BTreeSet<[u8; 32]>,
    pub(crate) actions: Vec<ActionDigest>,
    pub(crate) tachygrams: Vec<Tachygram>,
}

/// Errors from [`AggregatorProof::merge`].
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum MergeError {
    /// The two transactions together hold more tachygrams than one set
    /// polynomial has roots.
    #[display("too many roots for one set polynomial")]
    TooManyRoots,
    /// Proving failed.
    #[display("proof failed: {_0}")]
    Proof(ragu::Error),
}

/// Errors from [`AggregatorProof::unmerge`].
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum UnmergeError {
    /// The divisor holds a root the dividend lacks, so no quotient exists.
    #[display("the divisor does not divide the transaction")]
    NotADivisor,
    /// Proving failed.
    #[display("proof failed: {_0}")]
    Proof(ragu::Error),
}

/// Errors from [`pool::AnchorSpan::decompress`].
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum SpanImportError {
    /// A root list has more members than one set polynomial has roots.
    #[display("too many roots for one set polynomial")]
    TooManyRoots,
    /// Ragu refused the frame or the rebuilt polynomials, or proving failed.
    #[display("proof error: {_0}")]
    Proof(ragu::Error),
}

// The span import lives here rather than in the step module, which holds only
// `Header` and `Step` impls, beside its only consumer, `AggregatorProof::lift`.
impl pool::AnchorSpan {
    /// Import a wallet-compressed span at aggregator rank, rebuilding its
    /// members polynomial from `members` and its absorbed-stamp polynomial from
    /// `absorbed`. A seed absorbs one nonempty stamp; a fused span absorbs
    /// none, so its `absorbed` is empty.
    ///
    /// # Errors
    /// - [`SpanImportError::TooManyRoots`] if `members` or `absorbed` has more
    ///   entries than one set polynomial has roots.
    /// - [`SpanImportError::Proof`] if Ragu refuses the frame or the rebuilt
    ///   polynomials, or proving fails.
    pub fn decompress<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &Application<
            '_,
            Profiled<Pasta, Aggregator<HEADER_SIZE>>,
            AggregatorRank,
            HEADER_SIZE,
            AcceleratedProver,
        >,
        frame: &Compressed,
        endpoints: (Anchor, Anchor),
        members: &[Anchor],
        absorbed: &[Tachygram],
    ) -> Result<Pcd<Profiled<Pasta, Aggregator<HEADER_SIZE>>, AggregatorRank, Self>, SpanImportError>
    {
        if members.len().max(absorbed.len()) >= WalletRank::num_coeffs() {
            return Err(SpanImportError::TooManyRoots);
        }
        app.decompress_with_polynomials(
            rng,
            &frame.clone().carry::<Self>(endpoints),
            [
                members
                    .iter()
                    .copied()
                    .collect::<AnchorSetPoly>()
                    .coefficients(),
                absorbed
                    .iter()
                    .copied()
                    .collect::<TachygramSetPoly>()
                    .coefficients(),
            ],
        )
        .map_err(SpanImportError::Proof)
    }
}

/// Remove one occurrence per divisor root, returning whether every divisor
/// root was found.
fn divide<T: Ord + Copy>(dividend: &mut Vec<T>, divisor: &[T]) -> bool {
    let mut remaining = divisor.to_vec();
    remaining.sort_unstable();
    dividend.retain(|root| {
        remaining.binary_search(root).map_or(true, |index| {
            remaining.remove(index);
            false
        })
    });
    remaining.is_empty()
}

impl AggregatorProof {
    /// The historic pool state for which this transaction is valid.
    #[must_use]
    pub fn anchor(&self) -> Anchor {
        let (_, anchor) = *self.pcd.data();
        anchor
    }

    /// The txids of the other transactions this proof covers, empty for a
    /// lone host. The host transaction is never listed.
    #[must_use]
    pub const fn adjuncts(&self) -> &BTreeSet<[u8; 32]> {
        &self.adjuncts
    }

    /// Advance the transaction's anchor along `spans`. The first span must
    /// contain this proof's anchor, and each later span the previous span's
    /// `anchor_end`. A lift from outside a span proves a transaction that does
    /// not verify. Empty `spans` return the proof unchanged.
    ///
    /// # Errors
    /// Returns a Ragu error if proving fails.
    pub fn lift<RNG: CryptoRng>(
        mut self,
        rng: &mut RNG,
        app: &Application<
            '_,
            Profiled<Pasta, Aggregator<HEADER_SIZE>>,
            AggregatorRank,
            HEADER_SIZE,
            AcceleratedProver,
        >,
        spans: Vec<Pcd<Profiled<Pasta, Aggregator<HEADER_SIZE>>, AggregatorRank, pool::AnchorSpan>>,
    ) -> ragu::Result<Self> {
        if spans.is_empty() {
            return Ok(self);
        }
        let action_set: ActionSetPoly = self.actions.iter().copied().collect();
        for span in spans {
            let witness =
                witness::transaction_lift((*self.pcd.data(), *span.data()), action_set.clone());
            let (pcd, ()) = app.fuse(rng, TransactionLift, witness, self.pcd, span)?;
            self.pcd = pcd;
        }
        Ok(self)
    }

    /// Merge `right` into this transaction at the same anchor. The result
    /// keeps this transaction's host and lists `right_txid`, the txid of the
    /// one transaction `right` covers without listing, and `right`'s
    /// adjuncts.
    ///
    /// This method cannot check `right_txid`. A wrong txid yields an aggregate
    /// that consensus rejects, because its list omits a transaction it covers
    /// and can name one it does not. Transactions at different anchors, or
    /// covering a shared leaf, prove an aggregate that does not verify.
    ///
    /// # Errors
    /// - [`MergeError::TooManyRoots`] if the two transactions together hold
    ///   more tachygrams than one set polynomial has roots.
    /// - [`MergeError::Proof`] if proving fails.
    pub fn merge<RNG: CryptoRng>(
        mut self,
        rng: &mut RNG,
        app: &Application<
            '_,
            Profiled<Pasta, Aggregator<HEADER_SIZE>>,
            AggregatorRank,
            HEADER_SIZE,
            AcceleratedProver,
        >,
        right: Self,
        right_txid: [u8; 32],
    ) -> Result<Self, MergeError> {
        // Every transaction holds at least as many tachygrams as action and fee
        // digests, so the tachygram count bounds both polynomials.
        if self.tachygrams.len() + right.tachygrams.len() >= WalletRank::num_coeffs() {
            return Err(MergeError::TooManyRoots);
        }
        self.actions.extend(right.actions);
        self.tachygrams.extend(right.tachygrams);
        let witness = witness::transaction_merge(
            (*self.pcd.data(), *right.pcd.data()),
            self.actions.iter().copied().collect(),
            self.tachygrams.iter().copied().collect(),
        );
        let (pcd, ()) = app
            .fuse(rng, TransactionMerge, witness, self.pcd, right.pcd)
            .map_err(MergeError::Proof)?;
        self.pcd = pcd;
        self.adjuncts.extend(right.adjuncts);
        self.adjuncts.insert(right_txid);
        Ok(self)
    }

    /// Divide this transaction by `divisor` at the same anchor, removing the
    /// divisor's leaves, its adjuncts and `divisor_txid`, the txid of the one
    /// transaction the divisor covers without listing.
    ///
    /// A quotient whose divisor removed this proof's host covers only the
    /// transactions it lists, so it is not a valid divisor or right-hand
    /// merge operand.
    ///
    /// # Errors
    /// - [`UnmergeError::NotADivisor`] if the divisor holds a root this
    ///   transaction lacks.
    /// - [`UnmergeError::Proof`] if proving fails.
    pub fn unmerge<RNG: CryptoRng>(
        mut self,
        rng: &mut RNG,
        app: &Application<
            '_,
            Profiled<Pasta, Aggregator<HEADER_SIZE>>,
            AggregatorRank,
            HEADER_SIZE,
            AcceleratedProver,
        >,
        divisor: Self,
        divisor_txid: [u8; 32],
    ) -> Result<Self, UnmergeError> {
        if !divide(&mut self.actions, &divisor.actions)
            || !divide(&mut self.tachygrams, &divisor.tachygrams)
        {
            return Err(UnmergeError::NotADivisor);
        }
        let witness = witness::transaction_unmerge(
            (*self.pcd.data(), *divisor.pcd.data()),
            self.actions.iter().copied().collect(),
            self.tachygrams.iter().copied().collect(),
        );
        let (pcd, ()) = app
            .fuse(rng, TransactionUnmerge, witness, self.pcd, divisor.pcd)
            .map_err(UnmergeError::Proof)?;
        self.pcd = pcd;
        self.adjuncts
            .retain(|txid| *txid != divisor_txid && !divisor.adjuncts.contains(txid));
        Ok(self)
    }

    /// Rerandomize and compress the transaction for publication.
    ///
    /// A transaction still carrying its imported wallet bridge hash, as from
    /// [`Bundle::decompress`](crate::Bundle::decompress) with no later step,
    /// first passes through [`TransactionConvert`] to take the aggregator's.
    ///
    /// # Errors
    /// Returns a Ragu error if conversion, rerandomization or compression
    /// fails.
    pub fn compress<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &Application<
            '_,
            Profiled<Pasta, Aggregator<HEADER_SIZE>>,
            AggregatorRank,
            HEADER_SIZE,
            AcceleratedProver,
        >,
    ) -> ragu::Result<super::Aggregate> {
        let anchor = self.anchor();
        let [_, tachygrams] = self.pcd.commitments();
        let own = TachygramSetBridge::from(app.bridge_hash(tachygrams)?);
        let pcd = if self.pcd.data().0 == own {
            self.pcd
        } else {
            app.fuse(
                &mut *rng,
                TransactionConvert,
                (),
                self.pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )?
            .0
        };
        let refreshed = app.rerandomize(pcd, &mut *rng)?;
        let (frame, _) = app.compress(&refreshed, rng)?.into_parts();
        Ok(Stamp {
            anchor,
            tachygram_set: TachygramSetCommit::from(tachygrams),
            adjuncts: self.adjuncts,
            proof: Box::new(frame),
        })
    }
}
