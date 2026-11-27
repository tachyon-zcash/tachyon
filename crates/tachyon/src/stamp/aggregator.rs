//! Full aggregator-rank transactions decompressed from wallet publications.
//!
//! An [`AggregatorProof`] holds the roots of both its set polynomials, which
//! [`Bundle::decompress`](crate::Bundle::decompress) rebuilds from
//! the published bodies. Merging concatenates them and unmerging removes one
//! occurrence per divisor occurrence, so no later operation takes descriptors.

use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};

use derive_more::{Debug, Display, Error};
use polynomials::AggregatorRank;
use ragu::{
    AcceleratedProver, Application, CompressedProof, Pcd,
    circuits::polynomials,
    pasta::Pasta,
    pcd::profile::{Aggregator, Profiled},
};
use rand_core::CryptoRng;

use super::{
    Stamp,
    proof::{
        HEADER_SIZE,
        transaction::{Transaction, TransactionMerge, TransactionUnmerge},
    },
};
use crate::{
    ActionDigest, ActionSetPoly, Anchor, Tachygram, TachygramSetCommit, TachygramSetPoly, witness,
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
    /// Returns a Ragu error if the witness polynomials cannot be encoded or
    /// proving fails.
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
    ) -> ragu::Result<Self> {
        self.actions.extend(right.actions);
        self.tachygrams.extend(right.tachygrams);
        let witness = witness::transaction_merge(
            (*self.pcd.data(), *right.pcd.data()),
            ActionSetPoly::try_from_roots(self.actions.iter().copied())?,
            TachygramSetPoly::try_from_roots(self.tachygrams.iter().copied())?,
        );
        let (pcd, ()) = app.fuse(rng, TransactionMerge, witness, self.pcd, right.pcd)?;
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
            ActionSetPoly::try_from_roots(self.actions.iter().copied())
                .map_err(UnmergeError::Proof)?,
            TachygramSetPoly::try_from_roots(self.tachygrams.iter().copied())
                .map_err(UnmergeError::Proof)?,
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
    /// # Errors
    /// Returns a Ragu error if rerandomization or compression fails.
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
    ) -> ragu::Result<Stamp<CompressedProof<Profiled<Pasta, Aggregator<HEADER_SIZE>>>>> {
        let anchor = self.anchor();
        let [_, tachygrams] = self.pcd.commitments();
        let refreshed = app.rerandomize(self.pcd, &mut *rng)?;
        let (frame, _) = app.compress(&refreshed, rng)?.into_parts();
        Ok(Stamp {
            anchor,
            tachygram_set: TachygramSetCommit::from(tachygrams),
            adjuncts: self.adjuncts,
            proof: Box::new(frame),
        })
    }
}
