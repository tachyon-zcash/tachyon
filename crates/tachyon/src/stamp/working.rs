//! Work on the full, typed aggregator-rank transaction.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use ragu::{Rank as _, WalletRank};
use rand_core::CryptoRng;

use super::{
    ProofStamp, PublicationProof,
    proof::{
        aggregator,
        transaction::{TransactionLift, TransactionMerge, TransactionUnmerge},
    },
    sealed,
};
use crate::{
    ActionDigest, ActionSetPoly, Tachygram, TachygramSetCommit, TachygramSetPoly, action, fee,
};

impl sealed::Sealed for aggregator::Transaction {}

type Descriptors<'maps> = &'maps BTreeMap<action::Descriptor, (Tachygram, Tachygram)>;
type Fees<'maps> = &'maps BTreeMap<fee::Descriptor, Tachygram>;
type Maps<'maps> = (Descriptors<'maps>, Fees<'maps>);
type Leaf = (ActionDigest, Tachygram, Option<Tachygram>);

fn leaves((actions, fees): Maps<'_>) -> impl Iterator<Item = Leaf> {
    actions
        .iter()
        .map(|(desc, &pair)| {
            (
                desc.digest(pair),
                pair.0.min(pair.1),
                Some(pair.0.max(pair.1)),
            )
        })
        .chain(
            fees.iter()
                .map(|(desc, &change)| (desc.digest(change), change, None)),
        )
}

fn checked_leaves(
    pcd: &aggregator::Transaction,
    maps: Maps<'_>,
) -> ragu::Result<(Vec<Leaf>, ActionSetPoly)> {
    if maps.0.len().saturating_add(maps.1.len()) >= WalletRank::num_coeffs() {
        return Err(ragu::Error::InvalidWitness(
            "action witness exceeds the wallet polynomial bound".into(),
        ));
    }
    let rows: Vec<_> = leaves(maps).collect();
    let set: ActionSetPoly = rows.iter().map(|row| row.0).collect();
    if pcd.commitments()[1] != set.commit().into() {
        return Err(ragu::Error::InvalidWitness(
            "descriptor maps do not reproduce the working action commitment".into(),
        ));
    }
    Ok((rows, set))
}

fn accumulators(
    rows: impl Iterator<Item = Leaf>,
) -> ragu::Result<(ActionSetPoly, TachygramSetCommit)> {
    let mut digests = Vec::new();
    let mut tachygrams = BTreeSet::new();
    for (digest, first, second) in rows {
        digests.push(digest);
        tachygrams.insert(first);
        tachygrams.extend(second);
        if digests.len() >= WalletRank::num_coeffs() || tachygrams.len() >= WalletRank::num_coeffs()
        {
            return Err(ragu::Error::InvalidWitness(
                "stamp sets exceed the public polynomial bound".into(),
            ));
        }
    }
    Ok((
        digests.into_iter().collect(),
        tachygrams
            .into_iter()
            .collect::<TachygramSetPoly>()
            .commit(),
    ))
}

impl ProofStamp<aggregator::Transaction> {
    fn from_pcd(
        pcd: aggregator::Transaction,
        tachygram_set: TachygramSetCommit,
        adjuncts: BTreeSet<[u8; 32]>,
    ) -> Self {
        Self {
            anchor: pcd.data().1,
            proof: Box::new(pcd),
            tachygram_set,
            adjuncts,
        }
    }

    /// Advance the transaction reference along restored anchor spans.
    /// The native witness supports at most 8,191 action and fee roots.
    /// Supply all covered bodies' distinct action and fee descriptors.
    ///
    /// # Errors
    /// Returns a Ragu error if a witness is too large or proving fails.
    pub fn lift<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &aggregator::App<'_>,
        actions: Descriptors<'_>,
        fees: Fees<'_>,
        spans: Vec<aggregator::Span>,
    ) -> ragu::Result<Self> {
        if spans.is_empty() {
            return Ok(self);
        }
        let (_, set) = checked_leaves(&self.proof, (actions, fees))?;
        let mut pcd = *self.proof;
        for span in spans {
            pcd = app.fuse(rng, TransactionLift, (set.clone(),), pcd, span)?.0;
        }
        Ok(Self::from_pcd(
            app.rerandomize(pcd, rng)?,
            self.tachygram_set,
            self.adjuncts,
        ))
    }

    /// Merge two working transactions at the same reference, retaining the left
    /// host.
    /// The native witness supports up to 8,191 roots in each output set.
    /// Each side's maps must reproduce its full working commitment, as they do
    /// for covered bodies with distinct descriptors.
    ///
    /// # Errors
    /// Returns a Ragu error if a witness is too large or proving fails.
    pub fn merge<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &aggregator::App<'_>,
        left: Maps<'_>,
        (right, id, actions, fees): (Self, [u8; 32], Descriptors<'_>, Fees<'_>),
    ) -> ragu::Result<Self> {
        let (left_rows, _) = checked_leaves(&self.proof, left)?;
        let (right_rows, _) = checked_leaves(&right.proof, (actions, fees))?;
        let (set, tachygrams) = accumulators(left_rows.into_iter().chain(right_rows))?;
        let (pcd, ()) = app.fuse(rng, TransactionMerge, (set,), *self.proof, *right.proof)?;
        let mut adjuncts = self.adjuncts;
        adjuncts.extend(right.adjuncts);
        adjuncts.insert(id);
        Ok(Self::from_pcd(
            app.rerandomize(pcd, rng)?,
            tachygrams,
            adjuncts,
        ))
    }

    /// Divide one working transaction by another at the same reference.
    /// Supply all distinct action and fee descriptors for each side. An input
    /// whose repeated descriptors cannot be represented by its maps is
    /// rejected.
    ///
    /// # Errors
    /// Returns a Ragu error if a witness is too large or proving fails.
    pub fn unmerge<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &aggregator::App<'_>,
        dividend: Maps<'_>,
        (divisor, id, actions, fees): (Self, [u8; 32], Descriptors<'_>, Fees<'_>),
    ) -> ragu::Result<Self> {
        // Remove one occurrence per divisor leaf; equal digests do not identify rows.
        let mut removed = BTreeMap::<_, usize>::new();
        for row in checked_leaves(&divisor.proof, (actions, fees))?.0 {
            *removed.entry(row).or_default() += 1;
        }
        let remaining = checked_leaves(&self.proof, dividend)?
            .0
            .into_iter()
            .filter(|row| {
                if let Some(count) = removed.get_mut(row)
                    && *count != 0
                {
                    *count -= 1;
                    false
                } else {
                    true
                }
            });
        let (set, tachygrams) = accumulators(remaining)?;
        let (pcd, ()) = app.fuse(rng, TransactionUnmerge, (set,), *self.proof, *divisor.proof)?;
        let mut adjuncts = self.adjuncts;
        adjuncts.retain(|txid| id != *txid && !divisor.adjuncts.contains(txid));
        Ok(Self::from_pcd(
            app.rerandomize(pcd, rng)?,
            tachygrams,
            adjuncts,
        ))
    }

    /// Rerandomize and compress the full working transaction for inclusion in a
    /// block.
    ///
    /// # Errors
    /// Returns a Ragu error if rerandomization or compression fails.
    pub fn finalize<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &aggregator::App<'_>,
    ) -> ragu::Result<ProofStamp<PublicationProof>> {
        let anchor = self.proof.data().1;
        let proof = aggregator::finalize(rng, app, *self.proof)?;
        Ok(ProofStamp {
            anchor,
            adjuncts: self.adjuncts,
            tachygram_set: self.tachygram_set,
            proof: Box::new(PublicationProof::Aggregator(proof)),
        })
    }
}

#[cfg(test)]
mod tests;
