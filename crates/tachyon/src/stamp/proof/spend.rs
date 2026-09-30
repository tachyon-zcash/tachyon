//! Spend nullifier-binding header and step.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};

use super::{delegation::NoteMaster, spendable::NoteSpendable};
use crate::{
    note,
    nullifier::Nullifier,
    primitives::Anchor,
    ragu_constraint::{enforce_nonzero, enforce_zero},
};

/// Header binding a spend to its lineage note and epoch nullifier pair.
///
/// Carries the note commitment `cm`, the lineage's nullifier and its
/// neighbour `(nf_current, nf_next)` derived from the note's master key, and
/// the pool `anchor`. [`SpendStamp`](super::stamp::SpendStamp) publishes
/// the pair unordered and produces the action pair `(cv, rk)`.
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    /// `(cm, nf_current, nf_next, anchor)`. `cm` binds the spent note;
    /// `nf_current` is the lineage's member and `nf_next` its neighbour one
    /// epoch on; `anchor` threads the spendable lineage's pool position.
    type Data = (note::Commitment, Nullifier, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, nf_current, nf_next, anchor) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(nf_current),
                Fp::from(nf_next),
                Fp::from(anchor),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Derives a spend's epoch nullifier pair from the note's master key and
/// binds it to the spendable lineage.
///
/// The master is tied to the lineage's note by `master_cm == spendable_cm`.
/// The pair is `mk`'s nullifiers at the lineage's epoch $e$ and at $e + 1$,
/// one group sponge each. Both are emitted on the [`SpendHeader`] for the
/// action-producing step to publish.
///
/// # Soundness
///
/// `mk` and `cm` are threaded from the right header, bound together at
/// [`NoteSeed`](super::delegation::NoteSeed). `epoch_current` is a left-header
/// field, and $e + 1$ comes from
/// [`EpochIndex::next`](crate::primitives::EpochIndex::next). The pair is
/// computed from threaded values only, so nothing in it is free.
///
/// Two sponges run whether or not $e$ and $e + 1$ share a group.
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = NoteSpendable;
    type Output = SpendHeader;
    type Right = NoteMaster;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (spendable_cm, spendable_epoch_current, anchor): <Self::Left as Header>::Data,
        (master_cm, _note, mk): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(master_cm) - Fp::from(spendable_cm),
            "SpendBind: master does not match note",
        )?;

        // The pair needs a following epoch; the final epoch has none.
        let epoch_next = spendable_epoch_current.next().ok_or_else(|| {
            ragu_core::Error::InvalidWitness("SpendBind: no epoch follows the spend epoch".into())
        })?;

        // TODO: a real circuit needs a low-bit decomposition of each epoch for
        // its group start and position; mock ragu computes both natively.
        let nf_current = mk.derive_nullifier(spendable_epoch_current);
        let nf_next = mk.derive_nullifier(epoch_next);

        // A zero nullifier would collide with the note's own cm tachygram.
        enforce_nonzero(
            Fp::from(nf_current),
            "SpendBind: current-epoch nullifier is zero",
        )?;
        enforce_nonzero(Fp::from(nf_next), "SpendBind: next-epoch nullifier is zero")?;

        Ok(((spendable_cm, nf_current, nf_next, anchor), ()))
    }
}
