//! Spend nullifier-binding header and step.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};

use super::{delegation::NoteNullifiers, spendable::NoteSpendable};
use crate::{
    collections::indexed_multiset,
    note,
    nullifier::Nullifier,
    primitives::{Anchor, NfSeqPoly},
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

/// Header binding a spend to its lineage note and epoch nullifier pair.
///
/// Carries the note commitment `cm`, the lineage's nullifier and its
/// neighbour `(nf_current, nf_next)` confirmed against the covering range, and
/// the pool `anchor`. `nf_next` is the member at `epoch_current + 1`;
/// [`SpendStamp`](super::stamp::SpendStamp) publishes the pair unordered,
/// and `_next` records how [`SpendBind`] established it. The action pair
/// `(cv, rk)` is produced downstream at
/// [`SpendStamp`](super::stamp::SpendStamp).
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

/// Confirms a spend's epoch nullifier pair against a covering
/// [`NoteNullifiers`] and binds it to the spendable lineage.
///
/// The range is tied to the lineage's note by `nullifiers_cm == spendable_cm`
/// (both are the note commitment, bound where the range was derived and at
/// [`SpendableInit`](super::spendable::SpendableInit) respectively), so no
/// note witness is needed here. Any range covering the lineage's epoch and
/// the next serves: the divisibility
/// of `nf_seq` by the product of the `nf_current` factor at $e$, the
/// `nf_next` factor at $e+1$, and the complement confirms the pair
/// at adjacent epochs, with `nf_current` pinned against the spendable. Both
/// nullifiers are emitted on the [`SpendHeader`] for the action-producing
/// step to publish.
///
/// # Soundness
///
/// Neither epoch index is free. The current member's scalars are left-header
/// fields, fixed by the recursive verification of the spendable PCD, and
/// adjacency is the pair's own epochs `e` and `e + 1`. `nf_next` is free, the
/// divisibility forcing it to the range's member at `e + 1`.
///
/// The step compares no bounds against the derivation's range, the
/// divisibility concluding coverage.
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = NoteSpendable;
    type Output = SpendHeader;
    type Right = NoteNullifiers;
    /// `(nf_seq, complement_seq, nf_next)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, Nullifier);

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (nf_seq, complement_seq, nf_next): Self::Witness<'source>,
        (spendable_cm, (spendable_epoch_current, nf_current), anchor): <Self::Left as Header>::Data,
        (nullifiers_cm, _, nf_commit, _): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(nullifiers_cm) - Fp::from(spendable_cm),
            "SpendBind: derived range does not match note",
        )?;
        enforce_equal_point(
            Eq::from(nf_seq.commit()),
            Eq::from(nf_commit),
            "SpendBind: covering sequence does not match header",
        )?;

        // The 2-wide read at the lineage's epoch: the divisibility
        // `nf_seq = current · next · complement` at a challenge absorbing the
        // witnessed commitments; the current member is native from the
        // spendable header, pinned by the recursive verification of the left
        // PCD.
        let z = ctx.derive_challenge(&[nf_seq.commit().into(), complement_seq.commit().into()])?;
        let nf_seq_at_z = nf_seq.eval(z);
        ctx.enforce_poly_query(nf_seq.commit().into(), z, nf_seq_at_z)?;

        let complement_at_z = complement_seq.eval(z);
        ctx.enforce_poly_query(complement_seq.commit().into(), z, complement_at_z)?;

        // The pair read needs a following epoch; the final epoch has none.
        let epoch_next = spendable_epoch_current.next().ok_or_else(|| {
            ragu_core::Error::InvalidWitness("SpendBind: no epoch follows the spend epoch".into())
        })?;
        let pair_at_z = indexed_multiset::direct_eval(
            [
                (spendable_epoch_current.into(), nf_current.into()),
                (epoch_next.into(), nf_next.into()),
            ],
            z,
        );
        enforce_zero(
            nf_seq_at_z - pair_at_z * complement_at_z,
            "SpendBind: nullifier pair does not match the derivation",
        )?;

        // A zero nullifier would collide with the note's own cm tachygram.
        enforce_nonzero(
            Fp::from(nf_current),
            "SpendBind: current-epoch nullifier is zero",
        )?;
        enforce_nonzero(Fp::from(nf_next), "SpendBind: next-epoch nullifier is zero")?;

        Ok(((spendable_cm, nf_current, nf_next, anchor), ()))
    }
}
