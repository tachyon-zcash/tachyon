//! Spendable bootstrap and lift.
//!
//! The spendable carries `(cm, epoch_current, anchor)`: the note's current
//! epoch, its pool position, and the minted-note commitment binding the
//! lineage (and its value) across lifts. [`SpendableInit`] bootstraps it from a
//! minted note for a spend in the creation epoch, and [`QrSpendableInit`] from
//! a [`QrBucket`] holding the creation over the note's own [`NoteUnspent`] for
//! that epoch; [`SpendableLift`] advances the latter over [`NoteUnspent`]
//! segments.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};

use super::{delegation::NoteNullifiers, pool::NoteUnspent, qr::QrBucket};
use crate::{
    note,
    primitives::{Anchor, EpochIndex, TachygramSetPoly},
    ragu_constraint::{enforce_equal_point, enforce_zero},
};

/// Wallet's spendable position, certified up to this point in every
/// coordinate.
///
/// `cm` keeps the spent value from drifting to a different same-`mk` note.
#[derive(Clone, Debug)]
pub struct NoteSpendable;

impl Header for NoteSpendable {
    /// `(cm, epoch_current, anchor)`. `cm` threads unchanged; the rest
    /// advances per lift. A lift checks continuity by meeting this point with
    /// a [`NoteUnspent`] segment's near end.
    type Data = (note::Commitment, EpochIndex, Anchor);

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, epoch_current, anchor) = *data;
        (
            vec![Fp::from(cm), Fp::from(epoch_current), Fp::from(anchor)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Bootstrap a spendable from a minted note, pinned to the creation epoch.
///
/// Wallet-only, one-child over any [`NoteNullifiers`], which supplies `cm`.
/// `cm` is proven among the creation stamp's tachygrams, and the post-cm
/// anchor folds from a free-witnessed predecessor.
///
/// # Soundness
///
/// `anchor_prev`, `creation_epoch` and the creation set close through
/// consensus anchor membership: the fold absorbs the epoch and the set commit,
/// a genuine chain node is `H(prev || epoch || commit)` under the stamp
/// domain, and preimage resistance forces all three once the eventual spend's
/// anchor is consensus-checked, a wrong epoch landing off the published
/// sequence.
///
/// The step tests no exclusion. The spendable sits immediately after the
/// creation stamp, so the only stamp it covers is the one creating the note,
/// and a spend inside that stamp would need an anchor folding in the stamp's
/// own tachygrams.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = NoteNullifiers;
    type Output = NoteSpendable;
    type Right = ();
    /// `(anchor_prev, creation_set, creation_epoch)`
    type Witness<'source> = (Anchor, TachygramSetPoly, EpochIndex);

    const INDEX: Index = Index::new(6);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, creation_set, creation_epoch): Self::Witness<'source>,
        (cm, ..): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Inclusion: cm ∈ set ⇔ the set polynomial vanishes at cm.
        let cm_in_set = creation_set.eval(cm.into());
        ctx.enforce_poly_query(creation_set.commit().into(), cm.into(), cm_in_set)?;
        enforce_zero(cm_in_set, "SpendableInit: commitment not in set")?;
        let creation_commit = creation_set.commit();

        // The anchor immediately after the creation stamp, computed in-circuit
        // so the proof certifies the fold of `epoch` and `creation_commit`;
        // consensus membership of the eventual spend anchor binds the rest
        // (see the step doc).
        let anchor = anchor_prev
            .next_stamp(creation_epoch, &creation_commit)
            .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;

        Ok(((cm, creation_epoch, anchor), ()))
    }
}

/// Bootstrap a spendable from a [`QrBucket`] holding the note's creation,
/// over the note's [`NoteUnspent`] for that epoch.
///
/// The `NoteUnspent` is the epoch's QR segment bound to the note
/// ([`QrUnspentInit`](super::qr::QrUnspentInit) then
/// [`UnspentBind`](super::pool::UnspentBind)), so `cm` and the whole-epoch
/// absence of the note's nullifier arrive on its header. This step adds the
/// membership $\mathsf{contents}(\mathsf{cm}) = 0$ and emits the spendable on
/// the segment's `(epoch_next, anchor_next)`: the entry anchor of the epoch
/// after the bucket's, which [`QrBucketSeal`](super::qr::QrBucketSeal)
/// computed.
///
/// # Soundness
///
/// Membership needs no profile. Every bucket divides the epoch's stamp
/// polynomials, root through split and merge, so a root of any bucket is a
/// tachygram published in the bucket's span. The two extents coincide by
/// equality at both ends: `anchor_next` is emitted and reaches consensus
/// through the lineage, so the stamp commitments absorbed across the span are
/// the published ones. Without that equality a bucket over invented stamps
/// onto the real entry anchor would pass the opening.
#[derive(Debug)]
pub struct QrSpendableInit;

impl Step for QrSpendableInit {
    type Aux<'source> = ();
    type Left = NoteUnspent;
    type Output = NoteSpendable;
    type Right = QrBucket;
    /// `(contents)`
    type Witness<'source> = (TachygramSetPoly,);

    const INDEX: Index = Index::new(24);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (contents,): Self::Witness<'source>,
        (
            cm,
            unspent_anchor_start,
            unspent_epoch_start,
            unspent_epoch_next,
            unspent_anchor_next,
        ): <Self::Left as Header>::Data,
        (bucket_epoch, bucket_anchor_start, bucket_anchor_next, _, _, bucket_commit): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(contents.commit()),
            Eq::from(bucket_commit),
            "QrSpendableInit: contents do not match the bucket",
        )?;
        enforce_zero(
            Fp::from(unspent_epoch_start) - Fp::from(bucket_epoch),
            "QrSpendableInit: segment does not start in the bucket's epoch",
        )?;
        enforce_zero(
            Fp::from(unspent_anchor_start) - Fp::from(bucket_anchor_start),
            "QrSpendableInit: segment does not open where the bucket does",
        )?;
        enforce_zero(
            Fp::from(unspent_anchor_next) - Fp::from(bucket_anchor_next),
            "QrSpendableInit: segment does not close where the bucket does",
        )?;
        let bucket_epoch_next = bucket_epoch.next().ok_or_else(|| {
            ragu_core::Error::InvalidWitness("QrSpendableInit: bucket has no next epoch".into())
        })?;
        // Defensive: the anchor equality already rejects a wrong epoch label.
        enforce_zero(
            Fp::from(unspent_epoch_next) - Fp::from(bucket_epoch_next),
            "QrSpendableInit: segment does not end in the epoch after the bucket's",
        )?;

        // Inclusion: cm ∈ bucket ⇔ the contents vanish at cm.
        let cm_in_bucket = contents.eval(cm.into());
        ctx.enforce_poly_query(bucket_commit.into(), cm.into(), cm_in_bucket)?;
        enforce_zero(cm_in_bucket, "QrSpendableInit: commitment not in bucket")?;

        Ok(((cm, unspent_epoch_next, unspent_anchor_next), ()))
    }
}

/// Advance the spendable over one [`NoteUnspent`] segment.
///
/// Wallet-only, witness-free. The segment's near end must share the
/// lineage's epoch (`unspent.epoch_start == spendable.epoch_current`) and hand
/// off in anchor space (`unspent.anchor_start == spendable.anchor`). `cm`
/// threads through, and the lineage moves to the segment's far boundary
/// `(epoch_next, anchor_next)`.
///
/// The segment may span any number of epochs. Every segment opens on an entry
/// anchor, so only a lineage resting on one can lift: a [`QrSpendableInit`]
/// spendable, or one already lifted. A [`SpendableInit`] spendable spends in
/// its creation epoch.
///
/// # Soundness
///
/// [`UnspentBind`](super::pool::UnspentBind) makes every member of the segment
/// the genuine nullifier of `cm` at its epoch, so equal `cm` and `epoch_start`
/// fix the member the segment starts on. No nullifier needs comparing.
///
/// The lineage then rests on the entry anchor of `epoch_next`, certified for
/// every epoch before it. The spend's anchor epoch is consensus's to scan.
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = NoteSpendable;
    type Output = NoteSpendable;
    type Right = NoteUnspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (spendable_cm, spendable_epoch_current, spendable_anchor): <Self::Left as Header>::Data,
        (
            unspent_cm,
            unspent_anchor_start,
            unspent_epoch_start,
            unspent_epoch_next,
            unspent_anchor_next,
        ): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(unspent_cm) - Fp::from(spendable_cm),
            "SpendableLift: unspent cm does not match spendable",
        )?;
        enforce_zero(
            Fp::from(unspent_epoch_start) - Fp::from(spendable_epoch_current),
            "SpendableLift: segment does not start at the lineage epoch",
        )?;
        enforce_zero(
            Fp::from(unspent_anchor_start) - Fp::from(spendable_anchor),
            "SpendableLift: unspent not adjacent to spendable",
        )?;
        Ok(((spendable_cm, unspent_epoch_next, unspent_anchor_next), ()))
    }
}
