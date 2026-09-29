//! Spendable bootstrap and lift.
//!
//! The spendable carries `(cm, (epoch_current, nf_current), anchor)`: the
//! note's current epoch and its nullifier `F_mk(epoch_current)` there, its
//! pool position, and the minted-note commitment binding the lineage (and its
//! value) across lifts. [`SpendableInit`] bootstraps it from a minted note,
//! [`SummarySpendableInit`] from a [`Summary`] covering the creation, and
//! [`QrSpendableInit`] from a [`QrBucket`] holding the creation over the
//! note's own [`NoteUnspent`] for that epoch; [`SpendableLift`] advances it
//! over [`NoteUnspent`] segments.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};
use ragu_arithmetic::{Cycle as _, FixedGenerators as _};
use ragu_pasta::Pasta;

use super::{delegation::NoteNullifiers, pool::NoteUnspent, qr::QrBucket, summary::Summary};
use crate::{
    collections::indexed_multiset,
    note,
    nullifier::Nullifier,
    primitives::{Anchor, EpochIndex, NfSeqPoly, TachygramSetPoly},
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

/// Wallet's spendable position, certified up to this point in every
/// coordinate.
///
/// `cm` keeps the spent value from drifting to a different same-`mk` note.
#[derive(Clone, Debug)]
pub struct NoteSpendable;

impl Header for NoteSpendable {
    /// `(cm, (epoch_current, nf_current), anchor)`. `cm` threads unchanged;
    /// the rest advances per lift. A lift checks continuity by meeting this
    /// point with a [`NoteUnspent`] segment's near end.
    type Data = (note::Commitment, (EpochIndex, Nullifier), Anchor);

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, (epoch_current, nf_current), anchor) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(epoch_current),
                Fp::from(nf_current),
                Fp::from(anchor),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Bootstrap a spendable from a minted note, pinned to the creation epoch.
///
/// Wallet-only, one-child over any [`NoteNullifiers`] covering the
/// creation epoch, so one derived window feeds init, bind, and spend alike.
/// The divisibility of `nf_seq` by the `nf_current` factor at
/// `creation_epoch` times the complement forces `nf_current` to the window's
/// genuine member there, the complement absorbing the remaining span.
/// `cm` is proven among the creation stamp's tachygrams, and the post-cm
/// anchor folds from a free-witnessed predecessor.
///
/// # Soundness
///
/// Every free witness closes through consensus or the read. `anchor_prev`,
/// `creation_epoch` and the creation set close through consensus anchor
/// membership: the fold absorbs the epoch and the set commit, a genuine
/// chain node is `H(prev || epoch || commit)` under the stamp domain, and
/// preimage resistance forces all three once the eventual spend's anchor is
/// consensus-checked, a wrong epoch landing off the published sequence.
///
/// `nf_current` closes through the read, the identity forcing it to the
/// emitted pair.
///
/// `creation_epoch` needs no bound check against the derivation's range. The
/// divisibility forces the `nf_current` factor to
/// be one of the derivation's own members, so the epoch is one the derivation
/// holds a member for.
///
/// Nothing ties this window to the one the spend later reads; `cm` equality
/// binds every window of the same note.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = NoteNullifiers;
    type Output = NoteSpendable;
    type Right = ();
    /// `(anchor_prev, creation_set, creation_epoch, nf_current, nf_seq,
    /// complement_seq)`.
    type Witness<'source> = (
        Anchor,
        TachygramSetPoly,
        EpochIndex,
        Nullifier,
        NfSeqPoly,
        NfSeqPoly,
    );

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, creation_set, creation_epoch, nf_current, nf_seq, complement_seq): Self::Witness<
            'source,
        >,
        (cm, _, nf_commit, _): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(nf_seq.commit()),
            Eq::from(nf_commit),
            "SpendableInit: covering sequence does not match header",
        )?;

        // The 1-wide read at the creation epoch: the divisibility
        // `nf_seq = read · complement` at a challenge absorbing the witnessed
        // commitments.
        let z = ctx.derive_challenge(&[nf_seq.commit().into(), complement_seq.commit().into()])?;
        let nf_seq_at_z = nf_seq.eval(z);
        ctx.enforce_poly_query(nf_seq.commit().into(), z, nf_seq_at_z)?;

        let complement_at_z = complement_seq.eval(z);
        ctx.enforce_poly_query(complement_seq.commit().into(), z, complement_at_z)?;

        let read_at_z =
            indexed_multiset::direct_eval([(creation_epoch.into(), nf_current.into())], z);
        enforce_zero(
            nf_seq_at_z - read_at_z * complement_at_z,
            "SpendableInit: nullifier does not match the derivation",
        )?;

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

        Ok(((cm, (creation_epoch, nf_current), anchor), ()))
    }
}

/// Bootstrap a spendable from a [`Summary`] covering the note's creation.
///
/// [`SpendableInit`] with the summary in place of the creating stamp: `cm` is
/// proven among the summarized tachygrams, `nf_current` absent from them, and
/// the spendable emits at `anchor_end`. The same divisibility read, at a
/// challenge absorbing `nf_current`, forces it to the window's member at the
/// creation epoch.
///
/// # Soundness
///
/// The summary's `epoch` is absorbed into every anchor link, so a wrong epoch
/// lands the summary off the published anchor sequence, and
/// `summary_epoch == creation_epoch` carries that binding into the read.
/// Stamps before the creation exclude `nf_current` vacuously, so one
/// accumulator serves both openings.
#[derive(Debug)]
pub struct SummarySpendableInit;

impl Step for SummarySpendableInit {
    type Aux<'source> = ();
    type Left = NoteNullifiers;
    type Output = NoteSpendable;
    type Right = Summary;
    /// `(creation_epoch, nf_current, nf_seq, complement_seq, summary_set)`
    type Witness<'source> = (
        EpochIndex,
        Nullifier,
        NfSeqPoly,
        NfSeqPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(20);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (creation_epoch, nf_current, nf_seq, complement_seq, summary_set): Self::Witness<'source>,
        (cm, _, nf_commit, _): <Self::Left as Header>::Data,
        (summary_epoch, _summary_anchor_prev, summary_anchor_end, summary_acc_commit): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(nf_seq.commit()),
            Eq::from(nf_commit),
            "SummarySpendableInit: covering sequence does not match header",
        )?;
        enforce_equal_point(
            Eq::from(summary_set.commit()),
            Eq::from(summary_acc_commit),
            "SummarySpendableInit: accumulator does not match header",
        )?;
        enforce_zero(
            Fp::from(summary_epoch) - Fp::from(creation_epoch),
            "SummarySpendableInit: summary epoch must match the creation epoch",
        )?;

        // The 1-wide read at the creation epoch, as at `SpendableInit`.
        let z =
            ctx.derive_challenge(&[nf_seq.commit().into(), complement_seq.commit().into(), {
                // The mock absorbs only points, so absorb `[nf_current]·G_0`.
                #[expect(clippy::expect_used, reason = "constant size")]
                let &g0 = Pasta::host_generators(Pasta::baked())
                    .g()
                    .first()
                    .expect("at least one generator");
                g0 * Fp::from(nf_current)
            }])?;
        let nf_seq_at_z = nf_seq.eval(z);
        ctx.enforce_poly_query(nf_seq.commit().into(), z, nf_seq_at_z)?;

        let complement_at_z = complement_seq.eval(z);
        ctx.enforce_poly_query(complement_seq.commit().into(), z, complement_at_z)?;

        let read_at_z =
            indexed_multiset::direct_eval([(creation_epoch.into(), nf_current.into())], z);
        enforce_zero(
            nf_seq_at_z - read_at_z * complement_at_z,
            "SummarySpendableInit: nullifier does not match the derivation",
        )?;

        // Inclusion: cm ∈ summary ⇔ the accumulator vanishes at cm.
        let cm_in_summary = summary_set.eval(cm.into());
        ctx.enforce_poly_query(summary_set.commit().into(), cm.into(), cm_in_summary)?;
        enforce_zero(
            cm_in_summary,
            "SummarySpendableInit: commitment not in summary",
        )?;

        // Exclusion: nf ∉ summary ⇔ the accumulator is nonzero at nf.
        let nf_point = Fp::from(nf_current);
        let nf_in_summary = summary_set.eval(nf_point);
        ctx.enforce_poly_query(summary_set.commit().into(), nf_point, nf_in_summary)?;
        enforce_nonzero(
            nf_in_summary,
            "SummarySpendableInit: found nullifier in summary",
        )?;

        Ok(((cm, (creation_epoch, nf_current), summary_anchor_end), ()))
    }
}

/// Bootstrap a spendable from a [`QrBucket`] holding the note's creation,
/// over the note's [`NoteUnspent`] for that epoch.
///
/// The `NoteUnspent` is the epoch's QR segment bound to the note
/// ([`QrUnspentInit`](super::qr::QrUnspentInit) then
/// [`UnspentBind`](super::pool::UnspentBind)), so `cm` and the whole-epoch
/// absence of the note's nullifier arrive on its header. This step adds the
/// membership $\mathsf{contents}(\mathsf{cm}) = 0$ and emits the spendable at
/// the segment's `anchor_end`. [`QrBucketSeal`](super::qr::QrBucketSeal)
/// performs the boundary digest, so that anchor is the entry anchor of the
/// epoch after the bucket's and the lineage is already across.
///
/// # Soundness
///
/// Membership needs no profile. Every bucket divides the epoch's stamp
/// polynomials, root through split and merge, so a root of any bucket is a
/// tachygram published in the bucket's span. The two extents coincide by
/// equality at both ends: `anchor_end` is emitted and reaches consensus
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

    const INDEX: Index = Index::new(28);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (contents,): Self::Witness<'source>,
        (
            cm,
            unspent_anchor_prev,
            (unspent_epoch_start, _),
            (unspent_epoch_end, unspent_nf_end),
            unspent_anchor_end,
        ): <Self::Left as Header>::Data,
        (bucket_epoch, bucket_anchor_prev, bucket_anchor_end, _, _, bucket_commit): <Self::Right as Header>::Data,
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
            Fp::from(unspent_anchor_prev) - Fp::from(bucket_anchor_prev),
            "QrSpendableInit: segment does not open where the bucket does",
        )?;
        enforce_zero(
            Fp::from(unspent_anchor_end) - Fp::from(bucket_anchor_end),
            "QrSpendableInit: segment does not close where the bucket does",
        )?;
        let bucket_epoch_next = bucket_epoch.next().ok_or_else(|| {
            ragu_core::Error::InvalidWitness("QrSpendableInit: bucket has no next epoch".into())
        })?;
        // Defensive: the anchor equality already rejects a wrong epoch label.
        enforce_zero(
            Fp::from(unspent_epoch_end) - Fp::from(bucket_epoch_next),
            "QrSpendableInit: segment does not end in the epoch after the bucket's",
        )?;

        // Inclusion: cm ∈ bucket ⇔ the contents vanish at cm.
        let cm_in_bucket = contents.eval(cm.into());
        ctx.enforce_poly_query(bucket_commit.into(), cm.into(), cm_in_bucket)?;
        enforce_zero(cm_in_bucket, "QrSpendableInit: commitment not in bucket")?;

        Ok((
            (cm, (unspent_epoch_end, unspent_nf_end), unspent_anchor_end),
            (),
        ))
    }
}

/// Advance the spendable over one [`NoteUnspent`] segment.
///
/// Wallet-only, witness-free. The segment's near end must share the
/// lineage's member in epoch space (`unspent.{epoch,nf}_start ==
/// spendable.{epoch,nf}_current`) and hand off in anchor space
/// (`unspent.anchor_prev == spendable.anchor`). `cm` threads through, and the
/// lineage moves to the segment's far end at
/// `(epoch_end, nf_end, anchor_end)`.
///
/// The segment may span any number of epochs. A lineage resting on its epoch's
/// final anchor advances the same way, over a segment whose first fold is
/// the crossing ([`EndEpochUnspentSeed`](super::pool::EndEpochUnspentSeed)).
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = NoteSpendable;
    type Output = NoteSpendable;
    type Right = NoteUnspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (spendable_cm, (spendable_epoch_current, nf_current), spendable_anchor): <Self::Left as Header>::Data,
        (
            unspent_cm,
            unspent_anchor_prev,
            (unspent_epoch_start, unspent_nf_start),
            (unspent_epoch_end, unspent_nf_end),
            unspent_anchor_end,
        ): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(unspent_cm) - Fp::from(spendable_cm),
            "SpendableLift: unspent cm does not match spendable",
        )?;
        enforce_zero(
            Fp::from(unspent_nf_start) - Fp::from(nf_current),
            "SpendableLift: segment does not start at the lineage nullifier",
        )?;
        enforce_zero(
            Fp::from(unspent_epoch_start) - Fp::from(spendable_epoch_current),
            "SpendableLift: segment does not start at the lineage epoch",
        )?;
        enforce_zero(
            Fp::from(unspent_anchor_prev) - Fp::from(spendable_anchor),
            "SpendableLift: unspent not adjacent to spendable",
        )?;
        Ok((
            (
                spendable_cm,
                (unspent_epoch_end, unspent_nf_end),
                unspent_anchor_end,
            ),
            (),
        ))
    }
}
