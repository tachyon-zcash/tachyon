//! Spendable bootstrap and lift.
//!
//! The spendable carries `(cm, (epoch, present_nf), anchor)`: the note's
//! current epoch and its nullifier `F_mk(epoch)` there, its pool position,
//! and the minted-note commitment binding the lineage (and its value) across
//! lifts. [`SpendableInit`]
//! bootstraps it from a minted note and [`SummarySpendableInit`] from a
//! [`Summary`] covering the creation; [`SpendableLift`] advances it over
//! [`Unspent`] segments.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};
use ragu_arithmetic::{Cycle as _, FixedGenerators as _};
use ragu_pasta::Pasta;

use super::{delegation::NullifierDerivation, pool::Unspent, summary::Summary};
use crate::{
    collections::indexed_multiset,
    note,
    nullifier::Nullifier,
    primitives::{Anchor, EpochIndex, NfSeqPoly, TachygramSetPoly},
    relations::constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

/// Wallet's spendable position `(cm, (epoch, present_nf), anchor)`
///
/// The note's current epoch and its nullifier there, plus the pool position
/// (all advanced per lift) and the minted-note commitment, threaded unchanged
/// so the spent value cannot drift to a different same-`mk` note.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    /// `(cm, (epoch, present_nf), anchor)`. `cm` threads unchanged; the rest
    /// advances per lift. The boundary pairing matches
    /// [`Unspent`]'s, which is what a lift checks continuity against.
    type Data = (note::Commitment, (EpochIndex, Nullifier), Anchor);

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, (epoch, present_nf), anchor) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(epoch),
                Fp::from(present_nf),
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
/// Wallet-only, one-child over any [`NullifierDerivation`] covering the
/// creation epoch, so one derived window feeds init, bind, and spend alike.
/// The divisibility
/// $\mathsf{nf\_seq} = F_{\mathsf{creation\_epoch},\mathsf{present\_nf}}
/// \cdot \mathsf{complement}$ forces `present_nf` to the window's genuine
/// member at the creation epoch, the complement absorbing the remaining span.
/// `cm` is proven among the creation stamp's tachygrams, and the post-cm
/// anchor folds from a free-witnessed predecessor.
///
/// # Soundness
///
/// Every free witness closes through consensus or the read. `pre_cm_anchor`,
/// `creation_epoch` and the creation set close through consensus anchor
/// membership: the fold absorbs the epoch and the set commit, a genuine
/// chain node is `H(prev || epoch || commit)` under the stamp domain, and
/// preimage resistance forces all three once the eventual spend's anchor is
/// consensus-checked, a wrong epoch landing off the published sequence.
///
/// `present_nf` closes through the read, pinned by absorbing
/// $G_0 \cdot \mathsf{present\_nf}$, so the identity forces the read to the
/// emitted pair.
///
/// `creation_epoch` needs no bound check against the derivation's range. The
/// divisibility forces $F_{\mathsf{creation\_epoch},\mathsf{present\_nf}}$ to
/// be one of the derivation's own members, so the epoch is one the derivation
/// holds a member for.
///
/// Nothing ties this window to the one the spend later reads; `cm` equality
/// binds every window of the same note.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = NullifierDerivation;
    type Output = SpendableHeader;
    type Right = ();
    /// `(pre_cm_anchor, creation_set, creation_epoch, present_nf, nf_seq,
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
        (pre_cm_anchor, creation_set, creation_epoch, present_nf, nf_seq, complement_seq): Self::Witness<
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
        // commitments and the scalar-binding point of the free `present_nf`.
        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let z = ctx.derive_challenge(&[
            nf_seq.commit().into(),
            complement_seq.commit().into(),
            g0 * Fp::from(present_nf),
        ])?;
        let nf_seq_at_z = nf_seq.eval(z);
        let complement_at_z = complement_seq.eval(z);

        let read_at_z =
            indexed_multiset::direct_eval([(creation_epoch.into(), present_nf.into())], z);
        enforce_zero(
            nf_seq_at_z - read_at_z * complement_at_z,
            "SpendableInit: nullifier does not match the derivation",
        )?;
        ctx.enforce_poly_query(nf_seq.commit().into(), z, nf_seq_at_z)?;
        ctx.enforce_poly_query(complement_seq.commit().into(), z, complement_at_z)?;

        // Inclusion: cm ∈ set ⇔ the set polynomial vanishes at cm.
        let cm_in_set = creation_set.eval(cm.into());
        ctx.enforce_poly_query(creation_set.commit().into(), cm.into(), cm_in_set)?;
        enforce_zero(cm_in_set, "SpendableInit: commitment not in set")?;
        let creation_commit = creation_set.commit();

        // The anchor immediately after the creation stamp, computed in-circuit
        // so the proof certifies the fold of `epoch` and `creation_commit`;
        // consensus membership of the eventual spend anchor binds the rest
        // (see the step doc).
        let post_cm_anchor = pre_cm_anchor
            .next_stamp(creation_epoch, &creation_commit)
            .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;

        Ok(((cm, (creation_epoch, present_nf), post_cm_anchor), ()))
    }
}

/// Bootstrap a spendable from a [`Summary`] covering the note's creation.
///
/// [`SpendableInit`] with the summary in place of the creating stamp: `cm` is
/// proven among the summarized tachygrams, `present_nf` absent from them, and
/// the spendable emits at `anchor_last`. The same divisibility read forces
/// `present_nf` to the window's member at the creation epoch.
///
/// Committed polynomials: `nf_seq`, `complement_seq`, `summary_set`; three
/// oracles.
///
/// # Soundness
///
/// The summary's `epoch` is absorbed into every anchor link, so a wrong epoch
/// brackets the summary off the published anchor sequence, and
/// `summary_epoch == creation_epoch` carries that binding into the read.
/// Stamps before the creation exclude `present_nf` vacuously, so one
/// accumulator serves both openings.
#[derive(Debug)]
pub struct SummarySpendableInit;

impl Step for SummarySpendableInit {
    type Aux<'source> = ();
    type Left = NullifierDerivation;
    type Output = SpendableHeader;
    type Right = Summary;
    /// `(creation_epoch, present_nf, nf_seq, complement_seq, summary_set)`.
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
        (creation_epoch, present_nf, nf_seq, complement_seq, summary_set): Self::Witness<'source>,
        (cm, _, nf_commit, _): <Self::Left as Header>::Data,
        (summary_epoch, _summary_anchor_prev, summary_anchor_last, summary_acc_commit): <Self::Right as Header>::Data,
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
        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let z = ctx.derive_challenge(&[
            nf_seq.commit().into(),
            complement_seq.commit().into(),
            g0 * Fp::from(present_nf),
        ])?;
        let nf_seq_at_z = nf_seq.eval(z);
        let complement_at_z = complement_seq.eval(z);

        let read_at_z =
            indexed_multiset::direct_eval([(creation_epoch.into(), present_nf.into())], z);
        enforce_zero(
            nf_seq_at_z - read_at_z * complement_at_z,
            "SummarySpendableInit: nullifier does not match the derivation",
        )?;
        ctx.enforce_poly_query(nf_seq.commit().into(), z, nf_seq_at_z)?;
        ctx.enforce_poly_query(complement_seq.commit().into(), z, complement_at_z)?;

        // Inclusion: cm ∈ summary ⇔ the accumulator vanishes at cm.
        let cm_in_summary = summary_set.eval(cm.into());
        ctx.enforce_poly_query(summary_set.commit().into(), cm.into(), cm_in_summary)?;
        enforce_zero(
            cm_in_summary,
            "SummarySpendableInit: commitment not in summary",
        )?;

        // Exclusion: nf ∉ summary ⇔ the accumulator is nonzero at nf.
        let nf_point = Fp::from(present_nf);
        let nf_in_summary = summary_set.eval(nf_point);
        ctx.enforce_poly_query(summary_set.commit().into(), nf_point, nf_in_summary)?;
        enforce_nonzero(
            nf_in_summary,
            "SummarySpendableInit: found nullifier in summary",
        )?;

        Ok(((cm, (creation_epoch, present_nf), summary_anchor_last), ()))
    }
}

/// Advance the spendable over one [`Unspent`] segment.
///
/// Wallet-only, witness-free. Checks `cm`, the boundary pair `(epoch_start,
/// nf_start) == (epoch, present_nf)`, and anchor adjacency, then advances to
/// the tip `(epoch_last, nf_last, anchor_last)`.
///
/// The segment may span any number of epochs. A lineage resting on its epoch's
/// terminal anchor advances the same way, over a segment that opens with the
/// boundary tick ([`EndEpochUnspentSeed`](super::pool::EndEpochUnspentSeed)).
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (spendable_cm, (spendable_epoch, present_nf), spendable_anchor): <Self::Left as Header>::Data,
        (
            unspent_cm,
            unspent_anchor_prev,
            (unspent_epoch_start, unspent_nf_start),
            (unspent_epoch_last, unspent_nf_last),
            unspent_anchor_last,
        ): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(unspent_cm) - Fp::from(spendable_cm),
            "SpendableLift: unspent cm does not match spendable",
        )?;
        enforce_zero(
            Fp::from(unspent_nf_start) - Fp::from(present_nf),
            "SpendableLift: segment does not start at the lineage nullifier",
        )?;
        enforce_zero(
            Fp::from(unspent_epoch_start) - Fp::from(spendable_epoch),
            "SpendableLift: segment does not start at the lineage epoch",
        )?;
        enforce_zero(
            Fp::from(unspent_anchor_prev) - Fp::from(spendable_anchor),
            "SpendableLift: unspent not adjacent to spendable",
        )?;
        Ok((
            (
                spendable_cm,
                (unspent_epoch_last, unspent_nf_last),
                unspent_anchor_last,
            ),
            (),
        ))
    }
}
