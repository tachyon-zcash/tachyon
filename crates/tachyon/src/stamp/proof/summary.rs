//! Epoch summaries: per-epoch tachygram accumulators over runs of stamps.
//!
//! A summary condenses an ordered run of one epoch's stamps: their tachygram
//! sets fold into a single accumulator while the anchor absorbs the same
//! commitments, so a consumer clears the whole run with one exclusion query.
//! Boundaries are prover-chosen and
//! soundness-irrelevant: anchor adjacency forces a consumer through every
//! stamp link regardless of cuts. Summaries are note-independent; any party
//! may build and publish them.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix, constraint::enforce_equal_point};

use crate::{
    primitives::{Anchor, EpochIndex, TachygramSetCommit, TachygramSetPoly},
    relations::enforce::enforce_poly_product,
};

/// One summarized run of an epoch's published tachygrams.
///
/// `acc_commit` commits the root-encoded set polynomial of every tachygram
/// in the run's stamps; `anchor_prev` and `anchor_last` bracket exactly
/// those stamps' anchor links, welded to the accumulator at
/// [`SummaryAdvance`]. A product of root-encoded set polynomials is the root
/// polynomial of the multiset union, so the accumulator is an ordinary
/// [`TachygramSetPoly`] and consumers query it like a stamp's.
#[derive(Clone, Debug)]
pub struct Summary;

impl Header for Summary {
    /// `(epoch, anchor_prev, anchor_last, acc_commit)`.
    type Data = (EpochIndex, Anchor, Anchor, TachygramSetCommit);

    const SUFFIX: Suffix = Suffix::new(14);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_last, acc_commit) = *data;
        (
            vec![
                Fp::from(u64::from(epoch.0)),
                Fp::from(anchor_prev),
                Fp::from(anchor_last),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(acc_commit)],
        )
    }
}

/// Birth a summary from one stamp.
///
/// The accumulator is the stamp's own set commitment and the anchor advances
/// one link: structurally [`AnchorSeed`](super::pool::AnchorSeed), with the
/// commitment carried on the header.
///
/// # Soundness
///
/// Every witness is unconstrained here, as at
/// [`AnchorSeed`](super::pool::AnchorSeed): consensus recomputes the anchor
/// chain from block data, so a summary built on any other anchor, epoch, or
/// commitment ends at an anchor that is not a chain member. Binding closes
/// through the consuming lineage, whose anchors splice the summary's links
/// and close at the eventual spend's consensus anchor membership.
#[derive(Debug)]
pub struct SummarySeed;

impl Step for SummarySeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Summary;
    type Right = ();
    /// `(anchor_prev, epoch, stamp_commit)`.
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetCommit);

    const INDEX: Index = Index::new(17);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, epoch, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let anchor_last = anchor_prev.next_stamp(epoch, &stamp_commit);
        Ok(((epoch, anchor_prev, anchor_last, stamp_commit), ()))
    }
}

/// Fold the next stamp's set into the summary's accumulator while the anchor
/// absorbs the same commitment.
///
/// One-child step. The witnessed accumulator binds to the header by
/// commit-equality, the product relation folds the stamp in, and the anchor
/// link absorbs the same `stamp.commit()`, welding accumulator to anchor: no
/// stamp enters one without the other.
///
/// # Committed polynomials
///
/// | polynomial | role |
/// |---|---|
/// | `acc` | the accumulator so far, bound to the header commit |
/// | `stamp` | the folded stamp's set |
/// | `extended` | the new accumulator, `acc · stamp` |
#[derive(Debug)]
pub struct SummaryAdvance;

impl Step for SummaryAdvance {
    type Aux<'source> = ();
    type Left = Summary;
    type Output = Summary;
    type Right = ();
    /// `(acc, extended, stamp)`.
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (acc, extended, stamp): Self::Witness<'source>,
        (summary_epoch, summary_anchor_prev, summary_anchor_last, summary_acc_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(acc.commit()),
            Eq::from(summary_acc_commit),
            "SummaryAdvance: accumulator does not match header",
        )?;
        enforce_poly_product(
            ctx,
            acc.as_ref(),
            stamp.as_ref(),
            extended.as_ref(),
            "SummaryAdvance: extended accumulator must fold the stamp",
        )?;
        let anchor_last = summary_anchor_last.next_stamp(summary_epoch, &stamp.commit());
        Ok((
            (
                summary_epoch,
                summary_anchor_prev,
                anchor_last,
                extended.commit(),
            ),
            (),
        ))
    }
}
