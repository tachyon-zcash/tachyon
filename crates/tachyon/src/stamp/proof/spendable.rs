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

use ragu::{Encoded, Header, Index, Step, StepCtx, pasta::Fp};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use ragu_primitives::{Element, GadgetExt as _};

use super::{delegation::NoteNullifiers, pool::NoteUnspent, qr::QrBucket};
use crate::{
    primitives::{Anchor, EpochIndex, TachygramSetPoly},
    relations::enforce::{bind_poly_handle, poly_handle_limbs},
};

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
    type Shared = ();
    /// `(anchor_prev, creation_set, creation_epoch)`
    type Witness<'source> = (Anchor, TachygramSetPoly, EpochIndex);

    const INDEX: Index = Index::new(4);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
        let handle =
            ctx.witness_polynomial(witness.as_ref().map(|data| data.1.as_ref().clone()))?;
        let previous = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0)),
        )?;
        let epoch = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.2)),
        )?;
        let limbs = poly_handle_limbs(ctx.dr, &handle)?;
        let anchor = crate::gadgets::anchor::AnchorGadget::from(previous)
            .next_stamp(ctx.dr, epoch.clone(), limbs)
            .map(|anchor| anchor.element)?;
        let x = left_encoded.as_gadget().cm.element.clone();
        let evaluation_assignment = ctx.evaluate(&handle, x.value().map(|candidate| *candidate))?;
        let evaluation = Element::alloc(ctx.dr, &mut (), evaluation_assignment)?;
        evaluation.enforce_zero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendableInit: commitment not in set".into())
        })?;
        ctx.enforce_poly_query(&handle, x, evaluation)?;
        let output = D::just(|| {
            (
                left.take().0,
                witness.take().2,
                Anchor::from(*anchor.value().take()),
            )
        });
        let fields = crate::stamp::headers::spendable::NoteSpendableOutput {
            cm: (left_encoded.as_gadget().cm.element.clone()).into(),
            epoch_current: (epoch).into(),
            anchor: (anchor).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            output,
            D::unit(),
        ))
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
    type Shared = ();
    /// `(contents)`
    type Witness<'source> = (TachygramSetPoly,);

    const INDEX: Index = Index::new(22);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
        let bucket_epoch = right_encoded.as_gadget().epoch.element.clone();
        let unspent_epoch = left_encoded.as_gadget().epoch_start.element.clone();
        bucket_epoch
            .enforce_equal(ctx.dr, &unspent_epoch)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrSpendableInit: segment does not start in the bucket's epoch".into(),
                )
            })?;
        let bucket_start = right_encoded.as_gadget().anchor_start.element.clone();
        let unspent_start = left_encoded.as_gadget().anchor_start.element.clone();
        bucket_start
            .enforce_equal(ctx.dr, &unspent_start)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrSpendableInit: segment does not open where the bucket does".into(),
                )
            })?;
        let bucket_end = right_encoded.as_gadget().anchor_next.element.clone();
        let unspent_end = left_encoded.as_gadget().anchor_next.element.clone();
        bucket_end
            .enforce_equal(ctx.dr, &unspent_end)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrSpendableInit: segment does not close where the bucket does".into(),
                )
            })?;
        let next = crate::gadgets::epoch::EpochIndexGadget::from((bucket_epoch).clone())
            .next(ctx.dr)
            .map(|epoch| epoch.element)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("QrSpendableInit: bucket has no next epoch".into())
            })?;
        let unspent_next = left_encoded.as_gadget().epoch_next.element.clone();
        next.enforce_equal(ctx.dr, &unspent_next).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrSpendableInit: segment does not end in the epoch after the bucket's".into(),
            )
        })?;
        let contents_handle =
            ctx.witness_polynomial(witness.as_ref().map(|data| data.0.as_ref().clone()))?;
        bind_poly_handle(
            ctx,
            &contents_handle,
            &right_encoded.as_gadget().contents.encoding.limbs,
            "QrSpendableInit: contents do not match the bucket",
        )?;
        let x = left_encoded.as_gadget().cm.element.clone();
        let evaluation_assignment =
            ctx.evaluate(&contents_handle, x.value().map(|candidate| *candidate))?;
        let evaluation = Element::alloc(ctx.dr, &mut (), evaluation_assignment)?;
        evaluation.enforce_zero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("QrSpendableInit: commitment not in bucket".into())
        })?;
        ctx.enforce_poly_query(&contents_handle, x, evaluation)?;
        let output = D::just(|| {
            let data = left.take();
            (
                data.0,
                crate::gadgets::epoch::EpochIndexGadget::from((next).clone())
                    .value()
                    .take(),
                data.4,
            )
        });
        let fields = crate::stamp::headers::spendable::NoteSpendableOutput {
            cm: (left_encoded.as_gadget().cm.element.clone()).into(),
            epoch_current: (next).into(),
            anchor: (unspent_end).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            output,
            D::unit(),
        ))
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
    type Shared = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(5);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let spendable_cm = left_encoded.as_gadget().cm.element.clone();
        let unspent_cm = right_encoded.as_gadget().cm.element.clone();
        spendable_cm
            .enforce_equal(ctx.dr, &unspent_cm)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "SpendableLift: unspent cm does not match spendable".into(),
                )
            })?;
        let spendable_epoch = left_encoded.as_gadget().epoch_current.element.clone();
        let unspent_epoch = right_encoded.as_gadget().epoch_start.element.clone();
        spendable_epoch
            .enforce_equal(ctx.dr, &unspent_epoch)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "SpendableLift: segment does not start at the lineage epoch".into(),
                )
            })?;
        let spendable_anchor = left_encoded.as_gadget().anchor.element.clone();
        let unspent_anchor = right_encoded.as_gadget().anchor_start.element.clone();
        spendable_anchor
            .enforce_equal(ctx.dr, &unspent_anchor)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "SpendableLift: unspent not adjacent to spendable".into(),
                )
            })?;
        let output = D::just(|| {
            let (output_cm, ..) = left.take();
            let (_, _, _, unspent_epoch_next, unspent_anchor_next) = right.take();
            (output_cm, unspent_epoch_next, unspent_anchor_next)
        });
        let fields = crate::stamp::headers::spendable::NoteSpendableOutput {
            cm: (spendable_cm).into(),
            epoch_current: (right_encoded.as_gadget().epoch_next.element.clone()).into(),
            anchor: (right_encoded.as_gadget().anchor_next.element.clone()).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            output,
            D::unit(),
        ))
    }
}

pub use crate::stamp::headers::spendable::NoteSpendable;
