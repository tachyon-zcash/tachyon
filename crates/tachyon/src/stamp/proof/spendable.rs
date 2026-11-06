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

use alloc::vec::Vec;

use ragu::{
    header::{Header, Suffix},
    step::{Encoded, HeaderInput, Index, Oracles, Slot, Step},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::Pasta,
};
use ragu_primitives::{Element, allocator::Allocator, io::Write};

use super::{delegation::NoteNullifiers, pool::NoteUnspent, qr::QrBucket};
use crate::{
    note,
    pasta::Fp,
    primitives::{Anchor, EpochIndex, TachygramSetPoly},
    ragu_constraint::enforce_zero,
};

/// Wallet's spendable position, certified up to this point in every
/// coordinate.
///
/// `cm` keeps the spent value from drifting to a different same-`mk` note.
#[derive(Clone, Debug)]
pub struct NoteSpendable;

/// `NoteSpendable` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct NoteSpendableOutput<'dr, D: Driver<'dr>> {
    /// `cm`.
    pub cm: Element<'dr, D>,
    /// `epoch_current`.
    pub epoch_current: Element<'dr, D>,
    /// `anchor`.
    pub anchor: Element<'dr, D>,
}

impl Header<Fp> for NoteSpendable {
    /// `(cm, epoch_current, anchor)`. `cm` threads unchanged; the rest
    /// advances per lift. A lift checks continuity by meeting this point with
    /// a [`NoteUnspent`] segment's near end.
    type Data = (note::Commitment, EpochIndex, Anchor);
    type Output = Kind![Fp; NoteSpendableOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(NoteSpendableOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?,
            epoch_current: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            anchor: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?,
        })
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

impl Step<Pasta> for SpendableInit {
    type Aux<'source> = ();
    type Left = NoteNullifiers;
    type Output = NoteSpendable;
    type Right = ();
    /// `(anchor_prev, creation_set, creation_epoch)`
    type Witness<'source> = (Anchor, TachygramSetPoly, EpochIndex);

    const INDEX: Index = Index::new(4);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[1] = super::coefficients(witness.1.as_ref());
        Ok(polynomials)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let native = D::try_just(|| {
            let (anchor_prev, creation_set, creation_epoch) = witness.take();
            let (cm, ..) = left.take();
            let () = right.take();
            let creation_commit = creation_set.commit();
            // The anchor immediately after the creation stamp, computed in-circuit
            // so the proof certifies the fold of `epoch` and `creation_commit`;
            // consensus membership of the eventual spend anchor binds the rest
            // (see the step doc).
            let anchor = anchor_prev
                .next_stamp(creation_epoch, &creation_commit)
                .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
            Ok((creation_set, cm, (cm, creation_epoch, anchor)))
        })?;
        let x = Element::alloc(dr, &mut (), native.clone().map(|(_, cm, _)| Fp::from(cm)))?;
        // Inclusion: cm ∈ set ⇔ the set polynomial vanishes at cm.
        let evaluation = oracles.query(dr, Slot::output(1), &x)?;
        evaluation.enforce_zero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendableInit: commitment not in set".into())
        })?;
        let data = native.map(|(_, _, output)| output);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
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

impl Step<Pasta> for QrSpendableInit {
    type Aux<'source> = ();
    type Left = NoteUnspent;
    type Output = NoteSpendable;
    type Right = QrBucket;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(22);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let native = D::try_just(|| {
            let (
                cm,
                unspent_anchor_start,
                unspent_epoch_start,
                unspent_epoch_next,
                unspent_anchor_next,
            ) = left.take();
            let (bucket_epoch, bucket_anchor_start, bucket_anchor_next, ..) = right.take();
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
            Ok((cm, bucket_epoch_next, unspent_anchor_next))
        })?;
        let x = Element::alloc(dr, &mut (), native.clone().map(|(cm, ..)| Fp::from(cm)))?;
        // Inclusion: cm ∈ bucket ⇔ the contents vanish at cm.
        let evaluation = oracles.query(dr, Slot::right(0), &x)?;
        evaluation.enforce_zero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("QrSpendableInit: commitment not in bucket".into())
        })?;
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), native.clone())?;
        Ok(((left_encoded, right_encoded, encoded), native, D::unit()))
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

impl Step<Pasta> for SpendableLift {
    type Aux<'source> = ();
    type Left = NoteSpendable;
    type Output = NoteSpendable;
    type Right = NoteUnspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(5);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let () = witness.take();
            let (spendable_cm, spendable_epoch_current, spendable_anchor) = left.take();
            let (
                unspent_cm,
                unspent_anchor_start,
                unspent_epoch_start,
                unspent_epoch_next,
                unspent_anchor_next,
            ) = right.take();
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
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}
