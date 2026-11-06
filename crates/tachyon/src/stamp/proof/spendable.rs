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
use ragu_primitives::{Element, GadgetExt as _, allocator::Allocator, io::Write};
use udon::field::Field as _;

use super::{delegation::NoteNullifiers, pool::NoteUnspent, qr::QrBucket};
use crate::{
    digest::poseidon,
    note,
    pasta::Fp,
    primitives::{Anchor, EpochIndex, TachygramSetPoly},
    relations::arithmetic as circuit,
};

/// Wallet's spendable position, certified up to this point in every
/// coordinate.
///
/// `cm` keeps the spent value from drifting to a different same-`mk` note.
/// It threads unchanged while the epoch and anchor advance per lift. A lift
/// checks continuity by meeting this point with a [`NoteUnspent`] segment's
/// near end.
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
    /// `(cm, epoch_current, anchor)`
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
        Ok([
            alloc::vec![Fp::ONE],
            witness.1.as_ref().iter_coeffs().collect(),
        ])
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let previous = Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.0)))?;
        let epoch = Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.2)))?;
        super::enforce_stamp_domain(dr, &epoch, oracles.bridge_hash())?;
        // The anchor immediately after the creation stamp, computed in-circuit
        // so the proof certifies the fold of `epoch` and `creation_commit`;
        // consensus membership of the eventual spend anchor binds the rest
        // (see the step doc).
        let anchor =
            poseidon::with_driver::anchor_next_stamp(dr, &previous, &epoch, oracles.bridge_hash())?;
        let x = left_encoded.as_gadget().cm.clone();
        // Inclusion: cm ∈ set ⇔ the set polynomial vanishes at cm.
        let evaluation = oracles.query(dr, Slot::output(1), &x)?;
        evaluation.enforce_zero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendableInit: commitment not in set".into())
        })?;
        let output = D::just(|| {
            (
                left.take().0,
                witness.take().2,
                Anchor::from(*anchor.value().take()),
            )
        });
        let fields = NoteSpendableOutput {
            cm: left_encoded.as_gadget().cm.clone(),
            epoch_current: epoch,
            anchor,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let bucket_epoch = right_encoded.as_gadget().epoch.clone();
        let unspent_epoch = left_encoded.as_gadget().epoch_start.clone();
        bucket_epoch
            .enforce_equal(dr, &unspent_epoch)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrSpendableInit: segment does not start in the bucket's epoch".into(),
                )
            })?;
        let bucket_start = right_encoded.as_gadget().anchor_start.clone();
        let unspent_start = left_encoded.as_gadget().anchor_start.clone();
        bucket_start
            .enforce_equal(dr, &unspent_start)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrSpendableInit: segment does not open where the bucket does".into(),
                )
            })?;
        let bucket_end = right_encoded.as_gadget().anchor_next.clone();
        let unspent_end = left_encoded.as_gadget().anchor_next.clone();
        bucket_end.enforce_equal(dr, &unspent_end).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrSpendableInit: segment does not close where the bucket does".into(),
            )
        })?;
        let next = circuit::epoch_next(dr, &bucket_epoch).map_err(|_err| {
            ragu_core::Error::InvalidWitness("QrSpendableInit: bucket has no next epoch".into())
        })?;
        let unspent_next = left_encoded.as_gadget().epoch_next.clone();
        // Defensive: the anchor equality already rejects a wrong epoch label.
        next.enforce_equal(dr, &unspent_next).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrSpendableInit: segment does not end in the epoch after the bucket's".into(),
            )
        })?;
        let x = left_encoded.as_gadget().cm.clone();
        // Inclusion: cm ∈ bucket ⇔ the contents vanish at cm.
        let evaluation = oracles.query(dr, Slot::right(0), &x)?;
        evaluation.enforce_zero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("QrSpendableInit: commitment not in bucket".into())
        })?;
        let output = D::just(|| {
            let data = left.take();
            (data.0, circuit::epoch_value(&next).take(), data.4)
        });
        let fields = NoteSpendableOutput {
            cm: left_encoded.as_gadget().cm.clone(),
            epoch_current: next,
            anchor: unspent_end,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
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
        let spendable_cm = left_encoded.as_gadget().cm.clone();
        let unspent_cm = right_encoded.as_gadget().cm.clone();
        spendable_cm
            .enforce_equal(dr, &unspent_cm)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "SpendableLift: unspent cm does not match spendable".into(),
                )
            })?;
        let spendable_epoch = left_encoded.as_gadget().epoch_current.clone();
        let unspent_epoch = right_encoded.as_gadget().epoch_start.clone();
        spendable_epoch
            .enforce_equal(dr, &unspent_epoch)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "SpendableLift: segment does not start at the lineage epoch".into(),
                )
            })?;
        let spendable_anchor = left_encoded.as_gadget().anchor.clone();
        let unspent_anchor = right_encoded.as_gadget().anchor_start.clone();
        spendable_anchor
            .enforce_equal(dr, &unspent_anchor)
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
        let fields = NoteSpendableOutput {
            cm: spendable_cm,
            epoch_current: right_encoded.as_gadget().epoch_next.clone(),
            anchor: right_encoded.as_gadget().anchor_next.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}
