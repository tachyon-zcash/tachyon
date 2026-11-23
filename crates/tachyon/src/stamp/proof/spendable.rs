//! Spendable bootstrap and lift.
//!
//! The spendable carries `(cm, epoch_current, anchor)`: the note's current
//! epoch, its pool position, and the minted-note commitment binding the
//! lineage (and its value) across lifts. [`SpendableInit`] bootstraps it from a
//! minted note for a spend in the creation epoch, and [`QrSpendableInit`] from
//! a [`QrBucket`] holding the creation over the note's own [`NoteUnspent`] for
//! that epoch; [`SpendableLift`] advances the latter over [`NoteUnspent`]
//! segments.

use ragu::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Padding, Suffix},
    maybe::Maybe as _,
    pasta::Pasta,
    primitives::{Element, GadgetExt as _, allocator::Allocator, io::Write},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
};

use super::{delegation::NoteNullifiers, pool::NoteUnspent, qr::QrBucket};
use crate::{
    digest::poseidon,
    gadgets, note,
    pasta::Fp,
    primitives::{Anchor, EpochIndex, PolySlot, TachygramSetPoly},
};

/// Wallet's spendable position: a note, the epoch its nullifiers are tested up
/// to, and the anchor of that position.
///
/// # Injectivity
///
/// [`SpendableInit`], [`QrSpendableInit`] and [`SpendableLift`] output this
/// header. A verified `NoteSpendable` asserts that `epoch_current` is an
/// integer at most `EPOCH_MAX`, that its prover knows a verified
/// [`NoteNullifiers`] that carries this `cm`, and one of two things.
///
/// - **Creation.** The prover knows a [stamp chain](Anchor#chains-in-a-step) of
///   one absorption in `epoch_current` that ends at `anchor`. The absorption's
///   polynomial is the header's [`TachygramSetPoly`], and `cm` is a root of it.
/// - **Lineage.** The prover knows an epoch $e_0$ below `epoch_current` and an
///   anchor $b_e$ for each epoch $e$ from $e_0$ to `epoch_current`, with
///   `anchor` the last of them. It knows a verified [`QrBucket`] with `epoch`
///   $e_0$, `anchor_start` $b_{e_0}$ and `anchor_next` $b_{e_0+1}$, and `cm` is
///   a root of its contents. At every epoch $e$ from $e_0$ to the one before
///   `epoch_current`, the nullifier of `cm` at $e$ is
///   [excluded](super::pool::ArbitraryUnspent#injectivity) between $b_e$ and
///   $b_{e+1}$. The header's [`TachygramSetPoly`] is the constant one.
///
/// In the lineage form, the bucket's contents divide the product of the
/// polynomials of its stamp chain, so `cm` is a root of one of them. The
/// bucket that excludes the nullifier at $e_0$ has the same three fields and
/// so the same chain, by the bucket's [assertion](QrBucket#injectivity).
///
/// - `cm` determines the note and its master key
///   ([`NoteSecret`](super::delegation::NoteSecret)). Notes that share a master
///   key share their nullifiers, so the header carries `cm`, and
///   [`SpendBind`](super::spend::SpendBind) compares it with the `cm` of its
///   `NoteSecret`.
/// - `anchor` is a stamp absorption in the creation form and a boundary digest
///   in the lineage form. The two have different tags, so one anchor is of one
///   form. In both it absorbs `epoch_current` and so determines it, and in the
///   creation form it determines the polynomial, which no step reads from an
///   input.
#[derive(Clone, Debug)]
pub struct NoteSpendable;

#[derive(Gadget, Write)]
pub struct NoteSpendableOutput<'dr, D: Driver<'dr>> {
    pub cm: Element<'dr, D>,
    #[ragu(gadget)]
    pub epoch_current: gadgets::epoch::EpochIndex<'dr, D>,
    pub anchor: Element<'dr, D>,
}

impl Header<Fp> for NoteSpendable {
    /// `(cm, epoch_current, anchor)`
    type Data = (note::Commitment, EpochIndex, Anchor);
    type OnlinePolyCommit = (Padding, PolySlot<TachygramSetPoly>);
    type Output = Kind![Fp; NoteSpendableOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Ok(NoteSpendableOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(cm, ..)| Fp::from(cm)),
            )?,
            epoch_current: gadgets::epoch::EpochIndex::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(_, epoch_current, _)| epoch_current),
            )?,
            anchor: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(.., anchor)| Fp::from(anchor)),
            )?,
        })
    }
}

/// Bootstrap a spendable from a minted note, pinned to the creation epoch.
///
/// Wallet-only, one-child over any [`NoteNullifiers`], which supplies `cm`.
///
/// # Soundness
///
/// The step copies `cm` from its input and
/// [adds an absorption](Anchor#chains-in-a-step) of `anchor_prev`,
/// `creation_epoch` and the creation polynomial, with both wires the prover's
/// choice. The circuit opens the creation polynomial at `cm` and holds the
/// value to zero, so `cm` is a root of it and it is not the constant one. The
/// step reads no challenge.
///
/// The step tests no exclusion, and the creation form asserts none. A spend
/// from this form relies on the consensus rule that rejects a tachygram
/// published twice within two epochs.
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

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let creation_set = &witness.1;
        Ok(TachygramSetPoly::SLOT.poly(Prepared::new(), creation_set))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let nullifiers = left_encoded.as_gadget();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let previous = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|&(anchor_prev, ..)| Fp::from(anchor_prev)),
        )?;
        let epoch_element = gadgets::epoch::EpochIndex::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|&(_, _, creation_epoch)| creation_epoch),
        )?;
        // The anchor immediately after the creation stamp: the stamp absorption
        // of the prover's `anchor_prev`, the epoch and the step's bridge hash.
        let anchor = poseidon::circuit::anchor_next_stamp(
            dr,
            &previous,
            &epoch_element,
            &[
                oracles.bridge_hash().x().clone(),
                oracles.bridge_hash().y().clone(),
            ],
        )?;
        // Inclusion: cm ∈ set ⇔ the set polynomial vanishes at cm.
        let evaluation = oracles
            .output(TachygramSetPoly::SLOT)
            .open(dr, &nullifiers.cm)?;
        evaluation.enforce_zero(dr)?;
        let output = D::just(|| {
            let (cm, ..) = left.take();
            let (_, _, creation_epoch) = witness.take();
            (cm, creation_epoch, Anchor::from(*anchor.value().take()))
        });
        let fields = NoteSpendableOutput {
            cm: nullifiers.cm.clone(),
            epoch_current: epoch_element,
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
/// [`UnspentBind`](super::pool::UnspentBind)). This step adds the membership
/// of `cm` in the bucket and emits the spendable on the segment's
/// `(epoch_next, anchor_next)`.
///
/// # Soundness
///
/// The circuit holds the bucket's `epoch`, `anchor_start` and `anchor_next`
/// equal to the segment's `epoch_start`, `anchor_start` and `anchor_next`,
/// and the successor of the bucket's epoch, range-checked, equal to the
/// segment's `epoch_next`. The epochs are integers, so the segment covers the
/// bucket's epoch and no other, and its one exclusion lies between the
/// bucket's two anchors.
///
/// The circuit opens the bucket's contents at the segment's `cm` and holds
/// the value to zero, so `cm` is a root of the contents. The bucket's profile
/// plays no part. This is the lineage form with $e_0$ the bucket's epoch. The
/// step opens no output slot.
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
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let unspent = left_encoded.as_gadget();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let bucket = right_encoded.as_gadget();
        bucket.epoch.enforce_equal(dr, &unspent.epoch_start)?;
        bucket
            .anchor_start
            .enforce_equal(dr, &unspent.anchor_start)?;
        bucket.anchor_next.enforce_equal(dr, &unspent.anchor_next)?;
        let epoch_next = bucket.epoch.next(dr)?;
        // The anchor equality rejects a wrong epoch label only through the
        // crossing digest's collision resistance; this ties `epoch_next` to the
        // bucket directly.
        epoch_next.enforce_equal(dr, &unspent.epoch_next)?;
        // Inclusion: cm ∈ bucket ⇔ the contents vanish at cm.
        let evaluation = oracles
            .right(TachygramSetPoly::SLOT)
            .open(dr, &unspent.cm)?;
        evaluation.enforce_zero(dr)?;
        let output = D::just(|| {
            let (unspent_cm, _, _, unspent_epoch_next, unspent_anchor_next) = left.take();
            (unspent_cm, unspent_epoch_next, unspent_anchor_next)
        });
        let fields = NoteSpendableOutput {
            cm: unspent.cm.clone(),
            epoch_current: epoch_next,
            anchor: unspent.anchor_next.clone(),
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
/// Wallet-only, witness-free. The lineage moves to the segment's far boundary
/// `(epoch_next, anchor_next)`. The segment may span any number of epochs. A
/// [`SpendableInit`] spendable cannot lift, and spends in its creation epoch.
///
/// # Soundness
///
/// The circuit holds the two `cm` equal, the spendable's `epoch_current`
/// equal to the segment's `epoch_start`, and the spendable's `anchor` equal
/// to the segment's `anchor_start`. The left input is in the lineage form. The
/// segment's `anchor_start` is a bucket's `anchor_start`, which is a boundary
/// digest. A creation anchor is a stamp absorption, and an element that is both
/// is a collision between the two tags.
///
/// Equal `cm` make the segment's tested values nullifiers of the spendable's
/// note, and the segment's epochs and anchors continue the spendable's. The
/// exclusions therefore run from $e_0$ to the epoch before the segment's
/// `epoch_next`, and the input's bucket still holds `cm`. The step opens no
/// output slot and reads no challenge.
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
        _oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let spendable = left_encoded.as_gadget();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let unspent = right_encoded.as_gadget();
        spendable.cm.enforce_equal(dr, &unspent.cm)?;
        spendable
            .epoch_current
            .enforce_equal(dr, &unspent.epoch_start)?;
        spendable.anchor.enforce_equal(dr, &unspent.anchor_start)?;
        let output = D::just(|| {
            let (output_cm, ..) = left.take();
            let (_, _, _, unspent_epoch_next, unspent_anchor_next) = right.take();
            (output_cm, unspent_epoch_next, unspent_anchor_next)
        });
        let fields = NoteSpendableOutput {
            cm: spendable.cm.clone(),
            epoch_current: unspent.epoch_next.clone(),
            anchor: unspent.anchor_next.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}
