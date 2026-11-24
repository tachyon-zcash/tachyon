//! Spendable bootstrap and lift.
//!
//! [`SpendableInit`] permits a spend in the note's creation epoch. To advance
//! beyond it, [`QrSpendableInit`] pairs the creation [`QrBucket`] with the
//! note's [`NoteUnspent`] for that epoch. [`SpendableLift`] advances over
//! subsequent segments, keeping the same note commitment and value.

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

/// Wallet's spendable position, holding a note, the epoch up to which its
/// nullifiers are tested, and the position's anchor.
///
/// # Injectivity
///
/// [`SpendableInit`], [`QrSpendableInit`] and [`SpendableLift`] output this
/// header. Every verified `NoteSpendable` asserts `epoch_current <= EPOCH_MAX`
/// as an integer, a prover-known verified [`NoteNullifiers`] carrying `cm`, and
/// one of two forms.
///
/// - **Creation.** The prover knows a one-absorption [stamp
///   chain](Anchor#chains-in-a-step) in `epoch_current` ending at `anchor`. The
///   header's [`TachygramSetPoly`] is that absorption's polynomial with `cm`
///   among its roots.
/// - **Lineage.** The prover knows an epoch $e_0 < \text{epoch\_current}$,
///   anchors $b_e$ across $e \in e_0..=\text{epoch\_current}$ ending at
///   `anchor`, and a verified [`QrBucket`] at $(e_0, b_{e_0}, b_{e_0+1})$ whose
///   contents have `cm` as a root. At each $e \in e_0..\text{epoch\_current}$,
///   `cm`'s nullifier is [excluded](super::pool::ArbitraryUnspent#injectivity)
///   between $b_e$ and $b_{e+1}$, and the header's [`TachygramSetPoly`] is the
///   constant one.
///
/// In the lineage form, `cm` is a root of one of the stamp chain's polynomials
/// because the creation bucket's contents divide their product, and the bucket
/// excluding `cm`'s nullifier at $e_0$ shares that chain by matching `(e_0,
/// b_{e_0}, b_{e_0+1})` ([`QrBucket`](QrBucket#injectivity)).
///
/// - `cm` determines the note and its master key
///   ([`NoteSecret`](super::delegation::NoteSecret)). Because notes sharing a
///   master key share nullifiers, the header carries `cm` for
///   [`SpendBind`](super::spend::SpendBind) to match against its `NoteSecret`.
/// - `anchor` fixes the form and determines `epoch_current`. Distinct tags
///   separate the creation form's stamp absorption from the lineage form's
///   boundary digest, both absorb `epoch_current`, and the creation form's
///   absorption also determines its polynomial, which no consumer reads.
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
/// Reading no challenge, the step copies `cm` from its input,
/// [adds an absorption](Anchor#chains-in-a-step) of prover-chosen `anchor_prev`
/// and `creation_epoch` with the creation polynomial, and opens that polynomial
/// to zero at `cm`. That zero opening proves `cm` is a root and rules out the
/// constant one.
///
/// Neither this step nor the creation form tests exclusion. Spending from this
/// form relies on consensus rejecting duplicate tachygrams within two epochs.
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
/// [`QrUnspentInit`](super::qr::QrUnspentInit) then
/// [`UnspentBind`](super::pool::UnspentBind) supply the segment. The spendable
/// takes its `(epoch_next, anchor_next)`.
///
/// # Soundness
///
/// Both anchor bounds must match. The segment starts at `bucket.epoch` and
/// ends at its range-checked successor, so it covers exactly that epoch.
/// A zero contents opening at `segment.cm` establishes creation there for the
/// lineage form, without reading the bucket profile or opening an output slot.
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
/// Wallet-only and witness-free, to `(epoch_next, anchor_next)` across any
/// segment length. [`SpendableInit`] spendables cannot lift and spend in their
/// creation epoch.
///
/// # Soundness
///
/// The segment's start epoch and anchor must match the spendable's current
/// epoch and anchor. Only the lineage form matches: a boundary digest and a
/// creation stamp absorption have distinct tags. Equal `cm` wires then extend
/// the same note's nullifier exclusions from $e_0$ through `unspent.epoch_next
/// - 1`, preserving membership in the creation bucket. No challenge or output
/// slot is read.
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
