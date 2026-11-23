//! Wallet-rank publication and restoration of the two sets of a working stamp.

use derive_more::{From, Into};
use ragu::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Padding, Suffix},
    maybe::Maybe as _,
    pasta::Pasta,
    primitives::{Element, GadgetExt as _, allocator::Allocator, io::Write},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
    udon::curve::Affine as _,
};

use super::stamp::{Stamp, StampOutput};
use crate::{
    ActionSetPoly, Anchor, PolySlot, TachygramSetPoly,
    pasta::{EpAffine, Fp},
};

/// A tachygram-set commitment bound in the wallet bridge basis.
#[derive(Clone, Copy, Debug, From, Into)]
pub struct PortableTachygramSetBridge(EpAffine);

/// An action-set commitment bound in the enclosing application's basis.
#[derive(Clone, Copy, Debug, From, Into)]
pub struct ActionSetBridge(EpAffine);

/// An action-set commitment bound in the wallet bridge basis.
#[derive(Clone, Copy, Debug, From, Into)]
pub struct PortableActionSetBridge(EpAffine);

/// The reference and both set bindings, in header order. `A` distinguishes
/// the intermediate's local action binding from the published portable one.
#[derive(Clone, Copy, Debug)]
pub struct StampBindings<A> {
    pub anchor: Anchor,
    pub portable_tachygrams: PortableTachygramSetBridge,
    pub actions: A,
}

#[derive(Gadget, Write)]
pub struct StampBindingsOutput<'dr, D: Driver<'dr>> {
    pub anchor: Element<'dr, D>,
    pub portable_tachygrams: [Element<'dr, D>; 2],
    pub actions: [Element<'dr, D>; 2],
}

impl<'dr, D: Driver<'dr, F = Fp>> StampBindingsOutput<'dr, D> {
    fn alloc<A: Copy + Send + Sync + Into<EpAffine>, Alloc: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut Alloc,
        witness: DriverValue<D, StampBindings<A>>,
    ) -> ragu::Result<Self> {
        let anchor = Element::alloc(
            dr,
            allocator,
            witness.as_ref().map(|fields| Fp::from(fields.anchor)),
        )?;
        let mut alloc_bridge = |assignment: DriverValue<D, EpAffine>| {
            #[expect(
                clippy::expect_used,
                reason = "set bridge hashes have affine coordinates"
            )]
            let xy = assignment.map(|point| {
                point
                    .coordinates()
                    .expect("bridge hash is not the identity")
            });
            Ok::<_, ragu::Error>([
                Element::alloc(dr, allocator, xy.as_ref().map(|coords| coords.0))?,
                Element::alloc(dr, allocator, xy.map(|coords| coords.1))?,
            ])
        };
        Ok(Self {
            anchor,
            portable_tachygrams: alloc_bridge(
                witness
                    .as_ref()
                    .map(|fields| fields.portable_tachygrams.into()),
            )?,
            actions: alloc_bridge(witness.map(|fields| fields.actions.into()))?,
        })
    }
}

fn oracle_point<'dr, D: Driver<'dr, F = Fp>>(
    xy: &[Element<'dr, D>; 2],
) -> DriverValue<D, EpAffine> {
    let [x, y] = xy.each_ref().map(Element::value);
    #[expect(
        clippy::expect_used,
        reason = "the oracle supplies commitment coordinates"
    )]
    D::just(|| {
        EpAffine::from_xy(*x.take(), *y.take())
            .expect("the bridge hash commitment is a curve point")
    })
}

/// A working stamp at `anchor` whose action polynomial is live in slot 1.
///
/// Slot 0 is padding. The portable tachygram point and local action point
/// bind the two sets of that same stamp. Neither point identifies a set by
/// itself: suffix 17, field position and the constraints of both writers do.
/// [`StampBindActionSet`] moves the certified action column; the other
/// writer, [`StampRestoreActionSet`], checks it against the certified
/// publication. Both emit their own last-slot oracle as the action point.
#[derive(Debug)]
pub struct StampActionSet;

impl Header<Fp> for StampActionSet {
    type Data = StampBindings<ActionSetBridge>;
    type OnlinePolyCommit = (Padding, PolySlot<ActionSetPoly>);
    type Output = Kind![Fp; StampBindingsOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(17);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        StampBindingsOutput::alloc(dr, allocator, witness)
    }
}

/// One fee-bearing stamp lineage at `anchor` binds the two portable set
/// commitments in order: tachygrams `(x,y)`, then actions and fees `(x,y)`.
///
/// Both slots are padding. The points have no intrinsic set tag: their
/// positions under authenticated suffix 18 and the constraints of every
/// writer give them meaning. [`StampPublish`] takes both from a single
/// [`StampActionSet`]; neither comes from a fresh witness or padding oracle.
/// Rerandomization preserves this statement. It does not certify ordering,
/// a txid, signatures, or eligibility of the historical reference.
#[derive(Debug)]
pub struct PublishedStamp;

impl Header<Fp> for PublishedStamp {
    type Data = StampBindings<PortableActionSetBridge>;
    type OnlinePolyCommit = (Padding, Padding);
    type Output = Kind![Fp; StampBindingsOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(18);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        StampBindingsOutput::alloc(dr, allocator, witness)
    }
}

/// Moves the action column of a [`Stamp`] to the bridge-bearing last slot.
///
/// The two commitments precede ζ, so equal openings bind the output to
/// the input polynomial up to polynomial-identity error. The anchor and
/// both coordinates of the certified tachygram bridge are input wires;
/// wallet export is a copy. The action bridge comes only from the output
/// slot's oracle, whose stage is bound before the later fold challenge.
#[derive(Debug)]
pub struct StampBindActionSet;

impl Step<Pasta> for StampBindActionSet {
    type Aux<'source> = ();
    type Left = Stamp;
    type Output = StampActionSet;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(39);

    fn prepare(
        &self,
        &(): &(),
        left: HeaderInput<'_, Fp, Stamp>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(ActionSetPoly::SLOT.copy_from(Prepared::new(), &left, ActionSetPoly::SLOT))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, ()>,
    ) -> ragu::Result<(
        (
            Encoded<'dr, D, Self::Left, H>,
            Encoded<'dr, D, Self::Right, H>,
            Encoded<'dr, D, Self::Output, H>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let input = Encoded::<D, Self::Left, H>::new(dr, &mut (), left.clone())?;
        let right_encoded = Encoded::new(dr, &mut (), right)?;
        let z = oracles.zeta().clone();
        let source = oracles.left(ActionSetPoly::SLOT).open(dr, &z)?;
        let moved = oracles.output(ActionSetPoly::SLOT).open(dr, &z)?;
        moved.enforce_equal(dr, &source)?;
        let actions = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let point = oracle_point(&actions);
        let data = D::just(|| {
            let (tachygrams, anchor) = left.take();
            StampBindings {
                anchor,
                portable_tachygrams: EpAffine::from(tachygrams).into(),
                actions: point.take().into(),
            }
        });
        let StampOutput {
            anchor,
            tachygram_set_bridge,
        } = input.as_gadget().clone();
        let output = Encoded::from_gadget(StampBindingsOutput {
            anchor,
            portable_tachygrams: tachygram_set_bridge,
            actions,
        });
        Ok(((input, right_encoded, output), data, D::unit()))
    }
}

/// Publishes the anchor and both bindings from one [`StampActionSet`].
///
/// At wallet rank the bases coincide, so all five header wires pass through
/// unchanged under the new suffix. No output query is issued: Ragu holds
/// each output to one at ζ, independently of the two carried bridge points.
#[derive(Debug)]
pub struct StampPublish;

impl Step<Pasta> for StampPublish {
    type Aux<'source> = ();
    type Left = StampActionSet;
    type Output = PublishedStamp;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(40);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, ()>,
    ) -> ragu::Result<(
        (
            Encoded<'dr, D, Self::Left, H>,
            Encoded<'dr, D, Self::Right, H>,
            Encoded<'dr, D, Self::Output, H>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let input = Encoded::<D, Self::Left, H>::new(dr, &mut (), left.clone())?;
        let right_encoded = Encoded::new(dr, &mut (), right)?;
        let output = Encoded::from_gadget(input.as_gadget().clone());
        let data = left.map(|fields| StampBindings {
            anchor: fields.anchor,
            portable_tachygrams: fields.portable_tachygrams,
            actions: EpAffine::from(fields.actions).into(),
        });
        Ok(((input, right_encoded, output), data, D::unit()))
    }
}

/// Restores only the action column, without opening a publication input
/// slot.
///
/// The output query keeps the candidate live. Its identity comes from
/// comparing both coordinates of its own bridge to the authenticated action
/// binding, not from the evaluation at ζ. Binding of the bridge stage and
/// the polynomial commitment excludes a different coefficient vector, even
/// one with a common root. The anchor and tachygram point pass through.
#[derive(Debug)]
pub struct StampRestoreActionSet;

impl Step<Pasta> for StampRestoreActionSet {
    type Aux<'source> = ();
    type Left = PublishedStamp;
    type Output = StampActionSet;
    type Right = ();
    type Witness<'source> = ActionSetPoly;

    const INDEX: Index = Index::new(41);

    fn prepare(
        &self,
        witness: &ActionSetPoly,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(ActionSetPoly::SLOT.poly(Prepared::new(), witness))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, ()>,
    ) -> ragu::Result<(
        (
            Encoded<'dr, D, Self::Left, H>,
            Encoded<'dr, D, Self::Right, H>,
            Encoded<'dr, D, Self::Output, H>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let input = Encoded::<D, Self::Left, H>::new(dr, &mut (), left.clone())?;
        let right_encoded = Encoded::new(dr, &mut (), right)?;
        let z = oracles.zeta().clone();
        let _opening = oracles.output(ActionSetPoly::SLOT).open(dr, &z)?;
        let actions = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let fields = input.as_gadget();
        for (local, portable) in actions.iter().zip(&fields.actions) {
            local.enforce_equal(dr, portable)?;
        }
        let point = oracle_point(&actions);
        let data = left.map(|published| StampBindings {
            anchor: published.anchor,
            portable_tachygrams: published.portable_tachygrams,
            actions: point.take().into(),
        });
        let output = Encoded::from_gadget(StampBindingsOutput {
            anchor: fields.anchor.clone(),
            portable_tachygrams: fields.portable_tachygrams.clone(),
            actions,
        });
        Ok(((input, right_encoded, output), data, D::unit()))
    }
}

/// Restores a [`Stamp`] with actions in slot 0 and tachygrams in slot 1.
///
/// Equal action openings at ζ bind the move between precommitted columns.
/// The query of the tachygram column keeps it live; equality of its own
/// bridge with both certified portable coordinates binds the commitment,
/// hence its coefficients. The emitted bridge is that output oracle. Both
/// sets and the unchanged anchor thus describe the same original stamp.
#[derive(Debug)]
pub struct StampRestoreTachygramSet;

impl Step<Pasta> for StampRestoreTachygramSet {
    type Aux<'source> = ();
    type Left = StampActionSet;
    type Output = Stamp;
    type Right = ();
    type Witness<'source> = TachygramSetPoly;

    const INDEX: Index = Index::new(42);

    fn prepare(
        &self,
        witness: &TachygramSetPoly,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let moved = ActionSetPoly::SLOT.copy_from(Prepared::new(), &left, ActionSetPoly::SLOT);
        Ok(TachygramSetPoly::SLOT.poly(moved, witness))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, ()>,
    ) -> ragu::Result<(
        (
            Encoded<'dr, D, Self::Left, H>,
            Encoded<'dr, D, Self::Right, H>,
            Encoded<'dr, D, Self::Output, H>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let input = Encoded::<D, Self::Left, H>::new(dr, &mut (), left.clone())?;
        let right_encoded = Encoded::new(dr, &mut (), right)?;
        let z = oracles.zeta().clone();
        let source = oracles.left(ActionSetPoly::SLOT).open(dr, &z)?;
        let moved = oracles.output(ActionSetPoly::SLOT).open(dr, &z)?;
        moved.enforce_equal(dr, &source)?;
        let _opening = oracles.output(TachygramSetPoly::SLOT).open(dr, &z)?;
        let tachygram_set_bridge = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let fields = input.as_gadget();
        for (local, portable) in tachygram_set_bridge.iter().zip(&fields.portable_tachygrams) {
            local.enforce_equal(dr, portable)?;
        }
        let point = oracle_point(&tachygram_set_bridge);
        let data = left.map(|bound| (point.take().into(), bound.anchor));
        let output = Encoded::from_gadget(StampOutput {
            anchor: fields.anchor.clone(),
            tachygram_set_bridge,
        });
        Ok(((input, right_encoded, output), data, D::unit()))
    }
}
