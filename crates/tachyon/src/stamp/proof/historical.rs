//! Historical wallet registry, whose fee-bearing stamp binds the tachygram
//! accumulator. Select this registry by chain context when verifying blocks
//! from those rules.

use alloc::boxed::Box;

use ragu::{
    AcceleratedProver, ApplicationBuilder, WalletRank,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Suffix},
    maybe::Maybe as _,
    pasta::Pasta,
    primitives::{Element, GadgetExt as _, allocator::Allocator, io::Write},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
    udon::{curve::Affine as _, field::Field as _},
};

use super::{
    App, HEADER_SIZE, delegation, evidence, output, pool,
    pool::{AnchorSpan, AnchorSpanOutput},
    qr, spend, spendable, summary, transaction,
    transaction::{Actions, ActionsOutput},
};
use crate::{
    ActionSetPoly, TachygramSetPoly,
    bridge_hash::bridge_hash,
    constants::MAX_MONEY,
    digest::poseidon,
    gadgets,
    note::Note,
    pasta::{self, EpAffine, EqAffine, Fp},
    primitives::{ActionDigest, Anchor, AnchorSetPoly, PolySlot, TachygramSetBridge},
    stamp::{Compressed, ProofStamp},
    value,
};

/// Verifies a historical block stamp with the original two public commitments.
///
/// The first slot must match the action commitment derived from `digests`.
/// The last slot must match `stamp.tachygram_set`, whose bridge hash and the
/// supplied anchor form the historical proof header.
///
/// # Errors
///
/// Returns an error if the proof system fails.
pub fn verify_proof(
    app: &App<'_>,
    stamp: &ProofStamp<Compressed>,
    digests: impl IntoIterator<Item = ActionDigest>,
) -> ragu::Result<bool> {
    let action_set = digests.into_iter().collect::<ActionSetPoly>().commit();
    let [actions, tachygrams] = stamp.proof.online_commitments();
    if actions != EqAffine::from(action_set)
        || tachygrams != EqAffine::from(stamp.tachygram_set)
        || tachygrams.is_identity()
    {
        return Ok(false);
    }
    let bridge = bridge_hash(tachygrams).into();
    app.verify_compressed(
        &stamp
            .proof
            .as_ref()
            .clone()
            .carry::<Stamp>((bridge, stamp.anchor)),
    )
}

/// Header for one or more fee-bearing lineages.
///
/// The polynomials are an [`ActionSetPoly`] and a [`TachygramSetPoly`].
/// `tachygram_set_bridge` holds the bridge hash of the [`TachygramSetPoly`].
/// [`StampMerge`] enforces both output sets as input products.
///
/// [`FeeFuse`] multiplies each set polynomial by a fee singleton set
/// polynomial. [`FeeSeed`] directly produces a stamp with fee singleton sets.
///
/// `anchor` is a free witness at [`FeeSeed`]. At [`FeeFuse`] it comes from
/// the left [`Actions`]. At [`StampMerge`] the step requires
/// `left.anchor == right.anchor`. At [`StampLift`] the step checks that
/// `stamp.anchor` is the right [`AnchorSpan`]'s `anchor_start` or a member,
/// and moves it to the span's `anchor_end`.
#[derive(Debug)]
pub struct Stamp;

#[derive(Gadget, Write)]
pub struct StampOutput<'dr, D: Driver<'dr>> {
    pub anchor: Element<'dr, D>,
    pub tachygram_set_bridge: [Element<'dr, D>; 2],
}

impl Header<Fp> for Stamp {
    /// `(tachygram_set_bridge, anchor)`
    type Data = (TachygramSetBridge, Anchor);
    type OnlinePolyCommit = (PolySlot<ActionSetPoly>, PolySlot<TachygramSetPoly>);
    type Output = Kind![Fp; StampOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        #[expect(
            clippy::expect_used,
            reason = "a bridge hash is the identity only under a discrete-log relation between its generators"
        )]
        let tachygram_set_bridge = witness.as_ref().map(|fields| {
            EpAffine::from(fields.0)
                .coordinates()
                .expect("bridge hash is not the identity")
        });
        Ok(StampOutput {
            anchor: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            tachygram_set_bridge: [
                Element::alloc(
                    dr,
                    allocator,
                    tachygram_set_bridge
                        .as_ref()
                        .map(|coordinates| coordinates.0),
                )?,
                Element::alloc(
                    dr,
                    allocator,
                    tachygram_set_bridge
                        .as_ref()
                        .map(|coordinates| coordinates.1),
                )?,
            ],
        })
    }
}

/// Transaction assembly and aggregation.
///
/// Opens both inputs' action and tachygram sets and both products at one
/// challenge.
#[derive(Debug)]
pub struct StampMerge;

impl Step<Pasta> for StampMerge {
    type Aux<'source> = ();
    type Left = Stamp;
    type Output = Stamp;
    type Right = Stamp;
    /// `(action_set, tachygram_set)`
    type Witness<'source> = (ActionSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(10);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let (action_set, tachygram_set) = (&witness.0, &witness.1);
        let prepared = ActionSetPoly::SLOT.poly(Prepared::new(), action_set);
        Ok(TachygramSetPoly::SLOT.poly(prepared, tachygram_set))
    }

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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        // Confirm union via product-opening relation.
        let z = oracles.zeta().clone();
        let left_actions = oracles.left(ActionSetPoly::SLOT).open(dr, &z)?;
        let right_actions = oracles.right(ActionSetPoly::SLOT).open(dr, &z)?;
        let merged_actions = oracles.output(ActionSetPoly::SLOT).open(dr, &z)?;
        let expected_actions = left_actions.mul(dr, &right_actions)?;
        merged_actions.enforce_equal(dr, &expected_actions)?;
        let left_tachygrams = oracles.left(TachygramSetPoly::SLOT).open(dr, &z)?;
        let right_tachygrams = oracles.right(TachygramSetPoly::SLOT).open(dr, &z)?;
        let merged_tachygrams = oracles.output(TachygramSetPoly::SLOT).open(dr, &z)?;
        let expected_tachygrams = left_tachygrams.mul(dr, &right_tachygrams)?;
        merged_tachygrams.enforce_equal(dr, &expected_tachygrams)?;
        let left_anchor_element = left_encoded.as_gadget().anchor.clone();
        left_anchor_element.enforce_equal(dr, &right_encoded.as_gadget().anchor)?;
        let tachygram_set_bridge = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let [x, y] = tachygram_set_bridge.each_ref().map(Element::value);
        let anchor_value = left_anchor_element.value();
        let data = D::just(|| {
            #[expect(
                clippy::expect_used,
                reason = "the oracle supplies commitment coordinates"
            )]
            let bridge_hash = EpAffine::from_xy(*x.take(), *y.take())
                .expect("the bridge hash commitment is a curve point");
            (
                TachygramSetBridge::from(bridge_hash),
                Anchor::from(*anchor_value.take()),
            )
        });
        let encoded = Encoded::from_gadget(StampOutput {
            anchor: left_anchor_element,
            tachygram_set_bridge,
        });
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
    }
}

/// Advance a stamp's anchor to the end of an [`AnchorSpan`].
///
/// The stamp's `anchor` must be the span's `anchor_start` or one of its
/// members:
///
/// $$
///   M(\mathsf{anchor}) \cdot (\mathsf{anchor} - \mathsf{anchor\_start}) = 0
/// $$
///
/// The output anchor is always `anchor_end`, because the members polynomial
/// does not record the order of its members. A stamp already at `anchor_end`
/// keeps its anchor.
///
/// Opens the span members and both input and output action and tachygram sets.
///
/// # Soundness
///
/// The span's member polynomial $M$ is bound by the right input proof.
#[derive(Debug)]
pub struct StampLift;

impl Step<Pasta> for StampLift {
    type Aux<'source> = ();
    type Left = Stamp;
    type Output = Stamp;
    type Right = AnchorSpan;
    /// `(action_set,)`
    type Witness<'source> = (ActionSetPoly,);

    const INDEX: Index = Index::new(11);

    // The output action set is the one the caller states, where other
    // pass-through steps copy their input's polynomial; the opening against the
    // left action set holds it to the input. The output tachygram set copies
    // the left one. The right anchor set supplies the span membership opening.
    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let action_set = &witness.0;
        let prepared = ActionSetPoly::SLOT.poly(Prepared::new(), action_set);
        Ok(TachygramSetPoly::SLOT.copy_from(prepared, &left, TachygramSetPoly::SLOT))
    }

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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let AnchorSpanOutput {
            anchor_start,
            anchor_end,
        } = right_encoded.as_gadget().clone();
        let z = oracles.zeta().clone();
        let left_actions = oracles.left(ActionSetPoly::SLOT).open(dr, &z)?;
        let output_actions = oracles.output(ActionSetPoly::SLOT).open(dr, &z)?;
        left_actions.enforce_equal(dr, &output_actions)?;
        let left_tachygrams = oracles.left(TachygramSetPoly::SLOT).open(dr, &z)?;
        let output_tachygrams = oracles.output(TachygramSetPoly::SLOT).open(dr, &z)?;
        left_tachygrams.enforce_equal(dr, &output_tachygrams)?;
        let StampOutput { anchor, .. } = left_encoded.as_gadget().clone();
        let anchor_evaluation = oracles.right(AnchorSetPoly::SLOT).open(dr, &anchor)?;
        let delta = anchor.sub(dr, &anchor_start);
        let membership = anchor_evaluation.mul(dr, &delta)?;
        membership.enforce_zero(dr)?;
        // The output tachygram set copies the left one, so the output's bridge
        // hash is the left stamp's.
        let data = D::just(|| {
            let (stamp_bridge, _) = left.take();
            let (_, span_anchor_end) = right.take();
            (stamp_bridge, span_anchor_end)
        });
        let encoded = Encoded::from_gadget(StampOutput {
            anchor: anchor_end,
            tachygram_set_bridge: [
                oracles.bridge_hash().x().clone(),
                oracles.bridge_hash().y().clone(),
            ],
        });
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
    }
}

/// Turns [`Actions`] into a [`Stamp`] by adding the fee digest and fee change
/// note's commitment to the action and tachygram sets.
///
/// Opens both input and output sets. The fee note and fee are fixed before
/// the challenge.
///
/// # Caller contract
///
/// The caller confirms that the max fee note's value is within `MAX_MONEY`
/// and the fee is at most that value, or it risks producing a proof that is
/// false.
#[derive(Debug)]
pub struct FeeFuse;

impl Step<Pasta> for FeeFuse {
    type Aux<'source> = ();
    type Left = Actions;
    type Output = Stamp;
    type Right = ();
    /// `(max_fee_note, fee, (output_action_set, output_tachygram_set))`
    type Witness<'source> = (Note, value::Positive, (ActionSetPoly, TachygramSetPoly));

    const INDEX: Index = Index::new(33);
    const NUM_STAGED: usize = 5;

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let (output_action_set, output_tachygram_set) = (&witness.2.0, &witness.2.1);
        let prepared = ActionSetPoly::SLOT.poly(Prepared::new(), output_action_set);
        Ok(TachygramSetPoly::SLOT
            .poly(prepared, output_tachygram_set)
            .stage([
                Fp::from(witness.0.pk),
                Fp::from(witness.0.psi),
                Fp::from(witness.0.rcm),
                Fp::from(u64::from(witness.0.value)),
                Fp::from(u64::from(witness.1)),
            ]))
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let slack = gadgets::uint::Uint::alloc(
            dr,
            witness
                .as_ref()
                .map(|&(Note { value, .. }, ..)| Fp::from(MAX_MONEY) - Fp::from(u64::from(value))),
        )?;
        let maximum = gadgets::value::Positive::from_slack(dr, &slack)?;
        let (fee, change) = maximum.split(
            dr,
            witness
                .as_ref()
                .map(|&(_, fee, _)| Fp::from(u64::from(fee))),
        )?;
        let max_fee_note = gadgets::note::Note {
            rcm: Element::alloc(
                dr,
                &mut (),
                witness
                    .as_ref()
                    .map(|&(Note { rcm, .. }, ..)| Fp::from(rcm)),
            )?,
            pk: Element::alloc(
                dr,
                &mut (),
                witness.as_ref().map(|&(Note { pk, .. }, ..)| Fp::from(pk)),
            )?,
            value: maximum,
            psi: Element::alloc(
                dr,
                &mut (),
                witness
                    .as_ref()
                    .map(|&(Note { psi, .. }, ..)| Fp::from(psi)),
            )?,
        };
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 5")]
        for (index, actual) in [
            &max_fee_note.pk,
            &max_fee_note.psi,
            &max_fee_note.rcm,
            &*max_fee_note.value,
            &*fee,
        ]
        .into_iter()
        .enumerate()
        {
            actual.enforce_equal(dr, &oracles.staged()[index])?;
        }
        let cv = max_fee_note.cv_feemax(dr, &slack)?;
        let fee_change = gadgets::note::Note {
            value: change,
            ..max_fee_note
        }
        .commitment(dr)?;
        let fee_digest = poseidon::circuit::fee_digest(dr, &cv, &fee, &fee_change)?;
        // A zero root leaves the set polynomial factor `(X - tg)` trivial.
        fee_change.clone().enforce_nonzero(dr)?;
        let z = oracles.zeta().clone();
        let left_actions = oracles.left(ActionSetPoly::SLOT).open(dr, &z)?;
        let output_actions = oracles.output(ActionSetPoly::SLOT).open(dr, &z)?;
        let left_tachygrams = oracles.left(TachygramSetPoly::SLOT).open(dr, &z)?;
        let output_tachygrams = oracles.output(TachygramSetPoly::SLOT).open(dr, &z)?;
        for (left_value, output_value, root) in [
            (left_actions, output_actions, fee_digest),
            (left_tachygrams, output_tachygrams, fee_change),
        ] {
            let factor = z.sub(dr, &root);
            let expected = left_value.mul(dr, &factor)?;
            output_value.enforce_equal(dr, &expected)?;
        }
        let ActionsOutput { anchor } = left_encoded.as_gadget().clone();
        let tachygram_set_bridge = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let [x, y] = tachygram_set_bridge.each_ref().map(Element::value);
        let data = D::just(|| {
            #[expect(
                clippy::expect_used,
                reason = "the oracle supplies commitment coordinates"
            )]
            let bridge_hash = EpAffine::from_xy(*x.take(), *y.take())
                .expect("the bridge hash commitment is a curve point");
            (
                TachygramSetBridge::from(bridge_hash),
                Anchor::from(*anchor.value().take()),
            )
        });
        let encoded = Encoded::from_gadget(StampOutput {
            anchor,
            tachygram_set_bridge,
        });
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
    }
}

/// Proves a zero-action bundle's zero fee.
///
/// Opens both singleton sets. The fee note is fixed before the challenge.
#[derive(Debug)]
pub struct FeeSeed;

impl Step<Pasta> for FeeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Stamp;
    type Right = ();
    /// `(max_fee_note, anchor, fee_action_set, fee_tachygram_set)`
    type Witness<'source> = (Note, Anchor, ActionSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(36);
    const NUM_STAGED: usize = 3;

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let (fee_action_set, fee_tachygram_set) = (&witness.2, &witness.3);
        let prepared = ActionSetPoly::SLOT.poly(Prepared::new(), fee_action_set);
        Ok(TachygramSetPoly::SLOT
            .poly(prepared, fee_tachygram_set)
            .stage([
                Fp::from(witness.0.pk),
                Fp::from(witness.0.psi),
                Fp::from(witness.0.rcm),
            ]))
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left)?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let anchor_element = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(_, anchor, ..)| Fp::from(anchor)),
        )?;
        let max_fee_note = gadgets::note::Note {
            rcm: Element::alloc(
                dr,
                &mut (),
                witness
                    .as_ref()
                    .map(|&(Note { rcm, .. }, ..)| Fp::from(rcm)),
            )?,
            pk: Element::alloc(
                dr,
                &mut (),
                witness.as_ref().map(|&(Note { pk, .. }, ..)| Fp::from(pk)),
            )?,
            value: Element::alloc(
                dr,
                &mut (),
                witness
                    .as_ref()
                    .map(|&(Note { value, .. }, ..)| Fp::from(u64::from(value))),
            )
            .and_then(|element| gadgets::value::Positive::from_zero(dr, element))?,
            psi: Element::alloc(
                dr,
                &mut (),
                witness
                    .as_ref()
                    .map(|&(Note { psi, .. }, ..)| Fp::from(psi)),
            )?,
        };
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 3")]
        for (index, actual) in [&max_fee_note.pk, &max_fee_note.psi, &max_fee_note.rcm]
            .into_iter()
            .enumerate()
        {
            actual.enforce_equal(dr, &oracles.staged()[index])?;
        }
        let cv = max_fee_note.cv_feemax_zero(dr)?;
        let zero = Element::constant(dr, Fp::ZERO);
        // With a zero maximum and fee, the change note is the max-fee note.
        let fee_change = max_fee_note.commitment(dr)?;
        let fee_digest = poseidon::circuit::fee_digest(dr, &cv, &zero, &fee_change)?;
        // A zero root leaves the set polynomial factor `(X - tg)` trivial.
        fee_change.clone().enforce_nonzero(dr)?;
        let z = oracles.zeta().clone();
        let action_set = oracles.output(ActionSetPoly::SLOT).open(dr, &z)?;
        let action_factor = z.sub(dr, &fee_digest);
        action_set.enforce_equal(dr, &action_factor)?;
        let tachygram_set = oracles.output(TachygramSetPoly::SLOT).open(dr, &z)?;
        let tachygram_factor = z.sub(dr, &fee_change);
        tachygram_set.enforce_equal(dr, &tachygram_factor)?;
        let tachygram_set_bridge = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let [x, y] = tachygram_set_bridge.each_ref().map(Element::value);
        let anchor_value = anchor_element.value();
        let data = D::just(|| {
            #[expect(
                clippy::expect_used,
                reason = "the oracle supplies commitment coordinates"
            )]
            let bridge_hash = EpAffine::from_xy(*x.take(), *y.take())
                .expect("the bridge hash commitment is a curve point");
            (
                TachygramSetBridge::from(bridge_hash),
                Anchor::from(*anchor_value.take()),
            )
        });
        let encoded = Encoded::from_gadget(StampOutput {
            anchor: anchor_element,
            tachygram_set_bridge,
        });
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
    }
}

/// Removes a divisor stamp's leaves from a dividend stamp at the same anchor.
///
/// Every [`Stamp`] is leaf-generated: its action polynomial is the monic
/// product $\prod_i (X - d_i)$ over a multiset of leaf digests, and its
/// tachygram polynomial is the product over exactly those leaves'
/// tachygrams. The output is leaf-generated over the dividend's leaf
/// multiset minus the divisor's, at the shared anchor.
///
/// # Soundness
///
/// The quotient is witnessed but not free. Each product relation opens the
/// dividend, divisor and quotient slots at the framework's challenge, so
/// $\mathsf{divisor} \cdot \mathsf{quotient} = \mathsf{dividend}$ holds as a
/// polynomial identity in each column.
///
/// Both columns are products of linear factors, so unique factorization in
/// $\mathbb{F}_p\[X\]$ places the divisor's digest multiset inside the
/// dividend's. Repeated roots subtract by multiplicity. Each action digest
/// absorbs its tachygram pair's sum and product, which fix the pair as a
/// multiset, and each fee digest absorbs its fee change. By Poseidon
/// collision resistance a digest determines its tachygrams, and the tachygram
/// quotient is exactly the removed leaves' tachygrams.
///
/// This quotient argument rests on the product check at a challenge fixed
/// after every set commitment, the commitments' binding, and collision
/// resistance of the domain-separated action and fee digests.
///
/// Sub-aggregate boundaries do not bound removal. A divisor is a stamp PCD in
/// hand, and merging in a complement first lets division remove any leaf
/// multiset the stamps in hand combine to express.
///
/// Six online polynomials open once each at one shared challenge.
#[derive(Debug)]
pub struct StampUnmerge;

impl Step<Pasta> for StampUnmerge {
    type Aux<'source> = ();
    type Left = Stamp;
    type Output = Stamp;
    type Right = Stamp;
    /// `(action_set, tachygram_set)`
    type Witness<'source> = (ActionSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(37);

    // The output sets are quotients; each right set times its output set must
    // equal the left one.
    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let (action_set, tachygram_set) = (&witness.0, &witness.1);
        let prepared = ActionSetPoly::SLOT.poly(Prepared::new(), action_set);
        Ok(TachygramSetPoly::SLOT.poly(prepared, tachygram_set))
    }

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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let z = oracles.zeta().clone();
        let divisor_actions = oracles.right(ActionSetPoly::SLOT).open(dr, &z)?;
        let quotient_actions = oracles.output(ActionSetPoly::SLOT).open(dr, &z)?;
        let dividend_actions = oracles.left(ActionSetPoly::SLOT).open(dr, &z)?;
        let expected_actions = divisor_actions.mul(dr, &quotient_actions)?;
        dividend_actions.enforce_equal(dr, &expected_actions)?;
        let divisor_tachygrams = oracles.right(TachygramSetPoly::SLOT).open(dr, &z)?;
        let quotient_tachygrams = oracles.output(TachygramSetPoly::SLOT).open(dr, &z)?;
        let dividend_tachygrams = oracles.left(TachygramSetPoly::SLOT).open(dr, &z)?;
        let expected_tachygrams = divisor_tachygrams.mul(dr, &quotient_tachygrams)?;
        dividend_tachygrams.enforce_equal(dr, &expected_tachygrams)?;
        let left_anchor_element = left_encoded.as_gadget().anchor.clone();
        left_anchor_element.enforce_equal(dr, &right_encoded.as_gadget().anchor)?;
        let tachygram_set_bridge = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let [x, y] = tachygram_set_bridge.each_ref().map(Element::value);
        let anchor_value = left_anchor_element.value();
        let data = D::just(|| {
            #[expect(
                clippy::expect_used,
                reason = "the oracle supplies commitment coordinates"
            )]
            let bridge_hash = EpAffine::from_xy(*x.take(), *y.take())
                .expect("the bridge hash commitment is a curve point");
            (
                TachygramSetBridge::from(bridge_hash),
                Anchor::from(*anchor_value.take()),
            )
        });
        let encoded = Encoded::from_gadget(StampOutput {
            anchor: left_anchor_element,
            tachygram_set_bridge,
        });
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
    }
}

/// Builds the Tachyon application with the baked setup.
///
/// Building runs the full setup, so a caller builds one application per
/// worker, keeps it on that worker and lends `&app` to each proof
/// operation.
///
/// # Errors
///
/// Returns an error if step registration or application finalization fails.
pub fn new_application() -> Result<Box<App<'static>>, ragu::Error> {
    ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE, AcceleratedProver>::new()
        .register(delegation::NoteSeed)?
        .register(delegation::NullifierDerive)?
        .register(pool::UnspentFuse)?
        .register(pool::UnspentBind)?
        .register(spendable::SpendableInit)?
        .register(spendable::SpendableLift)?
        .register(output::OutputBind)?
        .register(transaction::OutputAction)?
        .register(spend::HistoricalSpendBind)?
        .register(transaction::SpendAction)?
        .register(StampMerge)?
        .register(StampLift)?
        .register(delegation::NullifierFuse)?
        .register(summary::SummarySeed)?
        .register(summary::SummaryAdvance)?
        .register(qr::QrSummaryIntake)?
        .register(qr::QrIntakeMerge)?
        .register(qr::QrIntakeSplit)?
        .register(qr::QrSideDescend)?
        .register(qr::QrUnspentInit)?
        .register(qr::QrBucketSeal)?
        .register(qr::QrStampIntakeSeed)?
        .register(spendable::QrSpendableInit)?
        .register(qr::QrEmptyIntakeSeed)?
        .register(pool::UnspentLift)?
        .register(evidence::EvidenceTreePairFuse)?
        .register(evidence::EvidenceTreeFuse)?
        .register(evidence::EvidenceTreeCap)?
        .register(evidence::EvidenceTreeDescend)?
        .register(evidence::EvidenceTreeOpen)?
        .register(evidence::EvidenceTreeLeafPair)?
        .register(pool::AnchorSpanSeed)?
        .register(pool::AnchorSpanFuse)?
        .register(FeeFuse)?
        .register(transaction::ActionMerge)?
        .register(transaction::ActionLift)?
        .register(FeeSeed)?
        .register(StampUnmerge)?
        .register(qr::QrSideSelect)?
        .finalize(pasta::baked())
        .map(Box::new)
}
