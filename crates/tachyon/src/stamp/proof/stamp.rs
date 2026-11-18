//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;

use alloc::vec::Vec;

use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::Pasta,
};
use ragu_pcd::{
    header::{Header, OnlinePoly, Suffix},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
};
use ragu_primitives::{
    Element, GadgetExt as _, Point,
    allocator::Allocator,
    decompose,
    io::Write,
    vec::{ConstLen, FixedVec},
};
use udon::{curve::Affine as _, field::Field as _};

use super::{
    output::OutputHeader,
    pool::{AnchorSet, AnchorSpan, AnchorSpanOutput},
    spend::{SpendHeader, SpendHeaderOutput},
};
use crate::{
    ActionSetPoly, TachygramSetPoly,
    constants::MAX_MONEY,
    digest::poseidon,
    entropy::ActionEntropy,
    gadgets::{self, fixed_base},
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    pasta::{EpAffine, Fp},
    primitives::{ActionDigest, Anchor, Tachygram, TachygramSetBridge, effect},
    relations::enforce::{enforce_poly_product, enforce_poly_roots},
    value,
};

/// The polynomial whose roots are a set of action and fee digests.
#[derive(Clone, Copy, Debug)]
pub struct ActionSet;

impl OnlinePoly for ActionSet {}

/// The polynomial whose roots are a stamp's tachygrams. A header that carries
/// it keeps it last, where the bridge hash digests it.
#[derive(Clone, Copy, Debug)]
pub struct TachygramSet;

impl OnlinePoly for TachygramSet {}

/// The polynomial whose roots are the tachygrams of the stamp the producing
/// step folds into its anchor. A header that carries it keeps it last, where
/// the bridge hash the fold absorbs digests it.
#[derive(Clone, Copy, Debug)]
pub struct FoldedStamp;

impl OnlinePoly for FoldedStamp {}

/// Non-empty proven action content with no fee in its lineage.
///
/// The output polynomials are the action-digest and tachygram sets. Each leaf
/// step ([`OutputAction`], [`SpendAction`]) witnesses both set polynomials
/// and enforces them against their roots at a Fiat-Shamir challenge.
/// The action set is enforced against the action the step derives,
/// the tachygram set against the pair bound on the left bind header.
/// [`ActionMerge`] enforces each output set as the product of its inputs.
///
/// `anchor` is a free witness at [`OutputAction`]. At [`SpendAction`] it comes
/// from the left [`SpendHeader`]. At [`ActionMerge`] the step requires
/// `left.anchor == right.anchor`. At [`ActionLift`] the step checks that
/// `anchor` is the right [`AnchorSpan`]'s `anchor_start` or a member, and moves
/// it to the span's `anchor_end`.
#[derive(Debug)]
pub struct Actions;

#[derive(Gadget, Write)]
pub struct ActionsOutput<'dr, D: Driver<'dr>> {
    pub anchor: Element<'dr, D>,
}

impl Header<Fp> for Actions {
    /// `anchor`
    type Data = Anchor;
    type OnlinePolyCommit = (ActionSet, TachygramSet);
    type Output = Kind![Fp; ActionsOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(15);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(ActionsOutput {
            anchor: Element::alloc(dr, allocator, witness.map(Fp::from))?,
        })
    }
}

/// Header for one or more fee-bearing lineages.
///
/// [`ActionSet`] and [`TachygramSet`] hold the action and tachygram sets.
/// `tachygram_set_bridge` holds the bridge hash of [`TachygramSet`].
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
    type OnlinePolyCommit = (ActionSet, TachygramSet);
    type Output = Kind![Fp; StampOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
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

/// Proves an output's action as [`Actions`].
///
/// Reads `cm`, `pad` and `cv` off the [`OutputHeader`]
/// [`OutputBind`](super::output::OutputBind) derived, derives the action
/// randomizer `alpha` from the witnessed `theta` and `cm`, then the randomized
/// action key `rk`, and enforces the one-action set plus the stamp accumulator
/// over the two-element tachygram set `{cm, pad}`.
///
/// `theta` is free, but `alpha` is its hash with the certified `cm`, so an
/// `rk` planned over one note matches another only through a preimage.
///
/// Three permutations (`alpha`, two for the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set polynomials.
#[derive(Debug)]
pub struct OutputAction;

impl Step<Pasta> for OutputAction {
    type Aux<'source> = ();
    type Left = OutputHeader;
    type Output = Actions;
    type Right = ();
    /// `(theta, anchor, action_set, tachygram_set)`
    type Witness<'source> = (ActionEntropy, Anchor, ActionSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(7);
    // The derived action root is fixed before zeta.
    const NUM_STAGED: usize = 1;

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Prepared<Fp, Self::Output>> {
        let (cm, pad, cv) = *left.data;
        let alpha = witness
            .0
            .randomizer::<effect::Output>(note::Commitment::from(Fp::from(cm)));
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        let digest = ActionDigest::new(cv, rk, (cm, pad));
        Ok(Prepared::new()
            .poly(
                ActionSet,
                witness.2.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .poly(
                TachygramSet,
                witness.3.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .stage([Fp::from(digest)]))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
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
        let output_header = left_encoded.as_gadget();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let anchor_element = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(_, anchor, ..)| Fp::from(anchor)),
        )?;
        let cm_root = output_header.cm.clone();
        let theta = Element::alloc(dr, &mut (), witness.as_ref().map(|&(theta, ..)| theta.0))?;
        let alpha = poseidon::circuit::alpha_output(dr, &theta, &cm_root)?;
        // Alpha's 254 bits recompose to it, so they are its canonical bits.
        let alpha_bits = FixedVec::<_, ConstLen<254>>::try_from(decompose(dr, &mut (), &alpha)?)?;
        let rk = fixed_base::G_BASE.mul(dr, &alpha_bits)?;
        let action_root = poseidon::circuit::action_digest(
            dr,
            &output_header.cv,
            &rk,
            (&cm_root, &output_header.pad),
        )?;
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 1")]
        let staged_root = &oracles.staged()[0];
        action_root.enforce_equal(dr, staged_root)?;
        let action_roots = [action_root];
        let z = oracles.zeta().clone();
        // The action-set commitment commits to exactly the one action this
        // step derives. `cv` carries the note's value; `rk` derives from
        // `alpha`, and so from `cm`.
        let action_set = oracles.output(ActionSet).open(dr, &z)?;
        enforce_poly_roots(dr, &z, &action_set, &action_roots)?;
        let tachygram_roots = [cm_root, output_header.pad.clone()];
        // The stamp accumulator commits to exactly the tachygram pair on the
        // bind header, both roots fixed by the recursive verification of the
        // left PCD.
        let tachygram_set = oracles.output(TachygramSet).open(dr, &z)?;
        enforce_poly_roots(dr, &z, &tachygram_set, &tachygram_roots)?;
        let output = witness.map(|(_, anchor, ..)| anchor);
        let fields = ActionsOutput {
            anchor: anchor_element,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}

/// Proves a spend's action as [`Actions`].
///
/// The spent note's `pk` and value commitment `cv` arrive on the
/// [`SpendHeader`] [`SpendBind`](super::spend::SpendBind) derived. The step
/// derives the action randomizer `alpha` from the witnessed `theta` and `cm`,
/// then the randomized action key `rk`, and enforces the one-action set plus
/// the stamp accumulator over the two-element tachygram set
/// `{nf_current, nf_next}` (the pair `SpendBind` derived from the master
/// key).
///
/// `pk = payment_key(ak, nk)` is the only thing tying `ak` to the note.
/// `theta` is free, but `alpha` is its hash with the certified `cm`, so an
/// `rk` planned over one note matches another only through a preimage.
///
/// Four permutations (`pk`, `alpha`, two for the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set
/// polynomials.
#[derive(Debug)]
pub struct SpendAction;

impl Step<Pasta> for SpendAction {
    type Aux<'source> = ();
    type Left = SpendHeader;
    type Output = Actions;
    type Right = ();
    /// `(theta, pak, action_set, tachygram_set)`
    type Witness<'source> = (
        ActionEntropy,
        ProofAuthorizingKey,
        ActionSetPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(9);
    // The derived action root is fixed before zeta.
    const NUM_STAGED: usize = 1;

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Prepared<Fp, Self::Output>> {
        let (cm, nf_current, nf_next, _, _, cv) = *left.data;
        let alpha = witness.0.randomizer::<effect::Spend>(cm);
        let rk = witness.1.ak.derive_action_public(&alpha);
        let digest = ActionDigest::new(
            cv,
            rk,
            (Tachygram::from(nf_current), Tachygram::from(nf_next)),
        );
        Ok(Prepared::new()
            .poly(
                ActionSet,
                witness.2.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .poly(
                TachygramSet,
                witness.3.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .stage([Fp::from(digest)]))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
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
        let SpendHeaderOutput {
            cm,
            nf_current,
            nf_next,
            pk,
            cv,
            ..
        } = left_encoded.as_gadget().clone();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        #[expect(
            clippy::expect_used,
            reason = "ak is a typed RedPallas verification key"
        )]
        let ak_assignment = D::just(|| {
            let &(_, pak, ..) = witness.as_ref().take();
            let bytes: [u8; 32] = pak.ak.0.into();
            EpAffine::from_bytes(bytes).expect("a verification key encodes a curve point")
        });
        let ak = Point::alloc(dr, ak_assignment)?;
        let nk = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(_, pak, ..)| Fp::from(pak.nk)),
        )?;
        let derived_pk = poseidon::circuit::payment_key(dr, &ak, &nk)?;
        pk.enforce_equal(dr, &derived_pk)?;
        let theta = Element::alloc(dr, &mut (), witness.as_ref().map(|&(theta, ..)| theta.0))?;
        let alpha = poseidon::circuit::alpha_spend(dr, &theta, &cm)?;
        // Alpha's 254 bits recompose to it, so they are its canonical bits.
        let alpha_bits = FixedVec::<_, ConstLen<254>>::try_from(decompose(dr, &mut (), &alpha)?)?;
        let rk = fixed_base::G_BASE.mul_and_add(dr, &alpha_bits, &ak)?;
        let action_root = poseidon::circuit::action_digest(dr, &cv, &rk, (&nf_current, &nf_next))?;
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 1")]
        let staged_root = &oracles.staged()[0];
        action_root.enforce_equal(dr, staged_root)?;
        let z = oracles.zeta().clone();
        // The action-set commitment commits to exactly the one action this
        // step derives; the root is in-circuit from the certified note.
        let action_set = oracles.output(ActionSet).open(dr, &z)?;
        enforce_poly_roots(dr, &z, &action_set, &[action_root])?;
        // The stamp accumulator commits to exactly the nullifier pair on the
        // bind header, both roots fixed by the recursive verification of the
        // left PCD.
        let tachygram_set = oracles.output(TachygramSet).open(dr, &z)?;
        enforce_poly_roots(dr, &z, &tachygram_set, &[nf_current, nf_next])?;
        let output = left.map(|(_, _, _, anchor, ..)| anchor);
        let fields = ActionsOutput {
            anchor: left_encoded.as_gadget().anchor.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
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
    ) -> ragu_core::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new()
            .poly(
                ActionSet,
                witness.0.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .poly(
                TachygramSet,
                witness.1.as_ref().iter_coeffs().collect::<Vec<_>>(),
            ))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
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
        // Confirm union via product-opening relation.
        let z = oracles.zeta().clone();
        let left_actions = oracles.left(ActionSet).open(dr, &z)?;
        let right_actions = oracles.right(ActionSet).open(dr, &z)?;
        let merged_actions = oracles.output(ActionSet).open(dr, &z)?;
        enforce_poly_product(dr, &left_actions, &right_actions, &merged_actions)?;
        let left_tachygrams = oracles.left(TachygramSet).open(dr, &z)?;
        let right_tachygrams = oracles.right(TachygramSet).open(dr, &z)?;
        let merged_tachygrams = oracles.output(TachygramSet).open(dr, &z)?;
        enforce_poly_product(dr, &left_tachygrams, &right_tachygrams, &merged_tachygrams)?;
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

/// Merges action content.
///
/// Opens both inputs' action and tachygram sets and both products at one
/// challenge.
#[derive(Debug)]
pub struct ActionMerge;

impl Step<Pasta> for ActionMerge {
    type Aux<'source> = ();
    type Left = Actions;
    type Output = Actions;
    type Right = Actions;
    /// `(action_set, tachygram_set)`
    type Witness<'source> = (ActionSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(34);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new()
            .poly(
                ActionSet,
                witness.0.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .poly(
                TachygramSet,
                witness.1.as_ref().iter_coeffs().collect::<Vec<_>>(),
            ))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
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
        // Confirm union via product-opening relation.
        let z = oracles.zeta().clone();
        let left_actions = oracles.left(ActionSet).open(dr, &z)?;
        let right_actions = oracles.right(ActionSet).open(dr, &z)?;
        let merged_actions = oracles.output(ActionSet).open(dr, &z)?;
        enforce_poly_product(dr, &left_actions, &right_actions, &merged_actions)?;
        let left_tachygrams = oracles.left(TachygramSet).open(dr, &z)?;
        let right_tachygrams = oracles.right(TachygramSet).open(dr, &z)?;
        let merged_tachygrams = oracles.output(TachygramSet).open(dr, &z)?;
        enforce_poly_product(dr, &left_tachygrams, &right_tachygrams, &merged_tachygrams)?;
        let left_anchor_element = left_encoded.as_gadget().anchor.clone();
        left_anchor_element.enforce_equal(dr, &right_encoded.as_gadget().anchor)?;
        let fields = ActionsOutput {
            anchor: left_anchor_element,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            left,
            D::unit(),
        ))
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
    ) -> ragu_core::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new()
            .poly(
                ActionSet,
                witness.0.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .poly(TachygramSet, left.polynomial(TachygramSet)))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
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
        let AnchorSpanOutput {
            anchor_start,
            anchor_end,
        } = right_encoded.as_gadget().clone();
        let z = oracles.zeta().clone();
        let left_actions = oracles.left(ActionSet).open(dr, &z)?;
        let output_actions = oracles.output(ActionSet).open(dr, &z)?;
        left_actions.enforce_equal(dr, &output_actions)?;
        let left_tachygrams = oracles.left(TachygramSet).open(dr, &z)?;
        let output_tachygrams = oracles.output(TachygramSet).open(dr, &z)?;
        left_tachygrams.enforce_equal(dr, &output_tachygrams)?;
        let StampOutput { anchor, .. } = left_encoded.as_gadget().clone();
        let anchor_evaluation = oracles.right(AnchorSet).open(dr, &anchor)?;
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

/// Advances action content's anchor to the end of an [`AnchorSpan`].
///
/// The actions' `anchor` must be the span's `anchor_start` or one of its
/// members.
///
/// Opens the span members and both input and output action and tachygram sets.
#[derive(Debug)]
pub struct ActionLift;

impl Step<Pasta> for ActionLift {
    type Aux<'source> = ();
    type Left = Actions;
    type Output = Actions;
    type Right = AnchorSpan;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(35);

    // Preserve the left action and tachygram sets; the right anchor set
    // supplies the span membership opening.
    fn prepare(
        &self,
        &(): &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new()
            .poly(ActionSet, left.polynomial(ActionSet))
            .poly(TachygramSet, left.polynomial(TachygramSet)))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
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
        let AnchorSpanOutput {
            anchor_start,
            anchor_end,
        } = right_encoded.as_gadget().clone();
        let z = oracles.zeta().clone();
        let left_actions = oracles.left(ActionSet).open(dr, &z)?;
        let output_actions = oracles.output(ActionSet).open(dr, &z)?;
        left_actions.enforce_equal(dr, &output_actions)?;
        let left_tachygrams = oracles.left(TachygramSet).open(dr, &z)?;
        let output_tachygrams = oracles.output(TachygramSet).open(dr, &z)?;
        left_tachygrams.enforce_equal(dr, &output_tachygrams)?;
        let ActionsOutput { anchor } = left_encoded.as_gadget().clone();
        let anchor_evaluation = oracles.right(AnchorSet).open(dr, &anchor)?;
        let delta = anchor.sub(dr, &anchor_start);
        let membership = anchor_evaluation.mul(dr, &delta)?;
        membership.enforce_zero(dr)?;
        let fields = ActionsOutput { anchor: anchor_end };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            right.map(|(_, span_anchor_end)| span_anchor_end),
            D::unit(),
        ))
    }
}

/// Turns [`Actions`] into a [`Stamp`] by adding the fee digest and fee change
/// note's commitment to the action and tachygram sets.
///
/// Opens both input and output sets. The fee note and fee are fixed before
/// the challenge.
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
    ) -> ragu_core::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new()
            .poly(
                ActionSet,
                witness.2.0.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .poly(
                TachygramSet,
                witness.2.1.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .stage([
                Fp::from(witness.0.pk),
                Fp::from(witness.0.psi),
                Fp::from(witness.0.rcm),
                Fp::from(u64::from(witness.0.value)),
                Fp::from(u64::from(witness.1)),
            ]))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keep the fee note's checked parts and the set identities together"
    )]
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
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
        let slack = gadgets::uint::Uint::alloc(
            dr,
            witness
                .as_ref()
                .map(|&(Note { value, .. }, ..)| Fp::from(MAX_MONEY) - Fp::from(u64::from(value))),
        )
        .map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeFuse: maximum fee exceeds MAX_MONEY".into())
        })?;
        let maximum = gadgets::value::Positive::from_slack(dr, &slack)?;
        let (fee, change) = maximum
            .split(
                dr,
                witness
                    .as_ref()
                    .map(|&(_, fee, _)| Fp::from(u64::from(fee))),
            )
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("FeeFuse: change is out of range".into())
            })?;
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
        fee_change.clone().enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeFuse: fee change note commitment is zero".into())
        })?;
        let z = oracles.zeta().clone();
        let left_actions = oracles.left(ActionSet).open(dr, &z)?;
        let output_actions = oracles.output(ActionSet).open(dr, &z)?;
        let left_tachygrams = oracles.left(TachygramSet).open(dr, &z)?;
        let output_tachygrams = oracles.output(TachygramSet).open(dr, &z)?;
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
    ) -> ragu_core::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new()
            .poly(
                ActionSet,
                witness.2.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .poly(
                TachygramSet,
                witness.3.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
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
            .and_then(|element| gadgets::value::Positive::from_zero(dr, element))
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("FeeSeed: maximum fee must be zero".into())
            })?,
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
        fee_change.clone().enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeSeed: fee change note commitment is zero".into())
        })?;
        let z = oracles.zeta().clone();
        let action_set = oracles.output(ActionSet).open(dr, &z)?;
        enforce_poly_roots(dr, &z, &action_set, &[fee_digest])?;
        let tachygram_set = oracles.output(TachygramSet).open(dr, &z)?;
        enforce_poly_roots(dr, &z, &tachygram_set, &[fee_change])?;
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
    ) -> ragu_core::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new()
            .poly(
                ActionSet,
                witness.0.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .poly(
                TachygramSet,
                witness.1.as_ref().iter_coeffs().collect::<Vec<_>>(),
            ))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
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
        let z = oracles.zeta().clone();
        let divisor_actions = oracles.right(ActionSet).open(dr, &z)?;
        let quotient_actions = oracles.output(ActionSet).open(dr, &z)?;
        let dividend_actions = oracles.left(ActionSet).open(dr, &z)?;
        enforce_poly_product(dr, &divisor_actions, &quotient_actions, &dividend_actions)?;
        let divisor_tachygrams = oracles.right(TachygramSet).open(dr, &z)?;
        let quotient_tachygrams = oracles.output(TachygramSet).open(dr, &z)?;
        let dividend_tachygrams = oracles.left(TachygramSet).open(dr, &z)?;
        enforce_poly_product(
            dr,
            &divisor_tachygrams,
            &quotient_tachygrams,
            &dividend_tachygrams,
        )?;
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
