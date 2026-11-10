//! Stamp header and stamp-producing/transforming steps.

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
use udon::{curve::Affine as _, field::Field as _};

use super::{output::OutputHeader, pool::AnchorSpan, spend::SpendHeader};
use crate::{
    ActionSetPoly, TachygramSetPoly,
    constants::MAX_MONEY,
    digest::poseidon,
    entropy::ActionEntropy,
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    pasta::{EpAffine, Fp, Fq},
    primitives::{ActionDigest, Anchor, TachygramSetBridge, TachygramSetCommit, effect},
    ragu_constraint::{enforce_nonzero, enforce_zero},
    relations::enforce::{enforce_poly_equal, enforce_poly_product, enforce_poly_roots},
    value,
};

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
/// O0/O1 hold the action and tachygram sets. `stamp_tg_commit` holds O1's
/// bridge hash. [`StampMerge`] enforces both output sets as input products.
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
    pub stamp_tg_commit: [Element<'dr, D>; 2],
}

impl Header<Fp> for Stamp {
    /// `(stamp_tg_commit, anchor)`
    type Data = (TachygramSetBridge, Anchor);
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
        let stamp_tg_commit = witness.as_ref().map(|fields| {
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
            stamp_tg_commit: [
                Element::alloc(
                    dr,
                    allocator,
                    stamp_tg_commit.as_ref().map(|coordinates| coordinates.0),
                )?,
                Element::alloc(
                    dr,
                    allocator,
                    stamp_tg_commit.as_ref().map(|coordinates| coordinates.1),
                )?,
            ],
        })
    }
}

impl Stamp {
    /// Reconstructs the header from the public tachygram commitment and anchor.
    ///
    /// # Errors
    ///
    /// Fails if the commitment is the identity.
    pub fn header(
        commitment: TachygramSetCommit,
        anchor: Anchor,
    ) -> ragu_core::Result<(TachygramSetBridge, Anchor)> {
        Ok((commitment.bridge()?, anchor))
    }

    #[expect(
        clippy::type_complexity,
        reason = "the encoded header and its carried data"
    )]
    fn output<'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        dr: &mut D,
        oracles: &Oracles<'_, 'dr, D>,
        anchor: DriverValue<D, Anchor>,
    ) -> ragu_core::Result<(
        Encoded<'dr, D, Self, HEADER_SIZE>,
        DriverValue<D, <Self as Header<Fp>>::Data>,
    )> {
        let [x, y] = oracles.bridge_hash().each_ref().map(Element::value);
        let data = D::try_just(|| {
            let stamp_tg_commit = EpAffine::from_xy(*x.take(), *y.take()).ok_or_else(|| {
                ragu_core::Error::InvalidWitness("Stamp: bridge hash is not on the curve".into())
            })?;
            if stamp_tg_commit.is_identity() {
                return Err(ragu_core::Error::InvalidWitness(
                    "Stamp: bridge hash is the identity".into(),
                ));
            }
            Ok((
                TachygramSetBridge::from(stamp_tg_commit),
                anchor.clone().take(),
            ))
        })?;
        let encoded = Encoded::from_gadget(StampOutput {
            anchor: Element::alloc(dr, &mut (), anchor.map(Fp::from))?,
            stamp_tg_commit: oracles.bridge_hash().clone(),
        });
        Ok((encoded, data))
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
/// Two permutations (`alpha`, the action digest) and one scalar
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
    // O0/O1 carry action/tachygram sets; the derived action root is fixed before
    // zeta.
    const NUM_STAGED: usize = 1;

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        let (cm, _, cv) = *left.data;
        let alpha = witness
            .0
            .randomizer::<effect::Output>(note::Commitment::from(Fp::from(cm)));
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        let digest = ActionDigest::new(cv, rk).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "OutputAction: action digest construction failed".into(),
            )
        })?;
        Ok(alloc::vec![Fp::from(digest)])
    }

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.2.as_ref().iter_coeffs().collect(),
            witness.3.as_ref().iter_coeffs().collect(),
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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let native = D::try_just(|| {
            let (theta, anchor, ..) = witness.take();
            let (cm, pad, cv) = left.take();
            let () = right.take();
            // TODO: a real circuit squeezes alpha in Fp and needs its bit
            // decomposition to use it as an Fq scalar (p < q, so no reduction);
            // mock ragu embeds it natively.
            let alpha = theta.randomizer::<effect::Output>(note::Commitment::from(Fp::from(cm)));
            let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
            let action_digest = ActionDigest::new(cv, rk).map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "OutputAction: action digest construction failed".into(),
                )
            })?;
            Ok((anchor, Fp::from(action_digest), Fp::from(cm), Fp::from(pad)))
        })?;
        let action_root = Element::alloc(dr, &mut (), native.clone().map(|(_, root, ..)| root))?;
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 1")]
        let staged_root = &oracles.staged()[0];
        action_root.enforce_equal(dr, staged_root)?;
        let action_roots = [action_root];
        // The action-set commitment commits to exactly the one action this
        // step derives. `cv` carries the note's value; `rk` derives from
        // `alpha`, and so from `cm`.
        enforce_poly_roots(
            dr,
            oracles,
            &Slot::output(0),
            &action_roots,
            "OutputAction: action set does not commit to the action",
        )?;
        let cm_root = Element::alloc(dr, &mut (), native.clone().map(|(_, _, cm, _)| cm))?;
        let pad_root = Element::alloc(dr, &mut (), native.clone().map(|(_, _, _, pad)| pad))?;
        let tachygram_roots = [cm_root, pad_root];
        // The stamp accumulator commits to exactly the tachygram pair on the
        // bind header, both roots fixed by the recursive verification of the
        // left PCD.
        enforce_poly_roots(
            dr,
            oracles,
            &Slot::output(1),
            &tachygram_roots,
            "OutputAction: tachygram set does not commit to the bound pair",
        )?;
        let data = native.map(|(output, ..)| output);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
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
/// Three permutations (`pk`, `alpha`, the action digest) and one scalar
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
    // O0/O1 carry action/tachygram sets; the derived action root is fixed before
    // zeta.
    const NUM_STAGED: usize = 1;

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        let (cm, _, _, _, _, cv) = *left.data;
        let alpha = witness.0.randomizer::<effect::Spend>(cm);
        let rk = witness.1.ak.derive_action_public(&alpha);
        let digest = ActionDigest::new(cv, rk).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "SpendAction: action digest construction failed".into(),
            )
        })?;
        Ok(alloc::vec![Fp::from(digest)])
    }

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.2.as_ref().iter_coeffs().collect(),
            witness.3.as_ref().iter_coeffs().collect(),
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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let native = D::try_just(|| {
            let (theta, pak, ..) = witness.take();
            let (cm, nf_current, nf_next, anchor, pk, cv) = left.take();
            let () = right.take();
            enforce_zero(
                Fp::from(pk) - Fp::from(pak.derive_payment_key()),
                "SpendAction: pak not related to note",
            )?;
            // TODO: a real circuit squeezes alpha in Fp and needs its bit
            // decomposition to use it as an Fq scalar (p < q, so no reduction);
            // mock ragu embeds it natively.
            let alpha = theta.randomizer::<effect::Spend>(cm);
            let rk = pak.ak.derive_action_public(&alpha);
            let action_digest = ActionDigest::new(cv, rk).map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "SpendAction: action digest construction failed".into(),
                )
            })?;
            Ok((
                anchor,
                Fp::from(action_digest),
                Fp::from(nf_current),
                Fp::from(nf_next),
            ))
        })?;
        let action_root = Element::alloc(dr, &mut (), native.clone().map(|(_, root, ..)| root))?;
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 1")]
        let staged_root = &oracles.staged()[0];
        action_root.enforce_equal(dr, staged_root)?;
        // The action-set commitment commits to exactly the one action this
        // step derives; the root is in-circuit from the certified note.
        enforce_poly_roots(
            dr,
            oracles,
            &Slot::output(0),
            &[action_root],
            "SpendAction: action set does not commit to the action",
        )?;
        let current_root = Element::alloc(
            dr,
            &mut (),
            native.clone().map(|(_, _, current, _)| current),
        )?;
        let next_root = Element::alloc(dr, &mut (), native.clone().map(|(_, _, _, next)| next))?;
        // The stamp accumulator commits to exactly the nullifier pair on the
        // bind header, both roots fixed by the recursive verification of the
        // left PCD.
        enforce_poly_roots(
            dr,
            oracles,
            &Slot::output(1),
            &[current_root, next_root],
            "SpendAction: tachygram set does not commit to the nullifier pair",
        )?;
        let data = native.map(|(output, ..)| output);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
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

    // Child slots bind both inputs; O0/O1 carry their action/tachygram products.
    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.0.as_ref().iter_coeffs().collect(),
            witness.1.as_ref().iter_coeffs().collect(),
        ])
    }

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
        // Confirm union via product-opening relation.
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::right(0),
            &Slot::output(0),
            "StampMerge: merged action set must be the product of left and right action sets",
        )?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(1),
            &Slot::right(1),
            &Slot::output(1),
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets",
        )?;
        let output = D::try_just(|| {
            let (_, left_anchor) = left.take();
            let (_, right_anchor) = right.take();
            // Same-anchor constraint.
            enforce_zero(
                Fp::from(left_anchor) - Fp::from(right_anchor),
                "StampMerge: anchors must match",
            )?;
            Ok(left_anchor)
        })?;
        let (encoded, data) = Stamp::output(dr, oracles, output)?;
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

    // Child slots bind both inputs; O0/O1 carry their action/tachygram products.
    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.0.as_ref().iter_coeffs().collect(),
            witness.1.as_ref().iter_coeffs().collect(),
        ])
    }

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
        // Confirm union via product-opening relation.
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::right(0),
            &Slot::output(0),
            "ActionMerge: merged action set must be the product of left and right action sets",
        )?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(1),
            &Slot::right(1),
            &Slot::output(1),
            "ActionMerge: merged tachygram set must be the product of left and right tachygram sets",
        )?;
        let output = D::try_just(|| {
            let left_anchor = left.take();
            let right_anchor = right.take();
            // Same-anchor constraint.
            enforce_zero(
                Fp::from(left_anchor) - Fp::from(right_anchor),
                "ActionMerge: anchors must match",
            )?;
            Ok((left_anchor, ()))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
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

    // O0 carries the stated action set, checked equal to L0; O1 preserves L1;
    // R0 supplies the span membership opening.
    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.0.as_ref().iter_coeffs().collect(),
            left.polynomials[1].clone(),
        ])
    }

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
        enforce_poly_equal(dr, oracles, Slot::left(0), Slot::output(0))?;
        enforce_poly_equal(dr, oracles, Slot::left(1), Slot::output(1))?;
        let anchor = Element::alloc(dr, &mut (), left.as_ref().map(|data| Fp::from(data.1)))?;
        let anchor_start =
            Element::alloc(dr, &mut (), right.as_ref().map(|data| Fp::from(data.0)))?;
        let anchor_evaluation = oracles.query(dr, Slot::right(0), &anchor)?;
        let delta = anchor.sub(dr, &anchor_start);
        let membership = anchor_evaluation.mul(dr, &delta)?;
        membership.enforce_zero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "StampLift: stamp anchor is neither the span's start nor a member".into(),
            )
        })?;
        let (encoded, data) = Stamp::output(dr, oracles, right.map(|(_, end)| end))?;
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

    // Preserve L0/L1 in O0/O1; R0 supplies the span membership opening.
    fn polynomials(
        &self,
        &(): &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([left.polynomials[0].clone(), left.polynomials[1].clone()])
    }

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
        enforce_poly_equal(dr, oracles, Slot::left(0), Slot::output(0))?;
        enforce_poly_equal(dr, oracles, Slot::left(1), Slot::output(1))?;
        let anchor = Element::alloc(dr, &mut (), left.as_ref().map(|&data| Fp::from(data)))?;
        let anchor_start =
            Element::alloc(dr, &mut (), right.as_ref().map(|data| Fp::from(data.0)))?;
        let anchor_evaluation = oracles.query(dr, Slot::right(0), &anchor)?;
        let delta = anchor.sub(dr, &anchor_start);
        let membership = anchor_evaluation.mul(dr, &delta)?;
        membership.enforce_zero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "ActionLift: actions anchor is neither the span's start nor a member".into(),
            )
        })?;
        let (data, aux) = right
            .map(|(_, span_anchor_end)| (span_anchor_end, ()))
            .cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
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

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        let (max_fee_note, fee, _) = *witness;
        Ok(alloc::vec![
            Fp::from(u64::from(max_fee_note.value)),
            Fp::from(max_fee_note.pk),
            Fp::from(max_fee_note.psi),
            Fp::from(max_fee_note.rcm),
            Fp::from(u64::from(fee)),
        ])
    }

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.2.0.as_ref().iter_coeffs().collect(),
            witness.2.1.as_ref().iter_coeffs().collect(),
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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let native = D::try_just(|| {
            let (max_fee_note, fee, _) = witness.take();
            let left_anchor = left.take();
            let () = right.take();

            let feemax = u64::from(max_fee_note.value);
            if feemax > MAX_MONEY {
                return Err(ragu_core::Error::InvalidWitness(
                    "FeeFuse: maximum fee exceeds MAX_MONEY".into(),
                ));
            }
            // `feemax` and `fee` are below 2^64, far below the field modulus, so the
            // field difference lies in [0, MAX_MONEY] exactly when the integer
            // difference does.
            let change = feemax
                .checked_sub(u64::from(fee))
                .filter(|&change| change <= MAX_MONEY)
                .ok_or_else(|| {
                    ragu_core::Error::InvalidWitness("FeeFuse: change is out of range".into())
                })?;
            let (pk, psi, rcm) = (
                Fp::from(max_fee_note.pk),
                Fp::from(max_fee_note.psi),
                Fp::from(max_fee_note.rcm),
            );
            // TODO: a real circuit squeezes r in Fp and needs its bit
            // decomposition to use it as an Fq scalar (p < q, so no reduction);
            // mock ragu embeds it natively.
            let blind = poseidon::feemax_blind(pk, psi, rcm);
            #[expect(
                clippy::expect_used,
                reason = "p < q, so every Fp repr is canonical in Fq"
            )]
            let cv_feemax = EpAffine::from(
                value::Trapdoor::from_scalar(Fq::from_bytes(blind.to_bytes()).expect("p < q"))
                    .commit(-max_fee_note.value),
            );
            if cv_feemax.is_identity() {
                return Err(ragu_core::Error::InvalidWitness(
                    "FeeFuse: fee commitment is the identity".into(),
                ));
            }
            let fee_digest = poseidon::fee_digest(cv_feemax, u64::from(fee));
            // A zero root leaves the set polynomial factor `(X - tg)` trivial.
            let fee_change_commitment = enforce_nonzero(
                poseidon::note_commitment(rcm, pk, change, psi),
                "FeeFuse: fee change note commitment is zero",
            )?;
            Ok((
                left_anchor,
                fee_digest,
                fee_change_commitment,
                [
                    Fp::from(u64::from(max_fee_note.value)),
                    pk,
                    psi,
                    rcm,
                    Fp::from(u64::from(fee)),
                ],
            ))
        })?;

        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 5")]
        for index in 0..Self::NUM_STAGED {
            let value = native.clone().map(|(_, _, _, fields)| fields[index]);
            Element::alloc(dr, &mut (), value)?.enforce_equal(dr, &oracles.staged()[index])?;
        }
        let fee_digest = Element::alloc(dr, &mut (), native.clone().map(|(_, digest, ..)| digest))?;
        let fee_change =
            Element::alloc(dr, &mut (), native.clone().map(|(_, _, change, _)| change))?;
        let z = oracles.zeta().clone();
        for (column, root, err) in [
            (
                0,
                fee_digest,
                "FeeFuse: output action set must be the product of left and fee action sets",
            ),
            (
                1,
                fee_change,
                "FeeFuse: output tachygram set must be the product of left and fee tachygram sets",
            ),
        ] {
            let left_value = oracles.query(dr, Slot::left(column), &z)?;
            let output_value = oracles.query(dr, Slot::output(column), &z)?;
            let factor = z.sub(dr, &root);
            let expected = left_value.mul(dr, &factor)?;
            output_value
                .enforce_equal(dr, &expected)
                .map_err(|_err| ragu_core::Error::InvalidWitness(err.into()))?;
        }
        let (encoded, data) = Stamp::output(dr, oracles, native.map(|(anchor, ..)| anchor))?;
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
    const NUM_STAGED: usize = 4;

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        let &(max_fee_note, ..) = witness;
        Ok(alloc::vec![
            Fp::from(u64::from(max_fee_note.value)),
            Fp::from(max_fee_note.pk),
            Fp::from(max_fee_note.psi),
            Fp::from(max_fee_note.rcm),
        ])
    }

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.2.as_ref().iter_coeffs().collect(),
            witness.3.as_ref().iter_coeffs().collect(),
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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let native = D::try_just(|| {
            let (max_fee_note, anchor, ..) = witness.take();
            let () = left.take();
            let () = right.take();
            enforce_zero(
                Fp::from(u64::from(max_fee_note.value)),
                "FeeSeed: maximum fee must be zero",
            )?;
            let (pk, psi, rcm) = (
                Fp::from(max_fee_note.pk),
                Fp::from(max_fee_note.psi),
                Fp::from(max_fee_note.rcm),
            );
            // TODO: a real circuit squeezes r in Fp and needs its bit
            // decomposition to use it as an Fq scalar (p < q, so no reduction);
            // mock ragu embeds it natively.
            let blind = poseidon::feemax_blind(pk, psi, rcm);
            #[expect(
                clippy::expect_used,
                reason = "p < q, so every Fp repr is canonical in Fq"
            )]
            let cv_feemax = EpAffine::from(
                value::Trapdoor::from_scalar(Fq::from_bytes(blind.to_bytes()).expect("p < q"))
                    .commit(-max_fee_note.value),
            );
            if cv_feemax.is_identity() {
                return Err(ragu_core::Error::InvalidWitness(
                    "FeeSeed: fee commitment is the identity".into(),
                ));
            }
            let fee_digest = poseidon::fee_digest(cv_feemax, 0);
            // A zero root leaves the set polynomial factor `(X - tg)` trivial.
            let fee_change_commitment = enforce_nonzero(
                poseidon::note_commitment(rcm, pk, 0, psi),
                "FeeSeed: fee change note commitment is zero",
            )?;
            Ok((
                anchor,
                fee_digest,
                fee_change_commitment,
                [Fp::from(u64::from(max_fee_note.value)), pk, psi, rcm],
            ))
        })?;
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 4")]
        for index in 0..Self::NUM_STAGED {
            let value = native.clone().map(|(_, _, _, fields)| fields[index]);
            Element::alloc(dr, &mut (), value)?.enforce_equal(dr, &oracles.staged()[index])?;
        }
        let fee_digest = Element::alloc(dr, &mut (), native.clone().map(|(_, digest, ..)| digest))?;
        enforce_poly_roots(
            dr,
            oracles,
            &Slot::output(0),
            &[fee_digest],
            "FeeSeed: fee action set does not commit to the fee digest",
        )?;
        let fee_change =
            Element::alloc(dr, &mut (), native.clone().map(|(_, _, change, _)| change))?;
        enforce_poly_roots(
            dr,
            oracles,
            &Slot::output(1),
            &[fee_change],
            "FeeSeed: fee tachygram set does not commit to the fee change note",
        )?;
        let (encoded, data) = Stamp::output(dr, oracles, native.map(|(anchor, ..)| anchor))?;
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
/// dividend's. Repeated roots subtract by multiplicity. A digest determines
/// its tachygrams at a fixed epoch. The epoch closes through consensus anchor
/// membership: the output threads the dividend's anchor, a span folds only
/// under the `Tachyon-AnchorSt` domain, and
/// [`SpendableInit`](super::spendable::SpendableInit) absorbs the creation
/// epoch. Once consensus checks the published anchor, every spend leaf beneath
/// it derived its nullifier pair at that anchor's epoch, and the tachygram
/// quotient is exactly the removed leaves' tachygrams.
///
/// This rests on Poseidon collision resistance, Pedersen binding, discrete
/// log, and Poseidon preimage resistance composed through a discrete-log
/// relation. [`NoteSeed`](super::delegation::NoteSeed) derives `pk` and
/// [`SpendAction`] checks it, which closes that relation in-circuit.
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

    // O0/O1 are quotients; each R column times its O column must equal L.
    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.0.as_ref().iter_coeffs().collect(),
            witness.1.as_ref().iter_coeffs().collect(),
        ])
    }

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
        enforce_poly_product(
            dr,
            oracles,
            &Slot::right(0),
            &Slot::output(0),
            &Slot::left(0),
            "StampUnmerge: dividend action set must be the product of divisor and quotient action sets",
        )?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::right(1),
            &Slot::output(1),
            &Slot::left(1),
            "StampUnmerge: dividend tachygram set must be the product of divisor and quotient tachygram sets",
        )?;
        let output = D::try_just(|| {
            let (_, left_anchor) = left.take();
            let (_, right_anchor) = right.take();
            enforce_zero(
                Fp::from(left_anchor) - Fp::from(right_anchor),
                "StampUnmerge: anchors must match",
            )?;
            Ok(left_anchor)
        })?;
        let (encoded, data) = Stamp::output(dr, oracles, output)?;
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
    }
}
