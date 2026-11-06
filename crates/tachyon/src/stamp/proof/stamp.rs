//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;

use alloc::vec::Vec;

use ragu::{
    header::{Header, Suffix},
    step::{Encoded, HeaderInput, Index, Oracles, Slot, Step},
};
use ragu_core::{
    Cycle as _, FixedGenerators as _,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::Pasta,
};
use ragu_pcd::pasta::baked;
use ragu_primitives::{Element, GadgetExt as _, allocator::Allocator, io::Write};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use super::{output::OutputHeader, pool::AnchorSpan, spend::SpendHeader};
use crate::{
    ActionSetPoly, TachygramSetPoly,
    constants::MAX_MONEY,
    digest::poseidon,
    entropy::ActionEntropy,
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    pasta::{EpAffine, Eq, Fp, Fq},
    primitives::{
        ActionDigest, ActionSetCommit, Anchor, AnchorSetPoly, TachygramSetCommit, effect,
    },
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
    relations::enforce::{enforce_poly_equal, enforce_poly_product, enforce_poly_roots},
    value,
};

/// Non-empty proven action content with no fee in its lineage.
///
/// Slot `O0` carries the action-digest set and `O1` the tachygram set. Each
/// leaf step ([`OutputAction`], [`SpendAction`]) witnesses both set
/// polynomials and enforces them against their roots at a Fiat-Shamir
/// challenge. The action set is enforced against the action the step derives,
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

/// `Actions` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct ActionsOutput<'dr, D: Driver<'dr>> {
    /// `anchor`.
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
/// `action_commit` and `stamp_tg_commit` are Pedersen commitments to
/// the action-digest and tachygram sets, which slots `O0` and `O1` carry.
/// [`StampMerge`] binds its witnessed input sets to the child headers
/// and enforces each output commitment as the product of its inputs.
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

/// `Stamp` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct StampOutput<'dr, D: Driver<'dr>> {
    /// `anchor`.
    pub anchor: Element<'dr, D>,
    /// `action_commit`.
    pub action_commit: [Element<'dr, D>; 2],
    /// `stamp_tg_commit`.
    pub stamp_tg_commit: [Element<'dr, D>; 2],
}

impl Header<Fp> for Stamp {
    /// `(action_commit, stamp_tg_commit, anchor)`
    type Data = (ActionSetCommit, TachygramSetCommit, Anchor);
    type Output = Kind![Fp; StampOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        #[expect(
            clippy::expect_used,
            reason = "compressed point limbs contain exactly 16 bytes"
        )]
        let commitments = D::try_just(|| {
            let fields = witness.clone().take();
            let mut limbs = [[Fp::ZERO; 2]; 2];
            for (output, commitment) in limbs
                .iter_mut()
                .zip([Eq::from(fields.0), Eq::from(fields.1)])
            {
                let point = commitment.to_affine();
                if point.is_identity() {
                    return Err(ragu_core::Error::InvalidWitness(
                        "cannot encode the identity commitment".into(),
                    ));
                }
                let bytes = point.to_bytes();
                let (low, high) = bytes.split_at(16);
                *output = [
                    Fp::from_u128(u128::from_le_bytes(low.try_into().expect("16 byte limb"))),
                    Fp::from_u128(u128::from_le_bytes(high.try_into().expect("16 byte limb"))),
                ];
            }
            Ok(limbs)
        })?;
        Ok(StampOutput {
            anchor: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?,
            action_commit: [
                Element::alloc(
                    dr,
                    allocator,
                    commitments.as_ref().map(|values| values[0][0]),
                )?,
                Element::alloc(
                    dr,
                    allocator,
                    commitments.as_ref().map(|values| values[0][1]),
                )?,
            ],
            stamp_tg_commit: [
                Element::alloc(
                    dr,
                    allocator,
                    commitments.as_ref().map(|values| values[1][0]),
                )?,
                Element::alloc(
                    dr,
                    allocator,
                    commitments.as_ref().map(|values| values[1][1]),
                )?,
            ],
        })
    }
}

/// Fix the fee roots before ζ; the witness phase independently derives them.
fn fee_roots(
    max_fee_note: Note,
    fee: value::Positive,
    step: &'static str,
) -> ragu_core::Result<Vec<Fp>> {
    let invalid =
        |message| ragu_core::Error::InvalidWitness(alloc::format!("{step}: {message}").into());
    let max_fee = u64::from(max_fee_note.value);
    if max_fee > MAX_MONEY {
        return Err(invalid("maximum fee exceeds MAX_MONEY"));
    }
    let change = max_fee
        .checked_sub(u64::from(fee))
        .filter(|&change| change <= MAX_MONEY)
        .ok_or_else(|| invalid("change is out of range"))?;
    let commitment = max_fee_note.fee_blind().commit(-max_fee_note.value);
    let coordinates = EpAffine::from(commitment)
        .coordinates()
        .ok_or_else(|| invalid("fee commitment is the identity"))?;
    let digest = poseidon::fee_digest(coordinates, u64::from(fee));
    let change_commitment = enforce_nonzero(
        poseidon::note_commitment(
            Fp::from(max_fee_note.rcm),
            Fp::from(max_fee_note.pk),
            change,
            Fp::from(max_fee_note.psi),
        ),
        if step == "FeeSeed" {
            "FeeSeed: fee change note commitment is zero"
        } else {
            "FeeFuse: fee change note commitment is zero"
        },
    )?;
    Ok(alloc::vec![digest, change_commitment])
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
    // O0/O1 carry action/tachygram sets; the derived action root is fixed before ζ.
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
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.2.as_ref());
        polynomials[1] = super::coefficients(witness.3.as_ref());
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
        let action_handle = Slot::output(0);
        let tachygram_handle = Slot::output(1);
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
            let output = anchor;
            Ok((output, Fp::from(action_digest), Fp::from(cm), Fp::from(pad)))
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
            &action_handle,
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
            &tachygram_handle,
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
    // O0/O1 carry action/tachygram sets; the derived action root is fixed before ζ.
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
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.2.as_ref());
        polynomials[1] = super::coefficients(witness.3.as_ref());
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
        let action_handle = Slot::output(0);
        let tachygram_handle = Slot::output(1);
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
            let output = anchor;
            Ok((
                output,
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
            &action_handle,
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
            &tachygram_handle,
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
/// Opens six slots: L0/L1 and R0/R1 inputs, O0/O1 products, at one shared ζ.
#[derive(Debug)]
pub struct StampMerge;

impl Step<Pasta> for StampMerge {
    type Aux<'source> = ();
    type Left = Stamp;
    type Output = Stamp;
    type Right = Stamp;
    /// `(left, merged, right)`, each an `(action_set, tachygram_set)` pair.
    type Witness<'source> = (
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
    );

    const INDEX: Index = Index::new(10);

    // Child slots bind both inputs; O0/O1 carry their action/tachygram products.
    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.1.0.as_ref());
        polynomials[1] = super::coefficients(witness.1.1.as_ref());
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
        let left_action_handle = Slot::left(0);
        let left_tachygram_handle = Slot::left(1);
        let merged_action_handle = Slot::output(0);
        let merged_tachygram_handle = Slot::output(1);
        let right_action_handle = Slot::right(0);
        let right_tachygram_handle = Slot::right(1);
        // Confirm union via product-opening relation.
        enforce_poly_product(
            dr,
            oracles,
            &left_action_handle,
            &right_action_handle,
            &merged_action_handle,
            "StampMerge: merged action set must be the product of left and right action sets",
        )?;
        enforce_poly_product(
            dr,
            oracles,
            &left_tachygram_handle,
            &right_tachygram_handle,
            &merged_tachygram_handle,
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets",
        )?;
        let output = D::try_just(|| {
            let (
                (left_action_set, left_tachygram_set),
                (merged_action_set, merged_tachygram_set),
                (right_action_set, right_tachygram_set),
            ) = witness.take();
            let (left_action_commit, left_tachygram_commit, left_anchor) = left.take();
            let (right_action_commit, right_tachygram_commit, right_anchor) = right.take();
            // Same-anchor constraint.
            enforce_zero(
                Fp::from(left_anchor) - Fp::from(right_anchor),
                "StampMerge: anchors must match",
            )?;
            // Bind the witnessed left/right input sets to the public commitments on
            // the headers.
            enforce_equal_point(
                Eq::from(left_action_set.commit()),
                Eq::from(left_action_commit),
                "StampMerge: left action accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(right_action_set.commit()),
                Eq::from(right_action_commit),
                "StampMerge: right action accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(left_tachygram_set.commit()),
                Eq::from(left_tachygram_commit),
                "StampMerge: left tachygram accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(right_tachygram_set.commit()),
                Eq::from(right_tachygram_commit),
                "StampMerge: right tachygram accumulator must commit to header commit",
            )?;
            Ok((
                (
                    merged_action_set.commit(),
                    merged_tachygram_set.commit(),
                    left_anchor,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}

/// Merges action content.
///
/// Opens six slots: L0/L1 and R0/R1 inputs, O0/O1 products, at one shared ζ.
#[derive(Debug)]
pub struct ActionMerge;

impl Step<Pasta> for ActionMerge {
    type Aux<'source> = ();
    type Left = Actions;
    type Output = Actions;
    type Right = Actions;
    /// `(left, merged, right)`, each an `(action_set, tachygram_set)` pair.
    type Witness<'source> = (
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
    );

    const INDEX: Index = Index::new(34);

    // Child slots bind both inputs; O0/O1 carry their action/tachygram products.
    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        super::enforce_slot(
            &left.polynomials[0],
            witness.0.0.as_ref(),
            "ActionMerge: left action set does not match the left slot",
        )?;
        super::enforce_slot(
            &right.polynomials[0],
            witness.2.0.as_ref(),
            "ActionMerge: right action set does not match the right slot",
        )?;
        super::enforce_slot(
            &left.polynomials[1],
            witness.0.1.as_ref(),
            "ActionMerge: left tachygram set does not match the left slot",
        )?;
        super::enforce_slot(
            &right.polynomials[1],
            witness.2.1.as_ref(),
            "ActionMerge: right tachygram set does not match the right slot",
        )?;
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.1.0.as_ref());
        polynomials[1] = super::coefficients(witness.1.1.as_ref());
        Ok(polynomials)
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
        let left_action_handle = Slot::left(0);
        let left_tachygram_handle = Slot::left(1);
        let merged_action_handle = Slot::output(0);
        let merged_tachygram_handle = Slot::output(1);
        let right_action_handle = Slot::right(0);
        let right_tachygram_handle = Slot::right(1);
        // Confirm union via product-opening relation.
        enforce_poly_product(
            dr,
            oracles,
            &left_action_handle,
            &right_action_handle,
            &merged_action_handle,
            "ActionMerge: merged action set must be the product of left and right action sets",
        )?;
        enforce_poly_product(
            dr,
            oracles,
            &left_tachygram_handle,
            &right_tachygram_handle,
            &merged_tachygram_handle,
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
/// Opens five slots: R0 (span members), L0/L1 and O0/O1 (preserved sets).
///
/// # Soundness
///
/// The step opens $M$ at the stamp's anchor, and checks $M$'s commitment
/// against the header's `members`. A stamp anchored outside the span passes
/// only if its anchor collides with `anchor_start` or a member.
#[derive(Debug)]
pub struct StampLift;

impl Step<Pasta> for StampLift {
    type Aux<'source> = ();
    type Left = Stamp;
    type Output = Stamp;
    type Right = AnchorSpan;
    /// `(members)`
    type Witness<'source> = (AnchorSetPoly,);

    const INDEX: Index = Index::new(11);

    // Preserve L0/L1 in O0/O1; R0 supplies the span membership opening.
    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        super::enforce_slot(
            &right.polynomials[0],
            witness.0.as_ref(),
            "StampLift: members do not match the span slot",
        )?;
        let mut polynomials = super::unit_polynomials();
        polynomials[0].clone_from(&left.polynomials[0]);
        polynomials[1].clone_from(&left.polynomials[1]);
        Ok(polynomials)
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
        let anchor = Element::alloc(dr, &mut (), left.as_ref().map(|data| Fp::from(data.2)))?;
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
        let output = D::try_just(|| {
            let (stamp_action_commit, stamp_tachygram_commit, _stamp_anchor) = left.take();
            let (_span_anchor_start, span_anchor_end) = right.take();
            Ok((
                (stamp_action_commit, stamp_tachygram_commit, span_anchor_end),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}

/// Advances action content's anchor to the end of an [`AnchorSpan`].
///
/// The actions' `anchor` must be the span's `anchor_start` or one of its
/// members.
///
/// Opens five slots: R0 (span members), L0/L1 and O0/O1 (preserved sets).
#[derive(Debug)]
pub struct ActionLift;

impl Step<Pasta> for ActionLift {
    type Aux<'source> = ();
    type Left = Actions;
    type Output = Actions;
    type Right = AnchorSpan;
    /// `(members)`
    type Witness<'source> = (AnchorSetPoly,);

    const INDEX: Index = Index::new(35);

    // Preserve L0/L1 in O0/O1; R0 supplies the span membership opening.
    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        super::enforce_slot(
            &right.polynomials[0],
            witness.0.as_ref(),
            "ActionLift: members do not match the span slot",
        )?;
        let mut polynomials = super::unit_polynomials();
        polynomials[0].clone_from(&left.polynomials[0]);
        polynomials[1].clone_from(&left.polynomials[1]);
        Ok(polynomials)
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
/// Opens L0/L1 and O0/O1; staged singleton factors need no separate oracle.
#[derive(Debug)]
pub struct FeeFuse;

impl Step<Pasta> for FeeFuse {
    type Aux<'source> = ();
    type Left = Actions;
    type Output = Stamp;
    type Right = ();
    type Witness<'source> = (
        Note,
        value::Positive,
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
    );

    const INDEX: Index = Index::new(33);
    // Four openings (L0/L1/O0/O1); staged singleton factors replace fee oracles.
    const NUM_STAGED: usize = 2;

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        fee_roots(witness.0, witness.1, "FeeFuse")
    }

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        super::enforce_slot(
            &left.polynomials[0],
            witness.2.0.as_ref(),
            "FeeFuse: left action set does not match the left slot",
        )?;
        super::enforce_slot(
            &left.polynomials[1],
            witness.2.1.as_ref(),
            "FeeFuse: left tachygram set does not match the left slot",
        )?;
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.3.0.as_ref());
        polynomials[1] = super::coefficients(witness.3.1.as_ref());
        Ok(polynomials)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "fee derivation, singleton commitments, and product relations stay together"
    )]
    #[expect(
        clippy::missing_asserts_for_indexing,
        reason = "production parameters contain both fixed generators"
    )]
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
            let (
                max_fee_note,
                fee,
                _,
                (output_action_set, output_tachygram_set),
                (fee_action_set, fee_tachygram_set),
            ) = witness.take();
            let left_anchor = left.take();
            let () = right.take();

            let max_fee = u64::from(max_fee_note.value);
            if max_fee > MAX_MONEY {
                return Err(ragu_core::Error::InvalidWitness(
                    "FeeFuse: maximum fee exceeds MAX_MONEY".into(),
                ));
            }
            // `maxfee` and `fee` are below 2^64, far below the field modulus, so the
            // field difference lies in [0, MAX_MONEY] exactly when the integer
            // difference does.
            let change = max_fee
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
            let blind = poseidon::fee_blind(pk, psi, rcm);
            #[expect(
                clippy::expect_used,
                reason = "p < q, so every Fp repr is canonical in Fq"
            )]
            let cv_max_fee =
                value::Trapdoor::from_scalar(Fq::from_bytes(blind.to_bytes()).expect("p < q"))
                    .commit(-max_fee_note.value);
            let cv_max_fee_coords = EpAffine::from(cv_max_fee).coordinates().ok_or_else(|| {
                ragu_core::Error::InvalidWitness("FeeFuse: fee commitment is the identity".into())
            })?;
            let fee_digest = poseidon::fee_digest(cv_max_fee_coords, u64::from(fee));
            // A zero root leaves the set polynomial factor `(X - tg)` trivial.
            let fee_change_commitment = enforce_nonzero(
                poseidon::note_commitment(rcm, pk, change, psi),
                "FeeFuse: fee change note commitment is zero",
            )?;
            // Fixed-generator references bind supplied fee polynomials to X - root.
            let generators = Pasta::host_generators(baked()).g();
            #[expect(
                clippy::indexing_slicing,
                reason = "production parameters contain both fixed generators"
            )]
            let generator_constant = &generators[0];
            #[expect(
                clippy::indexing_slicing,
                reason = "production parameters contain both fixed generators"
            )]
            let generator_linear = &generators[1];
            enforce_equal_point(
                Eq::from(fee_action_set.commit()),
                Eq::from(*generator_linear) - *generator_constant * fee_digest,
                "FeeFuse: fee action set does not commit to the fee digest",
            )?;
            enforce_equal_point(
                Eq::from(fee_tachygram_set.commit()),
                Eq::from(*generator_linear) - *generator_constant * fee_change_commitment,
                "FeeFuse: fee tachygram set does not commit to the fee change note",
            )?;
            let output = (
                output_action_set.commit(),
                output_tachygram_set.commit(),
                left_anchor,
            );
            Ok((output, fee_digest, fee_change_commitment))
        })?;

        let fee_digest = Element::alloc(dr, &mut (), native.clone().map(|(_, digest, _)| digest))?;
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 2")]
        let staged_digest = &oracles.staged()[0];
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 2")]
        let staged_change = &oracles.staged()[1];
        fee_digest.enforce_equal(dr, staged_digest)?;
        let fee_change = Element::alloc(dr, &mut (), native.clone().map(|(_, _, change)| change))?;
        fee_change.enforce_equal(dr, staged_change)?;
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
        let data = native.map(|(output, ..)| output);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
    }
}

/// Proves a zero-action bundle's zero fee.
///
/// Opens O0/O1 singleton sets at ζ, with both derived roots staged before ζ.
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
    // O0/O1 carry the fee singleton sets; both derived roots are staged before ζ.
    const NUM_STAGED: usize = 2;

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        enforce_zero(
            Fp::from(u64::from(witness.0.value)),
            "FeeSeed: maximum fee must be zero",
        )?;
        fee_roots(witness.0, value::Positive::ZERO, "FeeSeed")
    }

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.2.as_ref());
        polynomials[1] = super::coefficients(witness.3.as_ref());
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
        let action_handle = Slot::output(0);
        let tachygram_handle = Slot::output(1);
        let native = D::try_just(|| {
            let (max_fee_note, anchor, fee_action_set, fee_tachygram_set) = witness.take();
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
            let blind = poseidon::fee_blind(pk, psi, rcm);
            #[expect(
                clippy::expect_used,
                reason = "p < q, so every Fp repr is canonical in Fq"
            )]
            let cv_max_fee =
                value::Trapdoor::from_scalar(Fq::from_bytes(blind.to_bytes()).expect("p < q"))
                    .commit(-max_fee_note.value);
            let cv_max_fee_coords = EpAffine::from(cv_max_fee).coordinates().ok_or_else(|| {
                ragu_core::Error::InvalidWitness("FeeSeed: fee commitment is the identity".into())
            })?;
            let fee_digest = poseidon::fee_digest(cv_max_fee_coords, 0);
            // A zero root leaves the set polynomial factor `(X - tg)` trivial.
            let fee_change_commitment = enforce_nonzero(
                poseidon::note_commitment(rcm, pk, 0, psi),
                "FeeSeed: fee change note commitment is zero",
            )?;
            let output = (fee_action_set.commit(), fee_tachygram_set.commit(), anchor);
            Ok((output, fee_digest, fee_change_commitment))
        })?;
        let fee_digest = Element::alloc(dr, &mut (), native.clone().map(|(_, digest, _)| digest))?;
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 2")]
        let staged_digest = &oracles.staged()[0];
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 2")]
        let staged_change_root = oracles.staged()[1].clone();
        fee_digest.enforce_equal(dr, staged_digest)?;
        enforce_poly_roots(
            dr,
            oracles,
            &action_handle,
            &[fee_digest],
            "FeeSeed: fee action set does not commit to the fee digest",
        )?;
        let fee_change = Element::alloc(dr, &mut (), native.clone().map(|(_, _, change)| change))?;
        fee_change.enforce_equal(dr, &staged_change_root)?;
        enforce_poly_roots(
            dr,
            oracles,
            &tachygram_handle,
            &[fee_change],
            "FeeSeed: fee tachygram set does not commit to the fee change note",
        )?;
        let data = native.map(|(output, ..)| output);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
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
/// The quotient is witnessed but not free. The dividend and divisor are bound
/// to their header commitments, and each product relation absorbs all three
/// operands into its challenge, so
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
/// Six committed polynomials and six openings, one shared challenge, four
/// commit-equalities and one scalar equality.
#[derive(Debug)]
pub struct StampUnmerge;

impl Step<Pasta> for StampUnmerge {
    type Aux<'source> = ();
    type Left = Stamp;
    type Output = Stamp;
    type Right = Stamp;
    /// `(dividend, quotient, divisor)`, each an `(action_set, tachygram_set)`
    /// pair.
    type Witness<'source> = (
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
    );

    const INDEX: Index = Index::new(37);

    // O0/O1 are quotients; each R column times its O column must equal L.
    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.1.0.as_ref());
        polynomials[1] = super::coefficients(witness.1.1.as_ref());
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
        let dividend_action_handle = Slot::left(0);
        let dividend_tachygram_handle = Slot::left(1);
        let quotient_action_handle = Slot::output(0);
        let quotient_tachygram_handle = Slot::output(1);
        let divisor_action_handle = Slot::right(0);
        let divisor_tachygram_handle = Slot::right(1);
        enforce_poly_product(
            dr,
            oracles,
            &divisor_action_handle,
            &quotient_action_handle,
            &dividend_action_handle,
            "StampUnmerge: dividend action set must be the product of divisor and quotient action sets",
        )?;
        enforce_poly_product(
            dr,
            oracles,
            &divisor_tachygram_handle,
            &quotient_tachygram_handle,
            &dividend_tachygram_handle,
            "StampUnmerge: dividend tachygram set must be the product of divisor and quotient tachygram sets",
        )?;
        let output = D::try_just(|| {
            let (
                (dividend_action_set, dividend_tachygram_set),
                (quotient_action_set, quotient_tachygram_set),
                (divisor_action_set, divisor_tachygram_set),
            ) = witness.take();
            let (left_action_commit, left_tachygram_commit, left_anchor) = left.take();
            let (right_action_commit, right_tachygram_commit, right_anchor) = right.take();
            enforce_zero(
                Fp::from(left_anchor) - Fp::from(right_anchor),
                "StampUnmerge: anchors must match",
            )?;
            enforce_equal_point(
                Eq::from(dividend_action_set.commit()),
                Eq::from(left_action_commit),
                "StampUnmerge: dividend action accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(divisor_action_set.commit()),
                Eq::from(right_action_commit),
                "StampUnmerge: divisor action accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(dividend_tachygram_set.commit()),
                Eq::from(left_tachygram_commit),
                "StampUnmerge: dividend tachygram accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(divisor_tachygram_set.commit()),
                Eq::from(right_tachygram_commit),
                "StampUnmerge: divisor tachygram accumulator must commit to header commit",
            )?;
            Ok((
                (
                    quotient_action_set.commit(),
                    quotient_tachygram_set.commit(),
                    left_anchor,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}
