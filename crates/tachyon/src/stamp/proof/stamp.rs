//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;
use alloc::vec::Vec;

use ragu::{
    Cycle as _, Encoded, Header, HeaderInput, Index, Oracles, PoseidonPermutation as _, Slot, Step,
    pasta::{EpAffine, Pasta, PoseidonFp},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    maybe::Maybe as _,
};
use ragu_primitives::{
    Element, GadgetExt as _,
    poseidon::{Sponge, SpongeState},
    vec::FixedVec,
};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use super::{output::OutputHeader, pool::AnchorSpan, spend::SpendHeader};
use crate::{
    ActionSetPoly, TachygramSetPoly,
    constants::MAX_MONEY,
    digest::poseidon,
    effect,
    entropy::ActionEntropy,
    gadgets::arithmetic as circuit,
    keys::{ProofAuthorizingKey, private, public::ACTION_AUTH_GENERATOR},
    note::{self, Note},
    pasta,
    pasta::Fp,
    primitives::{ActionDigest, Anchor, AnchorSetPoly},
    relations::enforce::{enforce_poly_equal, enforce_poly_product, enforce_poly_roots},
    value,
};

/// Prover-side fee roots used to validate the retained singleton witnesses.
fn fee_roots(note: Note, fee: value::Positive) -> ragu_core::Result<[Fp; 2]> {
    let change = u64::from(note.value)
        .checked_sub(u64::from(fee))
        .ok_or_else(|| {
            ragu_core::Error::InvalidWitness("FeeFuse: change is out of range".into())
        })?;
    let commitment = note.fee_blind().commit(-note.value);
    let coordinates = EpAffine::from(commitment).coordinates().ok_or_else(|| {
        ragu_core::Error::InvalidWitness("FeeFuse: fee commitment is the identity".into())
    })?;
    Ok([
        poseidon::fee_digest(coordinates, u64::from(fee)),
        poseidon::note_commitment(
            Fp::from(note.rcm),
            Fp::from(note.pk),
            change,
            Fp::from(note.psi),
        ),
    ])
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
/// `O0/O1` carry the action/tachygram sets; the derived action root is staged.
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
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        Ok([
            super::coefficients(witness.2.as_ref()),
            super::coefficients(witness.3.as_ref()),
            alloc::vec![Fp::ONE],
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
        let anchor_element =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.1)))?;
        let action_handle = Slot::output(0);
        let tachygram_handle = Slot::output(1);
        let cm_root = left_encoded.as_gadget().cm.element.clone();
        let pad_root = left_encoded.as_gadget().pad.element.clone();
        let theta = Element::alloc(dr, &mut (), witness.as_ref().map(|data| data.0.0))?;
        let state = SpongeState::from_elements(FixedVec::from_fn(|index| {
            Element::constant(
                dr,
                if index == PoseidonFp::RATE {
                    Fp::from_u128(u128::from_le_bytes(*b"Tachyon-Output\0\0"))
                } else {
                    Fp::ZERO
                },
            )
        }));
        let mut sponge = Sponge::resume(state, Pasta::circuit_poseidon(pasta::baked()));
        sponge.absorb(dr, &theta)?;
        sponge.absorb(dr, &cm_root)?;
        let alpha = sponge.squeeze(dr)?;
        let alpha_bits = circuit::bits::<D, 255>(dr, &alpha)?;
        let generator = crate::gadgets::point::CurvePoint::constant(dr, *ACTION_AUTH_GENERATOR)?;
        let rk = crate::gadgets::point::CurvePoint::scale(dr, &generator, &alpha_bits)?;
        rk.enforce_nonidentity(dr)?;
        let cv = left_encoded.as_gadget().cv.point.clone();
        let action_root = poseidon::action_digest_circuit(dr, &[cv.x, cv.y, rk.x, rk.y])?;
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 1")]
        action_root.enforce_equal(dr, &oracles.staged()[0])?;
        let action_roots = [action_root];
        enforce_poly_roots(
            dr,
            oracles,
            &action_handle,
            &action_roots,
            "OutputAction: action set does not commit to the action",
        )?;
        let tachygram_roots = [cm_root, pad_root];
        enforce_poly_roots(
            dr,
            oracles,
            &tachygram_handle,
            &tachygram_roots,
            "OutputAction: tachygram set does not commit to the bound pair",
        )?;
        let output = witness.map(|(_, anchor, action_set, tachygram_set)| {
            (action_set.commit(), tachygram_set.commit(), anchor)
        });
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), output.clone())?;
        let fields = crate::stamp::headers::stamp::ActionsOutput {
            anchor: (anchor_element).into(),
            action_commit: encoded.as_gadget().action_commit.clone(),
            stamp_tg_commit: encoded.as_gadget().stamp_tg_commit.clone(),
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
/// Three permutations (`pk`, `alpha`, the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set
/// polynomials.
/// `O0/O1` carry the action/tachygram sets; the derived action root is staged.
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
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        Ok([
            super::coefficients(witness.2.as_ref()),
            super::coefficients(witness.3.as_ref()),
            alloc::vec![Fp::ONE],
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
        let action_handle = Slot::output(0);
        let tachygram_handle = Slot::output(1);
        let ak_assignment = D::try_just(|| {
            let bytes: [u8; 32] = witness.as_ref().take().1.ak.0.into();
            EpAffine::from_bytes(bytes)
                .ok_or_else(|| ragu_core::Error::InvalidWitness("invalid ak encoding".into()))
        })?;
        let ak = crate::gadgets::point::CurvePoint::alloc(dr, &mut (), ak_assignment)?;
        let nk = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.1.nk)),
        )?;
        let derived_pk = poseidon::payment_key_circuit(dr, &[ak.x.clone(), ak.y.clone(), nk])?;
        let pk = left_encoded.as_gadget().pk.element.clone();
        pk.enforce_equal(dr, &derived_pk).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendAction: pak not related to note".into())
        })?;
        let cm = left_encoded.as_gadget().cm.element.clone();
        let theta = Element::alloc(dr, &mut (), witness.as_ref().map(|data| data.0.0))?;
        let state = SpongeState::from_elements(FixedVec::from_fn(|index| {
            Element::constant(
                dr,
                if index == PoseidonFp::RATE {
                    Fp::from_u128(u128::from_le_bytes(*b"Tachyon-Spend\0\0\0"))
                } else {
                    Fp::ZERO
                },
            )
        }));
        let mut sponge = Sponge::resume(state, Pasta::circuit_poseidon(pasta::baked()));
        sponge.absorb(dr, &theta)?;
        sponge.absorb(dr, &cm)?;
        let alpha = sponge.squeeze(dr)?;
        let alpha_bits = circuit::bits::<D, 255>(dr, &alpha)?;
        let generator = crate::gadgets::point::CurvePoint::constant(dr, *ACTION_AUTH_GENERATOR)?;
        let randomization = crate::gadgets::point::CurvePoint::scale(dr, &generator, &alpha_bits)?;
        let rk = crate::gadgets::point::CurvePoint::add(dr, &ak, &randomization)?;
        rk.enforce_nonidentity(dr)?;
        let cv = left_encoded.as_gadget().cv.point.clone();
        let action_root = poseidon::action_digest_circuit(dr, &[cv.x, cv.y, rk.x, rk.y])?;
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 1")]
        action_root.enforce_equal(dr, &oracles.staged()[0])?;
        enforce_poly_roots(
            dr,
            oracles,
            &action_handle,
            &[action_root],
            "SpendAction: action set does not commit to the action",
        )?;
        let current_root = left_encoded.as_gadget().nf_current.element.clone();
        let next_root = left_encoded.as_gadget().nf_next.element.clone();
        enforce_poly_roots(
            dr,
            oracles,
            &tachygram_handle,
            &[current_root, next_root],
            "SpendAction: tachygram set does not commit to the nullifier pair",
        )?;
        let output = D::just(|| {
            let (_, _, action_set, tachygram_set) = witness.take();
            (action_set.commit(), tachygram_set.commit(), left.take().3)
        });
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), output.clone())?;
        let fields = crate::stamp::headers::stamp::ActionsOutput {
            anchor: (left_encoded.as_gadget().anchor.element.clone()).into(),
            action_commit: encoded.as_gadget().action_commit.clone(),
            stamp_tg_commit: encoded.as_gadget().stamp_tg_commit.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}

/// Transaction assembly and aggregation.
/// `L0/L1` and `R0/R1` are the input sets; `O0/O1` their products, at one ζ.
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

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        super::check_polynomial(
            witness.0.0.as_ref(),
            &left.polynomials[0],
            "StampMerge: left action accumulator must commit to header commit",
        )?;
        super::check_polynomial(
            witness.0.1.as_ref(),
            &left.polynomials[1],
            "StampMerge: left tachygram accumulator must commit to header commit",
        )?;
        super::check_polynomial(
            witness.2.0.as_ref(),
            &right.polynomials[0],
            "StampMerge: right action accumulator must commit to header commit",
        )?;
        super::check_polynomial(
            witness.2.1.as_ref(),
            &right.polynomials[1],
            "StampMerge: right tachygram accumulator must commit to header commit",
        )?;
        Ok([
            super::coefficients(witness.1.0.as_ref()),
            super::coefficients(witness.1.1.as_ref()),
            alloc::vec![Fp::ONE],
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
        let left_action_handle = Slot::left(0);
        let left_tachygram_handle = Slot::left(1);
        let merged_action_handle = Slot::output(0);
        let merged_tachygram_handle = Slot::output(1);
        let right_action_handle = Slot::right(0);
        let right_tachygram_handle = Slot::right(1);
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
        let left_anchor_element = left_encoded.as_gadget().anchor.element.clone();
        let right_anchor_element = right_encoded.as_gadget().anchor.element.clone();
        left_anchor_element
            .enforce_equal(dr, &right_anchor_element)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("StampMerge: anchors must match".into())
            })?;
        let output = D::try_just(|| {
            let (_, (merged_action_set, merged_tachygram_set), _) = witness.take();
            let (_, _, left_anchor) = left.take();
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
        let fields = crate::stamp::headers::stamp::StampOutput {
            anchor: (left_anchor_element).into(),
            action_commit: encoded.as_gadget().action_commit.clone(),
            stamp_tg_commit: encoded.as_gadget().stamp_tg_commit.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
        ))
    }
}

/// Merges action content.
/// `L0/L1` and `R0/R1` are the input sets; `O0/O1` their products, at one ζ.
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

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        super::check_polynomial(
            witness.0.0.as_ref(),
            &left.polynomials[0],
            "ActionMerge: left action accumulator must commit to header commit",
        )?;
        super::check_polynomial(
            witness.0.1.as_ref(),
            &left.polynomials[1],
            "ActionMerge: left tachygram accumulator must commit to header commit",
        )?;
        super::check_polynomial(
            witness.2.0.as_ref(),
            &right.polynomials[0],
            "ActionMerge: right action accumulator must commit to header commit",
        )?;
        super::check_polynomial(
            witness.2.1.as_ref(),
            &right.polynomials[1],
            "ActionMerge: right tachygram accumulator must commit to header commit",
        )?;
        Ok([
            super::coefficients(witness.1.0.as_ref()),
            super::coefficients(witness.1.1.as_ref()),
            alloc::vec![Fp::ONE],
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
        let left_action_handle = Slot::left(0);
        let left_tachygram_handle = Slot::left(1);
        let merged_action_handle = Slot::output(0);
        let merged_tachygram_handle = Slot::output(1);
        let right_action_handle = Slot::right(0);
        let right_tachygram_handle = Slot::right(1);
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
        let left_anchor_element = left_encoded.as_gadget().anchor.element.clone();
        let right_anchor_element = right_encoded.as_gadget().anchor.element.clone();
        left_anchor_element
            .enforce_equal(dr, &right_anchor_element)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("ActionMerge: anchors must match".into())
            })?;
        let output = D::try_just(|| {
            let (_, (merged_action_set, merged_tachygram_set), _) = witness.take();
            let (_, _, left_anchor) = left.take();
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
        let fields = crate::stamp::headers::stamp::ActionsOutput {
            anchor: (left_anchor_element).into(),
            action_commit: encoded.as_gadget().action_commit.clone(),
            stamp_tg_commit: encoded.as_gadget().stamp_tg_commit.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
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
/// # Soundness
///
/// The step opens $M$ at the stamp's anchor, and checks $M$'s commitment
/// against the header's `members`. A stamp anchored outside the span passes
/// only if its anchor collides with `anchor_start` or a member.
/// `R0` supplies span membership; `L0/L1` are preserved into `O0/O1`.
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

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        super::check_polynomial(
            witness.0.as_ref(),
            &right.polynomials[0],
            "StampLift: members do not match header",
        )?;
        Ok(left.polynomials.clone())
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
        let anchor = left_encoded.as_gadget().anchor.element.clone();
        let anchor_start = right_encoded.as_gadget().anchor_start.element.clone();
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
            let (_, _, span_anchor_end) = right.take();
            Ok((
                (stamp_action_commit, stamp_tachygram_commit, span_anchor_end),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let fields = crate::stamp::headers::stamp::StampOutput {
            anchor: (right_encoded.as_gadget().anchor_end.element.clone()).into(),
            action_commit: (left_encoded.as_gadget().action_commit.encoding.clone()).into(),
            stamp_tg_commit: (left_encoded.as_gadget().stamp_tg_commit.encoding.clone()).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
        ))
    }
}

/// Advances action content's anchor to the end of an [`AnchorSpan`].
///
/// The actions' `anchor` must be the span's `anchor_start` or one of its
/// members.
/// `R0` supplies span membership; `L0/L1` are preserved into `O0/O1`.
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

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        super::check_polynomial(
            witness.0.as_ref(),
            &right.polynomials[0],
            "ActionLift: members do not match header",
        )?;
        Ok(left.polynomials.clone())
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
        let anchor = left_encoded.as_gadget().anchor.element.clone();
        let anchor_start = right_encoded.as_gadget().anchor_start.element.clone();
        let anchor_evaluation = oracles.query(dr, Slot::right(0), &anchor)?;
        let delta = anchor.sub(dr, &anchor_start);
        let membership = anchor_evaluation.mul(dr, &delta)?;
        membership.enforce_zero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "ActionLift: actions anchor is neither the span's start nor a member".into(),
            )
        })?;
        let output = D::try_just(|| {
            let (actions_action_commit, actions_tachygram_commit, _actions_anchor) = left.take();
            let (_, _, span_anchor_end) = right.take();
            Ok((
                (
                    actions_action_commit,
                    actions_tachygram_commit,
                    span_anchor_end,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let fields = crate::stamp::headers::stamp::ActionsOutput {
            anchor: (right_encoded.as_gadget().anchor_end.element.clone()).into(),
            action_commit: (left_encoded.as_gadget().action_commit.encoding.clone()).into(),
            stamp_tg_commit: (left_encoded.as_gadget().stamp_tg_commit.encoding.clone()).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
        ))
    }
}

/// Turns [`Actions`] into a [`Stamp`] by adding the fee digest and fee change
/// note's commitment to the action and tachygram sets.
///
/// Opens `L0/L1/O0/O1`; the note fields and fee are staged before ζ, so
/// the two driver-derived singleton factors need no separate oracle.
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
    const NUM_STAGED: usize = 5;

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        Ok(alloc::vec![
            Fp::from(witness.0.pk),
            Fp::from(witness.0.psi),
            Fp::from(witness.0.rcm),
            Fp::from(u64::from(witness.0.value)),
            Fp::from(u64::from(witness.1))
        ])
    }

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        super::check_polynomial(
            witness.2.0.as_ref(),
            &left.polynomials[0],
            "FeeFuse: left action accumulator must commit to header commit",
        )?;
        super::check_polynomial(
            witness.2.1.as_ref(),
            &left.polynomials[1],
            "FeeFuse: left tachygram accumulator must commit to header commit",
        )?;
        let [digest, change] = fee_roots(witness.0, witness.1)?;
        super::check_polynomial(
            witness.4.0.as_ref(),
            &[-digest, Fp::ONE],
            "FeeFuse: fee action set does not commit to the fee digest",
        )?;
        super::check_polynomial(
            witness.4.1.as_ref(),
            &[-change, Fp::ONE],
            "FeeFuse: fee tachygram set does not commit to the fee change note",
        )?;
        Ok([
            super::coefficients(witness.3.0.as_ref()),
            super::coefficients(witness.3.1.as_ref()),
            alloc::vec![Fp::ONE],
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
        let maximum = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|data| Fp::from(u64::from(data.0.value))),
        )?;
        circuit::bounded::<D, 51>(dr, &maximum, MAX_MONEY).map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeFuse: maximum fee exceeds MAX_MONEY".into())
        })?;
        let fee = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(u64::from(data.1))),
        )?;
        circuit::bounded::<D, 51>(dr, &fee, MAX_MONEY)?;
        let change = maximum.sub(dr, &fee);
        circuit::bounded::<D, 51>(dr, &change, MAX_MONEY).map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeFuse: change is out of range".into())
        })?;
        let pk = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.pk)),
        )?;
        let psi = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.psi)),
        )?;
        let rcm = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.rcm)),
        )?;
        let blind = poseidon::fee_blind_circuit(dr, &[pk.clone(), psi.clone(), rcm.clone()])?;
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 5")]
        for (index, actual) in [&pk, &psi, &rcm, &maximum, &fee].into_iter().enumerate() {
            actual.enforce_equal(dr, &oracles.staged()[index])?;
        }
        let maximum_bits = circuit::bits::<D, 51>(dr, &maximum)?;
        let blind_bits = circuit::bits::<D, 255>(dr, &blind)?;
        let value_generator =
            crate::gadgets::point::CurvePoint::constant(dr, (-*value::VALUE_COMMIT_V).to_affine())?;
        let blind_generator =
            crate::gadgets::point::CurvePoint::constant(dr, value::VALUE_COMMIT_R.to_affine())?;
        let value_point =
            crate::gadgets::point::CurvePoint::scale(dr, &value_generator, &maximum_bits)?;
        let blind_point =
            crate::gadgets::point::CurvePoint::scale(dr, &blind_generator, &blind_bits)?;
        let cv = crate::gadgets::point::CurvePoint::add(dr, &value_point, &blind_point)?;
        cv.enforce_nonidentity(dr)?;
        let fee_digest = poseidon::fee_digest_circuit(dr, &[cv.x, cv.y, fee])?;
        let fee_change = poseidon::note_commitment_circuit(dr, &[rcm, pk, change, psi])?;
        fee_change.clone().enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeFuse: fee change note commitment is zero".into())
        })?;
        let z = oracles.zeta().clone();
        for (slot, root, error) in [
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
            let input = oracles.query_at_zeta(dr, Slot::left(slot))?;
            let output = oracles.query_at_zeta(dr, Slot::output(slot))?;
            let factor = z.sub(dr, &root);
            input
                .mul(dr, &factor)?
                .enforce_equal(dr, &output)
                .map_err(|_err| ragu_core::Error::InvalidWitness(error.into()))?;
        }
        let output = D::just(|| {
            let (_, _, _, (actions, tachygrams), _) = witness.take();
            (actions.commit(), tachygrams.commit(), left.take().2)
        });
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), output.clone())?;
        let fields = crate::stamp::headers::stamp::StampOutput {
            anchor: (left_encoded.as_gadget().anchor.element.clone()).into(),
            action_commit: encoded.as_gadget().action_commit.clone(),
            stamp_tg_commit: encoded.as_gadget().stamp_tg_commit.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}

/// Proves a zero-action bundle's zero fee.
/// `O0/O1` carry singleton sets; the note's `pk/psi/rcm` are staged before ζ.
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

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        Ok(alloc::vec![
            Fp::from(witness.0.pk),
            Fp::from(witness.0.psi),
            Fp::from(witness.0.rcm)
        ])
    }

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        Ok([
            super::coefficients(witness.2.as_ref()),
            super::coefficients(witness.3.as_ref()),
            alloc::vec![Fp::ONE],
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left)?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let anchor_element =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.1)))?;
        let action_handle = Slot::output(0);
        let tachygram_handle = Slot::output(1);
        let maximum = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|data| Fp::from(u64::from(data.0.value))),
        )?;
        maximum.enforce_zero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeSeed: maximum fee must be zero".into())
        })?;
        let pk = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.pk)),
        )?;
        let psi = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.psi)),
        )?;
        let rcm = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.rcm)),
        )?;
        let blind = poseidon::fee_blind_circuit(dr, &[pk.clone(), psi.clone(), rcm.clone()])?;
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 3")]
        for (index, actual) in [&pk, &psi, &rcm].into_iter().enumerate() {
            actual.enforce_equal(dr, &oracles.staged()[index])?;
        }
        let blind_bits = circuit::bits::<D, 255>(dr, &blind)?;
        let blind_generator =
            crate::gadgets::point::CurvePoint::constant(dr, value::VALUE_COMMIT_R.to_affine())?;
        let cv = crate::gadgets::point::CurvePoint::scale(dr, &blind_generator, &blind_bits)?;
        cv.enforce_nonidentity(dr)?;
        let zero = Element::constant(dr, Fp::ZERO);
        let fee_digest = poseidon::fee_digest_circuit(dr, &[cv.x, cv.y, zero.clone()])?;
        let fee_change = poseidon::note_commitment_circuit(dr, &[rcm, pk, zero, psi])?;
        fee_change.clone().enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeSeed: fee change note commitment is zero".into())
        })?;
        enforce_poly_roots(
            dr,
            oracles,
            &action_handle,
            &[fee_digest],
            "FeeSeed: fee action set does not commit to the fee digest",
        )?;
        enforce_poly_roots(
            dr,
            oracles,
            &tachygram_handle,
            &[fee_change],
            "FeeSeed: fee tachygram set does not commit to the fee change note",
        )?;
        let output = witness.map(|(_, anchor, actions, tachygrams)| {
            (actions.commit(), tachygrams.commit(), anchor)
        });
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), output.clone())?;
        let fields = crate::stamp::headers::stamp::StampOutput {
            anchor: (anchor_element).into(),
            action_commit: encoded.as_gadget().action_commit.clone(),
            stamp_tg_commit: encoded.as_gadget().stamp_tg_commit.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
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
/// Six committed polynomials and six openings at the framework's shared
/// challenge, with child-slot binding and one scalar equality.
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

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        super::check_polynomial(
            witness.0.0.as_ref(),
            &left.polynomials[0],
            "StampUnmerge: dividend action accumulator must commit to header commit",
        )?;
        super::check_polynomial(
            witness.0.1.as_ref(),
            &left.polynomials[1],
            "StampUnmerge: dividend tachygram accumulator must commit to header commit",
        )?;
        super::check_polynomial(
            witness.2.0.as_ref(),
            &right.polynomials[0],
            "StampUnmerge: divisor action accumulator must commit to header commit",
        )?;
        super::check_polynomial(
            witness.2.1.as_ref(),
            &right.polynomials[1],
            "StampUnmerge: divisor tachygram accumulator must commit to header commit",
        )?;
        Ok([
            super::coefficients(witness.1.0.as_ref()),
            super::coefficients(witness.1.1.as_ref()),
            alloc::vec![Fp::ONE],
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
        let left_anchor_element = left_encoded.as_gadget().anchor.element.clone();
        let right_anchor_element = right_encoded.as_gadget().anchor.element.clone();
        left_anchor_element
            .enforce_equal(dr, &right_anchor_element)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("StampUnmerge: anchors must match".into())
            })?;
        let output = D::try_just(|| {
            let (_, (quotient_action_set, quotient_tachygram_set), _) = witness.take();
            let (_, _, left_anchor) = left.take();
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
        let fields = crate::stamp::headers::stamp::StampOutput {
            anchor: (left_anchor_element).into(),
            action_commit: encoded.as_gadget().action_commit.clone(),
            stamp_tg_commit: encoded.as_gadget().stamp_tg_commit.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
        ))
    }
}

pub use crate::stamp::headers::stamp::{Actions, Stamp};
