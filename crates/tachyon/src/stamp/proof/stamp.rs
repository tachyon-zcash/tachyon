//! Stamp header and stamp-producing/transforming steps.

use ragu::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Suffix},
    maybe::Maybe as _,
    pasta::Pasta,
    primitives::{Element, GadgetExt as _, Point, allocator::Allocator, decompose_n, io::Write},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
    udon::{curve::Affine as _, field::Field as _},
};

use super::{
    output::OutputHeader,
    pool::{AnchorSpan, AnchorSpanOutput},
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
    primitives::{
        ActionDigest, Anchor, AnchorSetPoly, PolySlot, Tachygram, TachygramSetBridge, effect,
    },
    value,
};

/// One or more proven actions at one anchor, with no fee.
///
/// Carries the actions' digest set and tachygram set polynomials, which
/// [`FeeFuse`] turns into a [`Stamp`].
///
/// # Injectivity
///
/// [`OutputAction`], [`SpendAction`], [`ActionMerge`] and [`ActionLift`] output
/// this header. Every verified `Actions` asserts a prover-known multiset of one
/// or more leaves, each contributing a digest $d$ to the
/// [set polynomial](crate::collections::multiset) $A$ ([`ActionSetPoly`]) and a
/// tachygram pair to $T$ ([`TachygramSetPoly`]).
///
/// - An *output leaf* pairs a verified [`OutputHeader`] with an element
///   $\theta$ and takes `(cm, pad)` from that header as its pair.
/// - A *spend leaf* pairs a verified [`SpendHeader`] with a point $\mathsf{ak}$
///   and elements $\mathsf{nk}$ and $\theta$, taking `(nf_current, nf_next)` as
///   its pair where `pk` equals the [payment key](poseidon::payment_key) of
///   $\mathsf{ak}$ and $\mathsf{nk}$ and a [stamp
///   chain](super#chains-in-a-step) leads from the header's `anchor` to this
///   `Actions`'s `anchor`.
///
/// Using `cm` and `cv` from the named header, $\alpha < 2^{254}$ is the
/// [output](poseidon::alpha_output) or [spend](poseidon::alpha_spend)
/// randomizer of $\theta$ and `cm`, $\mathsf{rk}$ equals
/// $\[\alpha\]\mathcal{G}$ ($\alpha \neq 0$) for an output and $\mathsf{ak} +
/// \[\alpha\]\mathcal{G}$ for a spend, and $d$ is the [action
/// digest](poseidon::action_digest) of `cv`, $\mathsf{rk}$ and the pair.
///
/// - `anchor` terminates a stamp chain from every spend leaf's anchor and
///   determines those absorptions ([`Anchor`]), while output leaves leave it
///   unconstrained to the prover's choice when no spend leaf is present.
/// - $A$ determines the digests with multiplicity, each $d$ determines `cv`,
///   $\mathsf{rk}$ and its pair, and the three distinct tags on `cm`, `pad` and
///   nullifiers let $d$ determine its leaf kind.
/// - $A$ determines $T$ because $T$ collects the pairs determined by $A$'s
///   roots.
/// - An output's pair determines `cm` and the note, whereas a spend's pair
///   determines the master key and epoch while `cv` determines the value
///   ([`SpendHeader`]), without fixing `cm` across notes sharing $\psi$ and
///   $\mathsf{nk}$.
/// - $\mathsf{rk}$ binds a leaf to `cm` for the signer, who derives $\alpha$
///   from $\theta$ and `cm` ([`ActionEntropy`]) and may delegate proving.
///   Because $\alpha$ lies below the order of $\mathcal{G}$, the point
///   $\[\alpha\]\mathcal{G}$ ($\mathsf{rk}$ for an output, $\mathsf{rk} -
///   \mathsf{ak}$ for a spend) determines $\alpha$ and thus $\theta$ and `cm`
///   for a fixed $\mathsf{ak}$. Nothing here forces two spend leaves sharing
///   $\mathsf{rk}$ under distinct $\mathsf{ak}$ to spend one note.
#[derive(Debug)]
pub struct Actions;

#[derive(Gadget, Write)]
pub struct ActionsOutput<'dr, D: Driver<'dr>> {
    pub anchor: Element<'dr, D>,
}

impl Header<Fp> for Actions {
    /// `anchor`
    type Data = Anchor;
    type OnlinePolyCommit = (PolySlot<ActionSetPoly>, PolySlot<TachygramSetPoly>);
    type Output = Kind![Fp; ActionsOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(15);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Ok(ActionsOutput {
            anchor: Element::alloc(dr, allocator, witness.map(Fp::from))?,
        })
    }
}

/// Proven actions and fees at one anchor.
///
/// Carries an [`ActionSetPoly`] and a [`TachygramSetPoly`].
///
/// # Injectivity
///
/// [`FeeFuse`], [`FeeSeed`], [`StampMerge`], [`StampLift`] and [`StampUnmerge`]
/// output this header. Every verified `Stamp` asserts the same leaf multiset
/// structure as [`Actions`], extended with optional single-tachygram fee leaves
/// and allowing an empty multiset ($A = T = 1$, as from [`StampUnmerge`]),
/// plus a [bridge hash](TachygramSetBridge) `tachygram_set_bridge` of
/// $T$'s accumulator. Even a nonempty `Stamp` need not contain a fee leaf.
///
/// Each *fee leaf* consists of a prover-known note $(\mathsf{rcm}, \mathsf{pk},
/// m, \psi)$ and integer $f$ satisfying $0 \leq f \leq m \leq
/// \text{MAX\_MONEY}$, where
///
/// - $\mathsf{cv}_\mathsf{feemax}$ is the note's [max fee
///   commitment](gadgets::note::Note::cv_feemax),
/// - $\mathsf{cm}_\mathsf{chg}$ is the nonzero [note
///   commitment](poseidon::note_commitment) of the same note with only its
///   value changed to $m - f$, serving as the leaf's tachygram,
/// - $d$ is the [fee digest](poseidon::fee_digest) of
///   $\mathsf{cv}_\mathsf{feemax}$, $f$ and $\mathsf{cm}_\mathsf{chg}$.
///
/// - Fee leaves, like output leaves, place no constraint on `anchor`.
/// - Because fee digests use a dedicated tag, $d$ identifies fee leaves and
///   determines $\mathsf{cv}_\mathsf{feemax}$, $f$ and
///   $\mathsf{cm}_\mathsf{chg}$, which in turn determines $\mathsf{rcm}$,
///   $\mathsf{pk}$, $m - f$ and $\psi$, fixing the note and fee.
/// - `tachygram_set_bridge` determines $T$'s accumulator. Producers write their
///   two bridge hash wires here, which the [Recursion
///   assumption](super#assumptions) ties to $T$ in the last output slot, while
///   the native verifier recomputes
///   [`bridge_hash`](crate::bridge_hash::bridge_hash) and no step reads the
///   field.
///
/// [`OutputBind`](super::output::OutputBind) holds `cm` and `pad` nonzero,
/// [`SpendBind`](super::spend::SpendBind) both nullifiers, and
/// [`FeeFuse`] and [`FeeSeed`] the fee change commitment. Thus no leaf of a
/// verified `Stamp` contributes a zero root to the published [set
/// polynomial](crate::collections::multiset). Its factors record no roles:
/// zero always contributes $X$.
///
/// Matching a note commitment (including fee change) to another note's
/// commitment or to a differently tagged pad or nullifier requires a Poseidon
/// collision. At zero the nonzero checks exclude a match independently of
/// collision resistance: zero cannot be the published root that
/// [`SpendableInit`](super::spendable::SpendableInit) tests for membership.
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

/// Proves an output's action as [`Actions`].
///
/// Three permutations (`alpha`, two for the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set polynomials.
///
/// # Soundness
///
/// Computing $\alpha$, $\mathsf{rk}$ and $d$ from the input header's `cm`,
/// `pad` and `cv` plus an unconstrained $\theta$ wire, the circuit decomposes
/// $\alpha$ into its unique 254 bits and multiplies
/// [`G_BASE`](struct@fixed_base::G_BASE), leaving zero unassigned.
///
/// Equating $d$ with a staged value fixes $d$ before $\zeta$ without fixing
/// $\theta$, asserting only that some $\theta$ yields $d$. With both output
/// polynomials committed and the input header fixed before $\zeta$, equating
/// the action set with $\zeta - d$ and the tachygram set with
/// $(\zeta - \mathsf{cm})(\zeta - \mathsf{pad})$ at $\zeta$
/// ([checks at the challenge](super#checks-at-the-challenge)) establishes a
/// single output leaf. `anchor` is an unconstrained wire.
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
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let (cm, pad, cv) = *left.data;
        let alpha = witness
            .0
            .randomizer::<effect::Output>(note::Commitment::from(Fp::from(cm)));
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        let digest = ActionDigest::new(cv, rk, (cm, pad));
        let (action_set, tachygram_set) = (&witness.2, &witness.3);
        let prepared = ActionSetPoly::SLOT.poly(Prepared::new(), action_set);
        Ok(TachygramSetPoly::SLOT
            .poly(prepared, tachygram_set)
            .stage([Fp::from(digest)]))
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
        let alpha_bits = decompose_n::<_, 254>(dr, &mut (), &alpha)?;
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
        let z = oracles.zeta().clone();
        // The action-set commitment commits to exactly the one action this
        // step derives. `cv` carries the note's value; `rk` derives from
        // `alpha`, and so from `cm`.
        let action_set = oracles.output(ActionSetPoly::SLOT).open(dr, &z)?;
        let action_factor = z.sub(dr, &action_root);
        action_set.enforce_equal(dr, &action_factor)?;
        // The tachygram set holds exactly the tachygram pair on the
        // bind header, both roots fixed by the recursive verification of the
        // left PCD.
        let tachygram_set = oracles.output(TachygramSetPoly::SLOT).open(dr, &z)?;
        let mut expected_tachygram_set = Element::constant(dr, Fp::ONE);
        for root in [&cm_root, &output_header.pad] {
            let factor = z.sub(dr, root);
            expected_tachygram_set = expected_tachygram_set.mul(dr, &factor)?;
        }
        tachygram_set.enforce_equal(dr, &expected_tachygram_set)?;
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
/// Four permutations (`pk`, `alpha`, two for the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set
/// polynomials.
///
/// # Soundness
///
/// Follows [`OutputAction`] for a spend leaf over `(nf_current, nf_next)`, with
/// three differences.
///
/// - Allocating curve point $\mathsf{ak}$ and unconstrained wire $\mathsf{nk}$
///   and equating their payment-key digest with `pk` ties both to the note's
///   [`NoteSecret`](super::delegation::NoteSecret), and neither witness wire
///   need be fixed before $\zeta$.
/// - [`mul_and_add`](ragu::primitives::FixedBase::mul_and_add) computes
///   $\mathsf{rk}=\mathsf{ak}+\[\alpha\]\mathcal{G}$, which must be finite and
///   non-identity.
/// - Copying the input header's `anchor` forms a zero-absorption stamp chain.
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
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let (cm, nf_current, nf_next, _, _, cv) = *left.data;
        let alpha = witness.0.randomizer::<effect::Spend>(cm);
        let rk = witness.1.ak.derive_action_public(&alpha);
        let digest = ActionDigest::new(
            cv,
            rk,
            (Tachygram::from(nf_current), Tachygram::from(nf_next)),
        );
        let (action_set, tachygram_set) = (&witness.2, &witness.3);
        let prepared = ActionSetPoly::SLOT.poly(Prepared::new(), action_set);
        Ok(TachygramSetPoly::SLOT
            .poly(prepared, tachygram_set)
            .stage([Fp::from(digest)]))
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
        let alpha_bits = decompose_n::<_, 254>(dr, &mut (), &alpha)?;
        let rk = fixed_base::G_BASE.mul_and_add(dr, &alpha_bits, &ak)?;
        let action_root = poseidon::circuit::action_digest(dr, &cv, &rk, (&nf_current, &nf_next))?;
        #[expect(clippy::indexing_slicing, reason = "framework enforces NUM_STAGED = 1")]
        let staged_root = &oracles.staged()[0];
        action_root.enforce_equal(dr, staged_root)?;
        let z = oracles.zeta().clone();
        // The action-set commitment commits to exactly the one action this
        // step derives; the root is in-circuit from the certified note.
        let action_set = oracles.output(ActionSetPoly::SLOT).open(dr, &z)?;
        let action_factor = z.sub(dr, &action_root);
        action_set.enforce_equal(dr, &action_factor)?;
        // The tachygram set holds exactly the nullifier pair on the
        // bind header, both roots fixed by the recursive verification of the
        // left PCD.
        let tachygram_set = oracles.output(TachygramSetPoly::SLOT).open(dr, &z)?;
        let mut expected_tachygram_set = Element::constant(dr, Fp::ONE);
        for root in [&nf_current, &nf_next] {
            let factor = z.sub(dr, root);
            expected_tachygram_set = expected_tachygram_set.mul(dr, &factor)?;
        }
        tachygram_set.enforce_equal(dr, &expected_tachygram_set)?;
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
///
/// # Soundness
///
/// Follows [`ActionMerge`], unchanged by fee leaves or empty multisets.
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

/// Merges action content.
///
/// Opens both inputs' action and tachygram sets and both products at one
/// challenge.
///
/// # Soundness
///
/// All six polynomials precede $\zeta$. Checking each output against the
/// product of its inputs there adds the
/// [multisets](crate::collections::multiset) with multiplicity. Matching and
/// copying the input anchors preserves the endpoint of every spend leaf's stamp
/// chain.
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
/// The stamp's `anchor` $a$ must be the span's `anchor_start` $s$ or one of
/// its members:
///
/// $$
///   M(a) \cdot (a - s) = 0
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
/// Follows [`ActionLift`], unchanged by fee leaves or an empty multiset.
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
        // The output tachygram set copies the left one. With the honest bridge
        // hash on both, the output's bridge hash is the left stamp's.
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
///
/// # Soundness
///
/// All four set polynomials precede $\zeta$; matching both output openings
/// to the left input's preserves its leaves. For the left anchor $a$ and
/// span start $s$, $M(a)(a-s)=0$ puts $a$ at the start or a member of the
/// [`AnchorSpan`]. Each spend leaf's chain thus extends to `anchor_end`.
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
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let prepared = ActionSetPoly::SLOT.copy_from(Prepared::new(), &left, ActionSetPoly::SLOT);
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
        let ActionsOutput { anchor } = left_encoded.as_gadget().clone();
        let anchor_evaluation = oracles.right(AnchorSetPoly::SLOT).open(dr, &anchor)?;
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
///
/// # Soundness
///
/// [`from_slack`](gadgets::value::Positive::from_slack) bounds the maximum
/// $m$ by `MAX_MONEY`; [`split`](gadgets::value::Positive::split) bounds both
/// fee $f$ and change $m-f$ to `0..=m`. The step stages $m,f$ and the note's
/// `pk`, `psi`, `rcm`. These fix the 51-bit encodings of `MAX_MONEY - m`
/// and $f$, and the unique 254-bit decomposition of the derived blind.
/// [`cv_feemax`](gadgets::note::Note::cv_feemax) uses the same slack bits;
/// the nonzero change commitment uses the same note fields with value $m-f$.
/// Thus both the fee digest $d$ and change commitment precede $\zeta$.
///
/// With all four polynomials fixed, the openings at $\zeta$ check each output
/// against its input times $\zeta-d$ or $\zeta-\mathsf{cm}_\mathsf{chg}$.
/// This appends one fee leaf at the input anchor.
///
/// # Caller contract
///
/// Callers must pass a max fee note within `MAX_MONEY` and a fee at most that
/// value. Otherwise the circuit has no satisfying assignment for those amounts.
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
        // Zero produces the factor `X` regardless of tachygram kind, so hold
        // the fee change nonzero.
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
///
/// # Soundness
///
/// Specializes [`FeeFuse`] to no input and $m = f = 0$. Holding the note's
/// value wire to zero with constant zero fee makes the note its own change for
/// $\mathsf{cm}_\mathsf{chg}$, while
/// [`cv_feemax_zero`](gadgets::note::Note::cv_feemax_zero) computes
/// $\mathsf{cv}_\mathsf{feemax}$ from the blind bits alone. Equating `pk`,
/// `psi` and `rcm` with staged values while value and fee are zero fixes $d$
/// and $\mathsf{cm}_\mathsf{chg}$ before $\zeta$.
///
/// Equating the pre-committed action and tachygram sets at $\zeta$ with
/// $\zeta - d$ and $\zeta - \mathsf{cm}_\mathsf{chg}$
/// ([checks at the challenge](super#checks-at-the-challenge)) establishes a
/// single fee leaf at an unconstrained `anchor` wire.
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
        // Zero produces the factor `X` regardless of tachygram kind, so hold
        // the fee change nonzero.
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
/// # Soundness
///
/// All six polynomials are fixed before $\zeta$ and opened once there. For each
/// set, the [challenge check](super#checks-at-the-challenge) gives left
/// dividend = right divisor × output.
///
/// Because both inputs' action polynomials are monic
/// [set polynomials](crate::collections::multiset), divisibility makes the
/// divisor's digests a sub-multiset of the dividend's and makes the monic
/// quotient the set polynomial of the remaining digests.
///
/// Matching leaves by digest cancels identical tachygram factors in $T$: each
/// digest determines its tachygrams. The output holds the unpaired dividend
/// leaves' factors, or one if every leaf pairs off.
///
/// Equating both `anchor` wires and outputting the left one preserves the end
/// of every remaining leaf's stamp chain. Any verified `Stamp` at that anchor
/// whose digests form a sub-multiset of the dividend's divides it regardless of
/// how the dividend was assembled.
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
