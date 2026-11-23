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
/// The polynomials are the actions' digest set and tachygram set.
/// [`FeeFuse`] turns an `Actions` into a [`Stamp`].
///
/// # Injectivity
///
/// [`OutputAction`], [`SpendAction`], [`ActionMerge`] and [`ActionLift`]
/// output this header. A verified `Actions` asserts that its prover knows a
/// multiset of one or more leaves, each with a digest $d$ and a pair of
/// tachygrams. Its [`ActionSetPoly`] $A$ is the
/// [set polynomial](crate::collections::multiset) of the digests, and its
/// [`TachygramSetPoly`] $T$ is that of the pairs' members.
///
/// An *output leaf* names a verified [`OutputHeader`] and an element
/// $\theta$. Its pair is the header's `cm` and `pad`. A *spend leaf* names a
/// verified [`SpendHeader`], a point $\mathsf{ak}$ and elements
/// $\mathsf{nk}$ and $\theta$. Its pair is the header's `nf_current` and
/// `nf_next`. The header's `pk` is the [payment key](poseidon::payment_key)
/// of $\mathsf{ak}$ and $\mathsf{nk}$, and a
/// [stamp chain](Anchor#chains-in-a-step) leads from the header's `anchor`
/// to the `anchor` of this `Actions`.
///
/// With `cm` and `cv` the named header's, $\alpha$ is the
/// [output](poseidon::alpha_output) or [spend](poseidon::alpha_spend)
/// randomizer of $\theta$ and `cm`, an integer below $2^{254}$.
/// $\mathsf{rk}$ is $\[\alpha\]\mathcal{G}$ with $\alpha$ not zero for an
/// output, and $\mathsf{ak} + \[\alpha\]\mathcal{G}$ for a spend. $d$ is the
/// [action digest](poseidon::action_digest) of `cv`, $\mathsf{rk}$ and the
/// pair.
///
/// - `anchor` ends a stamp chain from each spend leaf's anchor and determines
///   the chain's absorptions ([`Anchor`]). The assertion gives nothing about it
///   for an output leaf. With no spend leaf it is a wire of the prover's
///   choice.
/// - $A$ determines the digests with their multiplicities, and a digest
///   determines `cv`, $\mathsf{rk}$ and the pair. An output's pair is a note
///   commitment and a padding tachygram and a spend's is two nullifiers. Those
///   are digests under three tags, so $d$ determines its leaf's kind.
/// - $T$ holds the pairs that the roots of $A$ determine, so $A$ determines
///   $T$.
/// - An output's pair determines `cm` and with it the note. A spend's pair
///   determines the master key and the epoch, and its `cv` the value
///   ([`SpendHeader`]). They do not determine `cm`, because notes that share
///   $\psi$ and $\mathsf{nk}$ share a master key.
/// - $\mathsf{rk}$ ties a leaf to `cm` for the action's signer, who derives
///   $\alpha$ from $\theta$ and `cm` ([`ActionEntropy`]) and may leave the
///   proving to another party. $\[\alpha\]\mathcal{G}$ is $\mathsf{rk}$ for an
///   output and $\mathsf{rk} - \mathsf{ak}$ for a spend, and $\alpha$ is below
///   the order of $\mathcal{G}$. The point therefore determines $\alpha$, and
///   $\alpha$ determines $\theta$ and `cm`. For a spend this holds for one
///   $\mathsf{ak}$. Nothing here shows that two spend leaves with one
///   $\mathsf{rk}$ and different $\mathsf{ak}$ spend one note.
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
/// The polynomials are an [`ActionSetPoly`] and a [`TachygramSetPoly`].
///
/// # Injectivity
///
/// [`FeeFuse`], [`FeeSeed`], [`StampMerge`], [`StampLift`] and
/// [`StampUnmerge`] output this header. A verified `Stamp` asserts what a
/// verified [`Actions`] asserts, except that the multiset of leaves may be
/// empty, with $A$ and $T$ the constant one, and that a leaf may be a fee
/// leaf, which has one tachygram. It also asserts that `tachygram_set_bridge`
/// is a [bridge hash](TachygramSetBridge) of the accumulator of $T$. It does
/// not assert that a fee leaf is present, and [`StampUnmerge`] can remove
/// every leaf.
///
/// A *fee leaf* is a note $(\mathsf{rcm}, \mathsf{pk}, m, \psi)$ and an
/// integer $f$ that the prover knows, with $0 \leq f \leq m \leq$
/// `MAX_MONEY`.
///
/// - $\mathsf{cv}_\mathsf{feemax}$ is the note's [max fee
///   commitment](gadgets::note::Note::cv_feemax).
/// - $\mathsf{cm}_\mathsf{chg}$, the leaf's tachygram, is the [note
///   commitment](poseidon::note_commitment) of the note with value $m - f$. It
///   is nonzero, so it is not a root at zero ([zero
///   tachygrams](super#zero-tachygrams)).
/// - $d$ is the [fee digest](poseidon::fee_digest) of
///   $\mathsf{cv}_\mathsf{feemax}$, $f$ and $\mathsf{cm}_\mathsf{chg}$.
///
/// The values determine what they do in [`Actions`], and the following.
///
/// - `anchor` gets nothing from a fee leaf, as from an output leaf.
/// - A fee digest has its own tag, so $d$ determines whether its leaf is a fee
///   leaf. It then determines $\mathsf{cv}_\mathsf{feemax}$, $f$ and
///   $\mathsf{cm}_\mathsf{chg}$, and $\mathsf{cm}_\mathsf{chg}$ determines
///   $\mathsf{rcm}$, $\mathsf{pk}$, $m - f$ and $\psi$, so $d$ determines the
///   note and the fee.
/// - `tachygram_set_bridge` determines the accumulator of $T$. Each step that
///   outputs a `Stamp` writes its two bridge hash wires there, and the
///   [Recursion assumption](super#assumptions) makes them a bridge hash of the
///   accumulator in the step's last output slot, which holds $T$. The native
///   verifier recomputes the field with
///   [`bridge_hash`](crate::bridge_hash::bridge_hash). No step reads it.
/// - $A$ and $T$ are the set polynomials of digests and tachygrams that the
///   covered bundles publish. A verifier rebuilds both accumulators from the
///   bundles' actions, pairs, fees and fee changes
///   ([`Bundle::verify_covered`](crate::bundle::Bundle::verify_covered)), and
///   an accumulator determines its polynomial. A stamp proof that carries $A$
///   and $T$ in full therefore shows nothing of them that the bundles do not
///   ([full proofs](super#full-proofs-between-parties)).
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
/// Reads `cm`, `pad` and `cv` off the [`OutputHeader`]
/// [`OutputBind`](super::output::OutputBind) derived, derives the action
/// randomizer `alpha` from the witnessed `theta` and `cm`, then the randomized
/// action key `rk`, and enforces the one-action set plus the two-element
/// tachygram set `{cm, pad}`.
///
/// Three permutations (`alpha`, two for the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set polynomials.
///
/// # Soundness
///
/// The circuit computes $\alpha$, $\mathsf{rk}$ and $d$ as an output leaf of
/// [`Actions`] defines them, from the left header's `cm`, `pad` and `cv`
/// wires and a wire $\theta$ with no other constraint. $\alpha$ is
/// decomposed into 254 bits, its only decomposition, and
/// [`G_BASE`](struct@fixed_base::G_BASE) multiplied by them has no
/// assignment at zero.
///
/// $d$ is held equal to a staged value, so it is fixed before $\zeta$ though
/// $\theta$ is not. The leaf says only that some $\theta$ gives the staged
/// digest. The circuit equates the action set's opening at $\zeta$
/// with $\zeta - d$ and the tachygram set's with
/// $(\zeta - \mathsf{cm})(\zeta - \mathsf{pad})$. Both polynomials are
/// committed before $\zeta$ and the header's fields are fixed before it, so
/// by the [check at the challenge](super#checks-at-the-challenge) they are
/// the set polynomials of one output leaf.
///
/// The output's `anchor` is a wire with no constraint.
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
/// The spent note's `pk` and value commitment `cv` arrive on the
/// [`SpendHeader`] [`SpendBind`](super::spend::SpendBind) derived. The step
/// derives the action randomizer `alpha` from the witnessed `theta` and `cm`,
/// then the randomized action key `rk`, and enforces the one-action set plus
/// the two-element tachygram set `{nf_current, nf_next}` (the pair `SpendBind`
/// derived from the master key).
///
/// Four permutations (`pk`, `alpha`, two for the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set
/// polynomials.
///
/// # Soundness
///
/// The argument is [`OutputAction`]'s for a spend leaf, whose pair is the
/// left header's `nf_current` and `nf_next` wires. Three things differ.
///
/// - $\mathsf{ak}$ is allocated as a point, which enforces the curve equation,
///   and $\mathsf{nk}$ is a wire with no other constraint. The output of the
///   payment key circuit on them is held equal to the header's `pk` wire, which
///   determines both. They are therefore the keys of the note's
///   [`NoteSecret`](super::delegation::NoteSecret), and like $\theta$ they need
///   not be fixed before $\zeta$.
/// - $\mathsf{rk}$ is `G_BASE` multiplied by the bits of $\alpha$ and added to
///   $\mathsf{ak}$. The addition has [cases without an
///   assignment](fixed_base#cases-without-an-assignment), which exclude at most
///   five values of $\alpha$ for one $\mathsf{ak}$.
/// - The output's `anchor` is the header's `anchor` wire, a stamp chain of no
///   absorptions.
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
/// The argument is [`ActionMerge`]'s. Fee leaves and empty multisets change
/// nothing in it.
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
/// The circuit equates each output set's opening at $\zeta$ with the product
/// of the two inputs' openings. All six polynomials are fixed before $\zeta$,
/// so by the [check at the challenge](super#checks-at-the-challenge) each
/// output polynomial is the product of the inputs', which is the set
/// polynomial of the multiset sum
/// ([multiset](crate::collections::multiset)). The output's leaves are both
/// inputs' leaves.
///
/// The circuit holds the two `anchor` wires equal and outputs the left one,
/// where every spend leaf's stamp chain ends.
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
/// The argument is [`ActionLift`]'s. Fee leaves and an empty multiset change
/// nothing in it.
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
/// The circuit equates each output set's opening at $\zeta$ with the left
/// set's. All four polynomials are fixed before $\zeta$, so by the
/// [check at the challenge](super#checks-at-the-challenge) the output holds
/// the left input's polynomials and leaves.
///
/// The circuit opens the span's members polynomial $M$ at the left `anchor`
/// wire and holds that value times `anchor - anchor_start` to zero. `anchor`
/// is therefore `anchor_start` or a root of $M$, and the [`AnchorSpan`]
/// asserts a stamp chain from either to `anchor_end`, which is the output's
/// anchor. That chain extends each spend leaf's stamp chain to the output's
/// anchor.
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
/// The circuit computes a fee leaf of [`Stamp`] on its own wires.
/// [`from_slack`](gadgets::value::Positive::from_slack) makes the value $m$
/// an integer in `0..=MAX_MONEY` and
/// [`split`](gadgets::value::Positive::split) makes $f$ and $m - f$ integers
/// in `0..=m`. $\mathsf{cv}_\mathsf{feemax}$ comes from
/// [`cv_feemax`](gadgets::note::Note::cv_feemax) on the same `slack` bits,
/// and $\mathsf{cm}_\mathsf{chg}$, held nonzero, from the note commitment
/// circuit on the note's `rcm`, `pk` and `psi` wires and the change.
///
/// Those three wires, $m$ and $f$ are each held equal to a staged value.
/// $d$ and $\mathsf{cm}_\mathsf{chg}$ are fixed before $\zeta$, because every
/// wire they are computed from is a staged value or is determined by staged
/// values.
///
/// - The `slack` bits are the only 51-bit string that packs to `MAX_MONEY - m`.
/// - The bits that `split` allocates are the only 51-bit string that packs to
///   $f$, and the change is the element $m - f$.
/// - The blind bits are the only 254-bit decomposition of the blind digest of
///   `pk`, `psi` and `rcm`.
///
/// The circuit equates each output set's opening at $\zeta$ with the left
/// set's opening times $\zeta - d$ or $\zeta - \mathsf{cm}_\mathsf{chg}$. All
/// four polynomials are fixed before $\zeta$, so by the
/// [check at the challenge](super#checks-at-the-challenge) the output's
/// leaves are the left input's and the fee leaf. The output's `anchor` is
/// the left `anchor` wire.
///
/// # Caller contract
///
/// The caller confirms that the max fee note's value is within `MAX_MONEY`
/// and the fee is at most that value. The circuit has no assignment
/// otherwise, and proving fails.
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
        // A zero root is the factor `X` whatever kind of tachygram it was
        // meant to be, so the fee change is held nonzero.
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
/// The argument is [`FeeFuse`]'s with no input and $m = f = 0$. The note's
/// value wire is held to zero and the fee is the constant zero, so the change
/// is the note itself and $\mathsf{cm}_\mathsf{chg}$ is the commitment of
/// the note's own four wires. $\mathsf{cv}_\mathsf{feemax}$ comes from
/// [`cv_feemax_zero`](gadgets::note::Note::cv_feemax_zero). The step stages
/// `pk`, `psi` and `rcm` alone, each held equal to its wire, and of the
/// three sets of bits only the blind bits remain.
///
/// The circuit equates the action set's opening at $\zeta$ with $\zeta - d$
/// and the tachygram set's with $\zeta - \mathsf{cm}_\mathsf{chg}$. Both
/// polynomials are committed before $\zeta$ and both roots are fixed before
/// it, so by the [check at the challenge](super#checks-at-the-challenge)
/// they are one fee leaf's. The output's `anchor` is a wire with no
/// constraint.
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
        // A zero root is the factor `X` whatever kind of tachygram it was
        // meant to be, so the fee change is held nonzero.
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
/// The left input is the dividend and the right input the divisor. The
/// output holds the dividend's leaves less the divisor's.
///
/// Six online polynomials open once each at one shared challenge.
///
/// # Soundness
///
/// The circuit equates each dividend set's opening at $\zeta$ with the
/// product of the divisor's and the output's. All six polynomials are fixed
/// before $\zeta$, so by the
/// [check at the challenge](super#checks-at-the-challenge) the divisor's
/// polynomial times the output's is the dividend's, for both sets.
///
/// The dividend's and the divisor's action polynomials are set polynomials
/// by their own inputs' assertions. A polynomial that divides a set
/// polynomial is a scalar times the set polynomial of a sub-multiset
/// ([multiset](crate::collections::multiset)), and the divisor's is monic,
/// so its digests are a sub-multiset of the dividend's. The quotient of two
/// monic polynomials is monic, so the output's action polynomial is the set
/// polynomial of the dividend's digests less the divisor's.
///
/// Pair each divisor leaf with a dividend leaf of the same digest. A digest
/// determines its leaf's tachygrams, so paired leaves have one factor in
/// $T$, and the output's $T$ is the product of the unpaired dividend leaves'
/// factors. Those leaves are the output's, and there are none when every
/// dividend leaf is paired.
///
/// The circuit holds the two `anchor` wires equal and outputs the left one,
/// where the output's leaves' stamp chains end. Any verified `Stamp` at that
/// anchor whose digests are among the dividend's divides it, whether or not
/// it was merged into it.
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
