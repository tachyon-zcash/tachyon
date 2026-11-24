//! Working transaction header and stamp-producing/transforming steps.

#[cfg(test)]
mod tests;

use ragu::{
    Cycle,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Padding, Suffix},
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
        ActionDigest, ActionSetBridge, Anchor, AnchorSetPoly, PolySlot, Tachygram, effect,
    },
    value,
};

/// Non-empty proven action content with no fee in its lineage.
///
/// [`OutputAction`] and [`SpendAction`] check both the action-digest factor
/// and the tachygram factors for the pair on their input header.
/// [`ActionMerge`] checks the product in each slot, and [`ActionLift`] checks
/// that both are preserved. [`FeeFuse`] carries only the action polynomial into
/// [`Transaction`]: each action digest already binds its pair.
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

/// A multiset of valid action and fee leaves at `anchor`.
/// This is a working stamp statement, not a signed ledger transaction.
///
/// Every spend has proved history reaching that anchor. The last slot holds the
/// monic product of the leaves' digest factors, with multiplicity.
/// `action_set_bridge` binds the commitment to that same polynomial: every
/// writer returns both coordinates of its own last-slot oracle and
/// rerandomization preserves fields and slots. [`TransactionUnmerge`] may leave
/// no fees or even no leaves (the polynomial one).
///
/// The bridge stage binds the coordinates of the last slot's accumulator;
/// its point need not be a unique encoding of that accumulator. Native
/// verification supplies the canonical zero-blind bridge of the publicly
/// reconstructed accumulator and compares that accumulator to the last slot.
/// No set identity relies on the bridge point being fixed before $\zeta$.
///
/// An action digest binds the descriptor and the sum and product of the pair,
/// which determine its unordered tachygrams with multiplicity. A fee digest
/// binds the max-fee commitment, bounded fee and change commitment in a
/// separate domain. Under hash collision resistance the digest roots therefore
/// bind those public contributions. No slot carries a tachygram polynomial.
/// With $N$ action leaves and $B$ fee leaves, the last slot bounds $N+B$ by
/// its maximum degree, 8191. A merge can fit that slot even when the $2N+B$
/// tachygram contributions, counting multiplicity, would exceed that degree.
#[derive(Debug)]
pub struct Transaction;

#[derive(Gadget, Write)]
pub struct TransactionOutput<'dr, D: Driver<'dr>> {
    pub anchor: Element<'dr, D>,
    pub action_set_bridge: [Element<'dr, D>; 2],
}

impl Header<Fp> for Transaction {
    /// `(action_set_bridge, anchor)`
    type Data = (ActionSetBridge, Anchor);
    type OnlinePolyCommit = (Padding, PolySlot<ActionSetPoly>);
    type Output = Kind![Fp; TransactionOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        let action_set_bridge = D::try_just(|| {
            EpAffine::from(witness.as_ref().take().0)
                .coordinates()
                .ok_or_else(|| ragu::Error::InvalidWitness("identity action bridge".into()))
        })?;
        Ok(TransactionOutput {
            anchor: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            action_set_bridge: [
                Element::alloc(
                    dr,
                    allocator,
                    action_set_bridge.as_ref().map(|coordinates| coordinates.0),
                )?,
                Element::alloc(
                    dr,
                    allocator,
                    action_set_bridge.as_ref().map(|coordinates| coordinates.1),
                )?,
            ],
        })
    }
}

/// One working [`Transaction`] at the stated anchor has this action-set
/// binding.
///
/// The encoded fields are the reference and the portable point's `x,y`.
/// A point has no intrinsic set tag: its position under suffix 17 and
/// [`TransactionDehydrate`]'s copy from the certified working field identify
/// the action/fee accumulator. Its only ordinary issuer also pins the bridge of
/// **its own last padding slot** to the canonical wallet-rank value. This
/// establishes wallet origin, not canonical encoding of the separate action
/// bridge. Rerandomization preserves the statement; an aggregator import
/// must authenticate this same wallet statement, not issue a local one.
/// Ordinary dehydration leaves two padding slots; neither supplies the action
/// binding. The set may be empty after division. The header does not
/// certify a trailer or a signed body.
#[derive(Debug)]
pub struct PublicTransaction;

impl Header<Fp> for PublicTransaction {
    type Data = (ActionSetBridge, Anchor);
    type OnlinePolyCommit = (Padding, Padding);
    type Output = <Transaction as Header<Fp>>::Output;

    const SUFFIX: Suffix = Suffix::new(17);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Transaction::encode(dr, allocator, witness)
    }
}

/// Dehydrates an authenticated working [`Transaction`] into a
/// [`PublicTransaction`].
///
/// Every working writer binds its last action slot to the point it emits.
/// At wallet rank the local and portable bases coincide, so copying the
/// anchor and both coordinate wires exports that same binding. No output is
/// queried: Ragu holds both output polynomials to one at its challenge.
/// Independently, both coordinates of the last output oracle must equal
/// the fixed wallet bridge of the commitment to one. The aggregator mask
/// excludes the wallet coordinate degrees of this canonical point: a stage
/// in that basis cannot open it without violating commitment binding. No
/// assumption that arbitrary bridge stages are canonical is needed.
#[derive(Debug)]
pub struct TransactionDehydrate;

impl TransactionDehydrate {
    fn enforce_wallet_padding<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
    ) -> ragu::Result<()> {
        // Canonical little-endian x,y of h13(C([1])) under the baked setup.
        // These coefficients never depend on the enclosing rank or a witness.
        const K_W: [[u8; 32]; 2] = [
            *b"\xa3\x5e\x57\x0c\x9a\xe1\xe5\xe9\x80\xc5\xb5\xff\x16\xa8\xd4\xa0\x8b\x47\x73\x32\x5a\xaf\xc7\x94\x18\x90\xf6\xc8\xd1\x1c\xdc\x30",
            *b"\xb0\x19\x9c\x1d\x8d\xdb\x33\x44\xe3\xfb\x9a\xb4\xce\xd5\xa3\xc5\xb2\x93\xc2\x98\x23\x62\x51\xdd\xa5\xda\x86\x70\xec\xc1\xde\x09",
        ];
        for (coordinate, bytes) in [x, y].into_iter().zip(K_W) {
            let expected = Fp::from_bytes(bytes).ok_or_else(|| {
                ragu::Error::Initialization("invalid wallet padding constant".into())
            })?;
            let fixed = Element::constant(dr, expected);
            coordinate.enforce_equal(dr, &fixed)?;
        }
        Ok(())
    }
}

impl<C: Cycle<CircuitField = Fp>> Step<C> for TransactionDehydrate {
    type Aux<'source> = ();
    type Left = Transaction;
    type Output = PublicTransaction;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(39);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, C, Self>,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, ()>,
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
        Self::enforce_wallet_padding(dr, oracles.bridge_hash().x(), oracles.bridge_hash().y())?;
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded = Encoded::new(dr, &mut (), right)?;
        let output = Encoded::from_gadget(left_encoded.as_gadget().clone());
        Ok(((left_encoded, right_encoded, output), left, D::unit()))
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
/// Opens both inputs' action set polynomials and their product at one
/// challenge.
///
/// # Soundness
///
/// Both input polynomials and the output are committed before $\zeta$.
/// The product check at that challenge therefore binds the output to the
/// product polynomial, adding the digest multiplicities of the two valid
/// inputs. The circuit equates their anchors and emits that shared wire, so
/// every spend's history still reaches the output anchor. The output bridge
/// wires bind the product as described in [`Transaction`].
#[derive(Debug)]
pub struct TransactionMerge;

impl Step<Pasta> for TransactionMerge {
    type Aux<'source> = ();
    type Left = Transaction;
    type Output = Transaction;
    type Right = Transaction;
    /// `(action_set,)`
    type Witness<'source> = (ActionSetPoly,);

    const INDEX: Index = Index::new(10);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(ActionSetPoly::SLOT.poly(Prepared::new(), &witness.0))
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
        let left_anchor_element = left_encoded.as_gadget().anchor.clone();
        left_anchor_element.enforce_equal(dr, &right_encoded.as_gadget().anchor)?;
        let action_set_bridge = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let [x, y] = action_set_bridge.each_ref().map(Element::value);
        let anchor_value = left_anchor_element.value();
        let data = D::just(|| {
            #[expect(
                clippy::expect_used,
                reason = "the oracle supplies commitment coordinates"
            )]
            let bridge_hash = EpAffine::from_xy(*x.take(), *y.take())
                .expect("the bridge hash commitment is a curve point");
            (
                ActionSetBridge::from(bridge_hash),
                Anchor::from(*anchor_value.take()),
            )
        });
        let encoded = Encoded::from_gadget(TransactionOutput {
            anchor: left_anchor_element,
            action_set_bridge,
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
/// Opens the span members polynomial and both action set polynomials.
///
/// # Soundness
///
/// Equality of the two openings at $\zeta$ binds the output's committed
/// polynomial to the input's, preserving every leaf with its multiplicity.
/// The right input authenticates its start, end and member polynomial. The
/// product above can vanish only at the start or a member, so each spend
/// history continues along that span to the end wire the circuit emits. Both
/// bridge coordinates come from the output oracle for the preserved set.
#[derive(Debug)]
pub struct TransactionLift;

impl Step<Pasta> for TransactionLift {
    type Aux<'source> = ();
    type Left = Transaction;
    type Output = Transaction;
    type Right = AnchorSpan;
    /// `(action_set,)`
    type Witness<'source> = (ActionSetPoly,);

    const INDEX: Index = Index::new(11);

    // The output action set is the one the caller states, where other
    // pass-through steps copy their input's polynomial; the opening against the
    // left action set holds it to the input. The right anchor set supplies the
    // span membership opening.
    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(ActionSetPoly::SLOT.poly(Prepared::new(), &witness.0))
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
        let TransactionOutput { anchor, .. } = left_encoded.as_gadget().clone();
        let anchor_evaluation = oracles.right(AnchorSetPoly::SLOT).open(dr, &anchor)?;
        let delta = anchor.sub(dr, &anchor_start);
        let membership = anchor_evaluation.mul(dr, &delta)?;
        membership.enforce_zero(dr)?;
        let action_set_bridge = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let [x, y] = action_set_bridge.each_ref().map(Element::value);
        let data = D::just(|| {
            #[expect(
                clippy::expect_used,
                reason = "the oracle supplies commitment coordinates"
            )]
            let bridge_hash = EpAffine::from_xy(*x.take(), *y.take())
                .expect("the bridge hash commitment is a curve point");
            let (_, span_anchor_end) = right.take();
            (ActionSetBridge::from(bridge_hash), span_anchor_end)
        });
        let encoded = Encoded::from_gadget(TransactionOutput {
            anchor: anchor_end,
            action_set_bridge,
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

/// Turns [`Actions`] into a [`Transaction`] by adding the fee digest to the
/// action set.
///
/// The pre-fee tachygram polynomial is checked by [`ActionMerge`] and
/// [`ActionLift`], but is not an operand here. [`Transaction`] carries only the
/// action polynomial: the action digests bind their pairs and the new fee
/// digest binds the change.
///
/// # Soundness
///
/// The circuit computes a fee leaf of [`Transaction`] on its own wires.
/// [`from_slack`](gadgets::value::Positive::from_slack) makes the value $m$
/// an integer in `0..=MAX_MONEY` and
/// [`split`](gadgets::value::Positive::split) makes $f$ and $m - f$ integers
/// in `0..=m`. $\mathsf{cv}_\mathsf{feemax}$ comes from
/// [`cv_feemax`](gadgets::note::Note::cv_feemax) on the same `slack` bits,
/// and $\mathsf{cm}_\mathsf{chg}$, held nonzero, from the note commitment
/// circuit on the note's nonzero `rcm`, `pk` and `psi` wires and the change.
///
/// Those three wires, $m$ and $f$ are each held equal to a staged value.
/// $d$ is fixed before $\zeta$, because every wire it is computed from is a
/// staged value or is determined by staged values.
///
/// - The `slack` bits are the only 51-bit string that packs to `MAX_MONEY - m`.
/// - The bits that `split` allocates are the only 51-bit string that packs to
///   $f$, and the change is the element $m - f$.
/// - The blind bits are the only 254-bit decomposition of the blind digest of
///   `pk`, `psi` and `rcm`.
///
/// The circuit equates the output opening at $\zeta$ with the left
/// opening times $\zeta - d$. Both polynomials are fixed before $\zeta$, so
/// by the [check at the challenge](super) the output's
/// leaves are the left input's and the fee leaf. The output's `anchor` is
/// the left `anchor` wire. Its bridge wires bind the resulting polynomial as
/// described in [`Transaction`].
///
/// # Caller contract
///
/// The caller confirms that the max fee note's value is within `MAX_MONEY`
/// and the fee is at most that value. Otherwise no proof can verify.
#[derive(Debug)]
pub struct FeeFuse;

impl Step<Pasta> for FeeFuse {
    type Aux<'source> = ();
    type Left = Actions;
    type Output = Transaction;
    type Right = ();
    /// `(max_fee_note, fee, output_action_set)`
    type Witness<'source> = (Note, value::Positive, ActionSetPoly);

    const INDEX: Index = Index::new(33);
    const NUM_STAGED: usize = 5;

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(ActionSetPoly::SLOT
            .poly(Prepared::new(), &witness.2)
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
        // The fee change is held nonzero. No step relies on it.
        fee_change.enforce_nonzero(dr)?;
        let z = oracles.zeta().clone();
        let left_actions = oracles.left(ActionSetPoly::SLOT).open(dr, &z)?;
        let output_actions = oracles.output(ActionSetPoly::SLOT).open(dr, &z)?;
        let factor = z.sub(dr, &fee_digest);
        let expected_actions = left_actions.mul(dr, &factor)?;
        output_actions.enforce_equal(dr, &expected_actions)?;
        let ActionsOutput { anchor } = left_encoded.as_gadget().clone();
        let action_set_bridge = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let [x, y] = action_set_bridge.each_ref().map(Element::value);
        let data = D::just(|| {
            #[expect(
                clippy::expect_used,
                reason = "the oracle supplies commitment coordinates"
            )]
            let bridge_hash = EpAffine::from_xy(*x.take(), *y.take())
                .expect("the bridge hash commitment is a curve point");
            (
                ActionSetBridge::from(bridge_hash),
                Anchor::from(*anchor.value().take()),
            )
        });
        let encoded = Encoded::from_gadget(TransactionOutput {
            anchor,
            action_set_bridge,
        });
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
    }
}

/// Proves a zero-action bundle's zero fee.
///
/// Unlike [`FeeFuse`], this seed has no pre-fee [`Actions`] input or pair
/// polynomial. It emits the same action-only [`Transaction`]: the singleton fee
/// digest binds the change commitment derived from the zero-valued note.
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
/// The circuit equates the action set polynomial's opening at $\zeta$ with
/// $\zeta - d$. The polynomial is committed before $\zeta$ and the root is
/// fixed before it, so by the
/// [check at the challenge](super) the polynomial is
/// one fee leaf's. The output's `anchor` is a wire with no constraint. The
/// output bridge wires bind the polynomial as described in [`Transaction`].
#[derive(Debug)]
pub struct FeeSeed;

impl Step<Pasta> for FeeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Transaction;
    type Right = ();
    /// `(max_fee_note, anchor, fee_action_set)`
    type Witness<'source> = (Note, Anchor, ActionSetPoly);

    const INDEX: Index = Index::new(36);
    const NUM_STAGED: usize = 3;

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(ActionSetPoly::SLOT
            .poly(Prepared::new(), &witness.2)
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
        // The fee change is held nonzero. No step relies on it.
        fee_change.enforce_nonzero(dr)?;
        let z = oracles.zeta().clone();
        let action_set = oracles.output(ActionSetPoly::SLOT).open(dr, &z)?;
        let action_factor = z.sub(dr, &fee_digest);
        action_set.enforce_equal(dr, &action_factor)?;
        let action_set_bridge = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let [x, y] = action_set_bridge.each_ref().map(Element::value);
        let anchor_value = anchor_element.value();
        let data = D::just(|| {
            #[expect(
                clippy::expect_used,
                reason = "the oracle supplies commitment coordinates"
            )]
            let bridge_hash = EpAffine::from_xy(*x.take(), *y.take())
                .expect("the bridge hash commitment is a curve point");
            (
                ActionSetBridge::from(bridge_hash),
                Anchor::from(*anchor_value.take()),
            )
        });
        let encoded = Encoded::from_gadget(TransactionOutput {
            anchor: anchor_element,
            action_set_bridge,
        });
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
    }
}

/// Removes a divisor stamp's leaves from a dividend stamp at the same anchor.
///
/// The left input is the dividend and the right input the divisor. The
/// output holds the dividend's leaves less the divisor's.
///
/// Three action set polynomials open once each at one shared challenge.
///
/// # Soundness
///
/// The circuit equates the dividend's opening at $\zeta$ with the
/// product of the divisor's and the output's. All three polynomials are fixed
/// before $\zeta$, so by the
/// [check at the challenge](super) the divisor's
/// polynomial times the output's is the dividend's.
///
/// The dividend's and the divisor's action polynomials are set polynomials
/// by their own inputs' assertions. A polynomial that divides a set
/// polynomial is a scalar times the set polynomial of a sub-multiset,
/// and the divisor's is monic,
/// so its digests are a sub-multiset of the dividend's. The quotient of two
/// monic polynomials is monic, so the output's action polynomial is the set
/// polynomial of the dividend's digests less the divisor's.
///
/// The circuit holds the two `anchor` wires equal and outputs the left one,
/// where the output's spend leaves' stamp chains end. Any verified
/// `Transaction` at that anchor whose slot digests are a sub-multiset of the
/// dividend's divides it, whether or not it was merged into it. The output
/// bridge wires bind the quotient as described in [`Transaction`].
#[derive(Debug)]
pub struct TransactionUnmerge;

impl Step<Pasta> for TransactionUnmerge {
    type Aux<'source> = ();
    type Left = Transaction;
    type Output = Transaction;
    type Right = Transaction;
    /// `(action_set,)`
    type Witness<'source> = (ActionSetPoly,);

    const INDEX: Index = Index::new(37);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(ActionSetPoly::SLOT.poly(Prepared::new(), &witness.0))
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
        let left_anchor_element = left_encoded.as_gadget().anchor.clone();
        left_anchor_element.enforce_equal(dr, &right_encoded.as_gadget().anchor)?;
        let action_set_bridge = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let [x, y] = action_set_bridge.each_ref().map(Element::value);
        let anchor_value = left_anchor_element.value();
        let data = D::just(|| {
            #[expect(
                clippy::expect_used,
                reason = "the oracle supplies commitment coordinates"
            )]
            let bridge_hash = EpAffine::from_xy(*x.take(), *y.take())
                .expect("the bridge hash commitment is a curve point");
            (
                ActionSetBridge::from(bridge_hash),
                Anchor::from(*anchor_value.take()),
            )
        });
        let encoded = Encoded::from_gadget(TransactionOutput {
            anchor: left_anchor_element,
            action_set_bridge,
        });
        Ok(((left_encoded, right_encoded, encoded), data, D::unit()))
    }
}
