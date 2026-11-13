//! Spend nullifier-binding header and step.

extern crate alloc;

use ragu::{
    header::{Header, Suffix},
    step::{Encoded, Index, Oracles, Step},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::Pasta,
};
use ragu_primitives::{Element, GadgetExt as _, Point, allocator::Allocator, io::Write};
use udon::{curve::EndomorphismAffine, field::Field as _};

use super::{delegation::NoteSecret, spendable::NoteSpendable};
use crate::{
    constants::EPOCH_MAX,
    gadgets::{self, fixed_base},
    keys::PaymentKey,
    note,
    nullifier::Nullifier,
    pasta::{EpAffine, Fp, Fq},
    primitives::{Anchor, EpochIndex},
    value,
};

/// Header binding a spend to its lineage note, epoch nullifier pair and value
/// commitment.
///
/// Carries the note commitment `cm`, the lineage's nullifier and its
/// neighbour `(nf_current, nf_next)` derived from the note's master key, the
/// pool `anchor`, the note's payment key `pk` and the value commitment `cv`.
/// [`SpendAction`](super::stamp::SpendAction) publishes the pair unordered,
/// ties its `ak` to `pk`, and produces `rk`.
#[derive(Debug)]
pub struct SpendHeader;

#[derive(Gadget, Write)]
pub struct SpendHeaderOutput<'dr, D: Driver<'dr>, C: EndomorphismAffine<Base = D::F>> {
    pub cm: Element<'dr, D>,
    pub nf_current: Element<'dr, D>,
    pub nf_next: Element<'dr, D>,
    pub anchor: Element<'dr, D>,
    pub pk: Element<'dr, D>,
    #[ragu(gadget)]
    pub cv: Point<'dr, D, C>,
}

impl Header<Fp> for SpendHeader {
    /// `(cm, nf_current, nf_next, anchor, pk, cv)`
    type Data = (
        note::Commitment,
        Nullifier,
        Nullifier,
        Anchor,
        PaymentKey,
        value::Commitment,
    );
    type Output = Kind![Fp; SpendHeaderOutput<'_, _, EpAffine>];

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(SpendHeaderOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?,
            nf_current: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            nf_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?,
            anchor: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.3)),
            )?,
            pk: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.4)),
            )?,
            cv: Point::alloc(dr, witness.as_ref().map(|fields| EpAffine::from(fields.5)))?,
        })
    }
}

/// Derives a spend's epoch nullifier pair from the note's master key, commits
/// the note's value, and binds both to the spendable lineage.
///
/// The secret is tied to the lineage's note by `secret_cm == spendable_cm`.
/// The pair is `mk`'s nullifiers at the lineage's epoch $e$ and at $e + 1$,
/// one group sponge each. Both are emitted on the [`SpendHeader`] for the
/// action-producing step to publish, with the note's `pk` and
/// $\mathsf{cv} = \[v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R}$.
///
/// Two permutations (the pair) and two scalar multiplications (`cv`).
///
/// # Soundness
///
/// [`NoteSeed`](super::delegation::NoteSeed) proves that the input master key,
/// commitment and note belong together. The spendable proof supplies the epoch;
/// the circuit checks that it and its successor are in range, and selects each
/// nullifier by the epoch's constrained low bits. The nullifier pair,
/// payment key and value all come from these proved inputs. Only the value
/// commitment's blinding scalar `rcv` is freely chosen.
///
/// Two sponges run whether or not $e$ and $e + 1$ share a group.
#[derive(Debug)]
pub struct SpendBind;

impl Step<Pasta> for SpendBind {
    type Aux<'source> = ();
    type Left = NoteSpendable;
    type Output = SpendHeader;
    type Right = NoteSecret;
    /// `(rcv,)`
    type Witness<'source> = (value::Trapdoor,);

    const INDEX: Index = Index::new(8);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
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
        let spendable = left_encoded.as_gadget();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let secret = right_encoded.as_gadget();
        spendable.cm.enforce_equal(dr, &secret.cm).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendBind: secret does not match note".into())
        })?;
        // Each derivation proves its epoch under 2^32, so this bound places
        // both epochs in range, the current one below EPOCH_MAX.
        let one = Element::constant(dr, Fp::ONE);
        let epoch_next = spendable.epoch_current.add(dr, &one);
        let maximum = Element::constant(dr, Fp::from(u64::from(EPOCH_MAX)));
        let slack = maximum.sub(dr, &epoch_next);
        gadgets::range::enforce_width::<D, { EpochIndex::BITS }>(dr, &slack).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendBind: no epoch follows the spend epoch".into())
        })?;
        let nf_current = secret.mk.derive_nullifier(dr, &spendable.epoch_current)?;
        let nf_next = secret.mk.derive_nullifier(dr, &epoch_next)?;
        // A zero nullifier would collide with the note's own cm tachygram.
        nf_current.clone().enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendBind: current-epoch nullifier is zero".into())
        })?;
        nf_next.clone().enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendBind: next-epoch nullifier is zero".into())
        })?;

        let blind_point =
            fixed_base::R_BASE.mul_blinding(dr, &witness.as_ref().map(|&(rcv,)| Fq::from(rcv)))?;
        // `NoteSeed`, the only producer of `NoteSecret`, bounds the value by
        // MAX_MONEY.
        let cv = fixed_base::V_BASE.mul_amount(dr, &secret.note.value, &blind_point)?;
        let output = D::just(|| {
            let (spendable_cm, _, anchor) = left.take();
            let (_, note, _) = right.take();
            (
                spendable_cm,
                Nullifier::from(*nf_current.value().take()),
                Nullifier::from(*nf_next.value().take()),
                anchor,
                note.pk,
                value::Commitment::from(cv.value().take()),
            )
        });
        let fields = SpendHeaderOutput {
            cm: spendable.cm.clone(),
            nf_current,
            nf_next,
            anchor: spendable.anchor.clone(),
            pk: secret.note.pk.clone(),
            cv,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}
