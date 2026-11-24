//! Spend nullifier-binding header and step.

extern crate alloc;

use ragu::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Padding, Suffix},
    maybe::Maybe as _,
    pasta::Pasta,
    primitives::{Element, GadgetExt as _, Point, allocator::Allocator, io::Write},
    step::{Encoded, Index, Oracles, Step},
    udon::curve::EndomorphismAffine,
};

use super::{delegation::NoteSecret, spendable::NoteSpendable};
use crate::{
    gadgets::{fixed_base, uint::Uint},
    keys::PaymentKey,
    note,
    nullifier::Nullifier,
    pasta::{EpAffine, Fp, Fq},
    primitives::Anchor,
    value,
};

/// A spend's note, epoch nullifier pair, pool anchor, payment key and value
/// commitment (wallet-only).
///
/// Carries the note commitment `cm`, the lineage's nullifier and its
/// neighbour `(nf_current, nf_next)` derived from the note's master key, the
/// pool `anchor`, the note's payment key `pk` and the value commitment `cv`.
/// [`SpendAction`](super::stamp::SpendAction) publishes the pair unordered,
/// ties its `ak` to `pk`, and produces `rk`.
///
/// # Injectivity
///
/// [`SpendBind`] outputs this header. Every verified `SpendHeader` asserts a
/// verified [`NoteSpendable`] with `cm`, `anchor` and an epoch $e$ below
/// `EPOCH_MAX`, alongside a verified [`NoteSecret`] with `cm`, `pk`, value $v$
/// and master key $\mathsf{mk}$.
///
/// - `cm` stands for the spent note, determining its four fields and
///   $\mathsf{mk}$ ([`NoteSecret`]).
/// - `nf_current` and `nf_next` stand for the note's spend at $e$ as the
///   [nullifiers](crate::digest::poseidon::nullifier_group) of $\mathsf{mk}$ at
///   $e$ and $e + 1$. `cm` and $e$ determine the pair, and because each
///   nullifier determines its master key and epoch, the pair recovers $e$ even
///   though $e$ is omitted from the header. Notes sharing $\psi$ and
///   $\mathsf{nk}$ share $\mathsf{mk}$, so the pair does not determine `cm`.
///   Both nullifiers are nonzero, preventing a zero root from marking a
///   zero-commitment note as published ([zero
///   tachygrams](super#zero-tachygrams)).
/// - `anchor` stands for the pool history where [`NoteSpendable`] establishes
///   spendability.
/// - `pk` stands for the note's owner, determined by `cm` and determining
///   $\mathsf{ak}$ and $\mathsf{nk}$.
/// - `cv` stands for $v$ as $\[v\]\mathcal{V} + \[r\]\mathcal{R}$ for a
///   prover-known integer $0 < r < 2^{254}$, determining its opening as a
///   [value commitment](fixed_base#value-commitments).
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
    type OnlinePolyCommit = (Padding, Padding);
    type Output = Kind![Fp; SpendHeaderOutput<'_, _, EpAffine>];

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
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
/// Two permutations (the pair) and two scalar multiplications (`cv`). Two
/// sponges run whether or not $e$ and $e + 1$ share a group.
///
/// # Soundness
///
/// Equating both inputs' `cm` wires ties the secret's value, `pk` and `mk` to
/// the lineage's note.
/// [`EpochIndex::next`](crate::gadgets::epoch::EpochIndex::next) range-checks
/// $e$ and $e + 1$ so the sum never wraps and $e < \text{EPOCH\_MAX}$. Calling
/// [`derive_nullifier`](crate::gadgets::master::NoteMasterKey::derive_nullifier)
/// on `mk` computes its nullifier at both epochs, and the circuit holds each
/// nonzero.
///
/// Multiplying [`V_BASE`](struct@fixed_base::V_BASE) by the 51-bit
/// decomposition of the secret's value wire (which [`NoteSecret`] bounds to
/// `0..=MAX_MONEY`) and adding [`R_BASE`](struct@fixed_base::R_BASE) times 254
/// unconstrained blind bits (unassigned at zero) yields `cv`. Reading no
/// challenge, the step copies `cm` and `anchor` from the lineage and `pk` from
/// the secret.
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
        _oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
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
        let spendable = left_encoded.as_gadget();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let secret = right_encoded.as_gadget();
        spendable.cm.enforce_equal(dr, &secret.cm)?;
        let epoch_next = spendable.epoch_current.next(dr)?;
        let nf_current = secret.mk.derive_nullifier(dr, &spendable.epoch_current)?;
        let nf_next = secret.mk.derive_nullifier(dr, &epoch_next)?;
        // A zero nullifier would put a zero root in the tachygram set and mark
        // a zero-commitment note as published, so hold both nonzero.
        nf_current.clone().enforce_nonzero(dr)?;
        nf_next.clone().enforce_nonzero(dr)?;

        // The blind's 254 bits are free: nothing else binds rcv, and their
        // binary value below 2^254 is the scalar.
        let blind_bits = Uint::<_, 254>::alloc(dr, witness.as_ref().map(|&(rcv,)| Fq::from(rcv)))?;
        let blind_point = fixed_base::R_BASE.mul(dr, blind_bits.bits())?;
        let cv = secret
            .note
            .value
            .to_bits(dr)
            .and_then(|bits| fixed_base::V_BASE.mul_and_add(dr, bits.bits(), &blind_point))?;
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
