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
/// [`SpendBind`] outputs this header. A verified `SpendHeader` asserts that,
/// for one epoch $e$ below `EPOCH_MAX`,
///
/// - a verified [`NoteSpendable`] carries `cm`, $e$ and `anchor`,
/// - a verified [`NoteSecret`] carries `cm` and `pk`, with a value $v$ and a
///   master key $\mathsf{mk}$,
/// - `nf_current` and `nf_next` are the
///   [nullifiers](crate::digest::poseidon::nullifier_group) of $\mathsf{mk}$ at
///   $e$ and at $e + 1$, and both are nonzero,
/// - `cv` is $\[v\]\mathcal{V} + \[r\]\mathcal{R}$ for an integer $r$ that its
///   prover knows, with $0 < r < 2^{254}$.
///
/// No step relies on the nullifiers being nonzero.
///
/// Each field determines what it stands for.
///
/// - `cm` stands for the spent note. It determines the note's four fields, and
///   with them $\mathsf{mk}$ ([`NoteSecret`]).
/// - `nf_current` and `nf_next` stand for the note's spend at epoch $e$. A
///   nullifier determines its master key and its epoch, so the pair determines
///   $e$, which is not a field. `cm` and $e$ determine the pair. The pair does
///   not determine `cm`, because notes that share $\psi$ and $\mathsf{nk}$
///   share $\mathsf{mk}$.
/// - `anchor` stands for the pool history at which [`NoteSpendable`] shows the
///   note spendable.
/// - `pk` stands for the note's owner. `cm` determines it, and it determines
///   $\mathsf{ak}$ and $\mathsf{nk}$.
/// - `cv` stands for the note's value. It is a [value
///   commitment](fixed_base#value-commitments), so it determines its opening,
///   and the opening's value is the $v$ that `cm` determines.
///
/// Both slots are padding. `SpendBind` opens neither.
///
/// `Data` encodes as the five elements `cm`, `nf_current`, `nf_next`,
/// `anchor` and `pk`, then the two affine coordinates of `cv`. A point other
/// than the identity is its coordinates and the identity has no encoding, so
/// distinct `Data` encode differently.
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
/// Two permutations (the pair) and two scalar multiplications (`cv`).
///
/// # Soundness
///
/// The left input is a verified [`NoteSpendable`] and the right input a
/// verified [`NoteSecret`]. The circuit holds their `cm` wires equal. The
/// secret's value, `pk` and `mk` are then those of the note the lineage
/// follows, because `cm` determines all three.
///
/// [`EpochIndex::next`](crate::gadgets::epoch::EpochIndex::next) range-checks
/// the lineage's epoch wire $e$ and the wire $e + 1$. The sum does not wrap,
/// and $e$ is below `EPOCH_MAX`.
/// [`derive_nullifier`](crate::gadgets::master::NoteMasterKey::derive_nullifier)
/// on the secret's `mk` wire returns the nullifier of that key at $e$ and
/// then at $e + 1$. Both results are held nonzero.
///
/// The blind is 254 bit wires with no other constraint.
/// [`R_BASE`](struct@fixed_base::R_BASE) multiplied by them gives the blind
/// point, and a zero blind has no assignment. `cv` is
/// [`V_BASE`](struct@fixed_base::V_BASE) multiplied by the 51-bit
/// decomposition of the secret's value wire, added to the blind point. The
/// value wire is an amount because every circuit that encodes a `NoteSecret`
/// range-checks it, so the bits are its only decomposition.
///
/// The step reads no challenge. The output's `cm` and `anchor` are the
/// lineage's wires and its `pk` is the secret's. These are the equations
/// [`SpendHeader`] asserts.
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
        // A zero nullifier would collide with the note's own cm tachygram.
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
