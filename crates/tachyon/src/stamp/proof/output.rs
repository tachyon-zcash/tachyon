//! Output tachygram-binding header and step.

extern crate alloc;

use ragu::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Padding, Suffix},
    maybe::Maybe as _,
    pasta::Pasta,
    primitives::{Element, Point, allocator::Allocator, io::Write},
    step::{Encoded, Index, Oracles, Step},
    udon::curve::EndomorphismAffine,
};

use crate::{
    Tachygram,
    gadgets::{self, fixed_base},
    note::Note,
    pasta::{EpAffine, Fp, Fq},
    value,
};

/// An output's tachygram pair and value commitment, derived from one note
/// (wallet-only).
///
/// Carries the note commitment `cm`, the padding tachygram `pad`, and the
/// value commitment `cv`. `rk` is produced downstream at
/// [`OutputAction`](super::stamp::OutputAction), which reads all three
/// fields.
///
/// # Injectivity
///
/// [`OutputBind`] outputs this header. A verified `OutputHeader` asserts that
/// its prover knows a note $(\mathsf{rcm}, \mathsf{pk}, v, \psi)$ with $v$
/// an integer in `0..=MAX_MONEY`, and an integer $r$ with $0 < r < 2^{254}$.
///
/// - `cm` is the note's [note
///   commitment](crate::digest::poseidon::note_commitment) and stands for the
///   note, whose four fields it determines.
/// - `pad` is the note's [padding
///   tachygram](crate::digest::poseidon::pad_tachygram). It determines the same
///   four fields under its own tag, so `cm` and `pad` determine each other.
/// - `cv` is $\[-v\]\mathcal{V} + \[r\]\mathcal{R}$ and stands for the value,
///   negated. It is a [value commitment](fixed_base#value-commitments), so it
///   determines its opening.
///
/// `cm` and `pad` are nonzero, so neither is a root at zero
/// ([zero tachygrams](super#zero-tachygrams)). The commitment trapdoor
/// $\mathsf{rcm}$ is also nonzero. The assertion does not make $\mathsf{pk}$
/// a payment key; [`NoteSeed`](super::delegation::NoteSeed) proves that for
/// a note that is spent.
#[derive(Debug)]
pub struct OutputHeader;

#[derive(Gadget, Write)]
pub struct OutputHeaderOutput<'dr, D: Driver<'dr>, C: EndomorphismAffine<Base = D::F>> {
    pub cm: Element<'dr, D>,
    pub pad: Element<'dr, D>,
    #[ragu(gadget)]
    pub cv: Point<'dr, D, C>,
}

impl Header<Fp> for OutputHeader {
    /// `(cm, pad, cv)`
    type Data = (Tachygram, Tachygram, value::Commitment);
    type OnlinePolyCommit = (Padding, Padding);
    type Output = Kind![Fp; OutputHeaderOutput<'_, _, EpAffine>];

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Ok(OutputHeaderOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?,
            pad: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            cv: Point::alloc(dr, witness.as_ref().map(|fields| EpAffine::from(fields.2)))?,
        })
    }
}

/// Derives an output's tachygram pair from one note, and commits its negated
/// value as
/// $\mathsf{cv} = \[-v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R}$.
///
/// Two permutations (`cm`, `pad`) and two scalar multiplications (`cv`).
///
/// # Soundness
///
/// The step reads no input and no challenge, and builds the header from its
/// own wires. One `rcm` wire, one `pk` wire, one `psi` wire and the value
/// feed both digest circuits, whose outputs are held nonzero. The commitment
/// circuit holds `rcm` nonzero; `pk` and `psi` carry no other constraint.
/// The value is the
/// [amount](gadgets::value::Positive::from_bits) that 51 bit wires encode, and
/// [`NEG_V_BASE`](struct@fixed_base::NEG_V_BASE) multiplied by those same wires
/// is added to the blind point. The committed value is therefore the one both
/// digests absorb. The blind is 254 bit wires with no other constraint, and
/// [`R_BASE`](struct@fixed_base::R_BASE) multiplied by them has no assignment
/// at zero.
#[derive(Debug)]
pub struct OutputBind;

impl Step<Pasta> for OutputBind {
    type Aux<'source> = ();
    type Left = ();
    type Output = OutputHeader;
    type Right = ();
    /// `(note, rcv)`.
    type Witness<'source> = (Note, value::Trapdoor);

    const INDEX: Index = Index::new(6);

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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left)?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let amount = gadgets::uint::Uint::alloc(
            dr,
            witness
                .as_ref()
                .map(|&(note, _)| Fp::from(u64::from(note.value))),
        )?;
        let note = gadgets::note::Note {
            rcm: Element::alloc(
                dr,
                &mut (),
                witness.as_ref().map(|&(note, _)| Fp::from(note.rcm)),
            )?,
            pk: Element::alloc(
                dr,
                &mut (),
                witness.as_ref().map(|&(note, _)| Fp::from(note.pk)),
            )?,
            value: gadgets::value::Positive::from_bits(dr, &amount)?,
            psi: Element::alloc(
                dr,
                &mut (),
                witness.as_ref().map(|&(note, _)| Fp::from(note.psi)),
            )?,
        };
        let cm = note.commitment(dr)?;
        let pad = note.pad_tachygram(dr)?;
        // A zero root is the factor `X` whatever kind of tachygram it was
        // meant to be, so both are held nonzero.
        cm.clone().enforce_nonzero(dr)?;
        pad.clone().enforce_nonzero(dr)?;
        // The blind's 254 bits are free: nothing else binds rcv, and their
        // binary value below 2^254 is the scalar.
        let blind_bits = gadgets::uint::Uint::<_, 254>::alloc(
            dr,
            witness.as_ref().map(|&(_, rcv)| Fq::from(rcv)),
        )?;
        let blind_point = fixed_base::R_BASE.mul(dr, blind_bits.bits())?;
        let cv = fixed_base::NEG_V_BASE.mul_and_add(dr, amount.bits(), &blind_point)?;
        let output = D::just(|| {
            (
                Tachygram::from(*cm.value().take()),
                Tachygram::from(*pad.value().take()),
                value::Commitment::from(cv.value().take()),
            )
        });
        let fields = OutputHeaderOutput { cm, pad, cv };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}
