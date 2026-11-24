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
/// [`OutputAction`](super::stamp::OutputAction) reads all three fields and
/// derives `rk`.
///
/// # Injectivity
///
/// [`OutputBind`] outputs this header. Every verified `OutputHeader` asserts
/// that its prover knows a note $(\mathsf{rcm}, \mathsf{pk}, v, \psi)$ with
/// integer $v$ in `0..=MAX_MONEY` and an integer $r$ with $0 < r < 2^{254}$.
///
/// - `cm` is the [note commitment](crate::digest::poseidon::note_commitment),
///   standing for the note and determining its four fields.
/// - `pad` is the [padding tachygram](crate::digest::poseidon::pad_tachygram),
///   determining the same four fields under its own tag so that `cm` and `pad`
///   determine each other.
/// - `cv` equals $\[-v\]\mathcal{V} + \[r\]\mathcal{R}$, standing for $-v$ and
///   determining its opening as a [value
///   commitment](fixed_base#value-commitments).
///
/// Both `cm` and `pad` are nonzero, ruling out roots at zero
/// ([zero tachygrams](super#zero-tachygrams)), and $\mathsf{rcm}$ is nonzero.
/// Nothing here constrains $\mathsf{pk}$ to a derived payment key, which
/// [`NoteSeed`](super::delegation::NoteSeed) proves when spending the note.
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
/// Reading no input or challenge, the circuit builds `OutputHeader` directly
/// from its wires. Shared `rcm`, `pk`, `psi` and value wires feed both digest
/// circuits. `Note::commitment` holds `rcm` nonzero, this step holds `cm` and
/// `pad` nonzero, and `pk` and `psi` carry no separate constraint.
/// Multiplying [`R_BASE`](struct@fixed_base::R_BASE) by 254 freely chosen
/// Boolean blind wires computes the blind point, with no assignment at zero.
/// `NEG_V_BASE.mul_and_add` adds the negated value term from
/// the same 51 bits that encode the
/// [amount](gadgets::value::Positive::from_bits) for both digests.
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
        // Zero produces the factor `X` regardless of tachygram kind, so hold
        // both nonzero.
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
