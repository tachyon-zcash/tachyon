//! Output tachygram-binding header and step.

extern crate alloc;

use ragu::{
    Cycle as _, Encoded, Header, Index, PoseidonPermutation as _, Step, StepCtx,
    pasta::{Fp, Fq, Pasta, PoseidonFp},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use ragu_pcd::pasta::baked;
use ragu_primitives::{
    Element,
    poseidon::{Sponge, SpongeState},
    vec::FixedVec,
};
use udon::{curve::Projective as _, field::Field as _};

use crate::{
    Tachygram, constants::MAX_MONEY, digest::poseidon, gadgets::arithmetic as circuit, note::Note,
    value,
};

/// Derives an output's tachygram pair from one note, and commits its negated
/// value as
/// $\mathsf{cv} = \[-v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R}$.
///
/// Two permutations (`cm`, `pad`) and two scalar multiplications (`cv`).
#[derive(Debug)]
pub struct OutputBind;

impl Step for OutputBind {
    type Aux<'source> = ();
    type Left = ();
    type Output = OutputHeader;
    type Right = ();
    type Shared = ();
    /// `(note, rcv)`.
    type Witness<'source> = (Note, value::Trapdoor);

    const INDEX: Index = Index::new(6);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left)?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
        let amount = Element::alloc(
            ctx.dr,
            &mut (),
            witness
                .as_ref()
                .map(|data| Fp::from(u64::from(data.0.value))),
        )?;
        circuit::bounded::<D, 51>(ctx.dr, &amount, MAX_MONEY)?;
        let rcm = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.rcm)),
        )?;
        let pk = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.pk)),
        )?;
        let psi = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.psi)),
        )?;
        let input = [rcm, pk, amount.clone(), psi];
        let cm = poseidon::note_commitment_circuit(ctx.dr, &input)?;
        let state = SpongeState::from_elements(FixedVec::from_fn(|index| {
            Element::constant(
                ctx.dr,
                if index == PoseidonFp::RATE {
                    Fp::from_u128(u128::from_le_bytes(*b"Tachyon-CmOutPad"))
                } else {
                    Fp::ZERO
                },
            )
        }));
        let mut sponge = Sponge::resume(state, Pasta::circuit_poseidon(baked()));
        for element in &input {
            sponge.absorb(ctx.dr, element)?;
        }
        let pad = sponge.squeeze(ctx.dr)?;
        cm.clone().enforce_nonzero(ctx.dr)?;
        pad.clone().enforce_nonzero(ctx.dr)?;
        let amount_bits = circuit::bits::<D, 51>(ctx.dr, &amount)?;
        let rcv_bits = circuit::scalar_bits(ctx.dr, witness.as_ref().map(|data| Fq::from(data.1)))?;
        let value_generator = crate::gadgets::point::CurvePoint::constant(
            ctx.dr,
            (-*value::VALUE_COMMIT_V).to_affine(),
        )?;
        let blind_generator =
            crate::gadgets::point::CurvePoint::constant(ctx.dr, value::VALUE_COMMIT_R.to_affine())?;
        let value_point =
            crate::gadgets::point::CurvePoint::scale(ctx.dr, &value_generator, &amount_bits)?;
        let blind_point =
            crate::gadgets::point::CurvePoint::scale(ctx.dr, &blind_generator, &rcv_bits)?;
        let cv = crate::gadgets::point::CurvePoint::add(ctx.dr, &value_point, &blind_point)?;
        cv.enforce_nonidentity(ctx.dr)?;
        let output = D::just(|| {
            (
                Tachygram::from(*cm.value().take()),
                Tachygram::from(*pad.value().take()),
                value::Commitment::from(cv.value().take()),
            )
        });
        let fields = crate::stamp::headers::output::OutputHeaderOutput {
            cm: (cm).into(),
            pad: (pad).into(),
            cv: (cv).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            output,
            D::unit(),
        ))
    }
}

pub use crate::stamp::headers::output::OutputHeader;
