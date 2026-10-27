//! Spend nullifier-binding header and step.

extern crate alloc;

use ragu::{
    Encoded, Header, Index, Step, StepCtx,
    pasta::{Fp, Fq},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use ragu_primitives::{Element, GadgetExt as _};
use udon::{curve::Projective as _, field::Field as _};

use super::{delegation::NoteSecret, spendable::NoteSpendable};
use crate::{
    constants::{EPOCH_MAX, MAX_MONEY},
    gadgets::arithmetic as circuit,
    nullifier::Nullifier,
    value,
};

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
/// `mk`, `cm` and the note are threaded from the right header, bound together
/// at [`NoteSeed`](super::delegation::NoteSeed). `epoch_current` is a
/// left-header field, and $e + 1$ is a bounded driver-side successor. The pair,
/// `pk` and the value are threaded or computed from threaded values, so nothing
/// in them is free. `rcv` is free; it only blinds `cv`.
///
/// Two sponges run whether or not $e$ and $e + 1$ share a group.
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = NoteSpendable;
    type Output = SpendHeader;
    type Right = NoteSecret;
    type Shared = ();
    /// `(rcv,)`
    type Witness<'source> = (value::Trapdoor,);

    const INDEX: Index = Index::new(8);

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
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let cm = left_encoded.as_gadget().cm.element.clone();
        let secret_cm = right_encoded.as_gadget().cm.element.clone();
        cm.enforce_equal(ctx.dr, &secret_cm).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendBind: secret does not match note".into())
        })?;
        let value = right_encoded.as_gadget().note.value.element.clone();
        circuit::bounded::<D, 51>(ctx.dr, &value, MAX_MONEY)?;
        let epoch = left_encoded.as_gadget().epoch_current.element.clone();
        let one = Element::constant(ctx.dr, Fp::ONE);
        let next = epoch.add(ctx.dr, &one);
        circuit::bounded::<D, 32>(ctx.dr, &next, u64::from(EPOCH_MAX)).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendBind: no epoch follows the spend epoch".into())
        })?;
        let nf_current = right_encoded
            .as_gadget()
            .mk
            .derive_nullifier(ctx.dr, &epoch)?
            .element;
        let nf_next = right_encoded
            .as_gadget()
            .mk
            .derive_nullifier(ctx.dr, &next)?
            .element;
        nf_current.clone().enforce_nonzero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendBind: current-epoch nullifier is zero".into())
        })?;
        nf_next.clone().enforce_nonzero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendBind: next-epoch nullifier is zero".into())
        })?;

        let value_bits = circuit::bits::<D, 51>(ctx.dr, &value)?;
        let rcv_bits = circuit::scalar_bits(ctx.dr, witness.as_ref().map(|data| Fq::from(data.0)))?;
        let value_generator =
            crate::gadgets::point::CurvePoint::constant(ctx.dr, value::VALUE_COMMIT_V.to_affine())?;
        let blind_generator =
            crate::gadgets::point::CurvePoint::constant(ctx.dr, value::VALUE_COMMIT_R.to_affine())?;
        let value_point =
            crate::gadgets::point::CurvePoint::scale(ctx.dr, &value_generator, &value_bits)?;
        let blind_point =
            crate::gadgets::point::CurvePoint::scale(ctx.dr, &blind_generator, &rcv_bits)?;
        let cv = crate::gadgets::point::CurvePoint::add(ctx.dr, &value_point, &blind_point)?;
        cv.enforce_nonidentity(ctx.dr)?;
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
        let fields = crate::stamp::headers::spend::SpendHeaderOutput {
            cm: (cm).into(),
            nf_current: (nf_current).into(),
            nf_next: (nf_next).into(),
            anchor: (left_encoded.as_gadget().anchor.element.clone()).into(),
            pk: (right_encoded.as_gadget().note.pk.element.clone()).into(),
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

pub use crate::stamp::headers::spend::SpendHeader;
