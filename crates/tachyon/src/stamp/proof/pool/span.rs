//! Anchor spans keep the full members M available for lifts in slot zero.
//! Their endpoint e and the bridge of Q bind M = (X − e) Q for transport.

use alloc::vec::Vec;

use ragu::{header::OnlinePoly, udon::curve::Affine as _};

use super::*;
use crate::{
    AnchorSetBridge, pasta::EpAffine, primitives::coefficients,
    stamp::proof::transaction::TransactionDehydrate,
};

/// Last slot of a span: the seed's tachygram set or a collected span's prefix.
#[derive(Clone, Copy, Debug)]
pub struct AnchorSpanBridgeSlot;

impl OnlinePoly for AnchorSpanBridgeSlot {}

/// A path with one member for each post-fold anchor, including the end.
/// Its prefix excludes one occurrence of that end. A singleton has prefix one.
#[derive(Clone, Debug)]
pub struct AnchorSpan;

#[derive(Gadget, Write)]
pub struct AnchorSpanOutput<'dr, D: Driver<'dr>> {
    pub anchor_start: Element<'dr, D>,
    pub anchor_end: Element<'dr, D>,
}

impl Header<Fp> for AnchorSpan {
    type Data = (Anchor, Anchor, AnchorSetBridge);
    type OnlinePolyCommit = (PolySlot<AnchorSetPoly>, AnchorSpanBridgeSlot);
    type Output = Kind![Fp; (AnchorSpanOutput<'_, _>, (Element<'_,_>,Element<'_,_>))];

    const SUFFIX: Suffix = Suffix::new(14);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        let xy = D::try_just(|| {
            EpAffine::from(witness.as_ref().take().2)
                .coordinates()
                .ok_or_else(|| ragu::Error::InvalidWitness("identity prefix bridge".into()))
        })?;
        Ok((
            AnchorSpanOutput {
                anchor_start: Element::alloc(
                    dr,
                    allocator,
                    witness.as_ref().map(|span| span.0.into()),
                )?,
                anchor_end: Element::alloc(dr, allocator, witness.map(|span| span.1.into()))?,
            },
            (
                Element::alloc(dr, allocator, xy.as_ref().map(|coords| coords.0))?,
                Element::alloc(dr, allocator, xy.map(|coords| coords.1))?,
            ),
        ))
    }
}

fn point([x, y]: [Fp; 2]) -> ragu::Result<AnchorSetBridge> {
    EpAffine::from_xy(x, y)
        .map(Into::into)
        .ok_or_else(|| ragu::Error::InvalidWitness("invalid prefix bridge".into()))
}

/// Absorb one nonempty stamp. The last-slot oracle supplies the tachygram
/// bridge to the anchor hash; the singleton members check fixes the prefix to
/// one.
///
/// Both ranks register the same circuit, which hashes the executing rank's
/// oracle. The provided prover prepares the singleton members polynomial
/// using the wallet-rank bridge. It supports wallet seeds; aggregators import
/// a wallet span to obtain its canonical post-stamp anchors.
#[derive(Debug)]
pub struct AnchorSpanSeed;

impl<C: Cycle<CircuitField = Fp>> Step<C> for AnchorSpanSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorSpan;
    type Right = ();
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetPoly);

    const INDEX: Index = Index::new(31);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, ()>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> ragu::Result<Prepared<Fp, AnchorSpan>> {
        let end = Anchor::from(poseidon::anchor_next_stamp(
            witness.0.into(),
            witness.1.into(),
            bridge_hash(witness.2.commit().into()),
        ));
        let prepared = AnchorSetPoly::SLOT.poly(Prepared::new(), &AnchorSetPoly::from_iter([end]));
        Ok(prepared.poly(AnchorSpanBridgeSlot, coefficients(witness.2.as_ref())))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, C, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> ragu::Result<(
        (
            Encoded<'dr, D, (), N>,
            Encoded<'dr, D, (), N>,
            Encoded<'dr, D, AnchorSpan, N>,
        ),
        DriverValue<D, <AnchorSpan as Header<Fp>>::Data>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::new(dr, &mut (), left)?;
        let right_encoded = Encoded::new(dr, &mut (), right)?;
        let start = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.0.into()))?;
        let epoch = gadgets::epoch::EpochIndex::alloc(dr, &mut (), witness.as_ref().map(|w| w.1))?;
        let z = oracles.zeta().clone();
        let stamp = oracles.output(AnchorSpanBridgeSlot).open(dr, &z)?;
        let one = Element::constant(dr, Fp::ONE);
        stamp.sub(dr, &one).enforce_nonzero(dr)?;
        let oracle = oracles.bridge_hash();
        let end = poseidon::circuit::anchor_next_stamp(
            dr,
            &start,
            &epoch,
            &[oracle.x().clone(), oracle.y().clone()],
        )?;
        // Choosing the fold result after the challenge requires a preimage of the hash.
        let members = oracles.output(AnchorSetPoly::SLOT).open(dr, &z)?;
        let factor = z.sub(dr, &end);
        members.enforce_equal(dr, &factor)?;
        let unit = TransactionDehydrate::wallet_padding()?;
        let data = D::try_just(|| {
            Ok((
                witness.take().0,
                Anchor::from(*end.value().take()),
                point(unit)?,
            ))
        })?;
        let bridge = unit.map(|coord| Element::constant(dr, coord));
        let out = (
            AnchorSpanOutput {
                anchor_start: start,
                anchor_end: end,
            },
            bridge.into(),
        );
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(out)),
            data,
            D::unit(),
        ))
    }
}

/// Join adjacent paths. The committed product of their members must also equal
/// the committed prefix times the final factor from the authenticated right
/// end.
#[derive(Debug)]
pub struct AnchorSpanFuse;

impl<C: Cycle<CircuitField = Fp>> Step<C> for AnchorSpanFuse {
    type Aux<'source> = ();
    type Left = AnchorSpan;
    type Output = AnchorSpan;
    type Right = AnchorSpan;
    type Witness<'source> = (AnchorSetPoly,);

    const INDEX: Index = Index::new(32);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, AnchorSpan>,
        right: HeaderInput<'_, Fp, AnchorSpan>,
    ) -> ragu::Result<Prepared<Fp, AnchorSpan>> {
        let members = coefficients(witness.0.as_ref());
        let prefix = remove_end(&members, right.data.1.into());
        Ok(Prepared::new()
            .poly(AnchorSetPoly::SLOT, members)
            .poly(AnchorSpanBridgeSlot, prefix))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, C, Self>,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <AnchorSpan as Header<Fp>>::Data>,
        right: DriverValue<D, <AnchorSpan as Header<Fp>>::Data>,
    ) -> ragu::Result<(
        (
            Encoded<'dr, D, AnchorSpan, N>,
            Encoded<'dr, D, AnchorSpan, N>,
            Encoded<'dr, D, AnchorSpan, N>,
        ),
        DriverValue<D, <AnchorSpan as Header<Fp>>::Data>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, AnchorSpan, N>::new(dr, &mut (), left.clone())?;
        let right_encoded = Encoded::<D, AnchorSpan, N>::new(dr, &mut (), right.clone())?;
        left_encoded
            .as_gadget()
            .0
            .anchor_end
            .enforce_equal(dr, &right_encoded.as_gadget().0.anchor_start)?;
        let z = oracles.zeta().clone();
        let left_members = oracles.left(AnchorSetPoly::SLOT).open(dr, &z)?;
        let right_members = oracles.right(AnchorSetPoly::SLOT).open(dr, &z)?;
        let members = oracles.output(AnchorSetPoly::SLOT).open(dr, &z)?;
        left_members
            .mul(dr, &right_members)?
            .enforce_equal(dr, &members)?;
        let prefix = oracles.output(AnchorSpanBridgeSlot).open(dr, &z)?;
        enforce_end_factor(
            dr,
            &z,
            &right_encoded.as_gadget().0.anchor_end,
            &prefix,
            &members,
        )?;
        let oracle = oracles.bridge_hash();
        let bridge = [oracle.x().clone(), oracle.y().clone()];
        let data = D::try_just(|| {
            Ok((
                left.take().0,
                right.take().1,
                point(bridge.each_ref().map(|coord| *coord.value().take()))?,
            ))
        })?;
        let out = (
            AnchorSpanOutput {
                anchor_start: left_encoded.as_gadget().0.anchor_start.clone(),
                anchor_end: right_encoded.as_gadget().0.anchor_end.clone(),
            },
            bridge.into(),
        );
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(out)),
            data,
            D::unit(),
        ))
    }
}

pub(super) fn enforce_end_factor<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    z: &Element<'dr, D>,
    end: &Element<'dr, D>,
    prefix: &Element<'dr, D>,
    members: &Element<'dr, D>,
) -> ragu::Result<()> {
    z.sub(dr, end).mul(dr, prefix)?.enforce_equal(dr, members)
}

// Synthetic division by X - end. The circuit checks that the remainder is zero.
fn remove_end(members: &[Fp], end: Fp) -> Vec<Fp> {
    let mut carry = Fp::ZERO;
    let mut prefix: Vec<_> = members
        .iter()
        .skip(1)
        .rev()
        .map(|coefficient| {
            carry = *coefficient + end * carry;
            carry
        })
        .collect();
    prefix.reverse();
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_factor_rejects_a_substituted_opening() {
        use ragu::primitives::Simulator;
        let check = |openings: [Fp; 4]| {
            Simulator::<Fp>::simulate(openings, |dr, values| {
                let mut alloc = |index| {
                    Element::alloc(
                        dr,
                        &mut (),
                        values
                            .as_ref()
                            .map(|fields| fields.get(index).copied().unwrap()),
                    )
                };
                let z = alloc(0)?;
                let end = alloc(1)?;
                let prefix = alloc(2)?;
                let members = alloc(3)?;
                enforce_end_factor(dr, &z, &end, &prefix, &members)
            })
        };
        for (prefix, members, expected) in [(3, 15, true), (4, 15, false), (3, 16, false)] {
            assert_eq!(
                check([12, 7, prefix, members].map(Fp::from)).is_ok(),
                expected
            );
        }
    }

    #[test]
    fn synthetic_division_removes_one_occurrence_of_the_end() {
        let end = Anchor::from(Fp::from(11));
        let other = Anchor::from(Fp::from(17));
        let full = AnchorSetPoly::from_iter([end, other, end]);
        let prefix = AnchorSetPoly::from_iter([end, other]);
        assert_eq!(
            remove_end(&coefficients(full.as_ref()), end.into()),
            coefficients(prefix.as_ref())
        );
    }
}
