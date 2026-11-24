mod relation;

use ragu::{
    AcceleratedProver, Cycle as _, FixedGenerators as _, WalletRank,
    circuits::{Circuit, WithAux, polynomials::AggregatorRank, registry::RegistryBuilder},
    gadgets::{Bound, Kind},
    pasta::Pasta,
    pcd::{bridge_hash, ipa::IpaCycle as _},
    primitives::Simulator,
    udon::{curve::Projective as _, field::Field as _},
};

use super::*;
use crate::{
    Anchor,
    pasta::{self, EpAffine, Fq},
};

// Exercise the production body with a genuine encoded input and the two
// wires the output oracle supplies. Stage values are computed independently
// from real host commitments. This harness does not authenticate a PCD.
struct Restore<'setup>(&'setup TransactionRehydrate);

impl Circuit<Fp> for Restore<'_> {
    type Aux<'source> = ActionSetBridge;
    type Instance<'source> = (ActionSetBridge, Anchor);
    type Output = Kind![Fp; TransactionOutput<'_,_>];
    type Witness<'source> = ((ActionSetBridge, Anchor), EpAffine, EqAffine);

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        Transaction::encode(dr, &mut (), instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let public = PublicTransaction::encode(dr, &mut (), witness.as_ref().map(|case| case.0))?;
        let oracle = D::try_just(|| {
            witness
                .as_ref()
                .take()
                .1
                .coordinates()
                .ok_or_else(|| Error::InvalidWitness("identity test oracle".into()))
        })?;
        let x = Element::alloc(dr, &mut (), oracle.as_ref().map(|pair| pair.0))?;
        let y = Element::alloc(dr, &mut (), oracle.map(|pair| pair.1))?;
        let (output, data) = self
            .0
            .restore(dr, &public, [&x, &y], witness.map(|case| case.2))?;
        Ok(WithAux::new(output, data))
    }
}

#[test]
fn rehydrate_checks_the_slot_and_emits_its_local_bridge() {
    let params = pasta::baked();
    let step = TransactionRehydrate::new().unwrap();
    RegistryBuilder::<Fp, AggregatorRank>::new()
        .register_circuit(Restore(&step))
        .unwrap();
    let &[original, replacement] = Pasta::host_generators(params).g().first_chunk().unwrap();
    let portable = bridge_hash::digest::<AcceleratedProver, _, EpAffine, WalletRank, _>(
        original,
        Pasta::nested_generators(params),
    )
    .unwrap();
    let [local, other] = [original, replacement].map(|commitment| {
        bridge_hash::rx::<_, AggregatorRank>(commitment)
            .unwrap()
            .iter_stored_coeffs()
            .filter(|&(_, coefficient)| *coefficient != Fq::ZERO)
            .map(|(index, coefficient)| {
                Pasta::nested_generator(params, index).unwrap() * *coefficient
            })
            .reduce(|left, right| left + right)
            .unwrap()
            .to_affine()
    });
    let anchor = Anchor::from(Fp::from(42));
    let run = |input, oracle, commitment| {
        Simulator::simulate(
            ((ActionSetBridge::from(input), anchor), oracle, commitment),
            |dr, assignment| {
                let (output, data) = Restore(&step).witness(dr, assignment)?.into_parts();
                assert_eq!(*output.anchor.value().take(), Fp::from(anchor));
                assert_eq!(EpAffine::from(data.take()), oracle);
                let coordinates = output
                    .action_set_bridge
                    .each_ref()
                    .map(|wire| *wire.value().take());
                assert_eq!(Some(coordinates.into()), oracle.coordinates());
                Ok(())
            },
        )
    };
    run(portable, local, original).unwrap();
    for (input, oracle, commitment) in [
        (portable, other, original),
        (portable, other, replacement),
        (portable, local, EqAffine::identity()),
        (portable, portable, original),
        (local, local, original),
    ] {
        assert!(matches!(
            run(input, oracle, commitment),
            Err(Error::InvalidWitness(_))
        ));
    }
}
