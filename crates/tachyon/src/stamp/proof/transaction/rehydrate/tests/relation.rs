use alloc::string::ToString as _;
use core::ops::Add;

use group::GroupEncoding as _;
use pasta_curves::{arithmetic::CurveExt as _, pallas};
use ragu::{
    AcceleratedProver, WalletRank,
    circuits::{Circuit, WithAux, polynomials::AggregatorRank, registry::RegistryBuilder},
    gadgets::{Bound, Kind},
    primitives::Simulator,
};

use super::*;

// Make the two hashes the public instance; the opening is private. Both good
// and bad assignments run through exactly the same circuit and setup.
#[derive(Clone, Copy)]
struct Confirm<'setup>(&'setup TransactionRehydrate);

impl Circuit<Fp> for Confirm<'_> {
    type Aux<'source> = ();
    type Instance<'source> = [EpAffine; 2];
    type Output = Kind![Fp; (Point<'_, _, EpAffine>, Point<'_, _, EpAffine>)];
    type Witness<'source> = ([EpAffine; 2], [Fq; 2]);

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        Ok((
            Point::alloc(dr, instance.as_ref().map(|points| points[0]))?,
            Point::alloc(dr, instance.map(|points| points[1]))?,
        ))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
    where
        Self: 'dr,
    {
        let hashes = self.instance(dr, witness.as_ref().map(|assignment| assignment.0))?;
        let mut portable = Vec::new();
        hashes.0.write(dr, &mut portable)?;
        let mut oracle = Vec::new();
        hashes.1.write(dr, &mut oracle)?;
        self.0.enforce_same_coordinates(
            dr,
            [&portable[0], &portable[1]],
            [&oracle[0], &oracle[1]],
            witness.map(|assignment| assignment.1),
        )?;
        Ok(WithAux::new(hashes, D::unit()))
    }
}

// The stock rank-15 table for `digest` is feature-gated. Commit Ragu's
// stage polynomial as fuse does, independently deriving the generators at
// its occupied degrees by the pin's parameter-generation rule. This checks
// the stage supplement too, without using the gadget's generator accessor.
fn aggregator_hash(point: EqAffine) -> EpAffine {
    let derive = pallas::Point::hash_to_curve("Ragu-Parameters");
    bridge_hash::rx::<_, AggregatorRank>(point)
        .unwrap()
        .iter_stored_coeffs()
        .filter(|&(_, coefficient)| *coefficient != Fq::ZERO)
        .map(|(degree, coefficient)| {
            let mut message = [0; 5];
            message[1..].copy_from_slice(&u32::try_from(degree).unwrap().to_le_bytes());
            EpAffine::from_bytes(derive(&message).to_bytes()).unwrap() * *coefficient
        })
        .reduce(Add::add)
        .unwrap()
        .to_affine()
}

#[test]
fn shared_opening_checks_both_rank_digests() {
    // Register the circuits and check their witness constraints. We do not
    // verify a public instance or a PCD proof, so these inputs are test
    // values, not hashes authenticated by a parent or a verified header.
    let params = parameters::baked();
    let conversion = TransactionRehydrate::new().unwrap();
    let &[original, replacement] = Pasta::host_generators(params).g().first_chunk().unwrap();
    let (x, y) = original.coordinates().unwrap();
    let (other_x, other_y) = replacement.coordinates().unwrap();
    let [portable, other_wallet] = [original, replacement].map(|point| {
        bridge_hash::digest::<AcceleratedProver, _, EpAffine, WalletRank, _>(
            point,
            Pasta::nested_generators(params),
        )
        .unwrap()
    });
    let local = aggregator_hash(original);
    let different = aggregator_hash(replacement);
    let circuit = Confirm(&conversion);
    RegistryBuilder::<Fp, WalletRank>::new()
        .register_circuit(circuit)
        .unwrap();
    RegistryBuilder::<Fp, AggregatorRank>::new()
        .register_circuit(circuit)
        .unwrap();
    let check = |relation: Confirm<'_>, left, right, coordinates| {
        Simulator::<Fp>::simulate(([left, right], coordinates), |dr, assignment| {
            relation.witness(dr, assignment).map(|_| ())
        })
    };
    check(circuit, other_wallet, different, [other_x, other_y]).unwrap();
    assert!(matches!(
        check(circuit, portable, portable, [Fq::ZERO, Fq::ZERO]),
        Err(Error::InvalidWitness(_))
    ));
    let cost = check(circuit, portable, local, [x, y]).unwrap();
    // Includes the test's two public points as well as the bound local point.
    assert_eq!((cost.num_gates(), cost.num_constraints()), (1395, 2794));
    for (first, second, opening) in [
        (portable, different, [x, y]),
        (portable, different, [other_x, other_y]),
        (portable, local, [y, x]),
        (portable, portable, [x, y]),
        (local, local, [x, y]),
        (-portable, local, [x, y]),
        (portable, -local, [x, y]),
    ] {
        assert!(
            matches!(check(circuit, first, second, opening), Err(Error::InvalidWitness(reason)) if reason.to_string() == "constraint failed"),
            "expected inconsistent hashes {first:?}, {second:?} with opening {opening:?} to violate a constraint"
        );
    }
}

#[test]
#[should_panic(expected = "pinned bridge degrees changed")]
fn setup_rejects_an_unexpected_stage_layout() {
    let probe = Pasta::host_generators(parameters::baked()).g()[0];
    let stage = bridge_hash::rx::<_, WalletRank>(probe).unwrap();
    Layout::pinned(probe, &stage, (16263, 32647));
}

#[test]
fn either_off_curve_endpoint_returns_a_witness_error() {
    let conversion = TransactionRehydrate::new().unwrap();
    let (native_x, native_y) = Pasta::nested_generator(parameters::baked(), 3975)
        .unwrap()
        .coordinates()
        .unwrap();
    for bad_portable in [true, false] {
        let result = Simulator::<Fp>::simulate([Fq::ONE; 2], |dr, coordinates| {
            let one = Element::one(); // (1,1) is off Pallas, not the identity encoding.
            let x = Element::constant(dr, native_x);
            let y = Element::constant(dr, native_y);
            let good = [&x, &y];
            let bad = [&one; 2];
            let (portable, local) = if bad_portable {
                (bad, good)
            } else {
                (good, bad)
            };
            conversion
                .enforce_same_coordinates(dr, portable, local, coordinates)
                .map(|_| ())
        });
        assert!(
            matches!(result, Err(Error::InvalidWitness(reason)) if reason.to_string() == "invalid action bridge")
        );
    }
}

#[test]
fn fixed_base_exceptional_sums_fail_with_finite_endpoints() {
    let step = TransactionRehydrate::new().unwrap();
    let point = |i| {
        Pasta::nested_generator(parameters::baked(), i)
            .unwrap()
            .to_projective()
    };
    let dx = (point(3975) - point(16263)).to_affine();
    let dy = point(8071) - point(32647);
    // For scalar one the low 84 three-bit windows accumulate (1 + offset)·dx.
    let offset = (0..84).fold(Fq::ZERO, |acc, _| acc * Fq::from(8) + Fq::from(2));
    for factor in [Fq::ONE + offset, Fq::ONE] {
        // The local point cancels the low-window prefix or the entire first sum.
        let local = -(dx * factor);
        let portable = local + dx.to_projective() + dy;
        let endpoints = [portable.to_affine(), local.to_affine()];
        assert!(endpoints.iter().all(|endpoint| !endpoint.is_identity()));
        assert_ne!(endpoints[0], endpoints[1]);
        let result = Simulator::<Fp>::simulate((endpoints, [Fq::ONE; 2]), |dr, witness| {
            Confirm(&step).witness(dr, witness).map(|_| ())
        });
        assert!(matches!(result, Err(Error::InvalidWitness(_))));
    }
}
