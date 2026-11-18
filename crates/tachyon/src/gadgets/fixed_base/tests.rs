use ragu_primitives::Simulator;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

use super::*;
use crate::pasta;

#[test]
fn scalar_multiplication_is_the_scalar_times_the_base() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut scalars = Vec::from([
        Fq::ONE,
        -Fq::ONE,
        Fq::from(2).pow_u64(254),
        Fq::random(|bytes| rng.fill_bytes(bytes)),
    ]);
    // Each digit in every window.
    scalars.extend(
        (1..8).map(|digit| (0..85).fold(Fq::ZERO, |acc, _| acc * Fq::from(8) + Fq::from(digit))),
    );
    for scalar in scalars {
        Simulator::<Fp>::simulate(scalar, |dr, witness| {
            let point = R_BASE.mul_scalar(dr, &witness)?;
            assert_eq!(
                point.value().take(),
                (*orchard::VALUE_COMMIT_R * scalar).to_affine()
            );
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn element_multiplication_accepts_254_bit_elements_and_rejects_wider() {
    let rng = &mut StdRng::seed_from_u64(0);
    let start = *ACTION_AUTH_GENERATOR * Fq::random(|bytes| rng.fill_bytes(bytes));
    let accepted = [
        Fp::ONE,
        Fp::from(2).pow_u64(254) - Fp::ONE,
        Fp::random(|bytes| rng.fill_bytes(bytes)),
    ];
    let rejected = [Fp::from(2).pow_u64(254), -Fp::ONE];
    for (fixed_base, base, onto) in [
        (&*G_BASE, *ACTION_AUTH_GENERATOR, None),
        (&*G_BASE, *ACTION_AUTH_GENERATOR, Some(start)),
        (&*R_BASE, *orchard::VALUE_COMMIT_R, None),
    ] {
        for digest in accepted {
            Simulator::<Fp>::simulate(digest, |dr, witness| {
                let element = Element::alloc(dr, &mut (), witness)?;
                let onto_point = onto
                    .map(|point| Point::constant(dr, point.to_affine()))
                    .transpose()?;
                let point = fixed_base.mul_element(dr, &element, onto_point.as_ref())?;
                let expected =
                    base * pasta::digest_scalar(digest) + onto.unwrap_or_else(Ep::identity);
                assert_eq!(point.value().take(), expected.to_affine());
                Ok(())
            })
            .unwrap();
        }
        for digest in rejected {
            Simulator::<Fp>::simulate(digest, |dr, witness| {
                let element = Element::alloc(dr, &mut (), witness)?;
                let onto_point = onto
                    .map(|point| Point::constant(dr, point.to_affine()))
                    .transpose()?;
                fixed_base.mul_element(dr, &element, onto_point.as_ref())?;
                Ok(())
            })
            .map(|_| ())
            .unwrap_err();
        }
    }
}

/// The native embedding refuses the smallest digest the circuit rejects.
#[test]
#[should_panic(expected = "a Poseidon digest is below 2^254")]
fn digest_scalar_rejects_wider_digests() {
    let _scalar = pasta::digest_scalar(Fp::from(2).pow_u64(254));
}

#[test]
fn value_multiplication_accepts_51_bit_values_and_rejects_wider() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut accepted = Vec::from([0, 1, MAX_MONEY, (1u64 << 51) - 1]);
    // Each digit in every window.
    accepted.extend((1..8).map(|digit| (0..17).fold(0, |acc, _| acc * 8 + digit)));
    let rejected = [Fp::from(1u64 << 51), -Fp::ONE];
    for (fixed_base, base) in [
        (&*V_BASE, *orchard::VALUE_COMMIT_V),
        (&*NEG_V_BASE, -*orchard::VALUE_COMMIT_V),
    ] {
        let blind = Fq::random(|bytes| rng.fill_bytes(bytes));
        for amount in &accepted {
            Simulator::<Fp>::simulate(Fp::from(*amount), |dr, witness| {
                let value = Uint::alloc(dr, witness)?;
                let blind_point = R_BASE.mul_scalar(dr, &Simulator::<Fp>::just(|| blind))?;
                let point = fixed_base.mul_amount(dr, &value, &blind_point)?;
                let expected = *orchard::VALUE_COMMIT_R * blind + base * Fq::from(*amount);
                assert_eq!(point.value().take(), expected.to_affine());
                Ok(())
            })
            .unwrap();
        }
        for amount in rejected {
            Simulator::<Fp>::simulate(amount, |dr, witness| {
                let value = Uint::alloc(dr, witness)?;
                let blind_point = R_BASE.mul_scalar(dr, &Simulator::<Fp>::just(|| blind))?;
                fixed_base.mul_amount(dr, &value, &blind_point)?;
                Ok(())
            })
            .map(|_| ())
            .unwrap_err();
        }
    }
}

#[test]
fn fee_commitment_spans_zero_to_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let blind = Fp::random(|bytes| rng.fill_bytes(bytes));
    let blind_scalar = Fq::from_bytes(blind.to_bytes()).unwrap();
    for maximum in [0, 1, MAX_MONEY, MAX_MONEY + 1] {
        let result = Simulator::<Fp>::simulate(maximum, |dr, witness| {
            let digest = Element::constant(dr, blind);
            let slack = Uint::alloc(
                dr,
                witness.map(|value| Fp::from(MAX_MONEY) - Fp::from(value)),
            )?;
            let blind_point = R_BASE.mul_element(dr, &digest, None)?;
            let point = FEE_V_BASE.mul_amount(dr, &slack, &blind_point)?;
            let expected = *orchard::VALUE_COMMIT_R * blind_scalar
                - *orchard::VALUE_COMMIT_V * Fq::from(maximum);
            assert_eq!(point.value().take(), expected.to_affine());
            Ok(())
        })
        .map(|_| ());
        if maximum <= MAX_MONEY {
            result.unwrap();
        } else {
            result.unwrap_err();
        }
    }
}

/// Every input below forces an addition onto an operand with the same x
/// coordinate: an identity result, a doubling at the top entry, or a blind
/// point that meets the value prefix.
#[test]
fn exceptional_additions_are_rejected() {
    Simulator::<Fp>::simulate(Fq::ZERO, |dr, witness| {
        R_BASE.mul_scalar(dr, &witness)?;
        Ok(())
    })
    .map(|_| ())
    .unwrap_err();
    Simulator::<Fp>::simulate(Fp::ZERO, |dr, witness| {
        let element = Element::alloc(dr, &mut (), witness)?;
        G_BASE.mul_element(dr, &element, None)?;
        Ok(())
    })
    .map(|_| ())
    .unwrap_err();

    // Interior digits reading 8^84 - 4 (8^84 - 1) / 7 under a top digit of
    // one put the prefix on the top entry.
    let doubling = Fq::from(2).pow_u64(253)
        - Fq::from(4) * (0..84).fold(Fq::ZERO, |acc, _| acc * Fq::from(8) + Fq::ONE);
    Simulator::<Fp>::simulate(doubling, |dr, witness| {
        R_BASE.mul_scalar(dr, &witness)?;
        Ok(())
    })
    .map(|_| ())
    .unwrap_err();

    // A zero value leaves the prefix at [2 (8^16 - 1) / 7]V.
    let prefix =
        *orchard::VALUE_COMMIT_V * (0..16).fold(Fq::ZERO, |acc, _| acc * Fq::from(8) + Fq::from(2));
    for onto in [prefix, -prefix] {
        Simulator::<Fp>::simulate(Fp::ZERO, |dr, witness| {
            let value = Uint::alloc(dr, witness)?;
            let blind_point = Point::constant(dr, onto.to_affine())?;
            V_BASE.mul_amount(dr, &value, &blind_point)?;
            Ok(())
        })
        .map(|_| ())
        .unwrap_err();
    }
}
