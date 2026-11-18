use ragu::primitives::{Simulator, decompose};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

use super::*;
use crate::gadgets::{uint::Uint, value::Positive};

#[test]
fn blind_multiplication_reads_the_low_254_bits() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut accepted = Vec::from([
        Fq::ONE,
        Fq::from(2).pow_u64(254) - Fq::ONE,
        Fq::random(|bytes| rng.fill_bytes(bytes)),
    ]);
    // Each digit in every interior window, and each top digit below 2^254.
    accepted.extend((1..8).map(|digit| {
        (0..84).fold(Fq::from(digit & 3), |acc, _| {
            acc * Fq::from(8) + Fq::from(digit)
        })
    }));
    for scalar in accepted {
        Simulator::<Fp>::simulate(scalar, |dr, witness| {
            let bits = Uint::<_, 254>::alloc(dr, witness)?;
            let point = R_BASE.mul(dr, bits.bits())?;
            assert_eq!(
                point.value().take(),
                (*orchard::VALUE_COMMIT_R * scalar).to_affine()
            );
            Ok(())
        })
        .unwrap();
    }
    let top = Fq::from(2).pow_u64(254);
    for scalar in [top + Fq::ONE, -Fq::ONE] {
        Simulator::<Fp>::simulate(scalar, |dr, witness| {
            let bits = Uint::<_, 254>::alloc(dr, witness)?;
            let point = R_BASE.mul(dr, bits.bits())?;
            assert_eq!(
                point.value().take(),
                (*orchard::VALUE_COMMIT_R * (scalar - top)).to_affine()
            );
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn multiplication_accepts_254_bit_elements_and_rejects_wider() {
    let rng = &mut StdRng::seed_from_u64(0);
    let start = *ACTION_AUTH_GENERATOR * Fq::random(|bytes| rng.fill_bytes(bytes));
    let accepted = [
        Fp::ONE,
        Fp::from(2).pow_u64(254) - Fp::ONE,
        Fp::random(|bytes| rng.fill_bytes(bytes)),
    ];
    let rejected = [Fp::from(2).pow_u64(254), -Fp::ONE];
    for (fixed_base, base, added) in [
        (&*G_BASE, *ACTION_AUTH_GENERATOR, None),
        (&*G_BASE, *ACTION_AUTH_GENERATOR, Some(start)),
        (&*R_BASE, *orchard::VALUE_COMMIT_R, None),
    ] {
        for (digest, accepts) in accepted
            .map(|digest| (digest, true))
            .into_iter()
            .chain(rejected.map(|digest| (digest, false)))
        {
            let result = Simulator::<Fp>::simulate(digest, |dr, witness| {
                let element = Element::alloc(dr, &mut (), witness)?;
                let bits =
                    FixedVec::<_, ConstLen<254>>::try_from(decompose(dr, &mut (), &element)?)?;
                let point = match added {
                    Some(native) => {
                        let gadget = Point::constant(dr, native.to_affine())?;
                        fixed_base.mul_and_add(dr, &bits, &gadget)?
                    },
                    None => fixed_base.mul(dr, &bits)?,
                };
                let scalar = Fq::from_bytes(digest.to_bytes()).unwrap();
                let expected = base * scalar + added.unwrap_or_else(Ep::identity);
                assert_eq!(point.value().take(), expected.to_affine());
                Ok(())
            })
            .map(|_| ());
            if accepts {
                result.unwrap();
            } else {
                result.unwrap_err();
            }
        }
    }
}

#[test]
fn value_multiplication_reads_the_low_51_bits() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut amounts = Vec::from([0, 1, MAX_MONEY, (1u64 << 51) - 1].map(|amount| (amount, amount)));
    // Each digit in every window.
    amounts.extend(
        (1..8)
            .map(|digit| (0..17).fold(0, |acc, _| acc * 8 + digit))
            .map(|amount| (amount, amount)),
    );
    amounts.extend([(1u64 << 51, 0), ((1u64 << 51) + 5, 5)]);
    for (fixed_base, base) in [
        (&*V_BASE, *orchard::VALUE_COMMIT_V),
        (&*NEG_V_BASE, -*orchard::VALUE_COMMIT_V),
    ] {
        let blind = Fq::random(|bytes| rng.fill_bytes(bytes));
        for &(amount, low) in &amounts {
            Simulator::<Fp>::simulate(Fp::from(amount), |dr, witness| {
                let value = Uint::<_, 51>::alloc(dr, witness)?;
                let blind_bits = Uint::<_, 254>::alloc(dr, Simulator::<Fp>::just(|| blind))?;
                let blind_point = R_BASE.mul(dr, blind_bits.bits())?;
                let point = fixed_base.mul_and_add(dr, value.bits(), &blind_point)?;
                let expected = *orchard::VALUE_COMMIT_R * blind + base * Fq::from(low);
                assert_eq!(point.value().take(), expected.to_affine());
                Ok(())
            })
            .unwrap();
        }
    }
}

#[test]
fn fee_commitment_spans_zero_to_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let blind = Fp::random(|bytes| rng.fill_bytes(bytes));
    let blind_scalar = Fq::from_bytes(blind.to_bytes()).unwrap();
    // The slack is `MAX_MONEY - maximum`; one above `MAX_MONEY` is a negative
    // maximum, which the slack bound rejects.
    for slack in [MAX_MONEY, MAX_MONEY - 1, 0, MAX_MONEY + 1] {
        let result = Simulator::<Fp>::simulate(slack, |dr, witness| {
            let digest = Element::constant(dr, blind);
            let slack_bits = Uint::<_, 51>::alloc(dr, witness.map(Fp::from))?;
            Positive::from_slack(dr, &slack_bits)?;
            let digest_bits =
                FixedVec::<_, ConstLen<254>>::try_from(decompose(dr, &mut (), &digest)?)?;
            let blind_point = R_BASE.mul(dr, &digest_bits)?;
            let point = FEE_V_BASE.mul_and_add(dr, slack_bits.bits(), &blind_point)?;
            if slack <= MAX_MONEY {
                let expected = *orchard::VALUE_COMMIT_R * blind_scalar
                    - *orchard::VALUE_COMMIT_V * Fq::from(MAX_MONEY - slack);
                assert_eq!(point.value().take(), expected.to_affine());
            }
            Ok(())
        })
        .map(|_| ());
        if slack <= MAX_MONEY {
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
        let bits = Uint::<_, 254>::alloc(dr, witness)?;
        R_BASE.mul(dr, bits.bits())?;
        Ok(())
    })
    .map(|_| ())
    .unwrap_err();
    Simulator::<Fp>::simulate(Fp::ZERO, |dr, witness| {
        let element = Element::alloc(dr, &mut (), witness)?;
        let bits = FixedVec::<_, ConstLen<254>>::try_from(decompose(dr, &mut (), &element)?)?;
        G_BASE.mul(dr, &bits)?;
        Ok(())
    })
    .map(|_| ())
    .unwrap_err();

    // Interior digits reading 8^84 - 4 (8^84 - 1) / 7 under a top digit of
    // one put the prefix on the top entry.
    let doubling = Fq::from(2).pow_u64(253)
        - Fq::from(4) * (0..84).fold(Fq::ZERO, |acc, _| acc * Fq::from(8) + Fq::ONE);
    Simulator::<Fp>::simulate(doubling, |dr, witness| {
        let bits = Uint::<_, 254>::alloc(dr, witness)?;
        R_BASE.mul(dr, bits.bits())?;
        Ok(())
    })
    .map(|_| ())
    .unwrap_err();

    // A zero value leaves the prefix at [2 (8^16 - 1) / 7]V.
    let prefix =
        *orchard::VALUE_COMMIT_V * (0..16).fold(Fq::ZERO, |acc, _| acc * Fq::from(8) + Fq::from(2));
    for onto in [prefix, -prefix] {
        Simulator::<Fp>::simulate(Fp::ZERO, |dr, witness| {
            let value = Uint::<_, 51>::alloc(dr, witness)?;
            let blind_point = Point::constant(dr, onto.to_affine())?;
            V_BASE.mul_and_add(dr, value.bits(), &blind_point)?;
            Ok(())
        })
        .map(|_| ())
        .unwrap_err();
    }
}
