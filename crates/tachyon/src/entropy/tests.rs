use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{digest::poseidon, note, primitives::effect};

#[test]
fn randomizers_are_domain_separated_functions_of_theta_and_cm() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (theta, other_theta) = (ActionEntropy::random(rng), ActionEntropy::random(rng));
    let (cm, other_cm) = (
        note::Commitment::from(Fp::random(|bytes| rng.fill_bytes(bytes))),
        note::Commitment::from(Fp::random(|bytes| rng.fill_bytes(bytes))),
    );
    let spend = |entropy: ActionEntropy, commitment| {
        Fq::from(entropy.randomizer::<effect::Spend>(commitment))
    };
    let output = |entropy: ActionEntropy, commitment| {
        Fq::from(entropy.randomizer::<effect::Output>(commitment))
    };

    assert_ne!(spend(theta, cm), output(theta, cm));
    assert_ne!(spend(theta, cm), spend(other_theta, cm));
    assert_ne!(spend(theta, cm), spend(theta, other_cm));
    assert_ne!(output(theta, cm), output(other_theta, cm));
    assert_ne!(output(theta, cm), output(theta, other_cm));
    assert_eq!(
        spend(theta, cm).to_bytes(),
        poseidon::alpha_spend(theta.0, cm.into()).to_bytes()
    );
    assert_eq!(
        output(theta, cm).to_bytes(),
        poseidon::alpha_output(theta.0, cm.into()).to_bytes()
    );
}

#[test]
fn from_bytes_accepts_exactly_canonical_encodings() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut modulus = (-Fp::ONE).to_bytes();
    assert_eq!(modulus[0], 0);
    modulus[0] = 1;
    for (label, bytes, canonical) in [
        ("zero", [0u8; 32], true),
        (
            "a random element",
            ActionEntropy::random(rng).0.to_bytes(),
            true,
        ),
        ("the modulus minus one", (-Fp::ONE).to_bytes(), true),
        ("the modulus", modulus, false),
        ("all ones", [0xFF; 32], false),
    ] {
        let parsed = ActionEntropy::from_bytes(bytes);
        assert_eq!(parsed.is_some(), canonical, "{label}");
        if let Some(theta) = parsed {
            assert_eq!(theta.0.to_bytes(), bytes, "{label} writes back");
        }
    }
}

#[test]
fn debug_redacts_entropy_and_randomizers() {
    let rng = &mut StdRng::seed_from_u64(0);
    let cm = note::Commitment::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let theta = ActionEntropy::random(rng);
    assert_eq!(alloc::format!("{theta:?}"), "ActionEntropy(..)");
    assert_eq!(
        alloc::format!("{:?}", theta.randomizer::<effect::Spend>(cm)),
        "ActionRandomizer<zcash_tachyon::primitives::effect::Spend>"
    );
}
