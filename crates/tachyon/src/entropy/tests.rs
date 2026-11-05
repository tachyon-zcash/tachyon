use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{digest::poseidon, note, primitives::effect};

#[test]
fn spend_and_output_randomizers_differ() {
    let mut rng = StdRng::seed_from_u64(100);
    let theta = ActionEntropy::random(&mut rng);
    let cm = note::Commitment::from(Fp::random(|bytes| rng.fill_bytes(bytes)));

    let spend_alpha: Fq = theta.randomizer::<effect::Spend>(cm).into();
    let output_alpha: Fq = theta.randomizer::<effect::Output>(cm).into();

    assert_ne!(spend_alpha, output_alpha);
}

#[test]
fn randomizer_depends_on_theta() {
    let mut rng = StdRng::seed_from_u64(101);
    let theta_a = ActionEntropy::random(&mut rng);
    let theta_b = ActionEntropy::random(&mut rng);
    let cm = note::Commitment::from(Fp::random(|bytes| rng.fill_bytes(bytes)));

    let first: Fq = theta_a.randomizer::<effect::Spend>(cm).into();
    let other: Fq = theta_b.randomizer::<effect::Spend>(cm).into();
    assert_ne!(first, other);
}

#[test]
fn randomizer_embeds_the_poseidon_output() {
    let mut rng = StdRng::seed_from_u64(102);
    let theta = ActionEntropy::random(&mut rng);
    let cm = note::Commitment::from(Fp::random(|bytes| rng.fill_bytes(bytes)));

    let spend: Fq = theta.randomizer::<effect::Spend>(cm).into();
    let output: Fq = theta.randomizer::<effect::Output>(cm).into();

    assert_eq!(
        spend.to_bytes(),
        poseidon::alpha_spend(theta.0, cm.into()).to_bytes()
    );
    assert_eq!(
        output.to_bytes(),
        poseidon::alpha_output(theta.0, cm.into()).to_bytes()
    );
}

#[test]
fn debug_entropy_redacts_bytes() {
    let mut bytes = [0xAB; 32];
    bytes[31] = 0x2B;
    let theta = ActionEntropy::from_bytes(bytes).unwrap();
    let dbg = alloc::format!("{theta:?}");
    assert!(dbg.contains("ActionEntropy"));
    assert!(!dbg.contains("AB"));
    assert!(!dbg.contains("171"));
}
