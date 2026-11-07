use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{digest::poseidon, note, primitives::effect};

#[test]
fn randomizer_embeds_the_poseidon_output() {
    let rng = &mut StdRng::seed_from_u64(0);
    let theta = ActionEntropy::random(rng);
    let cm = note::Commitment::from(Fp::random(|bytes| rng.fill_bytes(bytes)));

    let spend: Fq = theta.randomizer::<effect::Spend>(cm).into();
    let output: Fq = theta.randomizer::<effect::Output>(cm).into();

    assert_ne!(spend, output);
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
    assert_eq!(alloc::format!("{theta:?}"), "ActionEntropy(..)");
}
