use ragu_primitives::Simulator;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{constants::EPOCH_MAX, keys, primitives::EpochIndex};

#[test]
fn derive_nullifier_matches_the_native_derivation() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mk = keys::NoteMasterKey(Fp::random(|bytes| rng.fill_bytes(bytes)));
    for epoch in [0, 1, 2, 3, 4, 7, EPOCH_MAX - 1, EPOCH_MAX] {
        Simulator::<Fp>::simulate(Fp::from(u64::from(epoch)), |dr, witness| {
            let key = NoteMasterKey {
                element: Element::constant(dr, mk.0),
            };
            let element = Element::alloc(dr, &mut (), witness)?;
            let nullifier = key.derive_nullifier(dr, &element)?;
            assert_eq!(
                *nullifier.value().take(),
                Fp::from(mk.derive_nullifier(EpochIndex::new(epoch)))
            );
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn derive_nullifier_rejects_epochs_of_32_bits_or_more() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mk = Fp::random(|bytes| rng.fill_bytes(bytes));
    for epoch in [Fp::from(1u64 << 32), -Fp::ONE, -Fp::from(4)] {
        Simulator::<Fp>::simulate(epoch, |dr, witness| {
            let key = NoteMasterKey {
                element: Element::constant(dr, mk),
            };
            let element = Element::alloc(dr, &mut (), witness)?;
            key.derive_nullifier(dr, &element)?;
            Ok(())
        })
        .map(|_| ())
        .unwrap_err();
    }
}
