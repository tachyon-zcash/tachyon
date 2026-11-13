use ragu_primitives::Simulator;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

use super::*;

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
