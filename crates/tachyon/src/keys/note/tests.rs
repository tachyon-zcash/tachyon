use alloc::vec::Vec;

use ragu_core::{PoseidonPermutation as _, pasta::PoseidonFp};
use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{constants::EPOCH_MAX, nullifier::Nullifier, primitives::EpochIndex, reddsa};

#[test]
#[should_panic(expected = "identity")]
fn derive_rejects_identity_ak() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ak = SpendValidatingKey(
        reddsa::VerificationKey::try_from([0u8; 32]).expect("identity is a valid key"),
    );
    let nk = NullifierKey::random(rng);

    let _derived = PaymentKey::derive(&ak, &nk);
}

#[test]
fn master_key_is_a_function_of_nk_and_psi() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (nk, other_nk) = (NullifierKey::random(rng), NullifierKey::random(rng));
    let (psi, other_psi) = (
        nullifier::Trapdoor::random(rng),
        nullifier::Trapdoor::random(rng),
    );
    let mk = nk.derive_note_private(psi);
    assert_ne!(mk, nk.derive_note_private(other_psi), "another psi");
    assert_ne!(mk, other_nk.derive_note_private(psi), "another nk");
}

#[test]
fn distinct_epochs_take_distinct_nullifiers() {
    let rng = &mut StdRng::seed_from_u64(0);
    let psi = nullifier::Trapdoor::random(rng);
    let mk = NullifierKey::random(rng).derive_note_private(psi);
    let rate = u32::try_from(PoseidonFp::RATE).unwrap();
    let mut epochs: Vec<u32> = [0, 96, EPOCH_MAX]
        .into_iter()
        .flat_map(|epoch| {
            #[expect(
                clippy::integer_division_remainder_used,
                reason = "the remainder is the epoch's slot in its sponge group"
            )]
            let group_start = epoch - epoch % rate;
            group_start..group_start + rate
        })
        .collect();
    epochs.sort_unstable();
    epochs.dedup();
    let nullifiers: Vec<(u32, Nullifier)> = epochs
        .into_iter()
        .map(|index| (index, mk.derive_nullifier(EpochIndex::new(index))))
        .collect();
    for (position, &(epoch, nf)) in nullifiers.iter().enumerate() {
        for &(other, other_nf) in &nullifiers[position + 1..] {
            assert_ne!(nf, other_nf, "epochs {epoch} and {other}");
        }
    }
}

#[test]
fn debug_redacts_the_nullifier_trapdoor() {
    let psi = nullifier::Trapdoor::random(&mut StdRng::seed_from_u64(0));
    assert_eq!(alloc::format!("{psi:?}"), "Trapdoor(..)");
}
