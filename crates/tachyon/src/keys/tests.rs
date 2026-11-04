use alloc::vec::Vec;

use ragu_core::{PoseidonPermutation as _, pasta::PoseidonFp};
use rand::{SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;

use crate::{
    constants::EPOCH_MAX,
    entropy::ActionEntropy,
    keys::{NoteMasterKey, NullifierKey, PaymentKey, SpendValidatingKey, private},
    note::{self, Note},
    nullifier::{self, Nullifier},
    pasta::Fp,
    primitives::{EpochIndex, effect},
    reddsa, value,
};

#[test]
fn child_keys_are_independent() {
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let ak = sk.derive_auth_private().derive_auth_public();
    let nk = sk.derive_nullifier_private();
    let pk = sk.derive_payment_key();

    let ak_bytes: [u8; 32] = ak.0.into();
    assert_ne!(ak_bytes, nk.0.to_bytes());
    assert_ne!(nk.0.to_bytes(), Fp::from(pk).to_bytes());
    assert_eq!(
        Fp::from(sk.derive_proof_private().derive_payment_key()),
        Fp::from(pk)
    );
}

#[test]
fn payment_key_binds_nk() {
    let rng = &mut StdRng::seed_from_u64(0);
    let sk = private::SpendingKey::random(rng);
    let ak = sk.derive_auth_private().derive_auth_public();
    let nk = sk.derive_nullifier_private();
    let other = NullifierKey::random(rng);
    assert_ne!(
        Fp::from(PaymentKey::derive(&ak, &nk)),
        Fp::from(PaymentKey::derive(&ak, &other))
    );
}

#[test]
fn signer_and_prover_derive_one_rk() {
    let rng = &mut StdRng::seed_from_u64(0);
    let sk = private::SpendingKey::random(rng);
    let ask = sk.derive_auth_private();
    let note = Note {
        pk: sk.derive_payment_key(),
        value: value::Positive::try_from(1000u64).unwrap(),
        psi: nullifier::Trapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    };
    let alpha = ActionEntropy::random(rng).randomizer::<effect::Spend>(note.commitment());

    let from_signer: [u8; 32] = ask
        .derive_action_private(&alpha)
        .derive_action_public()
        .0
        .into();
    let from_prover: [u8; 32] = ask
        .derive_auth_public()
        .derive_action_public(&alpha)
        .0
        .into();
    assert_eq!(from_signer, from_prover);
}

#[test]
fn debug_redacts_key_material() {
    let rng = &mut StdRng::seed_from_u64(0);
    assert_eq!(
        alloc::format!("{:?}", private::SpendingKey::random(rng)),
        "SpendingKey(..)"
    );
    assert_eq!(
        alloc::format!("{:?}", NullifierKey::random(rng)),
        "NullifierKey(..)"
    );
}

#[test]
fn window_matches_per_epoch_derivation() {
    let mk = NoteMasterKey::random(&mut StdRng::seed_from_u64(0));
    let epoch_start = EpochIndex::new(96);

    let epochs = (u32::from(epoch_start)..).map(EpochIndex::new);
    for (epoch, nf) in epochs.zip(mk.derive_window(epoch_start)) {
        assert_eq!(nf, mk.derive_nullifier(epoch), "epoch {}", u32::from(epoch));
    }
}

#[test]
#[should_panic(expected = "epoch index above EPOCH_MAX")]
fn window_rejects_a_start_too_close_to_the_final_epoch() {
    let mk = NoteMasterKey::random(&mut StdRng::seed_from_u64(0));
    let window = mk.derive_window(EpochIndex::new(EPOCH_MAX - 3));
    panic!("a window past the final epoch must not derive, got {window:?}");
}

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
    assert_ne!(mk, nk.derive_note_private(other_psi));
    assert_ne!(mk, other_nk.derive_note_private(psi));
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
