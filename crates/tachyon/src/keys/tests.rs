use rand::{SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;

use crate::{
    constants::EPOCH_MAX,
    entropy::ActionEntropy,
    keys::{NoteMasterKey, NullifierKey, PaymentKey, private},
    note::{self, Note},
    nullifier,
    pasta::Fp,
    primitives::{EpochIndex, effect},
    value,
};

#[test]
fn child_keys_are_independent() {
    let sk = private::SpendingKey::from([0x42u8; 32]);
    let ak = sk.derive_auth_private().derive_auth_public();
    let nk = sk.derive_nullifier_private();
    let pk = sk.derive_payment_key();

    let ak_bytes: [u8; 32] = ak.0.into();
    assert_ne!(ak_bytes, nk.0.to_bytes(), "ak against nk");
    assert_ne!(nk.0.to_bytes(), Fp::from(pk).to_bytes(), "nk against pk");
    assert_eq!(
        Fp::from(sk.derive_proof_private().derive_payment_key()),
        Fp::from(pk),
        "pak derives the spending key's pk"
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
    // Group-aligned when EPOCH_MAX is `2^k - 1`; a window short by three.
    let window = mk.derive_window(EpochIndex::new(EPOCH_MAX - 3));
    panic!("a window past the final epoch must not derive, got {window:?}");
}
