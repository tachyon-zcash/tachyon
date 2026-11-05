use rand::{SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;

use crate::{
    constants::EPOCH_MAX,
    keys::{NoteMasterKey, NullifierKey, PaymentKey, SpendValidatingKey, private},
    nullifier,
    pasta::Fp,
    primitives::EpochIndex,
    reddsa,
};

#[test]
fn payment_key_binds_nk() {
    let rng = &mut StdRng::seed_from_u64(0);
    let sk = private::SpendingKey::random(rng);
    let ak = sk.derive_auth_private().derive_auth_public();
    let nk = sk.derive_nullifier_private();
    let pk = PaymentKey::derive(&ak, &nk);

    let nk_other = NullifierKey(nk.0 + Fp::ONE);
    let pk_other = PaymentKey::derive(&ak, &nk_other);
    assert_ne!(Fp::from(pk), Fp::from(pk_other));
}

#[test]
fn window_matches_per_epoch_derivation() {
    let mk = NoteMasterKey::random(&mut StdRng::seed_from_u64(0));
    let epoch_start = EpochIndex::new(96);

    let epochs = (u32::from(epoch_start)..).map(EpochIndex::new);
    for (epoch, nf) in epochs.zip(mk.derive_window(epoch_start)) {
        assert_eq!(nf, mk.derive_nullifier(epoch));
    }
}

#[test]
#[should_panic(expected = "epoch index above EPOCH_MAX")]
fn window_rejects_a_start_too_close_to_the_final_epoch() {
    let mk = NoteMasterKey::random(&mut StdRng::seed_from_u64(0));
    let _window = mk.derive_window(EpochIndex::new(EPOCH_MAX - 3));
}

#[test]
fn debug_spending_key_redacts_bytes() {
    let sk = private::SpendingKey::from([0xAB; 32]);
    let dbg = alloc::format!("{sk:?}");
    assert!(dbg.contains("SpendingKey"));
    assert!(!dbg.contains("AB"));
    assert!(!dbg.contains("171"));
}

#[test]
fn debug_nullifier_key_redacts_value() {
    let nk = NullifierKey(Fp::from(0xDEADu64));
    let dbg = alloc::format!("{nk:?}");
    assert!(dbg.contains("NullifierKey"));
    assert!(!dbg.contains("DEAD"));
    assert!(!dbg.contains("57005"));
}

#[test]
#[should_panic(expected = "identity")]
fn derive_rejects_identity_ak() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ak = SpendValidatingKey(reddsa::VerificationKey::try_from([0u8; 32]).unwrap());
    let nk = NullifierKey::random(rng);

    let _derived = PaymentKey::derive(&ak, &nk);
}

#[test]
fn different_psi_different_mk() {
    let rng = &mut StdRng::seed_from_u64(0);
    let nk = NullifierKey::random(rng);
    let psi1 = nullifier::Trapdoor::random(rng);
    let psi2 = nullifier::Trapdoor::random(rng);
    let mk1 = nk.derive_note_private(psi1);
    let mk2 = nk.derive_note_private(psi2);
    assert_ne!(mk1, mk2);
}

#[test]
fn different_epochs_different_nullifiers() {
    let rng = &mut StdRng::seed_from_u64(0);
    let nk = NullifierKey::random(rng);
    let psi = nullifier::Trapdoor::random(rng);
    let mk = nk.derive_note_private(psi);
    assert_ne!(
        mk.derive_nullifier(EpochIndex::new(0u32)),
        mk.derive_nullifier(EpochIndex::new(1u32)),
    );
}
