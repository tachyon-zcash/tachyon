use core::array;

use ragu_core::{PoseidonPermutation as _, pasta::PoseidonFp};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;

use crate::{
    constants::EPOCH_MAX,
    keys::{NoteMasterKey, NullifierKey, PaymentKey, SpendValidatingKey, private},
    nullifier::NF_DERIVATION_WIDTH,
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
fn debug_spending_key_redacts_bytes() {
    let sk = private::SpendingKey::from([0xAB; 32]);
    assert_eq!(alloc::format!("{sk:?}"), "SpendingKey(..)");
}

#[test]
fn debug_nullifier_key_redacts_value() {
    let nk = NullifierKey(Fp::from(0xDEADu64));
    assert_eq!(alloc::format!("{nk:?}"), "NullifierKey(..)");
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
fn derive_window_reaches_the_final_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mk = NoteMasterKey(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let epoch_start = EPOCH_MAX + 1 - u32::try_from(NF_DERIVATION_WIDTH).unwrap();

    let window = mk.derive_window(EpochIndex::new(epoch_start));

    let expected: [_; NF_DERIVATION_WIDTH] = array::from_fn(|slot| {
        mk.derive_nullifier(EpochIndex::new(epoch_start + u32::try_from(slot).unwrap()))
    });
    assert_eq!(window, expected);
}

#[test]
#[should_panic(expected = "epoch index above EPOCH_MAX")]
fn derive_window_rejects_a_window_past_the_final_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mk = NoteMasterKey(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let epoch_start = EPOCH_MAX + 1 - u32::try_from(NF_DERIVATION_WIDTH).unwrap()
        + u32::try_from(PoseidonFp::RATE).unwrap();

    let _window = mk.derive_window(EpochIndex::new(epoch_start));
}

#[test]
#[should_panic(expected = "epoch_start must be group-aligned")]
fn derive_window_rejects_an_unaligned_start() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mk = NoteMasterKey(Fp::random(|bytes| rng.fill_bytes(bytes)));

    let _window = mk.derive_window(EpochIndex::new(1));
}
