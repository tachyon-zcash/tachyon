use rand::{SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;

use crate::{
    keys::{NullifierKey, PaymentKey, SpendValidatingKey, private},
    pasta::Fp,
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
