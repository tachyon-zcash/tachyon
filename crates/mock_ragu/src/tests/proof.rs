use crate::proof::{PROOF_SIZE_COMPRESSED, Pcd, Proof};

#[test]
fn round_trip() {
    let proof = Proof::new(b"header", b"witness");
    let bytes: [u8; PROOF_SIZE_COMPRESSED] = proof.clone().into();
    let recovered = Proof::try_from(&bytes).expect("round trip should succeed");
    assert_eq!(proof, recovered);
}

#[test]
fn tampered_fails() {
    let proof = Proof::new(b"header", b"witness");
    let mut bytes: [u8; PROOF_SIZE_COMPRESSED] = proof.into();
    bytes[0] ^= 0xFFu8;
    Proof::try_from(&bytes).expect_err("tampered proof should fail");
}

#[test]
fn carry_creates_pcd() {
    let proof = Proof::new(b"header", b"witness");
    let expected = proof.clone();
    let pcd: Pcd<'_, ()> = proof.carry(());
    assert_eq!(pcd.proof, expected);
}

#[test]
fn rerandomize() {
    let proof = Proof::new(b"header", b"witness");
    assert_eq!(proof.rerand_tag, [0u8; 32]);

    let once = proof.rerandomize();

    assert_eq!(proof.header_hash, once.header_hash);
    assert_eq!(proof.witness_hash, once.witness_hash);
    assert_eq!(proof.binding, once.binding);
    assert_ne!(proof, once);

    let twice = once.rerandomize();
    assert_eq!(proof.header_hash, twice.header_hash);
    assert_eq!(proof.witness_hash, twice.witness_hash);
    assert_eq!(proof.binding, twice.binding);
    assert_ne!(once, twice);

    assert_ne!(proof.rerand_tag, once.rerand_tag);
    assert_ne!(proof.rerand_tag, twice.rerand_tag);
    assert_ne!(once.rerand_tag, twice.rerand_tag);
}
