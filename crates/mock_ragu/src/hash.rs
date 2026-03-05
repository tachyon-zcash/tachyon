//! BLAKE2b-based mock Poseidon for note commitment and nullifier derivation.
//!
//! All functions return `[u8; 64]` so callers can use `Fp::from_uniform_bytes`
//! (which always succeeds, avoiding `unwrap`/`expect` in non-test code).

// All BLAKE2b personalization strings are exactly 16 bytes.

/// Mock note commitment.
///
/// `cm = BLAKE2b-512("Tachyon_NoteComm", rcm || value || pk || psi)`
#[must_use]
pub fn note_commit(rcm: [u8; 32], value: u64, pk: [u8; 32], psi: [u8; 32]) -> [u8; 64] {
    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    let value_bytes = value.to_le_bytes();
    let hash = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Tachyon_NoteComm")
        .to_state()
        .update(&rcm)
        .update(&value_bytes)
        .update(&pk)
        .update(&psi)
        .finalize();
    *hash.as_array()
}

/// Derive the per-note master root key.
///
/// `mk = BLAKE2b-512("Tachyon_MasterKy", psi || nk)`
#[must_use]
pub fn master_key_derive(psi: [u8; 32], nk: [u8; 32]) -> [u8; 64] {
    let hash = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Tachyon_MasterKy")
        .to_state()
        .update(&psi)
        .update(&nk)
        .finalize();
    *hash.as_array()
}

/// Derive nullifier from master key and flavor.
///
/// `nf = BLAKE2b-512("Tachyon_NfMaster", mk || flavor)`
#[must_use]
pub fn nullifier_from_master(mk: [u8; 32], flavor: [u8; 32]) -> [u8; 64] {
    let hash = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Tachyon_NfMaster")
        .to_state()
        .update(&mk)
        .update(&flavor)
        .finalize();
    *hash.as_array()
}

/// Derive epoch-restricted prefix key.
///
/// `psi_t = BLAKE2b-512("Tachyon_NfPrefix", mk || epoch)`
#[must_use]
pub fn prefix_key_derive(mk: [u8; 32], epoch: [u8; 32]) -> [u8; 64] {
    let hash = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Tachyon_NfPrefix")
        .to_state()
        .update(&mk)
        .update(&epoch)
        .finalize();
    *hash.as_array()
}

/// Derive nullifier from delegate (prefix) key and flavor.
///
/// `nf = BLAKE2b-512("Tachyon_NfDelegt", prefix_key || flavor)`
///
/// NOTE: the mock does NOT enforce GGM epoch restriction. The real
/// implementation limits evaluation to epochs within the authorized range.
#[must_use]
pub fn nullifier_from_delegate(prefix_key: [u8; 32], flavor: [u8; 32]) -> [u8; 64] {
    let hash = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Tachyon_NfDelegt")
        .to_state()
        .update(&prefix_key)
        .update(&flavor)
        .finalize();
    *hash.as_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_commit_deterministic() {
        let rcm = [0x01u8; 32];
        let pk = [0x02u8; 32];
        let psi = [0x03u8; 32];
        let val = 1000u64;

        let cm_a = note_commit(rcm, val, pk, psi);
        let cm_b = note_commit(rcm, val, pk, psi);
        assert_eq!(cm_a, cm_b);
    }

    #[test]
    fn note_commit_sensitive_to_value() {
        let rcm = [0x01u8; 32];
        let pk = [0x02u8; 32];
        let psi = [0x03u8; 32];

        let cm_a = note_commit(rcm, 1000u64, pk, psi);
        let cm_b = note_commit(rcm, 2000u64, pk, psi);
        assert_ne!(cm_a, cm_b);
    }

    #[test]
    fn nullifier_sensitive_to_flavor() {
        let mk = [0x01u8; 32];
        let flavor_a = [0x00u8; 32];
        let flavor_b = [0x01u8; 32];

        let nf_a = nullifier_from_master(mk, flavor_a);
        let nf_b = nullifier_from_master(mk, flavor_b);
        assert_ne!(nf_a, nf_b);
    }

    #[test]
    fn master_key_sensitive_to_nk() {
        let psi = [0x01u8; 32];
        let nk_a = [0x02u8; 32];
        let nk_b = [0x03u8; 32];

        let mk_a = master_key_derive(psi, nk_a);
        let mk_b = master_key_derive(psi, nk_b);
        assert_ne!(mk_a, mk_b);
    }
}
