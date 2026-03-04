//! Mock PCD proof (128 bytes) and proof-carrying data.
//!
//! ## Proof layout
//!
//! | Offset | Size | Content |
//! |--------|------|---------|
//! | 0..32 | 32 | header hash |
//! | 32..64 | 32 | witness hash |
//! | 64..96 | 32 | merge tag (zero for leaf) |
//! | 96..128 | 32 | binding hash |
//!
//! The binding hash ties the other components together:
//! `binding = BLAKE2b("MkRagu_Binding_\0", header_hash || witness_hash ||
//! merge_tag)`

use crate::{error::ValidationError, header::Header};

/// Size of the mock proof in bytes.
pub const PROOF_SIZE: usize = 128;

/// A mock PCD proof.
///
/// Mirrors `ragu_pcd::Proof`. Not cryptographically sound — provides
/// deterministic consistency checking for integration testing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Proof {
    bytes: [u8; PROOF_SIZE],
}

/// Proof-carrying data: a proof bundled with its header data.
///
/// Mirrors `ragu_pcd::Pcd`. Created by [`Proof::carry`].
#[derive(Clone, Debug)]
pub struct Pcd<'source, H: Header> {
    /// The proof bytes.
    pub proof: Proof,
    /// The header data carried by this proof.
    pub data: H::Data<'source>,
}

impl Proof {
    /// Attach header data to this proof, creating a [`Pcd`].
    ///
    /// Mirrors `ragu_pcd::Proof::carry`. Does not validate that the
    /// header data matches the proof — that happens in
    /// [`Application::verify`](crate::Application::verify).
    #[must_use]
    pub fn carry<H: Header>(self, data: H::Data<'_>) -> Pcd<'_, H> {
        Pcd { proof: self, data }
    }

    /// Extract the header hash from proof bytes.
    #[must_use]
    pub(crate) fn header_hash(&self) -> [u8; 32] {
        extract_field(&self.bytes, 0)
    }

    /// Extract the witness hash from proof bytes.
    #[must_use]
    pub(crate) fn witness_hash(&self) -> [u8; 32] {
        extract_field(&self.bytes, 32)
    }

    /// Extract the merge tag from proof bytes.
    #[must_use]
    pub(crate) fn merge_tag(&self) -> [u8; 32] {
        extract_field(&self.bytes, 64)
    }

    /// Extract the binding hash from proof bytes.
    #[must_use]
    pub(crate) fn binding(&self) -> [u8; 32] {
        extract_field(&self.bytes, 96)
    }
}

/// Extract a 32-byte field at the given offset.
fn extract_field(bytes: &[u8; PROOF_SIZE], offset: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(slice) = bytes.get(offset..offset + 32) {
        out.copy_from_slice(slice);
    }
    out
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; PROOF_SIZE]> for Proof {
    fn into(self) -> [u8; PROOF_SIZE] {
        self.bytes
    }
}

impl TryFrom<&[u8; PROOF_SIZE]> for Proof {
    type Error = ValidationError;

    fn try_from(bytes: &[u8; PROOF_SIZE]) -> Result<Self, Self::Error> {
        let proof = Self { bytes: *bytes };
        let expected_binding = compute_binding(
            &proof.header_hash(),
            &proof.witness_hash(),
            &proof.merge_tag(),
        );
        if expected_binding != proof.binding() {
            return Err(ValidationError::BindingInvalid);
        }
        Ok(proof)
    }
}

// ---------------------------------------------------------------------------
// Internal construction helpers
// ---------------------------------------------------------------------------

/// Hash encoded header data to produce the header hash.
pub(crate) fn compute_header_hash(encoded: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"MkRagu_HdrHash_\0")
        .hash(encoded);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Hash witness data (encoded header for seed, child proofs for fuse).
pub(crate) fn compute_witness_hash(witness_bytes: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"MkRagu_Witness_\0")
        .hash(witness_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Hash two children's bindings to produce the merge tag.
pub(crate) fn compute_merge_tag(left_binding: &[u8; 32], right_binding: &[u8; 32]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"MkRagu_MergeTag\0")
        .to_state()
        .update(left_binding)
        .update(right_binding)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Compute the binding hash tying header hash, witness hash, and merge tag.
pub(crate) fn compute_binding(
    header_hash: &[u8; 32],
    witness_hash: &[u8; 32],
    merge_tag: &[u8; 32],
) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"MkRagu_Binding_\0")
        .to_state()
        .update(header_hash)
        .update(witness_hash)
        .update(merge_tag)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Assemble a proof from its hash components.
pub(crate) fn assemble(
    header_hash: &[u8; 32],
    witness_hash: &[u8; 32],
    merge_tag: &[u8; 32],
) -> Proof {
    let binding = compute_binding(header_hash, witness_hash, merge_tag);
    let mut bytes = [0u8; PROOF_SIZE];
    if let Some(sl) = bytes.get_mut(..32) {
        sl.copy_from_slice(header_hash);
    }
    if let Some(sl) = bytes.get_mut(32..64) {
        sl.copy_from_slice(witness_hash);
    }
    if let Some(sl) = bytes.get_mut(64..96) {
        sl.copy_from_slice(merge_tag);
    }
    if let Some(sl) = bytes.get_mut(96..128) {
        sl.copy_from_slice(&binding);
    }
    Proof { bytes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_round_trip() {
        let header_hash = [0x01u8; 32];
        let witness_hash = [0x02u8; 32];
        let merge_tag = [0u8; 32];

        let proof = assemble(&header_hash, &witness_hash, &merge_tag);
        let bytes: [u8; PROOF_SIZE] = proof.into();
        let recovered = Proof::try_from(&bytes).expect("round trip should succeed");
        assert_eq!(proof, recovered);
    }

    #[test]
    fn tampered_proof_fails() {
        let proof = assemble(&[0x01u8; 32], &[0x02u8; 32], &[0u8; 32]);
        let mut bytes: [u8; PROOF_SIZE] = proof.into();
        bytes[0] ^= 0xFFu8;
        Proof::try_from(&bytes).expect_err("tampered proof should fail");
    }

    #[test]
    fn carry_creates_pcd() {
        let proof = assemble(&[0x01u8; 32], &[0x02u8; 32], &[0u8; 32]);
        let pcd: Pcd<'_, ()> = proof.carry(());
        assert_eq!(pcd.proof, proof);
    }
}
