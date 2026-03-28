//! Mock PCD proof and proof-carrying data.
//!
//! ## Serialized layout
//!
//! | Offset | Size | Content |
//! |--------|------|---------|
//! | 0..32 | 32 | header hash |
//! | 32..64 | 32 | witness hash |
//! | 64..96 | 32 | binding hash |
//! | 96..128 | 32 | rerandomization tag |
//! | 128..23000 | 22872 | zero padding |

use alloc::boxed::Box;

use crate::header::Header;

/// Compressed proof size in bytes.
pub const PROOF_SIZE_COMPRESSED: usize = 23_000;

/// Mocks `ragu_pcd::Proof`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub(crate) header_hash: [u8; 32],
    pub(crate) witness_hash: [u8; 32],
    pub(crate) binding: [u8; 32],
    pub(crate) rerand_tag: [u8; 32],
}

/// Mocks `ragu_pcd::Pcd`.
#[derive(Clone, Debug)]
pub struct Pcd<'source, H: Header> {
    pub proof: Proof,
    pub data: H::Data<'source>,
}

impl Proof {
    #[must_use]
    pub(crate) fn trivial() -> Self {
        Self::new(&[], &[])
    }

    #[must_use]
    pub(crate) fn new(encoded_header: &[u8], witness_data: &[u8]) -> Self {
        let header_hash = compute_header_hash(encoded_header);
        let witness_hash = compute_witness_hash(witness_data);
        let binding = compute_binding(&header_hash, &witness_hash);
        Self {
            header_hash,
            witness_hash,
            binding,
            rerand_tag: [0u8; 32],
        }
    }

    /// Mirrors `ragu_pcd::Proof::carry`.
    #[must_use]
    pub fn carry<H: Header>(self, data: H::Data<'_>) -> Pcd<'_, H> {
        Pcd { proof: self, data }
    }

    /// Serialize into the full compressed proof buffer.
    #[must_use]
    pub fn serialize(&self) -> Box<[u8; PROOF_SIZE_COMPRESSED]> {
        let mut bytes = [
            self.header_hash,
            self.witness_hash,
            self.binding,
            self.rerand_tag,
        ]
        .concat();
        bytes.resize(PROOF_SIZE_COMPRESSED, 0);
        bytes
            .into_boxed_slice()
            .try_into()
            .expect("resized to PROOF_SIZE_COMPRESSED")
    }

    #[must_use]
    pub(crate) fn rerandomize(&self) -> Self {
        let serialized = self.serialize();
        Self {
            header_hash: self.header_hash,
            witness_hash: self.witness_hash,
            binding: self.binding,
            rerand_tag: compute_rerand_tag(serialized.as_ref()),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Proof {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = Self::serialize(self);
        serializer.serialize_bytes(bytes.as_ref())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Proof {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ProofVisitor;

        impl<'de> serde::de::Visitor<'de> for ProofVisitor {
            type Value = Proof;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{} bytes for a mock ragu proof", PROOF_SIZE_COMPRESSED)
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Proof, E> {
                let arr: &[u8; PROOF_SIZE_COMPRESSED] = v.try_into().map_err(|_| {
                    E::invalid_length(v.len(), &self)
                })?;
                Proof::try_from(arr).map_err(|_| E::custom("invalid proof binding"))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Proof, A::Error> {
                let mut bytes = [0u8; PROOF_SIZE_COMPRESSED];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Proof::try_from(&bytes)
                    .map_err(|_| serde::de::Error::custom("invalid proof binding"))
            }
        }

        deserializer.deserialize_bytes(ProofVisitor)
    }
}

impl From<Proof> for [u8; PROOF_SIZE_COMPRESSED] {
    fn from(proof: Proof) -> [u8; PROOF_SIZE_COMPRESSED] {
        *proof.serialize()
    }
}

impl TryFrom<&[u8; PROOF_SIZE_COMPRESSED]> for Proof {
    type Error = crate::error::Error;

    fn try_from(bytes: &[u8; PROOF_SIZE_COMPRESSED]) -> Result<Self, Self::Error> {
        let mut fields = bytes
            .chunks_exact(32)
            .map(|chunk| chunk.try_into().expect("field is 32 bytes"));

        let header_hash = fields.next().expect("field 0");
        let witness_hash = fields.next().expect("field 1");
        let binding = fields.next().expect("field 2");
        let rerand_tag = fields.next().expect("field 3");

        let expected_binding = compute_binding(&header_hash, &witness_hash);
        if expected_binding != binding {
            return Err(crate::error::Error);
        }

        Ok(Self {
            header_hash,
            witness_hash,
            binding,
            rerand_tag,
        })
    }
}

pub(crate) fn compute_header_hash(encoded: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"MkRagu_HdrHash_\0")
        .hash(encoded);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub(crate) fn compute_witness_hash(witness_bytes: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"MkRagu_Witness_\0")
        .hash(witness_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub(crate) fn compute_binding(header_hash: &[u8; 32], witness_hash: &[u8; 32]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"MkRagu_Binding_\0")
        .to_state()
        .update(header_hash)
        .update(witness_hash)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub(crate) fn compute_rerand_tag(proof_bytes: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"MkRagu_Rerand_\0\0")
        .hash(proof_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}
