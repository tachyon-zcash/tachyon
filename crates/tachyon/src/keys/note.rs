//! Note-related keys: NullifierKey, NoteKey, PaymentKey.

use core::num::NonZeroU8;

use ff::PrimeField as _;
// TODO(#39): replace halo2_poseidon with Ragu Poseidon params
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

use super::ggm::{GGMTreeDepth as _, Master, Prefixed};
use crate::{constants::NOTE_MASTER_DOMAIN, note::NullifierTrapdoor};

/// A GGM tree node parameterized by its depth type.
///
/// - `NoteKey<Master>` is a root node (depth 0, ZST overhead).
/// - `NoteKey<Prefixed>` is a delegate node covering a specific subtree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteKey<D> {
    pub inner: Fp,
    pub prefix: D,
}

#[derive(Debug)]
pub enum NoteKeyError {
    InvalidRepr,
    InvalidPrefix,
}

impl TryFrom<[u8; 32]> for NoteKey<Master> {
    type Error = NoteKeyError;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        let inner = Fp::from_repr(bytes)
            .into_option()
            .ok_or(NoteKeyError::InvalidRepr)?;
        Ok(Self {
            inner,
            prefix: Master,
        })
    }
}

impl From<NoteKey<Master>> for [u8; 32] {
    fn from(key: NoteKey<Master>) -> [u8; 32] {
        key.inner.to_repr()
    }
}

impl TryFrom<[u8; 37]> for NoteKey<Prefixed> {
    type Error = NoteKeyError;

    fn try_from(bytes: [u8; 37]) -> Result<Self, Self::Error> {
        // [repr(32) | depth(1) | index_le(4)]
        let fp_bytes: &[u8; 32] = bytes.first_chunk().ok_or(NoteKeyError::InvalidRepr)?;
        let inner = Fp::from_repr(*fp_bytes)
            .into_option()
            .ok_or(NoteKeyError::InvalidRepr)?;
        let tail: &[u8; 5] = bytes.last_chunk().ok_or(NoteKeyError::InvalidPrefix)?;
        let (&depth_byte, index_slice) = tail.split_first().ok_or(NoteKeyError::InvalidPrefix)?;
        let depth = NonZeroU8::new(depth_byte).ok_or(NoteKeyError::InvalidPrefix)?;
        let index_bytes: &[u8; 4] = index_slice
            .first_chunk()
            .ok_or(NoteKeyError::InvalidPrefix)?;
        #[expect(clippy::little_endian_bytes, reason = "deserialization")]
        let index = u32::from_le_bytes(*index_bytes);
        let prefix =
            Prefixed::new(depth, index).map_err(|_prefix_err| NoteKeyError::InvalidPrefix)?;
        Ok(Self { inner, prefix })
    }
}

impl From<NoteKey<Prefixed>> for [u8; 37] {
    fn from(key: NoteKey<Prefixed>) -> [u8; 37] {
        // [repr(32) | depth(1) | index_le(4)]
        #[expect(clippy::expect_used, reason = "length is statically known")]
        [
            key.inner.to_repr().as_slice(),
            &[key.prefix.depth()],
            #[expect(clippy::little_endian_bytes, reason = "serialization")]
            &key.prefix.index().to_le_bytes(),
        ]
        .concat()
        .try_into()
        .expect("32 + 1 + 4 = 37")
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for NoteKey<Prefixed> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes: [u8; 37] = (*self).into();
        serializer.serialize_bytes(&bytes)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for NoteKey<Prefixed> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt;

        use serde::de;

        struct NoteKeyVisitor;

        impl de::Visitor<'_> for NoteKeyVisitor {
            type Value = NoteKey<Prefixed>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("37 bytes encoding a NoteKey<Prefixed>")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() != 37 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut bytes = [0u8; 37];
                bytes.copy_from_slice(v);
                NoteKey::<Prefixed>::try_from(bytes)
                    .map_err(|_err| de::Error::custom("invalid NoteKey<Prefixed>"))
            }
        }

        deserializer.deserialize_bytes(NoteKeyVisitor)
    }
}

/// A Tachyon nullifier deriving key.
///
/// Tachyon simplifies Orchard's nullifier construction
/// ("Tachyaction at a Distance", Bowe 2025):
///
/// $$\mathsf{nf} = F_{\mathsf{nk}}(\Psi \| \text{flavor})$$
///
/// where $F$ is a keyed PRF (Poseidon), $\Psi$ is the note's nullifier
/// trapdoor, and flavor is the epoch-id. This replaces Orchard's more
/// complex construction that defended against faerie gold attacks — which
/// are moot under out-of-band payments.
///
/// ## Capabilities
///
/// - **Nullifier derivation**: detecting when a note has been spent
/// - **Oblivious sync delegation** (Nullifier Derivation Scheme doc): the
///   master root key $\mathsf{mk} = \text{KDF}(\Psi, \mathsf{nk})$ seeds a GGM
///   tree PRF; prefix keys $\Psi_t$ permit evaluating the PRF only for epochs
///   $e \leq t$, enabling range-restricted delegation without revealing spend
///   capability
///
/// `nk` alone does NOT confer spend authority — combined with `ak` it
/// forms the proof authorizing key `pak`, enabling proof construction
/// and nullifier derivation without signing capability.
#[derive(Clone, Copy, Debug)]
pub struct NullifierKey(pub(super) Fp);

impl NullifierKey {
    /// Derive the per-note master root key: $\mathsf{mk} = \text{KDF}(\psi,
    /// \mathsf{nk})$.
    ///
    /// `mk` is the root of the GGM tree for one note. It is used to:
    /// - Derive nullifiers directly: $\mathsf{nf} =
    ///   F_{\mathsf{mk}}(\text{flavor})$
    /// - Derive epoch-restricted prefix keys $\Psi_t$ for OSS delegation
    #[must_use]
    pub fn derive_note_private(&self, psi: &NullifierTrapdoor) -> NoteMasterKey {
        #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
        let personalization = Fp::from_u128(u128::from_le_bytes(*NOTE_MASTER_DOMAIN));
        NoteKey {
            inner: Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
                personalization,
                psi.0,
                self.0,
            ]),
            prefix: Master,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for NullifierKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use ff::PrimeField as _;

        serializer.serialize_bytes(&self.0.to_repr())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for NullifierKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use crate::serde_helpers::FpVisitor;

        deserializer.deserialize_bytes(FpVisitor).map(Self)
    }
}

/// A Tachyon payment key — static per-spending-key recipient identifier.
///
/// Replaces Orchard's diversified transmission key $\mathsf{pk_d}$ and
/// the entire diversified address system. Tachyon removes the diversifier
/// $d$ because payment addresses are removed from the on-chain protocol
/// ("Tachyaction at a Distance", Bowe 2025):
///
/// > "The transmission key $\mathsf{pk_d}$ is substituted with a payment
/// > key $\mathsf{pk}$."
///
/// ## Derivation
///
/// Deterministic per-`sk`: $\mathsf{pk} =
/// \text{ToBase}(\text{PRF}^{\text{expand}}_{\mathsf{sk}}([0\text{x}0b]))$.
/// Every note from the same spending key shares the same `pk`. There is
/// no per-note diversification — unlinkability is the wallet layer's
/// responsibility, not the core protocol's.
///
/// ## Usage
///
/// The recipient's `pk` appears in the note and is committed to in the
/// note commitment. It is NOT an on-chain address; payment coordination
/// happens out-of-band via higher-level protocols (ZIP 321 payment
/// requests, ZIP 324 URI encapsulated payments).
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct PaymentKey(pub(crate) Fp);

#[cfg(feature = "serde")]
impl serde::Serialize for PaymentKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use ff::PrimeField as _;

        serializer.serialize_bytes(&self.0.to_repr())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PaymentKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use crate::serde_helpers::FpVisitor;

        deserializer.deserialize_bytes(FpVisitor).map(Self)
    }
}

/// Per-note master root key $\mathsf{mk} = \text{KDF}(\psi, \mathsf{nk})$.
///
/// Root of the GGM tree PRF for a single note. Derived by the user device
/// from [`NullifierKey`] and the note's $\psi$ trapdoor.
///
/// ## Delegation chain
///
/// ```text
/// nk + psi → mk (per-note root, user device)
///              ├── nf = F_mk(flavor)     nullifier for a specific epoch
///              └── psi_t = GGM(mk, t)    prefix key for epochs e ≤ t (OSS)
/// ```
///
/// `mk` is not stored or transmitted — the user device derives it
/// ephemerally when needed. The OSS receives only the prefix keys.
pub type NoteMasterKey = NoteKey<Master>;

#[cfg(test)]
mod tests {
    use core::num::NonZeroU8;

    use super::*;
    use crate::{keys::ggm::Prefixed, primitives::Epoch};

    #[test]
    fn derive_note_private_deterministic() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk1 = nk.derive_note_private(&psi);
        let mk2 = nk.derive_note_private(&psi);
        assert_eq!(mk1, mk2);
    }

    #[test]
    fn different_psi_different_mk() {
        let nk = NullifierKey(Fp::from(42u64));
        let mk1 = nk.derive_note_private(&NullifierTrapdoor::from(Fp::from(1u64)));
        let mk2 = nk.derive_note_private(&NullifierTrapdoor::from(Fp::from(2u64)));
        assert_ne!(mk1, mk2);
    }

    #[test]
    fn different_epochs_different_nullifiers() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);
        assert_ne!(
            mk.derive_nullifier(Epoch::from(0u32)),
            mk.derive_nullifier(Epoch::from(1u32)),
        );
    }

    /// Prefix key (index 0) produces same nullifier as master key for
    /// epochs within the authorized range.
    #[test]
    fn prefix_matches_master_at_index_zero() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);

        // depth=26 → window of 64 epochs at index 0 → epochs [0..=63]
        let prefix = Prefixed::new(NonZeroU8::new(26u8).unwrap(), 0).unwrap();
        let dk = &mk.derive_note_delegates([prefix])[0];

        for epoch in 0..64u32 {
            assert_eq!(
                mk.derive_nullifier(Epoch::from(epoch)),
                dk.derive_nullifier(Epoch::from(epoch)).unwrap(),
                "mismatch at epoch {epoch}"
            );
        }
    }

    /// Prefix key at a non-zero index produces same nullifiers as
    /// master key for epochs within its range.
    #[test]
    fn prefix_matches_master_at_nonzero_index() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);

        // depth=26 → window of 64 epochs at index 1 → epochs [64..=127]
        let prefix = Prefixed::new(NonZeroU8::new(26u8).unwrap(), 1).unwrap();
        let dk = &mk.derive_note_delegates([prefix])[0];

        for epoch in 64..128u32 {
            assert_eq!(
                mk.derive_nullifier(Epoch::from(epoch)),
                dk.derive_nullifier(Epoch::from(epoch)).unwrap(),
                "mismatch at epoch {epoch}"
            );
        }
    }

    /// Prefix cover produces same nullifiers as master for all
    /// epochs in the covered range.
    #[test]
    fn cover_matches_master() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);

        let prefixes = Prefixed::tight(0, 100);
        for dk in &mk.derive_note_delegates(prefixes) {
            for epoch in dk.prefix.first()..=dk.prefix.last() {
                assert_eq!(
                    mk.derive_nullifier(Epoch::from(epoch)),
                    dk.derive_nullifier(Epoch::from(epoch)).unwrap(),
                    "mismatch at epoch {epoch} with delegate {dk:?}"
                );
            }
        }
    }

    /// A prefix key returns `None` for epochs outside its authorized range.
    #[test]
    fn prefix_rejects_outside_range() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);

        // depth=26 index=0 → epochs [0..=63]
        let prefix = Prefixed::new(NonZeroU8::new(26u8).unwrap(), 0).unwrap();
        let dk = &mk.derive_note_delegates([prefix])[0];

        // epoch 64 is outside the authorized range
        assert!(dk.derive_nullifier(Epoch::from(64u32)).is_none());
    }
}
