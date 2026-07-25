//! Note-related keys: NullifierKey, PaymentKey.

use derive_more::Debug;
use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;

use super::{ggm::NoteMasterKey, proof::SpendValidatingKey};
use crate::{digest::poseidon, note};

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
pub struct NullifierKey(#[debug(skip)] pub(super) Fp);

impl NullifierKey {
    /// Derive a note's GGM master root from its nullifier trapdoor `psi`.
    #[must_use]
    pub fn derive_note_private(&self, psi: &note::NullifierTrapdoor) -> NoteMasterKey {
        NoteMasterKey(poseidon::nf_master(psi.0, self.0))
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
/// Derived from the proof authorizing key components:
///
/// $$\mathsf{pk} = \text{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x,
/// \mathsf{nk})$$
///
/// where $\mathsf{ak}_x$ is the x-coordinate of the spend validating key.
/// This binds `pk` to both `ak` and `nk`, so the note commitment `cm`
/// (which contains `pk`) transitively pins the full proof authorizing key.
/// Wrong `nk` produces wrong `pk`, wrong `cm`, and accumulator inclusion
/// fails.
///
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
pub struct PaymentKey(#[debug(skip)] pub(crate) Fp);

impl PaymentKey {
    /// Derive the payment key from `ak` and `nk`:
    /// $\mathsf{pk} = \text{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x,
    /// \mathsf{nk})$.
    ///
    /// # Panics
    ///
    /// Panics if `ak` is not sign-normalized or is the identity — either
    /// means it did not come from the crate's key derivation.
    #[must_use]
    pub fn derive(ak: &SpendValidatingKey, nk: &NullifierKey) -> Self {
        Self(poseidon::payment_key(vk_x_coordinate(ak), nk.0))
    }
}

/// Extract the Pallas base-field x-coordinate from a spend validating key.
///
/// A [`SpendValidatingKey`] only comes from
/// [`SpendAuthorizingKey::derive_auth_public`](super::private::SpendAuthorizingKey),
/// whose scalar is sign-normalized by `SpendingKey::derive_auth_private`
/// (§5.4.7.1), so the 32-byte encoding's y-sign bit (byte 31, bit 7) is always
/// clear and the bytes are the canonical x-coordinate, a valid `Fp`.
///
/// # Panics
///
/// Panics if the encoding is not a canonical x-coordinate (y-sign bit set:
/// `x + 2^255 > p` fails [`Fp::from_repr`]) or is the identity (`x = 0`, which
/// no valid point has). Either means `ak` did not come from the crate's
/// derivation — an invariant violation, not an input error — and deriving a
/// payment key from a transformed value would silently produce a different
/// key.
fn vk_x_coordinate(ak: &SpendValidatingKey) -> Fp {
    let bytes: [u8; 32] = ak.0.into();
    #[expect(
        clippy::expect_used,
        reason = "invariant: `ak` comes from the crate's sign-normalizing derivation"
    )]
    Fp::from_repr(bytes)
        .into_option()
        .filter(|x| *x != Fp::ZERO)
        .expect("`ak` must be a sign-normalized, non-identity verification key")
}

#[cfg(test)]
mod tests {
    use pasta_curves::Fq;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{primitives::EpochIndex, reddsa};

    /// A `SpendValidatingKey` whose compressed encoding has the y-sign bit set
    /// (byte 31, bit 7) did not come from the crate's sign-normalizing
    /// derivation — `derive` must panic on the invariant violation rather than
    /// silently deriving a payment key from a transformed value.
    #[test]
    #[should_panic(expected = "sign-normalized, non-identity")]
    fn derive_panics_on_unnormalized_ak() {
        let rng = &mut StdRng::seed_from_u64(7);

        // Find a valid verification key whose encoding sets the y-sign bit.
        let vk_bytes: [u8; 32] = loop {
            let sk =
                reddsa::SigningKey::<reddsa::ActionAuth>::try_from(Fq::random(&mut *rng).to_repr())
                    .expect("nonzero scalar is a valid signing key");
            let bytes: [u8; 32] = reddsa::VerificationKey::from(&sk).into();
            if bytes[31] & 0b1000_0000 != 0 {
                break bytes;
            }
        };

        let ak = SpendValidatingKey(
            reddsa::VerificationKey::try_from(vk_bytes).expect("bytes came from a valid key"),
        );
        let nk = NullifierKey(Fp::random(&mut *rng));

        let _ = PaymentKey::derive(&ak, &nk);
    }

    /// reddsa permits identity verification keys, but the crate's derivation
    /// never produces one and identity `ak` is unsupported — `derive` must
    /// panic rather than map the identity encoding to `Fp::ZERO`.
    #[test]
    #[should_panic(expected = "sign-normalized, non-identity")]
    fn derive_rejects_identity_ak() {
        let rng = &mut StdRng::seed_from_u64(0);
        let ak = SpendValidatingKey(
            reddsa::VerificationKey::try_from([0u8; 32]).expect("identity is a valid key"),
        );
        let nk = NullifierKey(Fp::random(&mut *rng));

        let _ = PaymentKey::derive(&ak, &nk);
    }

    #[test]
    fn derive_note_private_deterministic() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let mk1 = nk.derive_note_private(&psi);
        let mk2 = nk.derive_note_private(&psi);
        assert_eq!(mk1, mk2);
    }

    #[test]
    fn different_psi_different_mk() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi1 = note::NullifierTrapdoor::random(rng);
        let psi2 = note::NullifierTrapdoor::random(rng);
        let mk1 = nk.derive_note_private(&psi1);
        let mk2 = nk.derive_note_private(&psi2);
        assert_ne!(mk1, mk2);
    }

    #[test]
    fn different_epochs_different_nullifiers() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let mk = nk.derive_note_private(&psi);
        assert_ne!(
            mk.derive_nullifier(EpochIndex(0u32)),
            mk.derive_nullifier(EpochIndex(1u32)),
        );
    }

    /// Delegate key produces same nullifiers as master for epochs in range.
    #[test]
    fn delegate_matches_master() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let mk = nk.derive_note_private(&psi);

        for dk in &mk.derive_note_delegates(0..=99) {
            for epoch in dk.range() {
                assert_eq!(
                    mk.derive_nullifier(EpochIndex(epoch)),
                    dk.derive_nullifier(EpochIndex(epoch)),
                    "mismatch at epoch {epoch} with delegate {dk:?}"
                );
            }
        }
    }

    /// A delegate key panics for epochs outside its authorized range.
    #[test]
    #[should_panic(expected = "epoch out of range")]
    fn delegate_rejects_outside_range() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let mk = nk.derive_note_private(&psi);

        // Delegate covering [0..=63]
        let dk = &mk.derive_note_delegates(0..=63)[0];
        // epoch 64 is outside the authorized range
        let _compute = dk.derive_nullifier(EpochIndex(64u32));
    }
}
