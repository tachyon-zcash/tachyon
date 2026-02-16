//! ## Key Hierarchy
//!
//! Tachyon simplifies the key hierarchy compared to Orchard by removing
//! key diversification, viewing keys, and payment addresses from the core
//! protocol. These capabilities are handled by higher-level wallet software
//! through out-of-band payment protocols.
//!
//! ```mermaid
//! flowchart TB
//!     sk[SpendingKey]
//!     ask[SpendAuthorizingKey ask]
//!     ak[SpendValidatingKey ak]
//!     nk[NullifierKey nk]
//!     pk[PaymentKey pk]
//!     alpha[SpendAuthRandomizer alpha]
//!     rsk[RandomizedSigningKey rsk]
//!     rk[RandomizedVerificationKey rk]
//!     pak[ProofAuthorizingKey]
//!     sk --> ask & nk & pk
//!     ask --> ak
//!     ask -- "+alpha" --> rsk
//!     ak -- "+alpha" --> rk
//!     rsk --> rk
//!     ak & nk --> pak
//! ```
//!
//! - `ask`: Authorizes spends (long-lived, cannot sign directly)
//! - `ak`: Public counterpart of `ask` (long-lived, cannot verify action sigs)
//! - `alpha`: Per-action randomizer
//! - `rsk = ask + alpha`: Per-action signing key (can sign)
//! - `rk = ak + [alpha]G`: Per-action verification key (can verify, goes in Action)
//! - `nk`: Observes when funds are spent (nullifier derivation)
//! - `pk`: Used in note construction and out-of-band payment protocols
//! - `pak`: `ak` + `nk` (proof authorizing key): Constructs proofs without
//!   spend authority; might be delegated to a syncing service
//!
//! ## Nullifier Derivation
//!
//! Nullifiers are derived via a GGM tree PRF instantiated from Poseidon:
//!
//! $$\mathsf{mk} = \text{KDF}(\psi, \mathsf{nk})$$
//! $$\mathsf{nf} = F_{\mathsf{mk}}(\text{flavor})$$
//!
//! where $\psi$ is the note's nullifier trapdoor, $\mathsf{nk}$ is the
//! nullifier key, and flavor is the epoch-id.
//!
//! The master root key $\mathsf{mk}$ supports oblivious sync delegation:
//! prefix keys $\Psi_t$ permit evaluating the PRF only for epochs
//! $e \leq t$, enabling range-restricted delegation without revealing
//! spend capability.

#![allow(clippy::from_over_into)]

use crate::constants::PRF_EXPAND_PERSONALIZATION;
use crate::primitives::{Field, Fp, Fq, FromUniformBytes, PrimeField};
use rand::{CryptoRng, RngCore};

// Private type aliases — reddsa internals, not part of the public API.
use reddsa::orchard::Binding;
use reddsa::orchard::SpendAuth;

/// PRF^expand: domain-separated key expansion from a spending key.
///
/// `PRF^expand_sk(t) = BLAKE2b-512("Zcash_ExpandSeed", LEBS2OSP_256(sk) || t)`
///
/// Returns 64 bytes suitable for unbiased reduction into either field
/// via [`FromUniformBytes`].
///
/// Each child key uses a distinct single-byte domain separator `t`:
/// - `[0]` → `ask` (spend authorizing key, scalar field)
/// - `[1]` → `nk` (nullifier key, base field)
/// - `[2]` → `pk` (payment key, base field)
fn prf_expand(sk: &[u8; 32], t: &[u8]) -> [u8; 64] {
    *blake2b_simd::Params::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state()
        .update(sk)
        .update(t)
        .finalize()
        .as_array()
}

// =============================================================================
// Spend authorization signature
// =============================================================================

/// A spend authorization signature (RedPallas over SpendAuth).
#[derive(Debug, Clone, Copy)]
pub struct SpendAuthSignature(reddsa::Signature<SpendAuth>);

impl From<[u8; 64]> for SpendAuthSignature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(reddsa::Signature::<SpendAuth>::from(bytes))
    }
}

impl From<&SpendAuthSignature> for [u8; 64] {
    fn from(sig: &SpendAuthSignature) -> [u8; 64] {
        <[u8; 64]>::from(sig.0)
    }
}

// =============================================================================
// Spending key and child key derivation
// =============================================================================

/// A Tachyon spending key.
///
/// The root key from which all other keys are derived. This key must
/// be kept secret as it provides full spending authority.
///
/// Derives child keys via [`Into`]:
/// - [`SpendAuthorizingKey`] (`ask`)
/// - [`NullifierKey`] (`nk`)
/// - [`PaymentKey`] (`pk`)
#[derive(Clone, Debug)]
pub struct SpendingKey(Fp);

impl From<Fp> for SpendingKey {
    fn from(f: Fp) -> Self {
        Self(f)
    }
}

impl Into<SpendAuthorizingKey> for SpendingKey {
    fn into(self) -> SpendAuthorizingKey {
        // ask = ToScalar(PRF^expand_sk([0]))
        // BLAKE2b-512 output reduced to Fq (Pallas scalar field) via FromUniformBytes,
        // then serialized to 32 bytes for SigningKey construction.
        let expanded = prf_expand(&self.0.to_repr(), &[0]);
        let ask_scalar = Fq::from_uniform_bytes(&expanded);
        #[allow(clippy::expect_used)]
        SpendAuthorizingKey(
            reddsa::SigningKey::<SpendAuth>::try_from(ask_scalar.to_repr())
                .expect("PRF output yields valid signing key"),
        )
    }
}

impl Into<NullifierKey> for SpendingKey {
    fn into(self) -> NullifierKey {
        // nk = ToBase(PRF^expand_sk([1]))
        // BLAKE2b-512 output reduced to Fp (Pallas base field).
        let expanded = prf_expand(&self.0.to_repr(), &[1]);
        NullifierKey(Fp::from_uniform_bytes(&expanded))
    }
}

impl Into<PaymentKey> for SpendingKey {
    fn into(self) -> PaymentKey {
        // pk = ToBase(PRF^expand_sk([2]))
        // BLAKE2b-512 output reduced to Fp (Pallas base field).
        let expanded = prf_expand(&self.0.to_repr(), &[2]);
        PaymentKey(Fp::from_uniform_bytes(&expanded))
    }
}

// =============================================================================
// Spend authorization key (ask)
// =============================================================================

/// The spend authorizing key `ask` — a long-lived signing key derived
/// from [`SpendingKey`].
///
/// `ask` **cannot sign directly**. It must be randomized with a
/// [`SpendAuthRandomizer`] to produce a per-action
/// [`RandomizedSigningKey`] (`rsk`), which can then sign.
///
/// This prevents accidentally using the long-lived key for signing.
#[derive(Clone, Debug, Copy)]
pub struct SpendAuthorizingKey(reddsa::SigningKey<SpendAuth>);

impl SpendAuthorizingKey {
    /// Derive the spend validating key: `ak = [ask]G`.
    #[must_use]
    pub fn validating_key(&self) -> SpendValidatingKey {
        // reddsa::VerificationKey::from(&signing_key) performs [sk]G
        // (scalar-times-basepoint), not a trivial type conversion.
        SpendValidatingKey(reddsa::VerificationKey::from(&self.0))
    }

    /// Randomize this key: `rsk = ask + alpha`.
    #[must_use]
    pub fn randomize(&self, alpha: &SpendAuthRandomizer) -> RandomizedSigningKey {
        RandomizedSigningKey(self.0.randomize(&alpha.0))
    }
}

// =============================================================================
// Spend validating key (ak)
// =============================================================================

/// The spend validating key `ak = [ask]G` — the public counterpart of
/// [`SpendAuthorizingKey`].
///
/// `ak` **cannot verify action signatures directly**. It must be
/// randomized with a [`SpendAuthRandomizer`] to produce a per-action
/// [`RandomizedVerificationKey`] (`rk`), which can then verify.
///
/// `ak` goes into [`ProofAuthorizingKey`] for proof delegation.
#[derive(Clone, Debug, Copy)]
pub struct SpendValidatingKey(reddsa::VerificationKey<SpendAuth>);

impl SpendValidatingKey {
    /// Randomize this key: `rk = ak + [alpha]G`.
    #[must_use]
    pub fn randomize(&self, alpha: &SpendAuthRandomizer) -> RandomizedVerificationKey {
        RandomizedVerificationKey(self.0.randomize(&alpha.0))
    }
}

// =============================================================================
// Spend auth randomizer (alpha)
// =============================================================================

/// Per-action spend authorization randomizer `alpha`.
///
/// Used to derive:
/// - `rsk = ask + alpha` via [`SpendAuthorizingKey::randomize`]
/// - `rk = ak + [alpha]G` via [`SpendValidatingKey::randomize`]
///
/// Each action gets a fresh `alpha`, ensuring `rk` is unlinkable to `ak`.
#[derive(Clone, Debug)]
pub struct SpendAuthRandomizer(Fq);

impl SpendAuthRandomizer {
    /// Generate a fresh random spend auth randomizer.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(Fq::random(rng))
    }
}

impl Into<Fq> for SpendAuthRandomizer {
    /// Extract the raw scalar for circuit witness extraction.
    fn into(self) -> Fq {
        self.0
    }
}

// =============================================================================
// Randomized signing key (rsk)
// =============================================================================

/// Randomized signing key `rsk = ask + alpha` — per-action, ephemeral.
///
/// This is the only key type that **can sign**. Produced by
/// [`SpendAuthorizingKey::randomize`] (spends) or
/// [`for_output`](Self::for_output) (outputs).
#[derive(Debug)]
pub struct RandomizedSigningKey(reddsa::SigningKey<SpendAuth>);

impl RandomizedSigningKey {
    /// Sign `msg` with this randomized key.
    pub fn sign(&self, rng: &mut (impl RngCore + CryptoRng), msg: &[u8]) -> SpendAuthSignature {
        SpendAuthSignature(self.0.sign(rng, msg))
    }

    /// Construct `rsk` for an output action (identity `ask`).
    ///
    /// For outputs there is no real `ask`; `rsk = alpha` directly,
    /// giving `rk = [alpha]G`.
    #[must_use]
    pub fn for_output(alpha: &SpendAuthRandomizer) -> Self {
        Self(
            reddsa::SigningKey::<SpendAuth>::try_from(alpha.0.to_repr())
                .expect("random scalar yields valid signing key"),
        )
    }

    /// Derive the verification key: `rk = [rsk]G`.
    #[must_use]
    pub fn verification_key(&self) -> RandomizedVerificationKey {
        // reddsa::VerificationKey::from(&signing_key) performs [sk]G
        // (scalar-times-basepoint), not a trivial type conversion.
        RandomizedVerificationKey(reddsa::VerificationKey::from(&self.0))
    }
}

// =============================================================================
// Randomized verification key (rk)
// =============================================================================

/// Randomized verification key `rk = ak + [alpha]G` — per-action, public.
///
/// This is the only key type that **can verify** action signatures.
/// Goes into [`Action`](crate::Action). Terminal type — no further
/// derivation.
#[derive(Clone, Debug)]
pub struct RandomizedVerificationKey(reddsa::VerificationKey<SpendAuth>);

impl RandomizedVerificationKey {
    /// Verify a spend authorization signature.
    pub fn verify(&self, msg: &[u8], sig: &SpendAuthSignature) -> Result<(), reddsa::Error> {
        self.0.verify(msg, &sig.0)
    }
}

impl From<&RandomizedVerificationKey> for [u8; 32] {
    fn from(rk: &RandomizedVerificationKey) -> [u8; 32] {
        rk.0.into()
    }
}

impl TryFrom<[u8; 32]> for RandomizedVerificationKey {
    type Error = reddsa::Error;
    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        reddsa::VerificationKey::<SpendAuth>::try_from(bytes).map(Self)
    }
}

// =============================================================================
// Nullifier key
// =============================================================================

/// A Tachyon nullifier deriving key.
///
/// Used in the GGM tree PRF: $mk = \text{KDF}(\psi, nk)$, then
/// $nf = F_{mk}(\text{flavor})$. This key enables:
///
/// - **Nullifier derivation**: detecting when a note has been spent
/// - **Oblivious sync delegation**: prefix keys $\Psi_t$ derived from
///   $mk$ permit evaluating the PRF only for epochs $e \leq t$
///
/// `nk` alone does NOT confer spend authority — it only allows observing
/// spend status and constructing proofs (when combined with `ak`).
#[derive(Clone, Debug, Copy)]
pub struct NullifierKey(Fp);

impl Into<Fp> for NullifierKey {
    fn into(self) -> Fp {
        self.0
    }
}

// =============================================================================
// Payment key
// =============================================================================

/// A Tachyon payment key.
///
/// Used in note construction and out-of-band payment protocols. Replaces
/// Orchard's diversified transmission key (`pk_d`) — Tachyon removes key
/// diversification from the core protocol.
///
/// The recipient's `pk` appears in the note and is committed to in the
/// note commitment. It is NOT an on-chain address; payment coordination
/// happens out-of-band (e.g. URI encapsulated payments, payment requests).
#[derive(Clone, Debug, Copy)]
pub struct PaymentKey(Fp);

impl Into<Fp> for PaymentKey {
    fn into(self) -> Fp {
        self.0
    }
}

// =============================================================================
// Proof authorizing key
// =============================================================================

/// The proof authorizing key (`ak` + `nk`).
///
/// Allows constructing proofs without spend authority. This might be delegated
/// to a service that constructs non-membership proofs for nullifiers without
/// learning the wallet's spending key.
///
/// Derived from [`SpendAuthorizingKey`] $\to$ [`SpendValidatingKey`] and
/// [`NullifierKey`].
#[derive(Clone, Debug, Copy)]
pub struct ProofAuthorizingKey {
    /// The spend validating key `ak = [ask] G`.
    ak: SpendValidatingKey,
    /// The nullifier deriving key.
    nk: NullifierKey,
}

impl From<(SpendValidatingKey, NullifierKey)> for ProofAuthorizingKey {
    fn from((ak, nk): (SpendValidatingKey, NullifierKey)) -> Self {
        Self { ak, nk }
    }
}

impl Into<[u8; 64]> for ProofAuthorizingKey {
    fn into(self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&<[u8; 32]>::from(self.ak.0));
        bytes[32..].copy_from_slice(&<[u8; 32]>::from(self.nk.0));
        bytes
    }
}

// =============================================================================
// Binding signing key
// =============================================================================

/// Binding signing key — derived from the sum of value commitment trapdoors.
///
/// Only used internally to sign the binding sighash during bundle construction.
#[derive(Debug, Copy, Clone)]
pub(crate) struct BindingSigningKey(reddsa::SigningKey<Binding>);

impl BindingSigningKey {
    /// Sign the binding sighash.
    pub(crate) fn sign(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        msg: &[u8],
    ) -> BindingSignature {
        BindingSignature(self.0.sign(rng, msg))
    }
}

impl From<Fq> for BindingSigningKey {
    fn from(f: Fq) -> Self {
        Self(
            reddsa::SigningKey::<Binding>::try_from(f.to_repr())
                .expect("valid scalar yields valid signing key"),
        )
    }
}

// =============================================================================
// Binding verification key
// =============================================================================

/// Binding verification key — derived from value commitments.
///
/// Used by validators: `bvk = sum(cv_i) - ValueCommitment::balance(value_balance)`
#[derive(Clone, Debug, Copy)]
pub struct BindingVerificationKey(reddsa::VerificationKey<Binding>);

impl BindingVerificationKey {
    /// Verify a binding signature.
    pub fn verify(&self, msg: &[u8], sig: &BindingSignature) -> Result<(), reddsa::Error> {
        self.0.verify(msg, &sig.0)
    }
}

impl TryFrom<[u8; 32]> for BindingVerificationKey {
    type Error = reddsa::Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        reddsa::VerificationKey::<Binding>::try_from(bytes).map(Self)
    }
}

// =============================================================================
// Binding signature
// =============================================================================

/// A binding signature for value balance verification (RedPallas over Binding).
#[derive(Debug, Clone, Copy)]
pub struct BindingSignature(reddsa::Signature<Binding>);

impl From<[u8; 64]> for BindingSignature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes.into())
    }
}

impl From<BindingSignature> for [u8; 64] {
    fn from(sig: BindingSignature) -> Self {
        sig.0.into()
    }
}
