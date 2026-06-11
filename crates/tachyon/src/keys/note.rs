//! Note-related keys: NullifierKey, NoteMasterKey, PaymentKey.

#![allow(missing_docs, reason = "todo")]

extern crate alloc;

use alloc::vec::Vec;
use core::{array, fmt};

use derive_more::Debug;
use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use ragu::{Domain, Polynomial};
use zcash_mimc::spec::tachyon::{TachyonP5R64, TachyonP5R8192};

use super::proof::SpendValidatingKey;
use crate::{
    constants::{NF_EMITTERS, POLY_LEN_MAX},
    digest::{mimc, poseidon},
    note,
    primitives::{ExpKeySpectrumPoly, ExpandedKeyPoly, NfEmitterPoly},
};

/// A Tachyon nullifier deriving key.
///
/// Tachyon simplifies Orchard's nullifier construction
/// ("Tachyaction at a Distance", Bowe 2025): a per-note keyset
/// $[\mathsf{mk}_0, \ldots, \mathsf{mk}_{n-1}]$, each $\mathsf{mk}_i =
/// \text{Poseidon}(\Psi, \mathsf{nk}, i)$; the leading keys key the
/// multi-key MiMC cipher and the last key is the input salt $\mathsf{mk}_s$,
/// so the nullifier for an epoch is
///
/// $$\mathsf{nf}_e = E_{\mathsf{mk}}(\mathsf{mk}_s + e)$$
///
/// where $\Psi$ is the note's nullifier trapdoor and $e$ the epoch-id.
///
/// `nk` alone does NOT confer spend authority; combined with `ak` it
/// forms the proof authorizing key `pak`, enabling proof construction
/// and nullifier derivation without signing capability.
#[derive(Clone, Copy, Debug)]
pub struct NullifierKey(#[debug(skip)] pub(super) Fp);

impl NullifierKey {
    /// Derive a note's master-key seed from its nullifier trapdoor `psi`.
    #[must_use]
    pub fn derive_note_private(&self, psi: &note::NullifierTrapdoor, index: u64) -> Fp {
        poseidon::nf_master(psi.0, self.0, Fp::from(index))
    }
}

/// Per-note master secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NoteMasterKey(pub [Fp; Self::MK_LENGTH]);

impl NoteMasterKey {
    pub const MK_LENGTH: usize = 6;

    /// Get the round key at the given index.
    #[must_use]
    pub const fn round_key(&self, index: usize) -> Fp {
        #[expect(clippy::integer_division_remainder_used, reason = "constant size")]
        self.0[index % self.0.len()]
    }

    #[must_use]
    pub fn derive_expanded(&self) -> ExpandedKey {
        ExpandedKey(array::from_fn(|index| {
            #[expect(clippy::as_conversions, reason = "constant expansion size")]
            mimc::mk_dk_expand(Fp::ZERO, self.0, Fp::from(index as u64))
        }))
    }

    /// The note's expansion trace polynomial and keyset. Runs the
    /// `ExpandedKey::EK_LENGTH` keyed-cipher expansions and interpolates their
    /// row-major `EK_LENGTH × ROUNDS` cells over `⟨ω⟩` into the trace
    /// polynomial `T` (so `T(ω^{ROUNDS·r + c})` is row `r`'s `c`-th cipher
    /// state); the per-row whitened outputs are the keyset. `T` is only
    /// ever the interpolant (the quotient builders and the in-circuit
    /// relations both treat it that way), so the inverse FFT lives here,
    /// with its producer.
    #[must_use]
    pub fn derive_expanded_trace(&self) -> (ExpKeySpectrumPoly, ExpandedKey) {
        let mut cells: Vec<Fp> = Vec::with_capacity(ExpandedKey::EK_LENGTH * TachyonP5R64::ROUNDS);
        let mut keys: Vec<Fp> = Vec::with_capacity(ExpandedKey::EK_LENGTH);

        #[expect(clippy::as_conversions, reason = "constant size")]
        for (row, key) in (0..(ExpandedKey::EK_LENGTH as u64))
            .map(|index| mimc::mk_dk_expand_sequence(Fp::ZERO, self.0, Fp::from(index)))
        {
            cells.extend_from_slice(&row);
            keys.push(key);
        }

        Domain::new(cells.len().ilog2()).ifft(&mut cells);
        #[expect(clippy::expect_used, reason = "constant size")]
        (
            ExpKeySpectrumPoly(Polynomial::from_coeffs(&cells)),
            ExpandedKey(keys.try_into().expect("constant size")),
        )
    }
}

/// Per-note nullifier derivation material.
///
/// The `ExpandedKey::EK_LENGTH` keyed-cipher expansion outputs `E_mk(mk_s +
/// i)`, used as the full `κ = ExpandedKey::EK_LENGTH` cyclic round-key schedule
/// of the note's derivation polynomials.
///
/// A flat `[Fp; ExpandedKey::EK_LENGTH]` newtype handled only as a polynomial
/// downstream: [`key_poly`](Self::key_poly) is the eval-form interpolant over
/// the order-`ExpandedKey::EK_LENGTH` subgroup `⟨ζ⟩` (`K(ζ^r) = k_r`), and
/// [`commit`](Self::commit) is the commitment the key-expansion step emits. The
/// per-poly salts, the weight bases `ρ_j`, and the shift `c` come from `mk`
/// (via the nullifier-query sponge, [`poseidon::nf_query_params`]), not from
/// these outputs.
///
/// Wallet-only secret material: the wallet is the sole prover of derivation,
/// and delegation operates on value windows only (no key-material delegation
/// API).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExpandedKey(pub [Fp; Self::EK_LENGTH]);

impl ExpandedKey {
    /// The expansion trace is `TachyonP5R64::ROUNDS` rows of `EK_LENGTH` cells
    /// (`ROUNDS x EK_LENGTH = POLY_LEN_MAX`), so the key length is derived.
    #[expect(
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "constant size"
    )]
    pub const EK_LENGTH: usize = POLY_LEN_MAX / TachyonP5R64::ROUNDS;

    /// Get the round key at the given index.
    #[must_use]
    pub const fn round_key(&self, index: usize) -> Fp {
        #[expect(clippy::integer_division_remainder_used, reason = "constant size")]
        self.0[index % self.0.len()]
    }

    /// The eval-form key polynomial `K` over the order-`EK_LENGTH` subgroup
    /// `⟨ζ⟩` (`K(ζ^r) = self.0[r]`). The strided-column and committed-offset
    /// relations open `K` by evaluation, so it is always the interpolant; the
    /// inverse FFT into coefficient form lives here.
    #[must_use]
    pub fn key_poly(&self) -> ExpandedKeyPoly {
        let mut coeffs = self.0.to_vec();
        Domain::new(Self::EK_LENGTH.ilog2()).ifft(&mut coeffs);
        ExpandedKeyPoly(Polynomial::from_coeffs(&coeffs))
    }

    /// One derivation polynomial: the 8192-round keyed cipher on input `salt`
    /// under this full 128-key schedule, interpolated over `⟨ω⟩` (so `T(ω^i)`
    /// is the `i`-th cipher state). The query reads it by evaluation, so it
    /// is always the interpolant, never raw cipher states as coefficients.
    #[must_use]
    pub fn derivation_poly(&self, salt: Fp) -> NfEmitterPoly {
        let mut coeffs = zcash_mimc::state_sequence::<
            TachyonP5R8192,
            Fp,
            { TachyonP5R8192::POW },
            { TachyonP5R8192::ROUNDS },
        >(&self.0, salt)
        .to_vec();
        Domain::new(TachyonP5R8192::ROUNDS.ilog2()).ifft(&mut coeffs);
        NfEmitterPoly(Polynomial::from_coeffs(&coeffs))
    }

    /// The note's `N` derivation polynomials, one per per-poly `salt`.
    #[must_use]
    pub fn derivation_polys(&self, salts: &[Fp; NF_EMITTERS]) -> [NfEmitterPoly; NF_EMITTERS] {
        salts.map(|salt| self.derivation_poly(salt))
    }
}

impl From<[Fp; Self::EK_LENGTH]> for ExpandedKey {
    fn from(keys: [Fp; Self::EK_LENGTH]) -> Self {
        Self(keys)
    }
}

impl From<ExpandedKey> for [Fp; ExpandedKey::EK_LENGTH] {
    fn from(keyset: ExpandedKey) -> Self {
        keyset.0
    }
}

impl fmt::Debug for ExpandedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivationKeyset").finish_non_exhaustive()
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
    #[must_use]
    pub fn derive(ak: &SpendValidatingKey, nk: &NullifierKey) -> Self {
        let ak_bytes: [u8; 32] = ak.0.into();
        let ak_fp = Fp::from_repr(ak_bytes).expect("ak bytes should be a valid Fp");
        Self(poseidon::payment_key(ak_fp, nk.0))
    }
}


impl fmt::Debug for NoteMasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoteMasterKey").finish_non_exhaustive()
    }
}


#[cfg(test)]
mod tests {
    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    /// The note's `MK_LENGTH`-part master key, one part per index.
    fn master_key(nk: &NullifierKey, psi: &note::NullifierTrapdoor) -> NoteMasterKey {
        NoteMasterKey(array::from_fn(|index| {
            nk.derive_note_private(psi, u64::try_from(index).expect("index fits u64"))
        }))
    }

    #[test]
    fn derive_note_private_deterministic() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        assert_eq!(
            nk.derive_note_private(&psi, 0),
            nk.derive_note_private(&psi, 0),
        );
    }

    #[test]
    fn different_psi_different_mk() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi1 = note::NullifierTrapdoor::random(rng);
        let psi2 = note::NullifierTrapdoor::random(rng);
        assert_ne!(
            nk.derive_note_private(&psi1, 0),
            nk.derive_note_private(&psi2, 0),
        );
    }

    #[test]
    fn derivation_keyset_deterministic() {
        let rng = &mut StdRng::seed_from_u64(1);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        assert_eq!(
            master_key(&nk, &psi).derive_expanded(),
            master_key(&nk, &psi).derive_expanded(),
        );
    }

    #[test]
    fn different_psi_different_keyset() {
        let rng = &mut StdRng::seed_from_u64(1);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi1 = note::NullifierTrapdoor::random(rng);
        let psi2 = note::NullifierTrapdoor::random(rng);
        assert_ne!(
            master_key(&nk, &psi1).derive_expanded(),
            master_key(&nk, &psi2).derive_expanded(),
        );
    }

    #[test]
    fn derivation_keyset_elements_are_distinct() {
        // The expansion's per-index domain separation gives distinct key
        // outputs across the schedule.
        let rng = &mut StdRng::seed_from_u64(3);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let keys = master_key(&nk, &psi).derive_expanded().0;

        assert_ne!(keys[0], keys[1], "distinct successive keys");
        assert_ne!(
            keys[0],
            keys[ExpandedKey::EK_LENGTH - 1],
            "distinct first and last keys"
        );
    }
}
