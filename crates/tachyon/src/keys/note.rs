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
    constants::{NF_DOMAIN, NF_EMITTERS, POLY_LEN_MAX},
    digest::{mimc, poseidon},
    note::{self, Nullifier},
    primitives::{EpochOffset, ExpKeySpectrumPoly, HalfKeyPoly, NfEmitterPoly},
    relations::{
        quotient::{QuerySalts, QueryShift, WeightRatios, nullifier_query},
        subgroup_generator,
    },
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

    /// The per-emitter nullifier-query salts `mk_s^{(j)}`, each seeding one
    /// derivation poly's 8192-round cipher. Domain-separated from
    /// [`query_weights`](Self::query_weights) so the two cannot collide.
    #[must_use]
    pub fn query_salts(&self) -> QuerySalts {
        QuerySalts(poseidon::nf_query_salts(self.0))
    }

    /// The nullifier-query weight parameters `(ρ_j, c)`: the per-poly
    /// geometric weight bases `ρ_j` and the secret query-coset origin `c`
    /// (the `shift`). Domain-separated from
    /// [`query_salts`](Self::query_salts).
    #[must_use]
    pub fn query_weights(&self) -> (WeightRatios, QueryShift) {
        let (rt, sh) = poseidon::nf_query_weights(self.0);
        (WeightRatios(rt), QueryShift(sh))
    }

    /// The note's full interleaved 256-key schedule. Even position `2r` holds
    /// half 0's key `E_mk(r)`, odd position `2r+1` holds half 1's key
    /// `E_mk(EK_HALF + r)`, matching [`from_halves`](ExpandedKey::from_halves)
    /// and the in-circuit offset recurrence. The wallet's emitter cipher cycles
    /// this same interleaved schedule.
    #[must_use]
    pub fn derive_expanded(&self) -> ExpandedKey {
        ExpandedKey(array::from_fn(|index| {
            #[expect(
                clippy::as_conversions,
                clippy::integer_division,
                clippy::integer_division_remainder_used,
                reason = "constant expansion size; index < EK_LENGTH"
            )]
            let cipher_index = ((index % 2) * ExpandedKey::EK_HALF + index / 2) as u64;
            mimc::mk_dk_expand(Fp::ZERO, self.0, Fp::from(cipher_index))
        }))
    }

    /// One expansion half's trace polynomial and its `EK_HALF` keys. The `half`
    /// (0 or 1) selects the cipher-input window via `base = half · EK_HALF`, so
    /// half 0 runs inputs `0..EK_HALF` and half 1 runs `EK_HALF..2·EK_HALF`.
    /// Runs `EK_HALF` keyed-cipher expansions and interpolates their row-major
    /// `EK_HALF × ROUNDS = POLY_LEN_MAX` cells over `⟨ω⟩` into the trace `T`
    /// (so `T(ω^{ROUNDS·r + c})` is row `r`'s `c`-th cipher state); the per-row
    /// whitened outputs are this half's keys. `T` is only ever the interpolant,
    /// so the inverse FFT lives here with its producer.
    #[must_use]
    pub fn derive_expanded_trace(
        &self,
        half: usize,
    ) -> (ExpKeySpectrumPoly, [Fp; ExpandedKey::EK_HALF]) {
        let mut cells: Vec<Fp> = Vec::with_capacity(ExpandedKey::EK_HALF * TachyonP5R64::ROUNDS);
        let mut keys: Vec<Fp> = Vec::with_capacity(ExpandedKey::EK_HALF);

        #[expect(clippy::as_conversions, reason = "constant size")]
        let base = Fp::from((half * ExpandedKey::EK_HALF) as u64);
        #[expect(clippy::as_conversions, reason = "constant size")]
        for (states, key) in (0..(ExpandedKey::EK_HALF as u64))
            .map(|row| mimc::mk_dk_expand_sequence(base, self.0, Fp::from(row)))
        {
            cells.extend_from_slice(&states);
            keys.push(key);
        }

        Domain::new(cells.len().ilog2()).ifft(&mut cells);
        #[expect(clippy::expect_used, reason = "constant size")]
        (
            ExpKeySpectrumPoly(Polynomial::from_coeffs(&cells)),
            keys.try_into().expect("constant size"),
        )
    }
}

/// Per-note nullifier derivation material.
///
/// The full `κ = ExpandedKey::EK_LENGTH` cyclic round-key schedule of the
/// note's derivation polynomials, assembled by interleaving two expansion
/// halves of `EK_HALF` keyed-cipher outputs each.
///
/// A flat `[Fp; ExpandedKey::EK_LENGTH]` newtype handled only as a polynomial
/// downstream: each half is the eval-form interpolant
/// [`half_key_poly`](Self::half_key_poly) over the order-`EK_HALF` subgroup
/// `⟨ζ⟩`, and the derivation step's interleaved offset recurrence reconstructs
/// the full schedule from the two halves. The per-poly salts, the weight bases
/// `ρ_j`, and the shift `c` come from `mk` (via the nullifier-query sponge
/// methods on [`NoteMasterKey`]), not from these outputs.
///
/// Wallet-only secret material: the wallet is the sole prover of derivation,
/// and delegation operates on value windows only (no key-material delegation
/// API).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExpandedKey(pub [Fp; Self::EK_LENGTH]);

impl ExpandedKey {
    /// One expansion half is `TachyonP5R64::ROUNDS` rows of `EK_HALF` cells
    /// (`ROUNDS x EK_HALF = POLY_LEN_MAX`), so the per-half key count is
    /// derived from the single-trace cap. Each half is certified by one
    /// expansion step.
    #[expect(
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "constant size"
    )]
    pub const EK_HALF: usize = POLY_LEN_MAX / TachyonP5R64::ROUNDS;
    /// The full cyclic round-key schedule width: two interleaved halves. The
    /// emitter's 8192-round cipher cycles this many distinct keys
    /// (`8192 / EK_LENGTH = 32` cycles).
    pub const EK_LENGTH: usize = 2 * Self::EK_HALF;

    /// Get the round key at the given index.
    #[must_use]
    pub const fn round_key(&self, index: usize) -> Fp {
        #[expect(clippy::integer_division_remainder_used, reason = "constant size")]
        self.0[index % self.0.len()]
    }

    /// Assemble the full interleaved schedule from two expansion halves: even
    /// position `2r` takes `half_even[r]`, odd position `2r+1` takes
    /// `half_odd[r]`. This is the ordering the in-circuit offset recurrence
    /// reconstructs (`K(ζ_256^{2r}) = A_r`, `K(ζ_256^{2r+1}) = B_r`).
    #[must_use]
    pub fn from_halves(half_even: &[Fp; Self::EK_HALF], half_odd: &[Fp; Self::EK_HALF]) -> Self {
        Self(array::from_fn(|index| {
            #[expect(
                clippy::indexing_slicing,
                clippy::integer_division,
                clippy::integer_division_remainder_used,
                reason = "index < EK_LENGTH = 2*EK_HALF, so index/2 < EK_HALF"
            )]
            let key = if index % 2 == 0 {
                half_even[index / 2]
            } else {
                half_odd[index / 2]
            };
            key
        }))
    }

    /// The eval-form half-key polynomial over the order-`EK_HALF` subgroup
    /// `⟨ζ⟩` (`A(ζ^r) = half_keys[r]`). One per expansion half; the
    /// strided-column relation binds it to that half's trace, and the
    /// derivation step's interleaved offset recurrence opens the two halves.
    #[must_use]
    pub fn half_key_poly(half_keys: &[Fp; Self::EK_HALF]) -> HalfKeyPoly {
        let mut coeffs = half_keys.to_vec();
        Domain::new(Self::EK_HALF.ilog2()).ifft(&mut coeffs);
        HalfKeyPoly(Polynomial::from_coeffs(&coeffs))
    }

    /// One derivation polynomial: the 8192-round keyed cipher on input `salt`
    /// under this full 256-key interleaved schedule (cycled 32 times),
    /// interpolated over `⟨ω⟩` (so `T(ω^i)` is the `i`-th cipher state). The
    /// query reads it by evaluation, so it is always the interpolant, never raw
    /// cipher states as coefficients.
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
    pub fn derivation_polys(&self, salts: &QuerySalts) -> [NfEmitterPoly; NF_EMITTERS] {
        salts.0.map(|salt| self.derivation_poly(salt))
    }

    /// The new-scheme nullifier at epoch offset `d` from the note's creation:
    /// `nf_d = Σ_j ρ_j^d·T_j(c·γ^d)`, the query the spend circuit reproduces.
    ///
    /// This is the wallet's native nullifier — the in-circuit query relation
    /// mirrors it. The `keyset` (the FFT product of `mk`) is `self`, borrowed
    /// so the wallet can expand once and query many offsets cheaply; `mk`
    /// supplies the query salts and weights via its domain-separated sponge
    /// methods.
    #[must_use]
    pub fn derive_nullifier(&self, mk: &NoteMasterKey, offset: EpochOffset) -> Nullifier {
        let salts = mk.query_salts();
        let (ratios, shift) = mk.query_weights();
        let polys = self.derivation_polys(&salts);
        Nullifier::from(nullifier_query(
            &polys,
            shift,
            ratios,
            subgroup_generator::<NF_DOMAIN>(),
            u64::from(offset),
        ))
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

    #[test]
    fn derive_expanded_matches_interleaved_halves() {
        // The native full-schedule path (derive_expanded) and the proof path
        // (two half traces assembled by from_halves) must produce the identical
        // interleaved 256-key schedule, or the certified nullifier would diverge
        // from the wallet's native one.
        let rng = &mut StdRng::seed_from_u64(4);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let mk = master_key(&nk, &psi);

        let full = mk.derive_expanded();
        let (_, even) = mk.derive_expanded_trace(0);
        let (_, odd) = mk.derive_expanded_trace(1);

        assert_eq!(
            full,
            ExpandedKey::from_halves(&even, &odd),
            "derive_expanded equals the interleaved expansion halves"
        );
        // Domain separation: the two halves run disjoint cipher-input windows.
        assert_ne!(even[0], odd[0], "halves use distinct cipher inputs");
    }
}
