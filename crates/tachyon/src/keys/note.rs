//! Note-related keys: NullifierKey, NoteMasterKey, PaymentKey.

#![allow(missing_docs, reason = "todo")]

extern crate alloc;

use alloc::vec::Vec;
use core::{array, fmt};

use derive_more::Debug;
use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use ragu::{Domain, Polynomial};
use zcash_mimc::spec::tachyon::{TachyonP5R32, TachyonP5R8192};

use super::proof::SpendValidatingKey;
use crate::{
    constants::{
        EK_FULL_SIZE, EK_PART_SIZE, EK_PARTS, MK_LENGTH, MK_PART_LEN, MK_PARTS, NF_DOMAIN,
        NF_EMITTERS,
    },
    digest::{mimc, poseidon},
    note::{self, Nullifier},
    primitives::{EpochOffset, NfEmitterPoly, PartKeyPoly, PartKeySpectrumPoly},
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
    /// Derive one `mk` part (`MK_PART_LEN` round keys) of a note's master key
    /// from its nullifier trapdoor `psi` and the part index. One [`MasterSeed`]
    /// step derives one part; the parts concatenate into the full schedule via
    /// [`NoteMasterKey::from_parts`].
    ///
    /// [`MasterSeed`]: crate::stamp::proof::delegation::MasterSeed
    #[must_use]
    pub fn derive_note_part(&self, psi: &note::NullifierTrapdoor, part: u64) -> [Fp; MK_PART_LEN] {
        poseidon::nf_master_part(psi.0, self.0, part)
    }
}

/// Per-note master secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NoteMasterKey(pub [Fp; Self::MK_LENGTH]);

impl NoteMasterKey {
    pub const MK_LENGTH: usize = MK_LENGTH;

    /// Assemble the full master key by concatenating its `MK_PARTS` parts, in
    /// order. Each part is one [`MasterSeed`] step's `nf_master_part` output;
    /// part `i` occupies `mk[i·MK_PART_LEN .. (i+1)·MK_PART_LEN]`.
    ///
    /// [`MasterSeed`]: crate::stamp::proof::delegation::MasterSeed
    #[must_use]
    pub fn from_parts(parts: &[[Fp; MK_PART_LEN]; MK_PARTS]) -> Self {
        Self(array::from_fn(|index| {
            #[expect(
                clippy::indexing_slicing,
                clippy::integer_division,
                clippy::integer_division_remainder_used,
                reason = "index < MK_LENGTH = MK_PARTS*MK_PART_LEN"
            )]
            let key = parts[index / MK_PART_LEN][index % MK_PART_LEN];
            key
        }))
    }

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
        QuerySalts(poseidon::nf_query_salts(&self.0))
    }

    /// The nullifier-query weight parameters `(ρ_j, c)`: the per-poly
    /// geometric weight bases `ρ_j` and the secret query-coset origin `c`
    /// (the `shift`). Domain-separated from
    /// [`query_salts`](Self::query_salts).
    #[must_use]
    pub fn query_weights(&self) -> (WeightRatios, QueryShift) {
        let (rt, sh) = poseidon::nf_query_weights(&self.0);
        (WeightRatios(rt), QueryShift(sh))
    }

    /// The note's full interleaved `EK_FULL_SIZE`-key schedule. Position
    /// `p + EK_PARTS·r` holds part `p`'s key `E_mk(p·EK_PART_SIZE + r)`,
    /// matching [`from_parts`](ExpandedKey::from_parts) and the in-circuit
    /// offset recurrence. The wallet's emitter cipher cycles this same
    /// interleaved schedule.
    #[must_use]
    pub fn derive_expanded(&self) -> ExpandedKey {
        ExpandedKey(array::from_fn(|index| {
            #[expect(
                clippy::as_conversions,
                clippy::integer_division,
                clippy::integer_division_remainder_used,
                reason = "constant expansion size; index < EK_FULL_SIZE"
            )]
            let cipher_index = ((index % EK_PARTS) * EK_PART_SIZE + index / EK_PARTS) as u64;
            mimc::mk_dk_expand(Fp::ZERO, &self.0, Fp::from(cipher_index))
        }))
    }

    /// One expansion part's trace polynomial and its `EK_PART_SIZE` keys. The
    /// `part` (`0..EK_PARTS`) selects the cipher-input window via `base = part
    /// · EK_PART_SIZE`, so part `p` runs inputs
    /// `p·EK_PART_SIZE..(p+1)·EK_PART_SIZE`. Runs `EK_PART_SIZE`
    /// keyed-cipher expansions and interpolates their
    /// row-major `EK_PART_SIZE × ROUNDS = POLY_LEN_MAX` cells over `⟨ω⟩` into
    /// the trace `T` (so `T(ω^{ROUNDS·r + c})` is row `r`'s `c`-th cipher
    /// state); the per-row whitened outputs are this part's keys. `T` is
    /// only ever the interpolant, so the inverse FFT lives here with its
    /// producer.
    #[must_use]
    pub fn derive_expanded_trace(&self, part: usize) -> (PartKeySpectrumPoly, PartKey) {
        let mut cells: Vec<Fp> = Vec::with_capacity(EK_PART_SIZE * TachyonP5R32::ROUNDS);
        let mut keys: Vec<Fp> = Vec::with_capacity(EK_PART_SIZE);

        #[expect(clippy::as_conversions, reason = "constant size")]
        let base = Fp::from((part * EK_PART_SIZE) as u64);
        #[expect(clippy::as_conversions, reason = "constant size")]
        for (states, key) in (0..(EK_PART_SIZE as u64))
            .map(|row| mimc::mk_dk_expand_sequence(base, &self.0, Fp::from(row)))
        {
            cells.extend_from_slice(&states);
            keys.push(key);
        }

        Domain::new(cells.len().ilog2()).ifft(&mut cells);
        #[expect(clippy::expect_used, reason = "constant size")]
        (
            PartKeySpectrumPoly(Polynomial::from_coeffs(&cells)),
            PartKey(keys.try_into().expect("constant size")),
        )
    }
}

/// Per-note nullifier derivation material.
///
/// The full `κ = EK_FULL_SIZE` cyclic round-key schedule of the
/// note's derivation polynomials, assembled by interleaving `EK_PARTS`
/// expansion parts of `EK_PART_SIZE` keyed-cipher outputs each.
///
/// A flat `[Fp; EK_FULL_SIZE]` newtype handled only as a
/// polynomial downstream: each part is the eval-form interpolant
/// [`PartKey::key_poly`] over the order-`EK_PART_SIZE` subgroup
/// `⟨ζ⟩`, and the derivation step's interleaved offset recurrence reconstructs
/// the full schedule from the parts. The per-poly salts, the weight bases
/// `ρ_j`, and the shift `c` come from `mk` (via the nullifier-query sponge
/// methods on [`NoteMasterKey`]), not from these outputs.
///
/// Wallet-only secret material: the wallet is the sole prover of derivation,
/// and delegation operates on value windows only (no key-material delegation
/// API).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExpandedKey(pub [Fp; EK_FULL_SIZE]);

impl ExpandedKey {
    /// Get the round key at the given index.
    #[must_use]
    pub const fn round_key(&self, index: usize) -> Fp {
        #[expect(clippy::integer_division_remainder_used, reason = "constant size")]
        self.0[index % self.0.len()]
    }

    /// Assemble the full interleaved schedule from the `EK_PARTS` expansion
    /// parts: position `p + EK_PARTS·r` takes `parts[p].0[r]`. This is the
    /// ordering the in-circuit offset recurrence reconstructs
    /// (`K(ζ^{p+EK_PARTS·r}) = A_p[r]`).
    #[must_use]
    pub fn from_parts(parts: &[PartKey; EK_PARTS]) -> Self {
        Self(array::from_fn(|index| {
            #[expect(
                clippy::indexing_slicing,
                clippy::integer_division,
                clippy::integer_division_remainder_used,
                reason = "index < EK_FULL_SIZE = EK_PARTS*EK_PART_SIZE, so part < EK_PARTS and row < EK_PART_SIZE"
            )]
            let key = parts[index % EK_PARTS].0[index / EK_PARTS];
            key
        }))
    }

    /// One derivation polynomial: the 8192-round keyed cipher on input `salt`
    /// under this full `EK_FULL_SIZE`-key interleaved schedule (cycled
    /// `POLY_LEN_MAX / EK_FULL_SIZE` times),
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

impl From<[Fp; EK_FULL_SIZE]> for ExpandedKey {
    fn from(keys: [Fp; EK_FULL_SIZE]) -> Self {
        Self(keys)
    }
}

impl From<ExpandedKey> for [Fp; EK_FULL_SIZE] {
    fn from(keyset: ExpandedKey) -> Self {
        keyset.0
    }
}

impl fmt::Debug for ExpandedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandedKey").finish_non_exhaustive()
    }
}

/// One expansion part's `EK_PART_SIZE` keyed-cipher outputs.
///
/// Part `p` occupies schedule positions `≡ p (mod EK_PARTS)`;
/// [`ExpandedKey::from_parts`] interleaves the `EK_PARTS` parts into the full
/// schedule. Each is certified by one
/// [`ExpandedKeyStep`](crate::stamp::proof::delegation::ExpandedKeyStep) step.
///
/// Wallet-only secret material, like [`ExpandedKey`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PartKey(pub [Fp; EK_PART_SIZE]);

impl PartKey {
    /// The eval-form part-key polynomial over the order-`EK_PART_SIZE` subgroup
    /// `⟨ζ⟩` (`A(ζ^r) = self.0[r]`). The strided-column relation binds it to
    /// that part's trace, and the derivation step's interleaved offset
    /// recurrence opens the parts.
    #[must_use]
    pub fn key_poly(&self) -> PartKeyPoly {
        let mut coeffs = self.0.to_vec();
        Domain::new(EK_PART_SIZE.ilog2()).ifft(&mut coeffs);
        PartKeyPoly(Polynomial::from_coeffs(&coeffs))
    }
}

impl fmt::Debug for PartKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartKey").finish_non_exhaustive()
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

impl From<PaymentKey> for Fp {
    fn from(pk: PaymentKey) -> Self {
        pk.0
    }
}

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

    /// The note's master key, assembled from its `MK_PARTS` parts.
    fn master_key(nk: &NullifierKey, psi: &note::NullifierTrapdoor) -> NoteMasterKey {
        NoteMasterKey::from_parts(&array::from_fn(|part| {
            nk.derive_note_part(psi, u64::try_from(part).expect("part fits u64"))
        }))
    }

    #[test]
    fn derive_note_part_deterministic() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        assert_eq!(nk.derive_note_part(&psi, 0), nk.derive_note_part(&psi, 0));
    }

    #[test]
    fn different_psi_different_mk() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi1 = note::NullifierTrapdoor::random(rng);
        let psi2 = note::NullifierTrapdoor::random(rng);
        assert_ne!(nk.derive_note_part(&psi1, 0), nk.derive_note_part(&psi2, 0),);
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
            keys[EK_FULL_SIZE - 1],
            "distinct first and last keys"
        );
    }

    #[test]
    fn derive_expanded_matches_interleaved_parts() {
        // The native full-schedule path (derive_expanded) and the proof path
        // (EK_PARTS part traces assembled by from_parts) must produce the
        // identical interleaved schedule, or the certified nullifier would
        // diverge from the wallet's native one.
        let rng = &mut StdRng::seed_from_u64(4);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let mk = master_key(&nk, &psi);

        let full = mk.derive_expanded();
        let parts: [PartKey; EK_PARTS] = array::from_fn(|part| mk.derive_expanded_trace(part).1);

        assert_eq!(
            full,
            ExpandedKey::from_parts(&parts),
            "derive_expanded equals the interleaved expansion parts"
        );
        // Domain separation: the parts run disjoint cipher-input windows.
        for part in 1..EK_PARTS {
            assert_ne!(
                parts[part].0[0],
                parts[part - 1].0[0],
                "parts use distinct cipher inputs"
            );
        }
    }
}
