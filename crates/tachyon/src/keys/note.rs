//! Note-related keys: NullifierKey, NoteMasterKey, PaymentKey.

extern crate alloc;

use alloc::vec::Vec;
use core::{array, fmt};

use derive_more::{Debug, Eq as TotalEq, PartialEq};
use ff::PrimeField as _;
use pasta_curves::Fp;
use ragu::{Domain, Polynomial};
use zcash_mimc::spec::tachyon::{TachyonP5R32, TachyonP5R8192};

use super::proof::SpendValidatingKey;
use crate::{
    constants::{
        EK_LENGTH, EK_PART_LENGTH, EK_PARTS, MK_LENGTH, MK_PART_LEN, MK_PARTS, NF_DOMAIN,
        NF_EMITTERS,
    },
    digest::{mimc, poseidon},
    note::{self, Nullifier},
    primitives::{
        EpochOffset, ExpandedKeyPartSpectrum, ExpandedKeyTraceSpectrum, NfEmitterSpectrum,
        NoteMasterKeyPartSpectrum,
    },
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
    /// step derives one part; the parts interleave into the full schedule via
    /// [`NoteMasterKey::from_parts`].
    ///
    /// [`MasterSeed`]: crate::stamp::proof::delegation::MasterSeed
    #[must_use]
    pub fn derive_note_part(&self, psi: &note::NullifierTrapdoor, part: u64) -> [Fp; MK_PART_LEN] {
        poseidon::nf_master_part(psi.0, self.0, part)
    }
}

/// The key-expansion input parameters, squeezed from the note's `mk` prefix
/// by the domain-separated `Tachyon-NfExpand` sponge: the secret input salt
/// `s`, the input stride `δ`, and the whitening key `w`.
///
/// The expansion cipher runs on the affine inputs `s + δ·index`, so both the
/// inputs and their pairwise differences are note secrets rather than public
/// constants (a leaked schedule key yields no known plaintext/ciphertext
/// pair), and its outputs are whitened by the dedicated `w` rather than a
/// reused round key.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct ExpansionParams {
    /// The secret input salt `s`.
    #[debug(skip)]
    pub salt: Fp,
    /// The secret input stride `δ`.
    #[debug(skip)]
    pub stride: Fp,
    /// The dedicated whitening key `w`.
    #[debug(skip)]
    pub whitening: Fp,
}

impl ExpansionParams {
    /// Derive the parameters from the `mk` prefix (one element per interleaved
    /// part) via the domain-separated `Tachyon-NfExpand` sponge. The proof
    /// steps run the same sponge in-step over prefix elements pinned to the
    /// certified part spectra.
    #[must_use]
    pub fn from_prefix(prefix: &[Fp; MK_PARTS]) -> Self {
        let (salt, stride, whitening) = poseidon::nf_expansion_params(prefix);
        Self {
            salt,
            stride,
            whitening,
        }
    }

    /// The expansion-cipher input at schedule `index`: `s + δ·index`.
    #[must_use]
    pub fn input(&self, index: Fp) -> Fp {
        self.salt + self.stride * index
    }
}

/// Per-note master secret.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct NoteMasterKey(#[debug(skip)] pub [Fp; MK_LENGTH]);

impl NoteMasterKey {
    /// Assemble the full master key by interleaving its `MK_PARTS` parts:
    /// position `p + MK_PARTS·r` takes `parts[p][r]`, so part `p` occupies
    /// the positions `≡ p (mod MK_PARTS)`. Each part is one [`MasterSeed`]
    /// step's `nf_master_part` output. The same interleave convention as
    /// [`ExpandedKeySchedule::from_parts`].
    ///
    /// [`MasterSeed`]: crate::stamp::proof::delegation::MasterSeed
    #[must_use]
    pub fn from_parts(parts: &[NoteMasterKeyPart; MK_PARTS]) -> Self {
        #[expect(
            clippy::indexing_slicing,
            clippy::integer_division,
            clippy::integer_division_remainder_used,
            reason = "constant size"
        )]
        Self(array::from_fn(|index| {
            parts[index % MK_PARTS].0[index / MK_PARTS]
        }))
    }

    /// This key's `MK_PARTS`-element prefix, one element of every interleaved
    /// part (`prefix[p] = mk[p] = part_p[0]`): the seed material of the
    /// domain-separated parameter sponges ([`expansion_params`],
    /// [`query_salts`], [`query_weights`]). The proof steps pin the same
    /// elements by opening each certified part spectrum at `1`.
    ///
    /// [`expansion_params`]: Self::expansion_params
    /// [`query_salts`]: Self::query_salts
    /// [`query_weights`]: Self::query_weights
    #[must_use]
    pub fn prefix(&self) -> [Fp; MK_PARTS] {
        #[expect(clippy::indexing_slicing, reason = "MK_PARTS <= MK_LENGTH")]
        array::from_fn(|part| self.0[part])
    }

    /// Recover one interleaved part: `part_p[r] = mk[p + MK_PARTS·r]`, the
    /// inverse of [`from_parts`](Self::from_parts).
    #[must_use]
    pub fn part(&self, part: usize) -> NoteMasterKeyPart {
        assert!(part < MK_PARTS, "part out of range 0..MK_PARTS");
        #[expect(
            clippy::indexing_slicing,
            reason = "part < MK_PARTS and row < MK_PART_LEN"
        )]
        NoteMasterKeyPart(array::from_fn(|row| self.0[part + MK_PARTS * row]))
    }

    /// Get the round key at the given index.
    #[must_use]
    pub const fn round_key(&self, index: usize) -> Fp {
        #[expect(clippy::integer_division_remainder_used, reason = "constant size")]
        self.0[index % self.0.len()]
    }

    /// The key-expansion input parameters `(s, δ, w)`: the expansion cipher's
    /// secret input salt, input stride, and whitening key (see
    /// [`ExpansionParams`]). Domain-separated from the query salts and
    /// weights so the outputs are cryptographically independent.
    #[must_use]
    pub fn expansion_params(&self) -> ExpansionParams {
        ExpansionParams::from_prefix(&self.prefix())
    }

    /// The per-emitter nullifier-query salts `mk_s^{(j)}`, each seeding one
    /// derivation poly's 8192-round cipher. Domain-separated from
    /// [`query_weights`](Self::query_weights) so the two cannot collide.
    #[must_use]
    pub fn query_salts(&self) -> QuerySalts {
        QuerySalts(poseidon::nf_query_salts(&self.prefix()))
    }

    /// The nullifier-query weight parameters `(ρ_j, c)`: the per-poly
    /// geometric weight bases `ρ_j` and the secret query-coset origin `c`
    /// (the `shift`). Domain-separated from
    /// [`query_salts`](Self::query_salts).
    #[must_use]
    pub fn query_weights(&self) -> (WeightRatios, QueryShift) {
        let (ratios, shift) = poseidon::nf_query_weights(&self.prefix());
        (WeightRatios(ratios), QueryShift(shift))
    }

    /// The note's full interleaved `EK_LENGTH`-key schedule. Position
    /// `p + EK_PARTS·r` holds part `p`'s key
    /// `E_mk(s + δ·(p·EK_PART_LENGTH + r))`, matching
    /// [`ExpandedKeySchedule::from_parts`] and the in-circuit
    /// offset recurrence. The wallet's emitter cipher cycles this same
    /// interleaved schedule.
    #[must_use]
    pub fn derive_emitter_schedule(&self) -> ExpandedKeySchedule {
        let params = self.expansion_params();
        ExpandedKeySchedule(array::from_fn(|index| {
            #[expect(
                clippy::as_conversions,
                clippy::integer_division,
                clippy::integer_division_remainder_used,
                reason = "constant expansion size; index < EK_LENGTH"
            )]
            let cipher_index = ((index % EK_PARTS) * EK_PART_LENGTH + index / EK_PARTS) as u64;
            mimc::schedule_key(
                &self.0,
                params.input(Fp::from(cipher_index)),
                params.whitening,
            )
        }))
    }

    /// One expansion part's raw internal cipher states and its `EK_PART_LENGTH`
    /// keys.
    #[must_use]
    pub fn derive_schedule_part(&self, part: usize) -> (ExpandedKeyTrace, ExpandedKeyPart) {
        let params = self.expansion_params();
        let mut cells: Vec<Fp> = Vec::with_capacity(EK_PART_LENGTH * TachyonP5R32::ROUNDS);
        let mut keys: Vec<Fp> = Vec::with_capacity(EK_PART_LENGTH);

        #[expect(clippy::as_conversions, reason = "constant size")]
        let base = (part * EK_PART_LENGTH) as u64;
        #[expect(clippy::as_conversions, reason = "constant size")]
        for (states, key) in (0..(EK_PART_LENGTH as u64)).map(|row| {
            mimc::schedule_key_trace(
                &self.0,
                params.input(Fp::from(base + row)),
                params.whitening,
            )
        }) {
            cells.extend_from_slice(&states);
            keys.push(key);
        }

        #[expect(clippy::expect_used, reason = "constant size")]
        (
            ExpandedKeyTrace(cells),
            ExpandedKeyPart(keys.try_into().expect("constant size")),
        )
    }
}

/// One `mk` part's `MK_PART_LEN` round keys, one [`MasterSeed`] step's
/// `nf_master_part` output.
///
/// Part `p` occupies `mk` positions `≡ p (mod MK_PARTS)`;
/// [`NoteMasterKey::from_parts`] interleaves the `MK_PARTS` parts into the
/// full schedule. Wallet-only secret material.
///
/// [`MasterSeed`]: crate::stamp::proof::delegation::MasterSeed
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct NoteMasterKeyPart(#[debug(skip)] pub [Fp; MK_PART_LEN]);

impl NoteMasterKeyPart {
    /// The eval-form part spectrum over the order-`MK_PART_LEN` subgroup
    /// `⟨ζ⟩` (`M_p(ζ^r) = self.0[r]`). [`MasterSeed`] certifies it against the
    /// in-step key derivation, and the committed-key row recurrence opens the
    /// `MK_PARTS` spectra to reconstruct the interleaved expansion schedule.
    ///
    /// [`MasterSeed`]: crate::stamp::proof::delegation::MasterSeed
    #[must_use]
    pub fn spectrum(&self) -> NoteMasterKeyPartSpectrum {
        let mut coeffs = self.0.to_vec();
        Domain::new(MK_PART_LEN.ilog2()).ifft(&mut coeffs);
        NoteMasterKeyPartSpectrum(Polynomial::from_coeffs(&coeffs))
    }
}

/// Per-note nullifier derivation material.
///
/// The full `κ = EK_LENGTH` cyclic round-key schedule of the
/// note's derivation polynomials, assembled by interleaving `EK_PARTS`
/// expansion parts of `EK_PART_LENGTH` keyed-cipher outputs each.
///
/// A flat `[Fp; EK_LENGTH]` newtype handled only as a
/// polynomial downstream: each part is the eval-form interpolant
/// [`ExpandedKeyPart::key_spectrum`] over the order-`EK_PART_LENGTH` subgroup
/// `⟨ζ⟩`, and the derivation step's interleaved offset recurrence reconstructs
/// the full schedule from the parts. The per-poly salts, the weight bases
/// `ρ_j`, and the shift `c` come from `mk` (via the nullifier-query sponge
/// methods on [`NoteMasterKey`]), not from these outputs.
///
/// Wallet-only secret material: the wallet is the sole prover of derivation,
/// and delegation operates on value windows only (no key-material delegation
/// API).
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct ExpandedKeySchedule(#[debug(skip)] pub [Fp; EK_LENGTH]);

impl ExpandedKeySchedule {
    /// Get the round key at the given index.
    #[must_use]
    pub const fn round_key(&self, index: usize) -> Fp {
        #[expect(clippy::integer_division_remainder_used, reason = "constant size")]
        self.0[index % self.0.len()]
    }

    /// Assemble the full interleaved schedule from the `EK_PARTS` expansion
    /// parts: position `p + EK_PARTS·r` takes `parts[p].0[r]`. This is the
    /// ordering the in-circuit offset recurrence reconstructs
    /// (`K(ζ^{p+EK_PARTS·r}) = A_p[r]`), the same interleave convention as
    /// [`NoteMasterKey::from_parts`].
    #[must_use]
    pub fn from_parts(parts: &[ExpandedKeyPart; EK_PARTS]) -> Self {
        #[expect(
            clippy::indexing_slicing,
            clippy::integer_division,
            clippy::integer_division_remainder_used,
            reason = "constant size"
        )]
        Self(array::from_fn(|index| {
            parts[index % EK_PARTS].0[index / EK_PARTS]
        }))
    }

    /// One derivation polynomial: the 8192-round keyed cipher on input `salt`
    /// under this full `EK_LENGTH`-key interleaved schedule (cycled
    /// `POLY_LEN_MAX / EK_LENGTH` times),
    /// interpolated over `⟨ω⟩` (so `T(ω^i)` is the `i`-th cipher state). The
    /// query reads it by evaluation, so it is always the interpolant, never raw
    /// cipher states as coefficients.
    #[must_use]
    pub fn derivation_poly(&self, salt: Fp) -> NfEmitterSpectrum {
        let mut coeffs = zcash_mimc::state_sequence::<
            TachyonP5R8192,
            Fp,
            { TachyonP5R8192::POW },
            { TachyonP5R8192::ROUNDS },
        >(&self.0, salt)
        .to_vec();
        Domain::new(TachyonP5R8192::ROUNDS.ilog2()).ifft(&mut coeffs);
        NfEmitterSpectrum(Polynomial::from_coeffs(&coeffs))
    }

    /// The note's `N` derivation polynomials, one per per-poly `salt`.
    #[must_use]
    pub fn derivation_polys(&self, salts: &QuerySalts) -> [NfEmitterSpectrum; NF_EMITTERS] {
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

impl From<[Fp; EK_LENGTH]> for ExpandedKeySchedule {
    fn from(keys: [Fp; EK_LENGTH]) -> Self {
        Self(keys)
    }
}

impl From<ExpandedKeySchedule> for [Fp; EK_LENGTH] {
    fn from(keyset: ExpandedKeySchedule) -> Self {
        keyset.0
    }
}

/// One expansion part's `EK_PART_LENGTH` keyed-cipher outputs.
///
/// Part `p` occupies schedule positions `≡ p (mod EK_PARTS)`;
/// [`ExpandedKeySchedule::from_parts`] interleaves the `EK_PARTS`
/// parts into the full schedule. Each is certified by one
/// [`KeyExpansionStep`](crate::stamp::proof::delegation::KeyExpansionStep)
/// step.
///
/// Wallet-only secret material, like [`ExpandedKeySchedule`].
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct ExpandedKeyPart(#[debug(skip)] pub [Fp; EK_PART_LENGTH]);

impl ExpandedKeyPart {
    /// The eval-form part-key polynomial over the order-`EK_PART_LENGTH` subgroup
    /// `⟨ζ⟩` (`A(ζ^r) = self.0[r]`). The strided-column relation binds it to
    /// that part's trace, and the derivation step's interleaved offset
    /// recurrence opens the parts.
    #[must_use]
    pub fn key_spectrum(&self) -> ExpandedKeyPartSpectrum {
        let mut coeffs = self.0.to_vec();
        Domain::new(EK_PART_LENGTH.ilog2()).ifft(&mut coeffs);
        ExpandedKeyPartSpectrum(Polynomial::from_coeffs(&coeffs))
    }
}

/// One expansion part's raw internal cipher states.
///
/// Row-major `EK_PART_LENGTH × ROUNDS = POLY_LEN_MAX` cells, row `r`'s columns
/// being that row's per-round states (`c`'s cipher state at round `c`).
/// Distinct from [`ExpandedKeyPart`] (the per-row whitened outputs only): this is the
/// full state grid a spectrum interpolates over, not just its final column.
///
/// Wallet-only secret material, like [`ExpandedKeyPart`].
#[derive(Clone, Debug)]
pub struct ExpandedKeyTrace(#[debug(skip)] pub Vec<Fp>);

impl ExpandedKeyTrace {
    /// Interpolate this part's committed trace `T` over `⟨ω⟩`
    /// (`T(ω^{ROUNDS·r + c})` is row `r`'s `c`-th cipher state). `T` is only
    /// ever the interpolant, so the inverse FFT lives here with its producer.
    #[must_use]
    pub fn spectrum(&self) -> ExpandedKeyTraceSpectrum {
        let mut coeffs = self.0.clone();
        Domain::new(coeffs.len().ilog2()).ifft(&mut coeffs);
        ExpandedKeyTraceSpectrum(Polynomial::from_coeffs(&coeffs))
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

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    /// The note's master key, assembled from its `MK_PARTS` parts.
    fn master_key(nk: &NullifierKey, psi: &note::NullifierTrapdoor) -> NoteMasterKey {
        NoteMasterKey::from_parts(&array::from_fn(|part| {
            NoteMasterKeyPart(nk.derive_note_part(psi, u64::try_from(part).expect("part fits u64")))
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
            master_key(&nk, &psi).derive_emitter_schedule(),
            master_key(&nk, &psi).derive_emitter_schedule(),
        );
    }

    #[test]
    fn different_psi_different_keyset() {
        let rng = &mut StdRng::seed_from_u64(1);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi1 = note::NullifierTrapdoor::random(rng);
        let psi2 = note::NullifierTrapdoor::random(rng);
        assert_ne!(
            master_key(&nk, &psi1).derive_emitter_schedule(),
            master_key(&nk, &psi2).derive_emitter_schedule(),
        );
    }

    #[test]
    fn derivation_keyset_elements_are_distinct() {
        // The expansion's per-index domain separation gives distinct key
        // outputs across the schedule.
        let rng = &mut StdRng::seed_from_u64(3);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let keys = master_key(&nk, &psi).derive_emitter_schedule();

        assert_ne!(
            keys.round_key(0),
            keys.round_key(1),
            "distinct successive keys"
        );
        assert_ne!(
            keys.round_key(0),
            keys.round_key(EK_LENGTH - 1),
            "distinct first and last keys"
        );
    }

    #[test]
    fn derive_emitter_schedule_matches_interleaved_parts() {
        // The keys-only keyset path (derive_emitter_schedule) and the proof path
        // (EK_PARTS part keys from derive_schedule_part, assembled by
        // from_parts) must produce the identical interleaved schedule, or the
        // certified nullifier would diverge from the wallet's native one.
        let rng = &mut StdRng::seed_from_u64(4);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let mk = master_key(&nk, &psi);

        let full = mk.derive_emitter_schedule();
        let parts: [ExpandedKeyPart; EK_PARTS] =
            array::from_fn(|part| mk.derive_schedule_part(part).1);

        assert_eq!(
            full,
            ExpandedKeySchedule::from_parts(&parts),
            "derive_emitter_schedule equals the interleaved expansion parts"
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
