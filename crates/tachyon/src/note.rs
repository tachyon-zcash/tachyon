//! Tachyon notes and note commitments.
//!
//! A Tachyon note is simpler than an Orchard note: no diversifier, no `rho`,
//! no unique value for faerie gold defense. Out-of-band payment protocols
//! handle payment coordination, and the nullifier construction doesn't
//! require global uniqueness.
//!
//! ## Note Structure
//!
//! | Field | Type | Description |
//! | ----- | ---- | ----------- |
//! | `pk`  | [`PaymentKey`] | Recipient's payment key |
//! | `value`   | [`value::Value`] | Note value |
//! | `psi` | [`NullifierTrapdoor`] | Nullifier trapdoor ($\psi$) |
//! | `rcm` | [`CommitmentTrapdoor`] | Note commitment randomness |
//!
//! Both $\psi$ and $rcm$ can be derived from a shared key negotiated
//! through the out-of-band payment protocol.
//!
//! ## Nullifier Derivation
//!
//! $mk = \text{KDF}(\psi, nk)$, then $nf = F_{mk}(\text{flavor})$ via a GGM
//! tree PRF instantiated from Poseidon. The "flavor" is the epoch at which the
//! nullifier is revealed, enabling range-restricted delegation.
//!
//! Evaluated natively by wallets; the sync service handles only opaque
//! nullifier values. The Ragu circuit constrains that each consumed
//! nullifier matches the note's private fields.
//!
//! ## Note Commitment
//!
//! A commitment over the note fields, producing a `cm` tachygram that
//! enters the polynomial accumulator. The concrete commitment scheme
//! (e.g. Sinsemilla, Poseidon) depends on what is efficient inside
//! Ragu circuits and is TBD.

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::Fp;
use rand_core::{CryptoRng, RngCore};

use crate::{
    digest::poseidon,
    keys::{NullifierKey, PaymentKey},
    primitives::{EpochIndex, Tachygram},
    value,
};

/// Nullifier trapdoor ($\psi$) — per-note randomness for nullifier derivation.
///
/// Used to derive the master root key: $mk = \text{KDF}(\psi, nk)$.
/// The GGM tree PRF then evaluates $nf = F_{mk}(\text{flavor})$.
/// Prefix keys derived from $mk$ enable range-restricted delegation.
#[derive(Clone, Copy, Debug, From, Into)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct NullifierTrapdoor(#[debug(skip)] pub(super) Fp);

impl NullifierTrapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fp::random(rng))
    }
}

/// Note commitment trapdoor ($rcm$) — randomness that blinds the note
/// commitment.
///
/// Can be derived from a shared secret negotiated out-of-band.
#[derive(Clone, Copy, Debug, From, Into)]
pub struct CommitmentTrapdoor(#[debug(skip)] Fp);

impl CommitmentTrapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fp::random(rng))
    }
}

/// A Tachyon note.
///
/// Represents a discrete unit of value in the Tachyon shielded pool.
/// Created by output operations, consumed by spend operations.
#[derive(Clone, Copy, Debug)]
pub struct Note {
    /// The recipient's payment key.
    pub pk: PaymentKey,

    /// The note value in zatoshis, less than 2.1e15
    pub value: value::Positive,

    /// The nullifier trapdoor ($\psi$).
    pub psi: NullifierTrapdoor,

    /// Note commitment trapdoor ($rcm$).
    pub rcm: CommitmentTrapdoor,
}

impl Note {
    /// Computes the note commitment `cm`.
    ///
    /// Commits to $(pk, v, \psi)$ with randomness $rcm$
    ///
    /// # Panics
    ///
    /// Panics if the note commitment trapdoor is zero.
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        assert_ne!(
            self.rcm.0,
            Fp::ZERO,
            "note commitment trapdoor should not be zero"
        );

        Commitment::from(poseidon::note_commitment(
            self.rcm.0,
            self.pk.0,
            u64::from(self.value),
            self.psi.0,
        ))
    }

    /// Derives a nullifier for this note at the given flavor (epoch).
    ///
    /// GGM tree PRF:
    /// 1. $mk = \text{Poseidon}(\psi, nk)$ — master root key (per-note)
    /// 2. $nf = F_{mk}(\text{flavor})$ — tree walk with bits of flavor
    ///
    /// The same note at different flavors produces different nullifiers.
    #[must_use]
    pub fn nullifier(&self, nk: &NullifierKey, flavor: EpochIndex) -> Nullifier {
        let mk = nk.derive_note_private(&self.psi);
        mk.derive_nullifier(flavor)
    }
}

/// A Tachyon note commitment (`cm`).
///
/// A field element produced by committing to the note fields. This is
/// the value that becomes a tachygram:
/// - For **output** operations, `cm` IS the tachygram directly.
/// - For **spend** operations, `cm` is a private witness.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct Commitment(#[debug(skip)] Fp);

impl From<Commitment> for Tachygram {
    fn from(commitment: Commitment) -> Self {
        Self::from(commitment.0)
    }
}

/// A Tachyon nullifier.
///
/// Derived via GGM tree PRF: $mk = \text{KDF}(\psi, nk)$, then
/// $nf = F_{mk}(\text{flavor})$. Published when a note is spent;
/// becomes a tachygram in the polynomial accumulator.
///
/// Unlike Orchard, Tachyon nullifiers:
/// - Don't need collision resistance (no faerie gold defense)
/// - Have an epoch "flavor" component for sync delegation
/// - Are prunable by validators after a window of blocks
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct Nullifier(#[debug(skip)] Fp);

impl From<Nullifier> for Tachygram {
    fn from(nullifier: Nullifier) -> Self {
        Self::from(nullifier.0)
    }
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{constants::MAX_MONEY, keys::private::SpendingKey, primitives::EpochIndex, value};

    /// MAX_MONEY must be accepted (boundary is inclusive).
    #[test]
    fn value_accepts_max() {
        value::Positive::try_from(MAX_MONEY).unwrap();
    }

    /// Anything above MAX_MONEY must be rejected.
    #[test]
    fn value_rejects_overflow() {
        assert_eq!(
            value::Positive::try_from(MAX_MONEY + 1),
            Err(value::OutOfRange)
        );
    }

    /// Notes must have nonzero value.
    #[test]
    fn value_rejects_zero() {
        assert_eq!(value::Positive::try_from(0u64), Err(value::OutOfRange));
    }

    /// Different trapdoors produce different commitments.
    #[test]
    fn distinct_rcm_distinct_commitments() {
        let rng = &mut StdRng::seed_from_u64(0);
        let pk = PaymentKey(Fp::random(&mut *rng));
        let psi = NullifierTrapdoor::random(rng);

        let note1 = Note {
            pk,
            value: value::Positive::try_from(100u64).unwrap(),
            psi,
            rcm: CommitmentTrapdoor::random(rng),
        };
        let note2 = Note {
            pk,
            value: value::Positive::try_from(100u64).unwrap(),
            psi,
            rcm: CommitmentTrapdoor::random(rng),
        };

        assert_ne!(note1.commitment(), note2.commitment());
    }

    /// `Note::nullifier` delegates correctly to key derivation.
    #[test]
    fn note_nullifier_matches_key_derivation() {
        let rng = &mut StdRng::seed_from_u64(0);

        let sk = SpendingKey::random(rng);
        let nk = sk.derive_nullifier_private();
        let note = Note {
            pk: sk.derive_payment_key(),
            value: value::Positive::try_from(100u64).unwrap(),
            psi: NullifierTrapdoor::random(rng),
            rcm: CommitmentTrapdoor::random(rng),
        };
        let flavor = EpochIndex(5u32);

        let mk = nk.derive_note_private(&note.psi);
        assert_eq!(note.nullifier(&nk, flavor), mk.derive_nullifier(flavor));
    }

    #[test]
    fn debug_nullifier_trapdoor_redacts_value() {
        let psi = NullifierTrapdoor::from(Fp::from(0xCAFEu64));
        let dbg = alloc::format!("{psi:?}");
        assert!(dbg.contains("NullifierTrapdoor"), "must name the type");
        assert!(!dbg.contains("CAFE"), "must not leak field element");
        assert!(!dbg.contains("51966"), "must not leak decimal value");
    }

    #[test]
    fn debug_note_commitment_redacts_value() {
        let cm = Commitment::from(Fp::from(42u64));
        let dbg = alloc::format!("{cm:?}");
        assert!(dbg.contains("Commitment"), "must name the type");
        assert!(!dbg.contains("42"), "must not leak field element");
    }

    #[test]
    fn debug_nullifier_redacts_value() {
        let nf = Nullifier::from(Fp::from(0xBEEFu64));
        let dbg = alloc::format!("{nf:?}");
        assert!(dbg.contains("Nullifier"), "must name the type");
        assert!(!dbg.contains("BEEF"), "must not leak field element");
        assert!(!dbg.contains("48879"), "must not leak decimal value");
    }
}
