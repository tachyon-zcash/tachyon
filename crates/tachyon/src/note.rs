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
//! $mk = \text{KDF}(\psi, nk)$, then $nf = F_{mk}(\text{epoch})$ via a keyed
//! PRF evaluated directly per epoch, instantiated from Poseidon.
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

use crate::{digest::poseidon, keys::PaymentKey, nullifier, value};

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
    pub psi: nullifier::Trapdoor,

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
            self.value.into(),
            self.psi.into(),
        ))
    }
}

/// A Tachyon note commitment (`cm`).
///
/// A field element produced by committing to the note fields. This is
/// the value that becomes a tachygram:
/// - For **output** operations, `cm` IS the tachygram directly.
/// - For **spend** operations, `cm` is a private witness.
#[derive(Clone, Copy, Debug, From, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct Commitment(#[debug(skip)] Fp);

#[cfg(test)]
mod tests {
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{constants::MAX_MONEY, value};

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
        let psi = nullifier::Trapdoor::random(rng);

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

    #[test]
    fn debug_note_commitment_redacts_value() {
        let cm = Commitment::from(Fp::from(42u64));
        let dbg = alloc::format!("{cm:?}");
        assert!(dbg.contains("Commitment"), "must name the type");
        assert!(!dbg.contains("42"), "must not leak field element");
    }
}
