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
//! | `value`   | [`Value`] | Note value |
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
//! Evaluated natively by wallets and the Oblivious Syncing Service (via
//! delegated GGM prefix keys). The Ragu circuit constrains that the
//! externally-provided nullifier matches the note's private fields.
//!
//! ## Note Commitment
//!
//! A commitment over the note fields, producing a `cm` tachygram that
//! enters the polynomial accumulator. The concrete commitment scheme
//! (e.g. Sinsemilla, Poseidon) depends on what is efficient inside
//! Ragu circuits and is TBD.
use ff::{Field as _, PrimeField as _};
// TODO(#39): replace halo2_poseidon with Ragu Poseidon params
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;
use rand_core::{CryptoRng, RngCore};

use crate::{
    constants::{NOTE_COMMITMENT_DOMAIN, NOTE_VALUE_MAX},
    keys::{NullifierKey, PaymentKey},
    primitives::{EpochIndex, Tachygram},
};

/// Nullifier trapdoor ($\psi$) — per-note randomness for nullifier derivation.
///
/// Used to derive the master root key: $mk = \text{KDF}(\psi, nk)$.
/// The GGM tree PRF then evaluates $nf = F_{mk}(\text{flavor})$.
/// Prefix keys derived from $mk$ enable range-restricted delegation.
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct NullifierTrapdoor(pub(super) Fp);

impl NullifierTrapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(Fp::random(rng))
    }
}

impl From<Fp> for NullifierTrapdoor {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

impl From<NullifierTrapdoor> for Fp {
    fn from(trapdoor: NullifierTrapdoor) -> Self {
        trapdoor.0
    }
}

/// Note commitment trapdoor ($rcm$) — randomness that blinds the note
/// commitment.
///
/// Can be derived from a shared secret negotiated out-of-band.
#[derive(Clone, Copy, Debug)]
pub struct CommitmentTrapdoor(Fp);

impl CommitmentTrapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(Fp::random(rng))
    }
}

impl From<Fp> for CommitmentTrapdoor {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

impl From<CommitmentTrapdoor> for Fp {
    fn from(trapdoor: CommitmentTrapdoor) -> Self {
        trapdoor.0
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
    pub value: Value,

    /// The nullifier trapdoor ($\psi$).
    pub psi: NullifierTrapdoor,

    /// Note commitment trapdoor ($rcm$).
    pub rcm: CommitmentTrapdoor,
}

/// A note value in zatoshis. Non-zero and no greater than 2.1e15.
///
/// Zero-valued notes are forbidden by construction: a zero-value action
/// carries no economic meaning. The newtype enforces the invariant at
/// `Value::from` (panics on zero and on overflow). Each PCD step that
/// witnesses a `Note` *independently* rechecks `value != 0` — the
/// compiler cannot prove the invariant from inside the circuit, and a
/// compiled proof system sees only raw field elements without the
/// Rust-level newtype protection.
#[derive(Clone, Copy, Debug)]
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "test helpers use crate-internal construction to bypass the API check"
)]
pub struct Value(pub(crate) u64);

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        assert!(value > 0, "note value must be non-zero");
        assert!(
            value <= NOTE_VALUE_MAX,
            "note value must not exceed maximum"
        );
        Self(value)
    }
}

#[expect(clippy::expect_used, reason = "specified behavior")]
impl From<Value> for i64 {
    fn from(value: Value) -> Self {
        Self::try_from(value.0).expect("note value should fit in i64 (max 2.1e15 < i64::MAX)")
    }
}

impl From<Value> for u64 {
    fn from(value: Value) -> Self {
        value.0
    }
}

impl Note {
    /// Computes the note commitment `cm`.
    ///
    /// Commits to $(pk, v, \psi)$ with randomness $rcm$
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        let domain = Fp::from_u128(u128::from_le_bytes(*NOTE_COMMITMENT_DOMAIN));
        Commitment::from(
            &Hash::<_, P128Pow5T3, ConstantLength<5>, 3, 2>::init().hash([
                domain,
                self.rcm.0,
                self.pk.0,
                Fp::from(self.value.0),
                self.psi.0,
            ]),
        )
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Commitment(Fp);

impl From<&Fp> for Commitment {
    fn from(fp: &Fp) -> Self {
        Self(*fp)
    }
}

impl From<&Commitment> for Fp {
    fn from(cm: &Commitment) -> Self {
        cm.0
    }
}

impl From<&Commitment> for Tachygram {
    fn from(commitment: &Commitment) -> Self {
        Self::from(&commitment.0)
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nullifier(Fp);

impl From<&Fp> for Nullifier {
    fn from(fp: &Fp) -> Self {
        Self(*fp)
    }
}

impl From<&Nullifier> for Fp {
    fn from(nf: &Nullifier) -> Self {
        nf.0
    }
}

impl From<&Nullifier> for Tachygram {
    fn from(nullifier: &Nullifier) -> Self {
        Self::from(&nullifier.0)
    }
}

#[cfg(test)]
mod tests {
    use pasta_curves::Fp;
    use proptest::prelude::*;

    use super::*;
    use crate::{
        constants::NOTE_VALUE_MAX,
        keys::private,
        testing::{arb_note, arb_nullifier_trapdoor, arb_spending_key, arb_value},
    };

    /// NOTE_VALUE_MAX must be accepted (boundary is inclusive).
    #[test]
    fn value_accepts_max() {
        let _val: Value = Value::from(NOTE_VALUE_MAX);
    }

    /// Anything above NOTE_VALUE_MAX must be rejected.
    #[test]
    #[should_panic(expected = "note value must not exceed maximum")]
    fn value_rejects_overflow() {
        let _val: Value = Value::from(NOTE_VALUE_MAX + 1);
    }

    /// Zero must be rejected — notes carry economic value.
    #[test]
    #[should_panic(expected = "note value must be non-zero")]
    fn value_rejects_zero() {
        let _val: Value = Value::from(0u64);
    }

    /// Different trapdoors produce different commitments.
    #[test]
    fn distinct_rcm_distinct_commitments() {
        let pk = PaymentKey(Fp::from(1u64));
        let psi = NullifierTrapdoor::from(Fp::from(2u64));

        let note1 = Note {
            pk,
            value: Value::from(100u64),
            psi,
            rcm: CommitmentTrapdoor::from(Fp::from(3u64)),
        };
        let note2 = Note {
            pk,
            value: Value::from(100u64),
            psi,
            rcm: CommitmentTrapdoor::from(Fp::from(4u64)),
        };

        assert_ne!(note1.commitment(), note2.commitment());
    }

    /// `Note::nullifier` delegates correctly to key derivation.
    #[test]
    fn note_nullifier_matches_key_derivation() {
        use crate::{keys::private::SpendingKey, primitives::EpochIndex};

        let sk = SpendingKey::from([0x42u8; 32]);
        let nk = sk.derive_nullifier_private();
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let note = Note {
            pk: sk.derive_payment_key(),
            value: Value::from(100u64),
            psi,
            rcm: CommitmentTrapdoor::from(Fp::ZERO),
        };
        let flavor = EpochIndex(5u32);

        let mk = nk.derive_note_private(&psi);
        assert_eq!(note.nullifier(&nk, flavor), mk.derive_nullifier(flavor));
    }

    proptest! {
        /// Mutating pk produces a different commitment.
        #[test]
        fn mutated_pk_changes_commitment(
            note in arb_note(),
            other_sk in arb_spending_key(),
        ) {
            let other_pk = other_sk.derive_payment_key();
            prop_assume!(note.pk.0 != other_pk.0);
            let mutated = Note { pk: other_pk, ..note };
            prop_assert_ne!(note.commitment(), mutated.commitment());
        }

        /// Mutating value produces a different commitment.
        #[test]
        fn mutated_value_changes_commitment(
            note in arb_note(),
            other_val in arb_value(),
        ) {
            prop_assume!(note.value.0 != other_val.0);
            let mutated = Note { value: other_val, ..note };
            prop_assert_ne!(note.commitment(), mutated.commitment());
        }

        /// Mutating psi produces a different commitment.
        #[test]
        fn mutated_psi_changes_commitment(
            note in arb_note(),
            other_psi in arb_nullifier_trapdoor(),
        ) {
            prop_assume!(Fp::from(note.psi) != Fp::from(other_psi));
            let mutated = Note { psi: other_psi, ..note };
            prop_assert_ne!(note.commitment(), mutated.commitment());
        }

        /// Different nullifier key produces a different nullifier.
        #[test]
        fn different_nk_different_nullifier(
            note in arb_note(),
            sk_a_bytes in any::<[u8; 32]>(),
            sk_b_bytes in any::<[u8; 32]>(),
            epoch in 0u32..1000,
        ) {
            // Different sk -> different nk via PRF. Collision would be a security finding.
            prop_assume!(sk_a_bytes != sk_b_bytes);
            let nk_a = private::SpendingKey::from(sk_a_bytes).derive_nullifier_private();
            let nk_b = private::SpendingKey::from(sk_b_bytes).derive_nullifier_private();
            let flavor = EpochIndex(epoch);
            prop_assert_ne!(
                note.nullifier(&nk_a, flavor),
                note.nullifier(&nk_b, flavor)
            );
        }

        /// Nullifier is deterministic and epoch-sensitive.
        #[test]
        fn nullifier_deterministic_and_epoch_sensitive(
            note in arb_note(),
            sk in arb_spending_key(),
            epoch_a in 0u32..1000,
            epoch_b in 0u32..1000,
        ) {
            let nk = sk.derive_nullifier_private();
            let nf1 = note.nullifier(&nk, EpochIndex(epoch_a));
            let nf2 = note.nullifier(&nk, EpochIndex(epoch_a));
            prop_assert_eq!(nf1, nf2);

            if epoch_a != epoch_b {
                let nf_other = note.nullifier(&nk, EpochIndex(epoch_b));
                prop_assert_ne!(nf1, nf_other);
            }
        }
    }
}
