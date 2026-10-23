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
//! | `psi` | [`nullifier::Trapdoor`] | Nullifier trapdoor ($\psi$) |
//! | `rcm` | [`CommitmentTrapdoor`] | Note commitment randomness |
//!
//! Both $\psi$ and $rcm$ can be derived from a shared key negotiated
//! through the out-of-band payment protocol.
//!
//! ## Nullifier Derivation
//!
//! $mk = \text{KDF}(\psi, nk)$, then $nf_e$ is one squeeze of a Poseidon
//! sponge keyed on $mk$ and the epoch's group start.
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
use ff::{Field as _, PrimeField as _};
use pasta_curves::{Fp, Fq};
use rand_core::CryptoRng;

use crate::{digest::poseidon, keys::PaymentKey, nullifier, primitives::Tachygram, value};

/// Note commitment trapdoor ($rcm$): randomness that blinds the note
/// commitment.
///
/// Can be derived from a shared secret negotiated out-of-band.
#[derive(Clone, Copy, Debug, From, Into)]
pub struct CommitmentTrapdoor(#[debug(skip)] Fp);

impl CommitmentTrapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
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
    /// Derive a max fee blind $r$ from note fields.
    #[must_use]
    #[expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "p < q, so every Fp repr is canonical in Fq"
    )]
    pub fn fee_blind(&self) -> value::Trapdoor {
        let blind = poseidon::fee_blind(Fp::from(self.pk), Fp::from(self.psi), Fp::from(self.rcm));
        value::Trapdoor::from_scalar(Option::from(Fq::from_repr(blind.to_repr())).expect("p < q"))
    }

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
            Fp::from(self.pk),
            u64::from(self.value),
            self.psi.into(),
        ))
    }
}

/// A Tachyon note commitment (`cm`).
///
/// Produced by committing to the note fields. An output publishes `cm` as a
/// tachygram; a spend keeps it as a private witness.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
#[from(Fp, Tachygram)]
#[into(Fp, Tachygram)]
pub struct Commitment(Tachygram);

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{constants::MAX_MONEY, testing::check, value};

    /// The commitment binds every field: another trapdoor, key, value or
    /// nullifier trapdoor gives another commitment. The pad hashes the same
    /// fields under its own domain and never coincides.
    #[test]
    fn the_commitment_binds_every_field() {
        let strategy = (any::<u64>(), 0..=MAX_MONEY, 0..=MAX_MONEY);
        check(256, strategy, |(seed, amount, other_amount)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let note = Note {
                pk: PaymentKey::from(Fp::random(&mut *rng)),
                value: value::Positive::try_from(amount).unwrap(),
                psi: nullifier::Trapdoor::random(rng),
                rcm: CommitmentTrapdoor::random(rng),
            };
            let cm = note.commitment();
            let other_value = value::Positive::try_from(other_amount).unwrap();
            for (changed, other) in [
                (
                    true,
                    Note {
                        rcm: CommitmentTrapdoor::random(rng),
                        ..note
                    },
                ),
                (
                    true,
                    Note {
                        pk: PaymentKey::from(Fp::random(&mut *rng)),
                        ..note
                    },
                ),
                (
                    true,
                    Note {
                        psi: nullifier::Trapdoor::random(rng),
                        ..note
                    },
                ),
                (
                    amount != other_amount,
                    Note {
                        value: other_value,
                        ..note
                    },
                ),
            ] {
                prop_assert_eq!(other.commitment() != cm, changed);
            }
            let pad = poseidon::pad_tachygram(note.rcm.0, note.pk.into(), amount, note.psi.into());
            prop_assert_ne!(Fp::from(cm), pad);
            Ok(())
        });
    }
}
