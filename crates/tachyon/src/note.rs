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
use rand_core::CryptoRng;
use udon::field::Field as _;

use crate::{
    digest::poseidon,
    keys::PaymentKey,
    nullifier,
    pasta::{Fp, Fq},
    primitives::Tachygram,
    value,
};

/// Note commitment trapdoor ($rcm$): randomness that blinds the note
/// commitment.
///
/// Can be derived from a shared secret negotiated out-of-band.
#[derive(Clone, Copy, Debug, From, Into)]
pub struct CommitmentTrapdoor(#[debug(skip)] Fp);

impl CommitmentTrapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fp::random(|bytes| rng.fill_bytes(bytes)))
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
    /// The feemax blind, the trapdoor $r$ of `cv_feemax`, derived from note
    /// fields.
    #[must_use]
    #[expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "p < q, so every Fp repr is canonical in Fq"
    )]
    pub fn derive_feemax_blind(&self) -> value::Trapdoor {
        let blind =
            poseidon::feemax_blind(Fp::from(self.pk), Fp::from(self.psi), Fp::from(self.rcm));
        value::Trapdoor::from_scalar(Fq::from_bytes(blind.to_bytes()).expect("p < q"))
    }

    /// The max fee commitment, `cv_feemax`.
    #[must_use]
    pub fn cv_feemax(&self) -> value::Commitment {
        self.derive_feemax_blind().commit(-self.value)
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
mod tests;
