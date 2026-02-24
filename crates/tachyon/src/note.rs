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
//! A commitment over the note fields, producing a `cmx` tachygram that
//! enters the polynomial accumulator. The concrete commitment scheme
//! (e.g. Sinsemilla, Poseidon) depends on what is efficient inside
//! Ragu circuits and is TBD.
use ff::Field as _;
use pasta_curves::{Fp, Fq};

use crate::{
    constants::NOTE_VALUE_MAX,
    keys::{NullifierKey, PaymentKey},
    primitives::{Epoch, Tachygram},
};

/// Nullifier trapdoor ($\psi$) — per-note randomness for nullifier derivation.
///
/// Used to derive the master root key: $mk = \text{KDF}(\psi, nk)$.
/// The GGM tree PRF then evaluates $nf = F_{mk}(\text{flavor})$.
/// Prefix keys derived from $mk$ enable range-restricted delegation.
#[derive(Clone, Copy, Debug)]
pub struct NullifierTrapdoor(Fp);

impl From<Fp> for NullifierTrapdoor {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<Fp> for NullifierTrapdoor {
    fn into(self) -> Fp {
        self.0
    }
}

/// Note commitment trapdoor ($rcm$) — randomness that blinds the note
/// commitment.
///
/// Can be derived from a shared secret negotiated out-of-band.
#[derive(Clone, Copy, Debug)]
pub struct CommitmentTrapdoor(Fq);

impl CommitmentTrapdoor {
    /// Computes the note commitment `cmx`.
    ///
    /// Commits to $(pk, v, \psi)$ with randomness $rcm$
    #[must_use]
    pub fn commit(self, _v: Value, _pk: &PaymentKey, _psi: &NullifierTrapdoor) -> Commitment {
        // TODO: Implement note commitment
        // $cmx = \text{NoteCommit}_{rcm}(\text{"z.cash:Tachyon-NoteCommit"}, pk \| v \|
        // \psi)$
        //
        // CORRECTNESS: the crate-local `todo!` macro prints and continues
        // (does not panic). This stub returns Fp::ZERO for every note,
        // making all output tachygrams identical.
        todo!("note commitment");
        Commitment::from(Fp::ZERO)
    }
}

impl From<Fq> for CommitmentTrapdoor {
    fn from(fq: Fq) -> Self {
        Self(fq)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<Fq> for CommitmentTrapdoor {
    fn into(self) -> Fq {
        self.0
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

/// A note value, less than 2.1e15 zatoshis
#[derive(Clone, Copy, Debug)]
pub struct Value(u64);

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        assert!(
            value <= NOTE_VALUE_MAX,
            "note value must not exceed maximum"
        );
        Self(value)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<i64> for Value {
    fn into(self) -> i64 {
        #[expect(clippy::expect_used, reason = "specified behavior")]
        i64::try_from(self.0).expect("value fits in i64")
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<u64> for Value {
    fn into(self) -> u64 {
        self.0
    }
}

impl Note {
    /// Computes the note commitment `cmx`.
    ///
    /// Commits to $(pk, v, \psi)$ with randomness $rcm$
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        self.rcm.commit(self.value, &self.pk, &self.psi)
    }

    /// Derives a nullifier for this note at the given flavor (epoch).
    ///
    /// GGM tree PRF:
    /// 1. $mk = \text{Poseidon}(\psi, nk)$ — master root key (per-note)
    /// 2. $nf = F_{mk}(\text{flavor})$ — tree walk with bits of flavor
    ///
    /// The same note at different flavors produces different nullifiers.
    #[must_use]
    pub fn nullifier(&self, _nk: &NullifierKey, _flavor: Epoch) -> Nullifier {
        // TODO: GGM tree PRF nullifier derivation
        //   mk = Poseidon(self.psi, nk.inner())
        //   for i in 0..GGM_TREE_DEPTH:
        //       bit = (flavor_int >> i) & 1
        //       node = Poseidon(node, bit)
        //   nf = final node
        //
        // Requires native Poseidon with parameters matching the circuit Sponge.
        //
        // CORRECTNESS: the crate-local `todo!` macro prints and continues
        // (does not panic). This stub returns Fp::ZERO for every note,
        // making all spend nullifiers identical (double-spend detection broken).
        todo!("GGM tree PRF nullifier derivation");
        Nullifier::from(Fp::ZERO)
    }
}

/// A Tachyon note commitment (`cmx`).
///
/// A field element produced by committing to the note fields. This is
/// the value that becomes a tachygram:
/// - For **output** operations, `cmx` IS the tachygram directly.
/// - For **spend** operations, `cmx` is a private witness; the tachygram is the
///   derived nullifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Commitment(Fp);

impl From<Fp> for Commitment {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

impl From<Commitment> for Fp {
    fn from(cm: Commitment) -> Self {
        cm.0
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<Tachygram> for Commitment {
    fn into(self) -> Tachygram {
        Tachygram::from(self.0)
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

impl From<Fp> for Nullifier {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

impl From<Nullifier> for Fp {
    fn from(nf: Nullifier) -> Self {
        nf.0
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<Tachygram> for Nullifier {
    fn into(self) -> Tachygram {
        Tachygram::from(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::NOTE_VALUE_MAX;

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
}
