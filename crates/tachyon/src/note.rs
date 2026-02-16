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
//! | `v`   | `u64` | Note value |
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
//! This is evaluated both natively (for wallet use) and in-circuit (by the Ragu
//! proof system). Both must produce identical results.
//!
//! ## Note Commitment
//!
//! A commitment over the note fields, producing a `cmx` tachygram that
//! enters the polynomial accumulator. The concrete commitment scheme
//! (e.g. Sinsemilla, Poseidon) depends on what is efficient inside
//! Ragu circuits and is TBD.
use crate::keys::{NullifierKey, PaymentKey};
use crate::primitives::{Epoch, Field, Fp, Fq, Tachygram};

// =============================================================================
// Note trapdoors
// =============================================================================

/// Nullifier trapdoor ($\psi$) — per-note randomness for nullifier derivation.
///
/// Used to derive the master root key: $mk = \text{KDF}(\psi, nk)$.
/// The GGM tree PRF then evaluates $nf = F_{mk}(\text{flavor})$.
/// Prefix keys derived from $mk$ enable range-restricted delegation.
#[derive(Clone, Debug, Copy)]
pub struct NullifierTrapdoor(Fp);

impl From<Fp> for NullifierTrapdoor {
    fn from(f: Fp) -> Self {
        Self(f)
    }
}

#[allow(clippy::from_over_into)]
impl Into<Fp> for NullifierTrapdoor {
    fn into(self) -> Fp {
        self.0
    }
}

/// Note commitment trapdoor ($rcm$) — randomness that blinds the note commitment.
///
/// Can be derived from a shared secret negotiated out-of-band.
#[derive(Clone, Debug, Copy)]
pub struct CommitmentTrapdoor(Fq);

impl From<Fq> for CommitmentTrapdoor {
    fn from(f: Fq) -> Self {
        Self(f)
    }
}

#[allow(clippy::from_over_into)]
impl Into<Fq> for CommitmentTrapdoor {
    fn into(self) -> Fq {
        self.0
    }
}

// =============================================================================
// Note
// =============================================================================

/// A Tachyon note.
///
/// Represents a discrete unit of value in the Tachyon shielded pool.
/// Created by output operations, consumed by spend operations.
#[derive(Clone, Debug, Copy)]
pub struct Note {
    /// The recipient's payment key.
    pub pk: PaymentKey,

    /// The note value in zatoshis.
    pub value: u64,

    /// The nullifier trapdoor ($\psi$).
    pub psi: NullifierTrapdoor,

    /// Note commitment trapdoor ($rcm$).
    pub rcm: CommitmentTrapdoor,
}

impl Note {
    /// Computes the note commitment `cmx`.
    ///
    /// Commits to $(pk, v, \psi)$ with randomness $rcm$
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        // TODO: Implement note commitment
        //   $cmx = \text{NoteCommit}_{rcm}(\text{"z.cash:Tachyon-NoteCommit"}, pk \| v \| \psi)$
        todo!("note commitment");
        Commitment::from(Fp::ZERO)
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
        todo!("GGM tree PRF nullifier derivation");
        Nullifier::from(Fp::ZERO)
    }
}

// =============================================================================
// Note commitment (cmx)
// =============================================================================

/// A Tachyon note commitment (`cmx`).
///
/// A field element produced by committing to the note fields. This is
/// the value that becomes a tachygram:
/// - For **output** operations, `cmx` IS the tachygram directly.
/// - For **spend** operations, `cmx` is a private witness; the
///   tachygram is the derived nullifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(Fp);

impl From<Fp> for Commitment {
    fn from(f: Fp) -> Self {
        Self(f)
    }
}

impl From<Commitment> for Fp {
    fn from(cm: Commitment) -> Self {
        cm.0
    }
}

#[allow(clippy::from_over_into)]
impl Into<Tachygram> for Commitment {
    fn into(self) -> Tachygram {
        Tachygram::from(self.0)
    }
}

// =============================================================================
// Nullifier
// =============================================================================

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nullifier(Fp);

impl From<Fp> for Nullifier {
    fn from(f: Fp) -> Self {
        Self(f)
    }
}

impl From<Nullifier> for Fp {
    fn from(nf: Nullifier) -> Self {
        nf.0
    }
}

#[allow(clippy::from_over_into)]
impl Into<Tachygram> for Nullifier {
    fn into(self) -> Tachygram {
        Tachygram::from(self.0)
    }
}
