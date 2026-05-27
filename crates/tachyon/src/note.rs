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
//! | `psi` | [`ProNfSeqCommit`] | Commitment to the pronullifier sequence ($\psi = \sum_i M_i G_i$) |
//! | `rcm` | [`CommitmentTrapdoor`] | Note commitment randomness |
//!
//! $rcm$ can be derived from a shared key negotiated through the out-of-band
//! payment protocol; $\psi$ is the recipient's commitment to its pronullifier
//! polynomial $M$, supplied in the payment request.
//!
//! ## Nullifier Derivation
//!
//! Each epoch's nullifier is a coefficient of the recipient's pronullifier
//! polynomial $M$ shifted by the note commitment, $\mathsf{nf}_e = M_e +
//! \mathsf{cm}$, with $M$ committed as $\psi = \sum_i M_i G_i$ and frozen
//! into `cm`. Wallets read pronullifiers from $M$ natively; the Ragu proof
//! tree binds the published nullifier sequence to $\psi$ through the lift
//! relation rather than re-deriving it.
//!
//! ## Note Commitment
//!
//! A commitment over the note fields, producing a `cm` tachygram that
//! enters the polynomial accumulator. The concrete commitment scheme
//! (e.g. Sinsemilla, Poseidon) depends on what is efficient inside
//! Ragu circuits and is TBD.
use core::fmt;

use ff::Field as _;
use pasta_curves::{EqAffine, Fp, arithmetic::CurveAffine as _};
use rand_core::{CryptoRng, RngCore};

use crate::{
    constants::NOTE_VALUE_MAX,
    digest::poseidon,
    keys::PaymentKey,
    primitives::{ProNfSeqCommit, Tachygram},
};

/// Note commitment trapdoor ($rcm$) — randomness that blinds the note
/// commitment.
///
/// Can be derived from a shared secret negotiated out-of-band.
#[derive(Clone, Copy)]
pub struct CommitmentTrapdoor(Fp);

impl CommitmentTrapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
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

    /// Commitment to the note's pronullifier polynomial ($\psi =
    /// \sum_i M_i G_i$).
    pub psi: ProNfSeqCommit,

    /// Note commitment trapdoor ($rcm$).
    pub rcm: CommitmentTrapdoor,
}

/// A note value in zatoshis. Non-zero and no greater than 2.1e15.
///
/// Zero-valued notes are forbidden by construction: a zero-value action
/// carries no economic meaning. The newtype enforces the invariant at
/// `Value::from` (panics on zero and on overflow). Each PCD step that
/// witnesses a `value` *independently* rechecks `value != 0` — the
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
    /// Computes the note commitment `cm` using the stored `note.psi`.
    ///
    /// Commits to $(pk, v, \psi)$ with randomness $rcm$, where $\psi =
    /// \sum_i M_i G_i$ is digested by bit-decomposing its Vesta
    /// coordinates (see [`poseidon::note_commitment`]).
    ///
    /// # Panics
    ///
    /// Panics if the note commitment trapdoor is zero, or if $\psi$ is the
    /// identity point.
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        assert_ne!(
            self.rcm.0,
            Fp::ZERO,
            "note commitment trapdoor must be nonzero (rcm = 0 collapses hiding)"
        );
        let psi_eq: EqAffine = self.psi.into();
        Commitment(poseidon::note_commitment(
            self.rcm.0,
            self.pk.0,
            self.value.0,
            psi_eq.coordinates().expect("valid psi"),
        ))
    }
}

/// A Tachyon note commitment (`cm`).
///
/// A field element produced by committing to the note fields. This is
/// the value that becomes a tachygram:
/// - For **output** operations, `cm` IS the tachygram directly.
/// - For **spend** operations, `cm` is a private witness.
#[derive(Clone, Copy, Eq, PartialEq)]
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

impl From<Commitment> for Tachygram {
    fn from(commitment: Commitment) -> Self {
        Self::from(commitment.0)
    }
}

impl Commitment {
    /// Shift a pronullifier by this note commitment to obtain the published
    /// nullifier: $\mathsf{nf}_e = M_e + \mathsf{cm}$.
    #[must_use]
    pub fn nullify(self, pronf: ProNf) -> Nullifier {
        Nullifier::from(Fp::from(pronf) + self.0)
    }
}

/// A Tachyon nullifier.
///
/// A [`ProNf`] (one coefficient of the note's pronullifier polynomial $M$, one
/// per epoch) shifted by the note commitment: $\mathsf{nf}_e = M_e +
/// \mathsf{cm}$. The shift makes each note's nullifier sequence distinct even
/// when two notes share the same $M$. Published when a note is spent; becomes a
/// tachygram in the polynomial accumulator.
///
/// Unlike Orchard, Tachyon nullifiers:
/// - Don't need collision resistance (no faerie gold defense)
/// - Are indexed per-epoch for sync delegation
/// - Are prunable by validators after a window of blocks
#[derive(Clone, Copy, Eq, PartialEq)]
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

impl From<Nullifier> for Tachygram {
    fn from(nullifier: Nullifier) -> Self {
        Self::from(nullifier.0)
    }
}

/// The raw pronullifier coefficient $M_e$ that becomes a [`Nullifier`] once
/// shifted by the note commitment: $\mathsf{nf}_e = M_e + \mathsf{cm}$.
///
/// Same-$M$ notes get distinct nullifier sequences because each shifts by its
/// own `cm`. Unlike a [`Nullifier`], a `ProNf` is never published (no
/// [`Tachygram`] conversion): it stays private while its shifted form, the
/// nullifier, is published.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProNf(Fp);

impl ProNf {
    /// Generate a random pronullifier.
    #[must_use]
    pub fn random<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
        Self::from(Fp::random(rng))
    }
}

impl From<Fp> for ProNf {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

impl From<ProNf> for Fp {
    fn from(pre_nf: ProNf) -> Self {
        pre_nf.0
    }
}

impl fmt::Debug for CommitmentTrapdoor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitmentTrapdoor").finish_non_exhaustive()
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Commitment").finish_non_exhaustive()
    }
}

impl fmt::Debug for Nullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nullifier").finish_non_exhaustive()
    }
}

impl fmt::Debug for ProNf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProNf").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;
    use core::iter;

    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{constants::NOTE_VALUE_MAX, primitives::ProNfSeqPoly};

    /// A random pronullifier-polynomial commitment, standing in for
    /// `commit(M)`.
    fn random_psi(rng: &mut StdRng) -> ProNfSeqCommit {
        let pronfs: Vec<ProNf> = iter::repeat_with(|| ProNf::random(rng)).take(8).collect();
        ProNfSeqPoly::from(pronfs.as_slice()).commit()
    }

    /// `Commitment::nullify` is exactly the `+ cm` shift, and `ProNf`
    /// round-trips through `Fp`.
    #[test]
    fn nullify_shifts_by_cm() {
        let rng = &mut StdRng::seed_from_u64(0);
        let coefficient = Fp::random(&mut *rng);
        let cm = Commitment::from(Fp::random(&mut *rng));

        assert_eq!(Fp::from(ProNf::from(coefficient)), coefficient);
        assert_eq!(
            Fp::from(cm.nullify(ProNf::from(coefficient))),
            coefficient + Fp::from(cm)
        );
    }

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
        let rng = &mut StdRng::seed_from_u64(0);
        let pk = PaymentKey(Fp::random(&mut *rng));
        let psi = random_psi(rng);

        let note1 = Note {
            pk,
            value: Value::from(100u64),
            psi,
            rcm: CommitmentTrapdoor::random(rng),
        };
        let note2 = Note {
            pk,
            value: Value::from(100u64),
            psi,
            rcm: CommitmentTrapdoor::random(rng),
        };

        assert_ne!(note1.commitment(), note2.commitment());
    }

    /// Distinct pronullifier-sequence commitments produce distinct note
    /// commitments — `psi = commit(M)` is bound into `cm`.
    #[test]
    fn distinct_psi_distinct_commitments() {
        let rng = &mut StdRng::seed_from_u64(0);
        let pk = PaymentKey(Fp::random(&mut *rng));
        let rcm = CommitmentTrapdoor::random(rng);

        let note1 = Note {
            pk,
            value: Value::from(100u64),
            psi: random_psi(rng),
            rcm,
        };
        let note2 = Note {
            pk,
            value: Value::from(100u64),
            psi: random_psi(rng),
            rcm,
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

    #[test]
    fn debug_nullifier_redacts_value() {
        let nf = Nullifier::from(Fp::from(0xBEEFu64));
        let dbg = alloc::format!("{nf:?}");
        assert!(dbg.contains("Nullifier"), "must name the type");
        assert!(!dbg.contains("BEEF"), "must not leak field element");
        assert!(!dbg.contains("48879"), "must not leak decimal value");
    }

    #[test]
    fn debug_pronf_redacts_value() {
        // ProNf carries the secret pre-nullifier; its Debug must not leak it.
        let pronf = ProNf::from(Fp::from(0xBEEFu64));
        let dbg = alloc::format!("{pronf:?}");
        assert!(dbg.contains("ProNf"), "must name the type");
        assert!(!dbg.contains("BEEF"), "must not leak field element");
        assert!(!dbg.contains("48879"), "must not leak decimal value");
    }
}
