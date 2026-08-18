//! Tachyon Poseidon digests.
//!
//! Each named function provides one protocol-defined hash.

use core::array;

use ff::PrimeField as _;
use group::{Curve as _, GroupEncoding as _, prime::PrimeCurveAffine as _};
use pasta_curves::{EpAffine, Eq, EqAffine, Fp, arithmetic::Coordinates};
use ragu::Sponge;

use crate::EpochIndex;

/// Epoch nullifiers derived per sponge, the rate of ragu's `PoseidonFp`
/// ($T = 5$, rate 4), which ragu does not export.
pub(crate) const NF_GROUP: usize = 4;

#[expect(
    clippy::expect_used,
    reason = "mock sponge absorb/squeeze cannot fail in wireless `Always` mode"
)]
fn hash<const L: usize>(input: [Fp; L]) -> Fp {
    let mut sponge = Sponge::new();
    for value in input {
        sponge.absorb(value).expect("infallible");
    }
    sponge.squeeze().expect("infallible")
}

const ACTION_DIGEST_DOMAIN: &[u8; 16] = b"Tachyon-ActionDg";

/// Derives an action digest from action fields.
pub(crate) fn action_digest(cv: Coordinates<EpAffine>, rk: Coordinates<EpAffine>) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*ACTION_DIGEST_DOMAIN)),
        *cv.x(),
        *cv.y(),
        *rk.x(),
        *rk.y(),
    ])
}

const PAYMENT_KEY_DOMAIN: &[u8; 16] = b"Tachyon-PkDerive";

/// Derives a payment key from a spend validating key and nullifier key.
#[must_use]
pub(crate) fn payment_key(ak: Coordinates<EpAffine>, nk: Fp) -> Fp {
    hash::<4>([
        Fp::from_u128(u128::from_le_bytes(*PAYMENT_KEY_DOMAIN)),
        *ak.x(),
        *ak.y(),
        nk,
    ])
}

const NOTE_COMMITMENT_DOMAIN: &[u8; 16] = b"Tachyon-CmDerive";

/// Derives a note commitment from note fields.
#[must_use]
pub(crate) fn note_commitment(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*NOTE_COMMITMENT_DOMAIN)),
        rcm,
        pk,
        Fp::from(value),
        psi,
    ])
}

const PAD_TACHYGRAM_DOMAIN: &[u8; 16] = b"Tachyon-PadDeriv";

/// Derives an output's padding tachygram from the same note fields
/// [`note_commitment`] commits to.
///
/// The preimage is the note opening rather than the commitment: both values are
/// published in one multiset, so a pad derived from $\mathsf{cm}$ would let an
/// observer pair them off and recover the output count.
#[must_use]
pub(crate) fn pad_tachygram(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*PAD_TACHYGRAM_DOMAIN)),
        rcm,
        pk,
        Fp::from(value),
        psi,
    ])
}

const NULLIFIER_MASTER_DOMAIN: &[u8; 16] = b"Tachyon-NfMaster";

/// Derives a note's master key from its trapdoor and the wallet nullifier key.
///
/// $\mathsf{mk} = \mathsf{Poseidon}(\mathtt{NF\_MASTER\_DOMAIN}, \psi,
/// \mathsf{nk})$
#[must_use]
pub(crate) fn nf_master(psi: Fp, nk: Fp) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*NULLIFIER_MASTER_DOMAIN)),
        psi,
        nk,
    ])
}

const NULLIFIER_DOMAIN: &[u8; 16] = b"Tachyon-NfDerive";

/// Derives one group of [`NF_GROUP`] consecutive epoch nullifiers from the
/// note's master key.
///
/// With $w$ the group index and $j$ the squeeze ordinal, the epoch
/// $e = \mathsf{NF\_GROUP} \cdot w + j$ has
///
/// $$
/// \mathsf{nf}_e = \mathsf{squeeze}_j\big(
///     \mathsf{absorb}(\mathtt{NF\_DOMAIN},\ \mathsf{mk},\ w)\big).
/// $$
///
/// Three absorbs stay inside the sponge rate, so the first squeeze is the
/// group's only permutation and the remaining $\mathsf{NF\_GROUP} - 1$ come
/// from the same permutation's output buffer. Each group re-absorbs $w$, so
/// $\mathsf{nf}_e$ is a function of $(\mathsf{mk}, e)$ alone and overlapping
/// derivation windows agree on the epochs they share.
#[expect(
    clippy::expect_used,
    reason = "mock sponge absorb/squeeze cannot fail in wireless `Always` mode"
)]
#[must_use]
pub(crate) fn nullifier_group(mk: Fp, group: u32) -> [Fp; NF_GROUP] {
    let mut sponge = Sponge::new();
    for value in [
        Fp::from_u128(u128::from_le_bytes(*NULLIFIER_DOMAIN)),
        mk,
        Fp::from(u64::from(group)),
    ] {
        sponge.absorb(value).expect("infallible");
    }
    array::from_fn(|_| sponge.squeeze().expect("infallible"))
}

const NF_READ_DOMAIN: &[u8; 16] = b"Tachyon-NfReadCh";

/// The challenge for a covering read whose members enter as scalar
/// monomials, over the three polynomial commitments and every member.
///
/// A scalar member has no commitment, and the read identity is linear in
/// each, so every member is absorbed: that makes the solve a fixed point and
/// forces each member to the covering sequence's genuine coefficient. The
/// witness is built from this challenge, so it must be a Poseidon digest the
/// native witness builders replicate.
///
/// # Panics
///
/// Panics if any commitment is the identity point.
#[expect(
    clippy::expect_used,
    reason = "mock sponge absorb/squeeze cannot fail in wireless `Always` mode"
)]
#[must_use]
pub(crate) fn read_challenge(g: Eq, older: Eq, tail: Eq, members: &[Fp]) -> Fp {
    let (g_lo, g_hi) = point_limbs(g.to_affine());
    let (older_lo, older_hi) = point_limbs(older.to_affine());
    let (tail_lo, tail_hi) = point_limbs(tail.to_affine());
    let mut sponge = Sponge::new();
    for value in [
        Fp::from_u128(u128::from_le_bytes(*NF_READ_DOMAIN)),
        g_lo,
        g_hi,
        older_lo,
        older_hi,
        tail_lo,
        tail_hi,
    ] {
        sponge.absorb(value).expect("infallible");
    }
    for &member in members {
        sponge.absorb(member).expect("infallible");
    }
    sponge.squeeze().expect("infallible")
}

/// A Vesta point's compressed encoding as two 128-bit $\mathbb{F}_p$ limbs.
///
/// The 32-byte encoding carries $x$ with the sign of $y$ in its high bit, so
/// the limb pair determines the point. Each limb reads 16 bytes little-endian,
/// far below the $\mathbb{F}_p$ modulus.
///
/// # Panics
///
/// Panics if `point` is the identity.
#[expect(clippy::expect_used, reason = "constant-size decomposition")]
fn point_limbs(point: EqAffine) -> (Fp, Fp) {
    assert!(
        !bool::from(point.is_identity()),
        "commitment must not be the identity point"
    );

    let encoding = point.to_bytes();
    let (lo, hi) = encoding.split_at(16);
    (
        Fp::from_u128(u128::from_le_bytes(lo.try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(hi.try_into().expect("16 bytes"))),
    )
}

const ANCHOR_STAMP_DOMAIN: &[u8; 16] = b"Tachyon-StampFld";

/// Advances the anchor by absorbing one stamp's epoch and tachygram-set
/// commitment.
///
/// # Panics
///
/// Panics if `tgs` is the identity point.
#[must_use]
pub(crate) fn anchor_stamp_step(anchor_prev: Fp, epoch: EpochIndex, tgs: EqAffine) -> Fp {
    let (tgs_lo, tgs_hi) = point_limbs(tgs);
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_STAMP_DOMAIN)),
        anchor_prev,
        Fp::from(epoch),
        tgs_lo,
        tgs_hi,
    ])
}

const ANCHOR_EPOCH_DOMAIN: &[u8; 16] = b"Tachyon-EpochStp";

/// Advances the terminal anchor of an epoch into a new epoch's initial state.
#[must_use]
pub(crate) fn anchor_epoch_step(anchor_prev: Fp, new_epoch: EpochIndex) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_EPOCH_DOMAIN)),
        anchor_prev,
        Fp::from(new_epoch),
    ])
}
