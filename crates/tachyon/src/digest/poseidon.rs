//! Tachyon Poseidon digests.
//!
//! Each named function provides one protocol-defined hash.

use ff::PrimeField as _;
use pasta_curves::{EpAffine, EqAffine, Fp, arithmetic::Coordinates};
use ragu::Sponge;

use crate::EpochIndex;

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
pub(crate) fn payment_key(ak: Fp, nk: Fp) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*PAYMENT_KEY_DOMAIN)),
        ak,
        nk,
    ])
}

const NOTE_COMMITMENT_DOMAIN: &[u8; 16] = b"Tachyon-CmDerive";

/// Derives the note-commitment pair `(cm0, cm1)` from note fields: two
/// squeezes of the same sponge (`ragu`'s Poseidon sponge has rate 4, so both
/// come from a single permutation — no extra secret material, no extra
/// domain, no extra permutation).
#[expect(
    clippy::expect_used,
    reason = "mock sponge absorb/squeeze cannot fail in wireless `Always` mode"
)]
#[must_use]
pub(crate) fn note_commitment_pair(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> (Fp, Fp) {
    let mut sponge = Sponge::new();
    for input in [
        Fp::from_u128(u128::from_le_bytes(*NOTE_COMMITMENT_DOMAIN)),
        rcm,
        pk,
        Fp::from(value),
        psi,
    ] {
        sponge.absorb(input).expect("infallible");
    }
    let cm0 = sponge.squeeze().expect("infallible");
    let cm1 = sponge.squeeze().expect("infallible");
    (cm0, cm1)
}

const NULLIFIER_PREFIX_DOMAIN: &[u8; 16] = b"Tachyon-NfPrefix";

/// Derives a GGM root (master key) from note trapdoor and wallet nullifier key.
#[must_use]
pub(crate) fn nf_master(psi: Fp, nk: Fp) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*NULLIFIER_PREFIX_DOMAIN)),
        psi,
        nk,
    ])
}

/// Derives a nullifier prefix from a previous prefix and a walk direction.
#[must_use]
pub(crate) fn nf_prefix(prefix_prev: Fp, step: u8) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*NULLIFIER_PREFIX_DOMAIN)),
        prefix_prev,
        Fp::from(u64::from(step)), // TODO: chunk some booleans by arity?
    ])
}

const NULLIFIER_DOMAIN: &[u8; 16] = b"Tachyon-NfDerive";

/// Derives a nullifier from a leaf of the prefix tree.
#[must_use]
pub(crate) fn nullifier(leaf: Fp) -> Fp {
    hash::<2>([Fp::from_u128(u128::from_le_bytes(*NULLIFIER_DOMAIN)), leaf])
}

const ANCHOR_STAMP_DOMAIN: &[u8; 16] = b"Tachyon-StampFld";

/// Advances the anchor by absorbing one stamp's tachygram-set commitment.
#[must_use]
pub(crate) fn anchor_stamp_step(anchor_prev: Fp, tgs: Coordinates<EqAffine>) -> Fp {
    let (x, y) = (tgs.x().to_repr(), tgs.y().to_repr());

    #[expect(clippy::expect_used, reason = "constant size decomposition")]
    let (x_lo, x_hi, y_lo, y_hi) = (
        Fp::from_u128(u128::from_le_bytes(x[..16].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(x[16..].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(y[..16].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(y[16..].try_into().expect("16 bytes"))),
    );

    hash::<6>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_STAMP_DOMAIN)),
        anchor_prev,
        x_lo,
        x_hi,
        y_lo,
        y_hi,
    ])
}

const ANCHOR_EMPTY_DOMAIN: &[u8; 16] = b"Tachyon-EmptyBlk";

/// Advances the anchor through one block that contains zero stamps.
#[must_use]
pub(crate) fn anchor_empty_step(anchor_prev: Fp) -> Fp {
    hash::<2>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_EMPTY_DOMAIN)),
        anchor_prev,
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
