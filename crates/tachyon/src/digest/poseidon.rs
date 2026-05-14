//! Tachyon Poseidon digests.
//!
//! Each named function matches one protocol-defined hash. All use
//! `halo2_poseidon::P128Pow5T3` over the Pallas base field with a
//! 16-byte domain tag absorbed into the input.

// TODO(#39): replace halo2_poseidon with Ragu Poseidon params

use ff::PrimeField as _;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{EpAffine, EqAffine, Fp, arithmetic::Coordinates};

const NOTE_MASTER_DOMAIN: &[u8; 16] = b"Tachyon-MkDerive";
const NOTE_NULLIFIER_DOMAIN: &[u8; 16] = b"Tachyon-NfDerive";
const NOTE_COMMITMENT_DOMAIN: &[u8; 16] = b"Tachyon-CmDerive";
const DELEGATION_DOMAIN: &[u8; 16] = b"Tachyon-Delegate";
const STAMP_FOLD_DOMAIN: &[u8; 16] = b"Tachyon-StampFld";
const EMPTY_BLOCK_DOMAIN: &[u8; 16] = b"Tachyon-EmptyBlk";
const EPOCH_STEP_DOMAIN: &[u8; 16] = b"Tachyon-EpochStp";
const ACTION_DOMAIN: &[u8; 16] = b"Tachyon-ActnDgst";
const PAYMENT_KEY_DOMAIN: &[u8; 16] = b"Tachyon-PkDerive";

fn hash<const L: usize>(input: [Fp; L]) -> Fp {
    Hash::<Fp, P128Pow5T3, ConstantLength<L>, 3, 2>::init().hash(input)
}

/// Note commitment $H(\text{dom}, rcm, pk, v, \psi)$.
#[must_use]
pub fn note_commitment(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*NOTE_COMMITMENT_DOMAIN)),
        rcm,
        pk,
        Fp::from(value),
        psi,
    ])
}

/// Per-note master key $mk = H(\text{dom}, \psi, nk)$.
#[must_use]
pub fn note_master(psi: Fp, nk: Fp) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*NOTE_MASTER_DOMAIN)),
        psi,
        nk,
    ])
}

/// Delegation id $H(\text{dom}, mk, cm, \mathit{trap})$.
#[must_use]
pub fn delegation_id(mk: Fp, cm: Fp, trap: Fp) -> Fp {
    hash::<4>([
        Fp::from_u128(u128::from_le_bytes(*DELEGATION_DOMAIN)),
        mk,
        cm,
        trap,
    ])
}

/// Payment key $pk = H(\text{dom}, ak, nk)$.
#[must_use]
pub fn payment_key(ak: Fp, nk: Fp) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*PAYMENT_KEY_DOMAIN)),
        ak,
        nk,
    ])
}

/// One GGM tree step $H(\text{dom}, \mathit{node}, \mathit{chunk})$.
#[must_use]
pub fn ggm_step(node: Fp, chunk: u8) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*NOTE_NULLIFIER_DOMAIN)),
        node,
        Fp::from(u64::from(chunk)), // TODO: chunk some booleans by arity?
    ])
}

/// Action digest $H(\text{dom}, cv_x, cv_y, rk_x, rk_y)$.
pub(crate) fn action_digest(cv: Coordinates<EpAffine>, rk: Coordinates<EpAffine>) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*ACTION_DOMAIN)),
        *cv.x(),
        *cv.y(),
        *rk.x(),
        *rk.y(),
    ])
}

/// Per-stamp anchor advance $H(\text{dom}, \mathit{prev}, x_{lo}, x_{hi},
/// y_{lo}, y_{hi})$. Absorbs the curve coordinates of a stamp's tachygram-set
/// commitment into the running anchor.
#[must_use]
pub fn anchor_stamp_step(prev: Fp, update: Coordinates<EqAffine>) -> Fp {
    let (x, y) = (update.x().to_repr(), update.y().to_repr());

    #[expect(clippy::expect_used, reason = "constant size decomposition")]
    let [x_lo, x_hi, y_lo, y_hi] = [
        Fp::from_u128(u128::from_le_bytes(x[..16].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(x[16..].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(y[..16].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(y[16..].try_into().expect("16 bytes"))),
    ];

    hash::<6>([
        Fp::from_u128(u128::from_le_bytes(*STAMP_FOLD_DOMAIN)),
        prev,
        x_lo,
        x_hi,
        y_lo,
        y_hi,
    ])
}

/// Empty-block anchor tick $H(\text{dom}, \mathit{prev})$. Advances
/// the anchor through one block that contains zero stamps, preserving
/// per-height anchor uniqueness.
#[must_use]
pub fn anchor_empty_step(prev: Fp) -> Fp {
    hash::<2>([
        Fp::from_u128(u128::from_le_bytes(*EMPTY_BLOCK_DOMAIN)),
        prev,
    ])
}

/// Cross-epoch boundary lift $H(\text{dom}, \mathit{prev},
/// \mathit{new\_epoch})$. Performed by `SpendableRollover` to lift the old
/// epoch's terminal anchor into the new epoch's initial anchor.
#[must_use]
pub fn anchor_epoch_step(prev: Fp, new_epoch: u32) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*EPOCH_STEP_DOMAIN)),
        prev,
        Fp::from(u64::from(new_epoch)),
    ])
}
