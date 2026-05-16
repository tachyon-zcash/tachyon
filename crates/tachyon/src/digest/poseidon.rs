//! Tachyon Poseidon digests.
//!
//! Each named function matches one protocol-defined hash. All use
//! `halo2_poseidon::P128Pow5T3` over the Pallas base field with a
//! 16-byte domain tag absorbed into the input.

// TODO(#39): replace halo2_poseidon with Ragu Poseidon params

use ff::PrimeField as _;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{EpAffine, Fp, arithmetic::Coordinates};

const NOTE_MASTER_DOMAIN: &[u8; 16] = b"Tachyon-MkDerive";
const NOTE_NULLIFIER_DOMAIN: &[u8; 16] = b"Tachyon-NfDerive";
const NOTE_COMMITMENT_DOMAIN: &[u8; 16] = b"Tachyon-NoteCmmt";
const DELEGATION_DOMAIN: &[u8; 16] = b"Tachyon-Delegate";
const ACTION_DOMAIN: &[u8; 16] = b"Tachyon-ActnDgst";
const PAYMENT_KEY_DOMAIN: &[u8; 16] = b"Tachyon-PkDerive";

/// Note commitment $H(\text{dom}, rcm, pk, v, \psi)$.
pub(crate) fn note_commitment(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> Fp {
    Hash::<_, P128Pow5T3, ConstantLength<5>, 3, 2>::init().hash([
        Fp::from_u128(u128::from_le_bytes(*NOTE_COMMITMENT_DOMAIN)),
        rcm,
        pk,
        Fp::from(value),
        psi,
    ])
}

/// Per-note master key $mk = H(\text{dom}, \psi, nk)$.
pub(crate) fn note_master(psi: Fp, nk: Fp) -> Fp {
    Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
        Fp::from_u128(u128::from_le_bytes(*NOTE_MASTER_DOMAIN)),
        psi,
        nk,
    ])
}

/// Delegation id $H(\text{dom}, mk, cm, \mathit{trap})$.
pub(crate) fn delegation_id(mk: Fp, cm: Fp, trap: Fp) -> Fp {
    Hash::<_, P128Pow5T3, ConstantLength<4>, 3, 2>::init().hash([
        Fp::from_u128(u128::from_le_bytes(*DELEGATION_DOMAIN)),
        mk,
        cm,
        trap,
    ])
}

/// Payment key $pk = H(\text{dom}, ak, nk)$.
pub(crate) fn payment_key(ak: Fp, nk: Fp) -> Fp {
    Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
        Fp::from_u128(u128::from_le_bytes(*PAYMENT_KEY_DOMAIN)),
        ak,
        nk,
    ])
}

/// One GGM tree step $H(\text{dom}, \mathit{node}, \mathit{chunk})$.
pub(crate) fn ggm_step(node: Fp, chunk: u8) -> Fp {
    Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
        Fp::from_u128(u128::from_le_bytes(*NOTE_NULLIFIER_DOMAIN)),
        node,
        Fp::from(u64::from(chunk)),
    ])
}

/// Action digest $H(\text{dom}, cv_x, cv_y, rk_x, rk_y)$.
pub(crate) fn action_digest(cv: Coordinates<EpAffine>, rk: Coordinates<EpAffine>) -> Fp {
    Hash::<_, P128Pow5T3, ConstantLength<5>, 3, 2>::init().hash([
        Fp::from_u128(u128::from_le_bytes(*ACTION_DOMAIN)),
        *cv.x(),
        *cv.y(),
        *rk.x(),
        *rk.y(),
    ])
}
