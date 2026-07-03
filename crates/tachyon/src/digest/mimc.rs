//! The key-expansion cipher: `mk` keys a 32-round MiMC core whose whitened
//! outputs are the emitter cipher's round keys. These are the low-level
//! per-element operations; [`NoteMasterKey`](crate::keys::NoteMasterKey)
//! composes them into the full
//! [`EmitterKeySchedule`](crate::keys::EmitterKeySchedule), feeding the secret
//! affine inputs and the dedicated whitening key from its
//! [`ExpansionParams`](crate::keys::ExpansionParams).

use pasta_curves::Fp;
use zcash_mimc::spec::tachyon::TachyonP5R32;

use crate::keys::NoteMasterKey;

/// One key of the emitter schedule: the expansion cipher core on `input`,
/// finished with the dedicated `whitening` key (not the cyclic
/// `round_keys[ROUNDS % len]` wrap, which would reuse round key `0` at both
/// ends).
#[must_use]
pub(crate) fn schedule_key(
    round_keys: &[Fp; NoteMasterKey::MK_LENGTH],
    input: Fp,
    whitening: Fp,
) -> Fp {
    schedule_key_trace(round_keys, input, whitening).1
}

/// The per-round state trace behind one [`schedule_key`] output, with the
/// whitened final key.
#[must_use]
pub(crate) fn schedule_key_trace(
    round_keys: &[Fp; NoteMasterKey::MK_LENGTH],
    input: Fp,
    whitening: Fp,
) -> ([Fp; TachyonP5R32::ROUNDS], Fp) {
    let state_sequence = zcash_mimc::state_sequence::<TachyonP5R32, Fp, 5, 32>(round_keys, input);

    let output = state_sequence[TachyonP5R32::ROUNDS - 1] + whitening;

    (state_sequence, output)
}
