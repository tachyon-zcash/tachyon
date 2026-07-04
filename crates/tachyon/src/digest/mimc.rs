//! The key-expansion cipher: `mk` keys a 32-round MiMC instance whose outputs
//! are the emitter cipher's round keys. These are the low-level per-element
//! operations; [`NoteMasterKey`](crate::keys::NoteMasterKey) composes them into
//! the full [`EmitterKeySchedule`](crate::keys::EmitterKeySchedule).

use pasta_curves::Fp;
use zcash_mimc::spec::tachyon::TachyonP5R32;

use crate::keys::NoteMasterKey;

/// One key of the emitter schedule: the expansion cipher's output at
/// `salt + index` under the master key's round keys.
#[must_use]
pub(crate) fn schedule_key(salt: Fp, round_keys: &[Fp; NoteMasterKey::MK_LENGTH], index: Fp) -> Fp {
    zcash_mimc::encrypt_with::<TachyonP5R32, Fp, 5, 32>(round_keys, salt + index)
}

/// The per-round state trace behind one [`schedule_key`] output, with the
/// whitened final key.
#[must_use]
pub(crate) fn schedule_key_trace(
    salt: Fp,
    round_keys: &[Fp; NoteMasterKey::MK_LENGTH],
    index: Fp,
) -> ([Fp; TachyonP5R32::ROUNDS], Fp) {
    let state_sequence =
        zcash_mimc::state_sequence::<TachyonP5R32, Fp, 5, 32>(round_keys, salt + index);

    #[expect(
        clippy::indexing_slicing,
        clippy::integer_division_remainder_used,
        reason = "sequence length matches expected"
    )]
    let output = state_sequence[TachyonP5R32::ROUNDS - 1]
        + round_keys[TachyonP5R32::ROUNDS % round_keys.len()];

    (state_sequence, output)
}
