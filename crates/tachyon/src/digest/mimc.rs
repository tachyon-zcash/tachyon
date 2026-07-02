use pasta_curves::Fp;
use zcash_mimc::spec::tachyon::TachyonP5R32;

use crate::keys::NoteMasterKey;

/// Expands a note's master key into one element of the derivation keyset.
#[must_use]
pub(crate) fn mk_dk_expand(salt: Fp, round_keys: &[Fp; NoteMasterKey::MK_LENGTH], index: Fp) -> Fp {
    zcash_mimc::encrypt_with::<TachyonP5R32, Fp, 5, 32>(round_keys, salt + index)
}

/// The per-round state trace of one element of the derivation keyset.
#[must_use]
pub(crate) fn mk_dk_expand_sequence(
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
