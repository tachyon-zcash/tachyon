//! The GGM child cipher: a tree node's key schedule keys a 128-round MiMC
//! core whose whitened outputs are the child schedules (and, at the leaf
//! level, the nullifiers themselves). These are the low-level per-element
//! operations; [`keys::ggm`](crate::keys) composes them into whole-node
//! expansions, feeding the secret affine inputs and the dedicated whitening
//! key from the node's expansion parameters.

use pasta_curves::Fp;
use zcash_mimc::spec::tachyon::TachyonP5R128;

/// One expansion output: the child cipher core on `input` under the cyclic
/// key schedule `keys`, finished with the dedicated `whitening` key (not the
/// cyclic `keys[ROUNDS % len]` wrap, which would reuse a schedule key at both
/// ends).
#[must_use]
pub(crate) fn schedule_key(keys: &[Fp], input: Fp, whitening: Fp) -> Fp {
    schedule_key_trace(keys, input, whitening).1
}

/// The per-round state trace behind one [`schedule_key`] output, with the
/// whitened final key.
#[must_use]
pub(crate) fn schedule_key_trace(
    keys: &[Fp],
    input: Fp,
    whitening: Fp,
) -> ([Fp; TachyonP5R128::ROUNDS], Fp) {
    let state_sequence = zcash_mimc::state_sequence::<TachyonP5R128, Fp, 5, 128>(keys, input);

    let output = state_sequence[TachyonP5R128::ROUNDS - 1] + whitening;

    (state_sequence, output)
}
