use pasta_curves::Fp;
use zcash_mimc::specs::tachyon::TachyonP5R64;

/// Produce one nullifier.
#[must_use]
pub(super) fn nullifier(key: Fp, input: Fp, whitening: Fp) -> Fp {
    zcash_mimc::encrypt_with::<TachyonP5R64, 64>(&[key], input, Some(whitening))
}

/// Produce the per-round state trace for one nullifier.
///
/// The final state in this trace is not yet whitened.
#[must_use]
pub(super) fn nullifier_trace(key: Fp, input: Fp) -> [Fp; 64] {
    zcash_mimc::sbox_output_sequence::<TachyonP5R64, 64>(&[key], input)
}
