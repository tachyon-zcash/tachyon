//! # zcash_mimc
//!
//! The MiMC block cipher (additive construction, exponent $x^5$) over the
//! Pallas base field $\mathbb{F}_p$, per [eprint 2016/492] §2.1/§5.1: for
//! $i \in 0 \ldots r-1$, $x \gets (x + k + c_i)^5$; the ciphertext is the
//! final $x + k$, with $c_0 = 0$ and the same key added every round. Forward
//! direction only: no inverse cipher is provided, by design.
//!
//! ## Security posture
//!
//! - **Weak-PRF use only.** The key is per-note secret key material and inputs
//!   are never adversary-chosen. Binding and collision resistance live
//!   elsewhere (note commitment / Poseidon), not here.
//! - **MiMC is a cipher, not a hash.** Nothing in this API is collision
//!   resistant; do not use [`encrypt`] where a hash is required.
//! - **Fixed operation sequence.** Every round is square, square, multiply
//!   (three field multiplications) with a compile-time-fixed round count and no
//!   data-dependent branches, over `pasta_curves`' constant-time field
//!   arithmetic.
//! - **Key handling.** Keys are bare [`Fp`] arguments; this crate defines no
//!   key-holding types and hence derives no `Debug` over key material.
//!
//! The round count is a const generic; the deployed value is [`ROUNDS`].
//!
//! [eprint 2016/492]: https://eprint.iacr.org/2016/492

#![no_std]

use blake2b_simd::Params;
use ff::{Field as _, FromUniformBytes as _};
use lazy_static::lazy_static;
use pasta_curves::Fp;

/// Deployed MiMC round count.
///
/// Contested zone: r in [51, 110] pending external cryptanalysis; this is
/// the conservative ceiling. See
/// <https://github.com/tachyon-zcash/tachyon/issues/139>.
pub const ROUNDS: usize = 110;

/// Blake2b personalization for round-constant derivation (16 bytes,
/// versioned).
const ROUND_DOMAIN: &[u8; 16] = b"Tachyon-MiMCx5v1";

lazy_static! {
    /// Cached round-constant schedule for the deployed [`ROUNDS`]
    /// instantiation.
    static ref ROUND_CONSTANTS: [Fp; ROUNDS] = {
        let mut constants = [Fp::ZERO; ROUNDS];
        for (index, constant) in (1u64..).zip(constants.iter_mut().skip(1)) {
            *constant = {
                let digest = Params::new()
                    .hash_length(64)
                    .personal(ROUND_DOMAIN)
                    .to_state()
                    .update(&index.to_le_bytes())
                    .finalize();
                Fp::from_uniform_bytes(digest.as_array())
            };
        }
        constants
    };
}

/// Encrypts `input` under `key` with the deployed [`ROUNDS`]-round schedule
/// (cached constants).
///
/// Callable both wallet-side and inside step witness bodies: the body is
/// plain native [`Fp`] arithmetic with a compile-time-fixed iteration count.
#[must_use]
pub fn encrypt(key: Fp, input: Fp) -> Fp {
    encrypt_rounds::<ROUNDS>(key, input)
}

/// Encrypts `input` under `key` with an explicit `R`-round schedule,
/// deriving the round constants on every call.
///
/// Prefer [`encrypt`] for the deployed round count; this exists for
/// round-count variation and cross-checking
/// (<https://github.com/tachyon-zcash/tachyon/issues/139>). Compile-time
/// error if `R == 0`.
#[must_use]
pub fn encrypt_rounds<const R: usize>(key: Fp, input: Fp) -> Fp {
    let mut state = input;
    for constant in round_constants::<R>() {
        let base: Fp = state + key + constant;
        state = base.square().square().mul(&base);
    }
    state + key
}

/// The `R`-element schedule `[0, c_1, c_2, ..., c_{R-1}]`.
fn round_constants<const R: usize>() -> [Fp; R] {
    #[expect(clippy::expect_used, reason = "debug assertion")]
    *ROUND_CONSTANTS
        .split_first_chunk::<R>()
        .expect("round count must be less than or equal to ROUNDS")
        .0
}

#[cfg(test)]
mod tests;
