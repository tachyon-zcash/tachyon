//! Signed odd-digit radix-8 encoding of canonical digest bits.

use core::array;

use udon::field::Field as _;

use crate::pasta::{Fp, Fq};

/// The scalar a digest $h$ denotes, read as a signed odd-digit radix-8 sum:
///
/// $$
///   \sum_{i=0}^{84} (2 s_i - 1)(1 + 2 m_i + 4 n_i) \cdot 8^i \bmod q,
/// $$
///
/// where $(s_i, m_i, n_i)$ are bits $3i$, $3i + 1$ and $3i + 2$ of the
/// canonical little-endian encoding of $h$.
pub(crate) fn read(digest: Fp) -> Fq {
    let bits = digest
        .to_bytes()
        .map(|byte| array::from_fn::<u8, 8, _>(|shift| (byte >> shift) & 1));
    let (windows, _) = bits.as_flattened().as_chunks::<3>();
    windows
        .iter()
        .rev()
        .fold(Fq::ZERO, |acc, &[sign, low, high]| {
            let magnitude = Fq::from(u64::from(1 + 2 * low + 4 * high));
            acc * Fq::from(8u64) + if sign == 1 { magnitude } else { -magnitude }
        })
}

#[cfg(test)]
mod tests;
