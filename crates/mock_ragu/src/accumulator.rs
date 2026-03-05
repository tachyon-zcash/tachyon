//! Mock vector commitment via XOR-fold of BLAKE2b hashes.
//!
//! XOR is commutative and associative, giving order-independence —
//! matching the real Ragu accumulator's commutativity (point addition).

/// XOR-fold of individual BLAKE2b hashes over 32-byte elements.
///
/// Each element is hashed with `domain` as BLAKE2b personalization,
/// then the per-element hashes are XOR-folded into a single 32-byte digest.
#[must_use]
pub fn accumulate(domain: &[u8; 16], elements: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for element in elements {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(domain)
            .hash(element);
        xor_into(&mut acc, hash.as_bytes());
    }
    acc
}

/// XOR-fold over `(cv, rk)` byte pairs.
///
/// Each 64-byte concatenation is hashed, then folded.
#[must_use]
pub fn accumulate_pairs(domain: &[u8; 16], pairs: &[([u8; 32], [u8; 32])]) -> [u8; 32] {
    let mut acc = [0u8; 32];
    #[expect(
        clippy::pattern_type_mismatch,
        reason = "iterating borrowed slice of tuples"
    )]
    for (cv_bytes, rk_bytes) in pairs {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(domain)
            .to_state()
            .update(cv_bytes)
            .update(rk_bytes)
            .finalize();
        xor_into(&mut acc, hash.as_bytes());
    }
    acc
}

/// Combine two accumulators by XOR.
#[must_use]
pub fn combine(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    xor_into(&mut out, left);
    xor_into(&mut out, right);
    out
}

/// XOR `src` into `dst` byte-by-byte.
fn xor_into(dst: &mut [u8; 32], src: &[u8]) {
    for (dst_byte, src_byte) in dst.iter_mut().zip(src.iter()) {
        *dst_byte ^= src_byte;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulate_is_order_independent() {
        let domain = b"test_domain_0000";
        let elem_a = [0x01u8; 32];
        let elem_b = [0x02u8; 32];

        let ab = accumulate(domain, &[elem_a, elem_b]);
        let ba = accumulate(domain, &[elem_b, elem_a]);
        assert_eq!(ab, ba);
    }

    #[test]
    fn accumulate_pairs_is_order_independent() {
        let domain = b"test_pairs_00000";
        let pair_a = ([0x01u8; 32], [0x02u8; 32]);
        let pair_b = ([0x03u8; 32], [0x04u8; 32]);

        let ab = accumulate_pairs(domain, &[pair_a, pair_b]);
        let ba = accumulate_pairs(domain, &[pair_b, pair_a]);
        assert_eq!(ab, ba);
    }

    #[test]
    fn combine_matches_single_accumulate() {
        let domain = b"test_combine_000";
        let elem_a = [0x01u8; 32];
        let elem_b = [0x02u8; 32];

        let combined = accumulate(domain, &[elem_a, elem_b]);
        let left = accumulate(domain, &[elem_a]);
        let right = accumulate(domain, &[elem_b]);
        let merged = combine(&left, &right);
        assert_eq!(combined, merged);
    }

    #[test]
    fn distinct_elements_distinct_accumulators() {
        let domain = b"test_distinct_00";
        let acc_a = accumulate(domain, &[[0x01u8; 32]]);
        let acc_b = accumulate(domain, &[[0x02u8; 32]]);
        assert_ne!(acc_a, acc_b);
    }
}
