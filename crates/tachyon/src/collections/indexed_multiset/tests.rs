use alloc::vec::Vec;

use rand::{Rng as _, RngExt as _, SeedableRng as _, rngs::StdRng};

use super::*;

#[test]
fn sequence_evaluation_matches_the_encoding() {
    let rng = &mut StdRng::seed_from_u64(12);
    for len in 0..6u64 {
        let start_idx = u64::from(rng.random_range(0..u32::MAX));
        let members: Vec<(u64, Fp)> = (start_idx..start_idx + len)
            .map(|idx| (idx, Fp::random(|bytes| rng.fill_bytes(bytes))))
            .collect();
        let x = Fp::random(|bytes| rng.fill_bytes(bytes));
        assert_eq!(
            direct_eval(members.iter().copied(), x),
            encode(members).eval(x)
        );
    }
}
