use alloc::vec::Vec;

use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

use super::*;

const MAX_INDEX: u64 = 0xFFFF_FFFE;

#[test]
fn member_encoding_is_the_cubed_linear_factor() {
    let rng = &mut StdRng::seed_from_u64(0);
    for idx in [0, 96, MAX_INDEX] {
        let member = Fp::random(|bytes| rng.fill_bytes(bytes));
        let x = Fp::random(|bytes| rng.fill_bytes(bytes));

        let linear = [member, Fp::from(idx) + Fp::ONE];
        let mut coeffs = arithmetic::poly_mul(&arithmetic::poly_mul(&linear, &linear), &linear);
        coeffs[0] -= NON_RESIDUE;
        let cubed = Polynomial::<Fp, ProductionRank>::from_coeffs(coeffs);

        let encoded =
            Polynomial::<Fp, ProductionRank>::from_coeffs(encode_single(idx, member).to_vec());
        assert_eq!(encoded.eval(x), cubed.eval(x), "index {idx}: cubed");
        assert_eq!(
            encoded.eval(x),
            direct_eval([(idx, member)], x),
            "index {idx}: direct"
        );
    }
}

#[test]
fn direct_evaluation_matches_the_encoding() {
    let rng = &mut StdRng::seed_from_u64(0);
    let index_lists: [&[u64]; 4] = [
        &[],
        &[0],
        &[96, 96],
        &[0, 1, 96, MAX_INDEX, 96, 2, MAX_INDEX, 3],
    ];
    for indices in index_lists {
        let members: Vec<(u64, Fp)> = indices
            .iter()
            .map(|&idx| (idx, Fp::random(|bytes| rng.fill_bytes(bytes))))
            .collect();
        let x = Fp::random(|bytes| rng.fill_bytes(bytes));
        assert_eq!(
            direct_eval(members.iter().copied(), x),
            encode(members).eval(x),
            "indices {indices:?}"
        );
    }
}
