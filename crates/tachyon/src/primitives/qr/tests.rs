use alloc::vec::Vec;

use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

use super::*;

#[test]
fn the_root_profile_has_no_bits() {
    assert_eq!(QrProfile::ROOT.depth, 0);
    assert_eq!(QrProfile::ROOT.bits, 0);
}

#[test]
fn the_bits_record_the_splits_outermost_first() {
    let low = QrProfile::ROOT.descend(false).descend(false).descend(true);
    assert_eq!(low.depth, 3);
    assert_eq!(low.bits, 0b001);
    let high = QrProfile::ROOT.descend(true).descend(false).descend(false);
    assert_eq!(high.bits, 0b100);
}

#[test]
fn distinct_split_histories_yield_distinct_profiles() {
    let deep_zeroes = QrProfile::ROOT.descend(false).descend(false);
    let shallow_zero = QrProfile::ROOT.descend(false);
    assert_ne!(deep_zeroes, shallow_zero);
    assert_ne!(deep_zeroes, QrProfile::ROOT);
}

#[test]
fn the_profile_reaches_the_maximum_depth() {
    let mut profile = QrProfile::ROOT;
    for _ in 0..QrProfile::MAX_DEPTH {
        profile = profile.descend(true);
    }
    assert_eq!(profile.depth, u32::BITS);
    assert_eq!(profile.bits, u32::MAX);
}

#[test]
fn the_discriminants_progress_by_one() {
    let first = QrDiscriminant::from(Fp::from(7));
    assert_eq!(first.at(0), Fp::from(7));
    assert_eq!(first.at(1), Fp::from(8));
    assert_eq!(first.at(u32::BITS), Fp::from(7 + 32));
    assert_eq!(QrDiscriminant::from(-Fp::ONE).at(1), Fp::ZERO);
}

#[test]
fn class_roots_square_to_the_shifted_value() {
    let rng = &mut StdRng::seed_from_u64(0);
    for fixed_point in [None, Some(0), Some(17), Some(u32::BITS - 1)] {
        let discriminant = QrDiscriminant::random(rng);
        let value = fixed_point.map_or_else(
            || Fp::random(|bytes| rng.fill_bytes(bytes)),
            |position| -discriminant.at(position),
        );
        let classes = QrClassRoot::along(value, discriminant);
        for (depth, &QrClassRoot(side, root)) in (0..).zip(&classes) {
            assert_eq!(
                root.square(),
                qr::class_multiplier(side) * (value + discriminant.at(depth)),
                "fixed point {fixed_point:?}, depth {depth}"
            );
        }
        if let Some(position) = fixed_point {
            assert_eq!(
                classes[usize::try_from(position).unwrap()],
                QrClassRoot(true, Fp::ZERO),
                "fixed point {position}"
            );
        }
    }
}

#[test]
fn the_depth_mask_is_a_prefix_of_the_depth() {
    for depth in [0, 1, 17, u32::BITS] {
        for bits in [0, 0xA5A5_A5A5, u32::MAX] {
            let mask = QrProfile { depth, bits }.depth_mask();
            let selected: Vec<usize> = (0..)
                .zip(mask)
                .filter(|&(_, on)| on)
                .map(|(position, _)| position)
                .collect();
            assert_eq!(
                selected,
                (0..usize::try_from(depth).unwrap()).collect::<Vec<_>>(),
                "depth {depth}, bits {bits:#x}"
            );
        }
    }
}

#[test]
#[should_panic(expected = "profile has no bit left for another side")]
fn descending_past_the_maximum_depth_panics() {
    let mut profile = QrProfile::ROOT;
    for _ in 0..=QrProfile::MAX_DEPTH {
        profile = profile.descend(true);
    }
}

#[test]
#[should_panic(expected = "depth out of range")]
fn a_depth_mask_past_the_maximum_depth_panics() {
    let _mask = QrProfile {
        depth: u32::BITS + 1,
        bits: 0,
    }
    .depth_mask();
}

#[test]
#[should_panic(expected = "depth out of range")]
fn a_depth_mask_at_the_integer_limit_panics() {
    let _mask = QrProfile {
        depth: u32::MAX,
        bits: 0,
    }
    .depth_mask();
}
