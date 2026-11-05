use super::*;

#[test]
fn the_bits_record_the_splits_outermost_first() {
    let low = QrProfile::ROOT.descend(false).descend(false).descend(true);
    assert_eq!(low.depth, 3);
    assert_eq!(low.bits, 0b001);
    let high = QrProfile::ROOT.descend(true).descend(false).descend(false);
    assert_eq!(high.bits, 0b100);
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
fn the_profile_reaches_the_maximum_depth() {
    let mut profile = QrProfile::ROOT;
    for _ in 0..QrProfile::MAX_DEPTH {
        profile = profile.descend(true);
    }
    assert_eq!(profile.depth, u32::BITS);
    assert_eq!(profile.bits, u32::MAX);
}

#[test]
fn class_roots_square_to_the_shifted_value() {
    let discriminant = QrDiscriminant::from(Fp::from(11));
    for value in [Fp::from(3), Fp::from(1_000_003), -Fp::from(9)] {
        for (depth, QrClassRoot(side, root)) in (0..).zip(QrClassRoot::along(value, discriminant)) {
            let shifted = value + discriminant.at(depth);
            assert_eq!(root.square(), qr::class_multiplier(side) * shifted);
        }
    }
}

#[test]
fn the_depth_mask_is_a_prefix_of_the_depth() {
    for depth in [0, 1, 31, 32] {
        let mask = QrProfile { depth, bits: 0 }.depth_mask();
        let ones = mask.iter().filter(|&&selected| selected).count();
        assert_eq!(ones, usize::try_from(depth).unwrap());
        assert!(
            mask.iter()
                .zip(mask.iter().skip(1))
                .all(|(&earlier, &later)| earlier || !later)
        );
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
