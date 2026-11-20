use super::*;

#[test]
fn classification_solves_the_class_equation() {
    let discriminant = QrDiscriminant::from(Fp::from(11));
    let exceptional = -Fp::from(discriminant);
    for (value, class) in [
        (exceptional, QrClass::Residue),
        (Fp::ONE + exceptional, QrClass::Residue),
        (qr::QUADRATIC_NON_RESIDUE + exceptional, QrClass::NonResidue),
    ] {
        let classification = discriminant.classify(value.into());
        assert_eq!(classification.value(), Tachygram::from(value));
        assert_eq!(classification.discriminant(), discriminant);
        assert_eq!(classification.class(), class);
        assert_eq!(
            classification.claim(),
            QrClassClaim {
                class,
                root: classification.root()
            }
        );
        assert_eq!(
            classification.root().square(),
            class.multiplier() * (value + Fp::from(discriminant))
        );
    }
    assert_eq!(discriminant.classify(exceptional.into()).root(), Fp::ZERO);
    assert_eq!(QrClass::Residue.sibling(), QrClass::NonResidue);
    assert_eq!(QrClass::NonResidue.sibling(), QrClass::Residue);
}

#[test]
fn classification_recovers_the_class_from_a_known_root() {
    let discriminant = QrDiscriminant::from(Fp::from(11));
    let square = Fp::from(7).square();
    for class in [QrClass::NonResidue, QrClass::Residue] {
        let value = square * class.multiplier().invert().unwrap() - Fp::from(discriminant);
        let classification = discriminant.classify(value.into());
        assert_eq!(classification.class(), class);
        assert_eq!(classification.root().square(), square);
    }
}

#[test]
fn split_keeps_class_order_and_repeated_members() {
    let discriminant = QrDiscriminant::from(Fp::from(11));
    let exceptional = -Fp::from(discriminant);
    let zero = Tachygram::from(exceptional);
    let square = Tachygram::from(Fp::ONE + exceptional);
    let nonsquare = Tachygram::from(qr::QUADRATIC_NON_RESIDUE + exceptional);
    let other_nonsquare = Tachygram::from(Fp::from(4) * qr::QUADRATIC_NON_RESIDUE + exceptional);
    let members = [square, nonsquare, zero, other_nonsquare, nonsquare, square];

    let (non_residue, residue) = discriminant.split(&members);
    assert_eq!(
        non_residue.members().collect::<Vec<_>>(),
        [nonsquare, other_nonsquare, nonsquare]
    );
    assert_eq!(
        residue.members().collect::<Vec<_>>(),
        [square, zero, square]
    );
    for (class, side) in [
        (QrClass::NonResidue, non_residue),
        (QrClass::Residue, residue),
    ] {
        assert_eq!(side.class(), class);
        assert_eq!(side.discriminant(), discriminant);
        for classification in side.classifications() {
            assert_eq!(classification.class(), class);
            let shifted = Fp::from(classification.value()) + Fp::from(discriminant);
            assert_eq!(classification.root().square(), class.multiplier() * shifted);
            if shifted == Fp::ZERO {
                assert_eq!(class, QrClass::Residue);
            }
        }
    }
}

#[test]
fn class_decomposition_requires_distinct_members() {
    let discriminant = QrDiscriminant::from(Fp::from(11));
    let exceptional = -Fp::from(discriminant);
    let zero = Tachygram::from(exceptional);
    let square = Tachygram::from(Fp::ONE + exceptional);
    let (_, repeated) = discriminant.split(&[square, square]);
    assert!(repeated.class_decomposition().is_none());
    let (empty_non_residue, empty_residue) = discriminant.split(&[]);
    assert!(empty_non_residue.class_decomposition().is_some());
    assert!(empty_residue.class_decomposition().is_some());
    let (_, exceptional_residue) = discriminant.split(&[zero]);
    assert!(exceptional_residue.class_decomposition().is_some());
}

#[test]
fn profile_records_the_classes_from_the_first_discriminant() {
    let discriminant = QrDiscriminants::from(Fp::from(11));
    let value = Tachygram::from(Fp::from(3));
    for depth in [0, 1, 31, 32] {
        let first = Fp::from(value) + Fp::from(discriminant);
        let bits = (0..depth).fold(0, |bits, level| {
            let shifted = first + Fp::from(u64::from(level));
            (bits << 1) | u32::from(shifted.sqrt().is_some())
        });
        assert_eq!(
            discriminant.profile(value, depth),
            QrProfile { depth, bits }
        );
    }
}

#[test]
#[should_panic(expected = "profile has no bit left for another side")]
fn a_profile_past_the_maximum_depth_panics() {
    let discriminant = QrDiscriminants::from(Fp::from(11));
    let _profile = discriminant.profile(Tachygram::from(Fp::from(3)), u32::BITS + 1);
}

#[test]
fn discriminants_are_indexed_from_the_first() {
    let first = Fp::from(11);
    let discriminants = QrDiscriminants::from(first);
    for depth in [0, 31, 32] {
        assert_eq!(
            Fp::from(discriminants.at(depth)),
            first + Fp::from(u64::from(depth))
        );
    }
}

#[test]
fn the_bits_record_the_splits_outermost_first() {
    let low = QrProfile::ROOT
        .descend(QrClass::NonResidue)
        .descend(QrClass::NonResidue)
        .descend(QrClass::Residue);
    assert_eq!(low.depth, 3);
    assert_eq!(low.bits, 0b001);
    let high = QrProfile::ROOT
        .descend(QrClass::Residue)
        .descend(QrClass::NonResidue)
        .descend(QrClass::NonResidue);
    assert_eq!(high.bits, 0b100);
}

#[test]
#[should_panic(expected = "profile has no bit left for another side")]
fn descending_past_the_maximum_depth_panics() {
    let mut profile = QrProfile::ROOT;
    for _ in 0..=QrProfile::MAX_DEPTH {
        profile = profile.descend(QrClass::Residue);
    }
}

#[test]
fn the_profile_reaches_the_maximum_depth() {
    let mut profile = QrProfile::ROOT;
    for _ in 0..QrProfile::MAX_DEPTH {
        profile = profile.descend(QrClass::Residue);
    }
    assert_eq!(profile.depth, u32::BITS);
    assert_eq!(profile.bits, u32::MAX);
}

#[test]
fn class_claims_attest_the_shifted_value() {
    let discriminant = QrDiscriminants::from(Fp::from(11));
    for value in [Fp::from(3), Fp::from(1_000_003), -Fp::from(9)] {
        for (depth, QrClassClaim { class, root }) in
            (0..).zip(discriminant.class_claims(value.into()))
        {
            let shifted = value + Fp::from(discriminant.at(depth));
            assert_eq!(root.square(), class.multiplier() * shifted);
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
