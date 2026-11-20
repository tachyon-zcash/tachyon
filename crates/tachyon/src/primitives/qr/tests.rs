use super::*;

#[test]
fn class_roots_attest_the_class() {
    let discriminant = QrDiscriminant::from(Fp::from(11));
    let exceptional = -Fp::from(discriminant);
    for (value, class) in [
        (exceptional, QrClass::Residue),
        (Fp::ONE + exceptional, QrClass::Residue),
        (qr::QUADRATIC_NON_RESIDUE + exceptional, QrClass::NonResidue),
    ] {
        assert_eq!(discriminant.class(value.into()), class);
        assert_eq!(discriminant.class_root(value.into()).class(), class);
    }
    assert_eq!(
        discriminant.class_root(exceptional.into()),
        QrClassRoot::Residue(Fp::ZERO)
    );
    assert_eq!(QrClass::Residue.sibling(), QrClass::NonResidue);
    assert_eq!(QrClass::NonResidue.sibling(), QrClass::Residue);
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
    assert_eq!(non_residue, [nonsquare, other_nonsquare, nonsquare]);
    assert_eq!(residue, [square, zero, square]);
    for (class, list) in [
        (QrClass::NonResidue, non_residue),
        (QrClass::Residue, residue),
    ] {
        for member in list {
            assert_eq!(discriminant.class(member), class);
        }
    }
}

#[test]
fn class_decomposition_requires_distinct_members_of_the_class() {
    let discriminant = QrDiscriminant::from(Fp::from(11));
    let exceptional = -Fp::from(discriminant);
    let zero = Tachygram::from(exceptional);
    let square = Tachygram::from(Fp::ONE + exceptional);
    let nonsquare = Tachygram::from(qr::QUADRATIC_NON_RESIDUE + exceptional);

    assert!(
        discriminant
            .class_decomposition(QrClass::Residue, &[nonsquare])
            .is_none()
    );
    assert!(
        discriminant
            .class_decomposition(QrClass::NonResidue, &[square])
            .is_none()
    );
    assert!(
        discriminant
            .class_decomposition(QrClass::NonResidue, &[zero])
            .is_none()
    );
    assert!(
        discriminant
            .class_decomposition(QrClass::Residue, &[square, square])
            .is_none()
    );
    assert!(
        discriminant
            .class_decomposition(QrClass::NonResidue, &[])
            .is_some()
    );
    assert!(
        discriminant
            .class_decomposition(QrClass::Residue, &[zero])
            .is_some()
    );
}

#[test]
fn profile_records_the_classes_from_the_first_discriminant() {
    let discriminant = QrDiscriminant::from(Fp::from(11));
    let value = Tachygram::from(Fp::from(3));
    for depth in [0, 1, u32::try_from(QrProfile::MAX_DEPTH).unwrap()] {
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
    let discriminant = QrDiscriminant::from(Fp::from(11));
    let _profile = discriminant.profile(Tachygram::from(Fp::from(3)), u32::BITS + 1);
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
fn class_roots_square_to_the_shifted_value() {
    let discriminant = QrDiscriminant::from(Fp::from(11));
    for value in [Fp::from(3), Fp::from(1_000_003), -Fp::from(9)] {
        for (depth, class) in (0..).zip(discriminant.class_roots(value.into())) {
            let shifted = value + Fp::from(discriminant.at(depth));
            assert_eq!(class.root().square(), class.class().multiplier() * shifted);
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
