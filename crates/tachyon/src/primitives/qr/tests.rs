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
        let (actual_class, root) = discriminant.classify(value.into());
        assert_eq!(actual_class, class);
        assert_eq!(
            Fp::from(root).square(),
            class.multiplier() * (value + Fp::from(discriminant))
        );
    }
    assert_eq!(
        discriminant.classify(exceptional.into()),
        (QrClass::Residue, QrClassRoot::from(Fp::ZERO))
    );
    assert_eq!(QrClass::Residue.sibling(), QrClass::NonResidue);
    assert_eq!(QrClass::NonResidue.sibling(), QrClass::Residue);
}

#[test]
fn classification_recovers_the_class_from_a_known_root() {
    let discriminant = QrDiscriminant::from(Fp::from(11));
    let square = Fp::from(7).square();
    for class in [QrClass::NonResidue, QrClass::Residue] {
        let value = square * class.multiplier().invert().unwrap() - Fp::from(discriminant);
        let (actual_class, root) = discriminant.classify(value.into());
        assert_eq!(actual_class, class);
        assert_eq!(Fp::from(root).square(), square);
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

    let split = discriminant.split(&members);
    assert_eq!(
        split.members(QrClass::NonResidue).collect::<Vec<_>>(),
        [nonsquare, other_nonsquare, nonsquare]
    );
    assert_eq!(
        split.members(QrClass::Residue).collect::<Vec<_>>(),
        [square, zero, square]
    );
    for (class, side) in [
        (QrClass::NonResidue, &split.non_residue),
        (QrClass::Residue, &split.residue),
    ] {
        for &(member, root) in side {
            let shifted = Fp::from(member) + Fp::from(discriminant);
            assert_eq!(Fp::from(root).square(), class.multiplier() * shifted);
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
    let repeated = discriminant.split(&[square, square]);
    assert!(repeated.class_decomposition(QrClass::Residue).is_none());
    let empty = discriminant.split(&[]);
    assert!(empty.class_decomposition(QrClass::NonResidue).is_some());
    assert!(empty.class_decomposition(QrClass::Residue).is_some());
    let singleton = discriminant.split(&[zero]);
    assert!(singleton.class_decomposition(QrClass::Residue).is_some());
}

#[test]
#[should_panic(expected = "side's set polynomial exceeds WalletRank")]
fn set_polynomial_needs_one_coefficient_more_than_the_member_count() {
    let discriminant = QrDiscriminant::from(Fp::ZERO);
    let members = (1..=u64::try_from(WalletRank::num_coeffs()).unwrap())
        .map(|root| Tachygram::from(Fp::from(root).square()))
        .collect::<Vec<_>>();
    let _factors = discriminant.split(&members).factors();
}

#[test]
fn class_decomposition_rejects_a_side_over_its_rank() {
    let discriminant = QrDiscriminant::from(Fp::ZERO);
    let members = (1..=u64::try_from(WalletRank::num_coeffs() + 1).unwrap())
        .map(|root| Tachygram::from(Fp::from(root).square()))
        .collect::<Vec<_>>();
    assert!(
        discriminant
            .split(&members)
            .class_decomposition(QrClass::Residue)
            .is_none()
    );
}

#[test]
fn discriminants_are_indexed_from_the_first() {
    let first = Fp::from(11);
    let first_discriminant = QrDiscriminant::from(first);
    for depth in [0, 31, 32] {
        assert_eq!(
            Fp::from(first_discriminant.at(depth)),
            first + Fp::from(u64::from(depth))
        );
        assert_eq!(
            first_discriminant.at(depth).at(1),
            first_discriminant.at(depth + 1)
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
fn classifications_at_each_depth_solve_the_class_equation() {
    let discriminant = QrDiscriminant::from(Fp::from(11));
    let exceptional = -Fp::from(discriminant.at(1));
    for value in [Fp::from(3), Fp::from(1_000_003), -Fp::from(9), exceptional] {
        let (path, roots) = discriminant.classify_path(value.into());
        for (depth, (class, root)) in (0..).zip(path.into_iter().zip(roots)) {
            let at_depth = discriminant.at(depth);
            assert_eq!((class, root), at_depth.classify(value.into()));
            let shifted = value + Fp::from(at_depth);
            assert_eq!(Fp::from(root).square(), class.multiplier() * shifted);
            if value == exceptional && depth == 1 {
                assert_eq!(class, QrClass::Residue);
                assert_eq!(Fp::from(root), Fp::ZERO);
            }
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

#[test]
fn profile_round_trips_as_depth_then_bits() {
    for (profile, bytes) in [
        (QrProfile::ROOT, [0; 8]),
        (
            QrProfile::ROOT
                .descend(QrClass::Residue)
                .descend(QrClass::NonResidue)
                .descend(QrClass::Residue),
            [3, 0, 0, 0, 0b101, 0, 0, 0],
        ),
        (
            QrProfile {
                depth: u32::BITS,
                bits: u32::MAX,
            },
            [32, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        ),
    ] {
        let mut written = Vec::new();
        profile.write(&mut written).unwrap();
        assert_eq!(written, bytes);
        assert_eq!(QrProfile::read(written.as_slice()).unwrap(), profile);
    }
}

#[test]
fn profile_read_rejects_encodings_no_descent_produces() {
    // A depth past the last position.
    QrProfile::read([33, 0, 0, 0, 0, 0, 0, 0].as_slice()).unwrap_err();

    // A side recorded at or above the depth.
    QrProfile::read([3, 0, 0, 0, 0b1000, 0, 0, 0].as_slice()).unwrap_err();
    QrProfile::read([0, 0, 0, 0, 1, 0, 0, 0].as_slice()).unwrap_err();
    QrProfile::read([31, 0, 0, 0, 0, 0, 0, 0x80].as_slice()).unwrap_err();

    // A short input.
    QrProfile::read([3, 0, 0, 0, 0b101, 0, 0].as_slice()).unwrap_err();
}
