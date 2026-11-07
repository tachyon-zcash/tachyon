use alloc::vec;
use core::{array, assert_matches};

use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use super::{
    super::super::super::{
        ActionDigest, ActionSetPoly, Anchor, Tachygram, TachygramSetPoly,
        constants::MAX_MONEY,
        pasta::{Ep, EpAffine, Fp, Fq},
        value,
    },
    Base, Carrier, G, IdentityFlag, NEG_V_TABLE, PROOF_SYSTEM, R, ScalarHi, ScalarLo, ScaleEnd,
    ScaleMiddle, ScaleResult, ScaleStart, ScaleState, V_TABLE, canonical, decode, export, finite,
    limbs, match_scalar, scalar_bits, select_digit, value_product,
};

#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "byte and bit positions in the independent scalar encoding"
)]
fn check_stages<B: Base + Default>(scalar: Fq, base: Ep, rng: &mut StdRng) {
    let bits = scalar_bits(scalar);
    let bytes = scalar.to_bytes();
    let mut low_bytes = [0u8; 32];
    low_bytes[..16].copy_from_slice(&bytes[..16]);
    let mut high_bytes = [0u8; 32];
    high_bytes[..16].copy_from_slice(&bytes[16..]);
    let expected_limbs = (
        Fp::from_bytes(low_bytes).unwrap(),
        Fp::from_bytes(high_bytes).unwrap(),
    );
    let (start, ()) = PROOF_SYSTEM
        .seed(rng, ScaleStart::<B>::default(), (bits,))
        .unwrap();
    let (middle, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            ScaleMiddle::<B>::default(),
            (bits,),
            start.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (end, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            ScaleEnd::<B>::default(),
            (bits,),
            middle.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    for (data, width) in [(start.data(), 72), (middle.data(), 162), (end.data(), 255)] {
        let mut truncated = scalar.to_bytes();
        for bit in width..256 {
            let byte = bit / 8;
            truncated[byte] &= !(1 << (bit % 8));
        }
        let expected = base * Fq::from_bytes(truncated).unwrap();
        assert_eq!(decode(data.2, data.3).unwrap(), expected);
        assert_eq!((data.0.0, data.1.0), expected_limbs);
    }
    assert!(PROOF_SYSTEM.verify(&end, rng).unwrap());
}

#[test]
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "byte positions and radix-8 window boundaries"
)]
fn scalar_boundaries_and_all_one_hot_bits_match_native_products() {
    let rng = &mut StdRng::seed_from_u64(0);
    let p_minus_one = Fq::from_bytes((-Fp::ONE).to_bytes()).unwrap();
    let mut scalars = vec![
        Fq::ZERO,
        Fq::ONE,
        p_minus_one,
        p_minus_one + Fq::ONE,
        -Fq::ONE,
    ];
    for bit in 0..255 {
        let mut bytes = [0u8; 32];
        let byte = bit / 8;
        bytes[byte] = 1 << (bit % 8);
        let power = Fq::from_bytes(bytes).unwrap();
        scalars.push(power);
        if bit % 3 == 0 || bit == 127 || bit == 128 || bit == 254 {
            scalars.extend([power - Fq::ONE, power + Fq::ONE]);
        }
    }
    for _ in 0..32 {
        scalars.push(Fq::random(|bytes| rand_core::Rng::fill_bytes(rng, bytes)));
    }
    let r_base = Ep::from(value::Trapdoor::from_scalar(Fq::ONE).commit(value::Positive::ZERO));
    let g_base = Ep::from(EpAffine::from(super::ActionVerificationKey(
        super::reddsa::VerificationKey::from(
            &super::reddsa::SigningKey::<super::reddsa::ActionAuth>::try_from(Fq::ONE.to_bytes())
                .unwrap(),
        ),
    )));
    for scalar in scalars {
        check_stages::<R>(scalar, r_base, rng);
        check_stages::<G>(scalar, g_base, rng);
    }
}

#[test]
fn every_table_entry_and_selector_matches_independent_multiplication() {
    let one = value::Positive::try_from(1).unwrap();
    let r_base = Ep::from(value::Trapdoor::from_scalar(Fq::ONE).commit(value::Positive::ZERO));
    let g_base = Ep::from(EpAffine::from(super::ActionVerificationKey(
        super::reddsa::VerificationKey::from(
            &super::reddsa::SigningKey::<super::reddsa::ActionAuth>::try_from(Fq::ONE.to_bytes())
                .unwrap(),
        ),
    )));
    let v_base = Ep::from(value::Trapdoor::ZERO.commit(one));
    for (rows, base) in [
        (R::table().as_slice(), r_base),
        (G::table().as_slice(), g_base),
        (V_TABLE.as_slice(), v_base),
        (NEG_V_TABLE.as_slice(), -v_base),
    ] {
        let mut power = Fq::ONE;
        for row in rows {
            for digit in 0u8..8 {
                let expected = base * (power * Fq::from(u64::from(digit)));
                assert_eq!(Ep::from(row[usize::from(digit)]), expected);
                let bits = array::from_fn(|i| (digit >> i) & 1 == 1);
                assert_eq!(select_digit(row, bits).unwrap(), expected);
            }
            power *= Fq::from(8);
        }
    }
    for amount in [0, 1, 7, 8, 9, 63, 64, 65, MAX_MONEY] {
        let bounded = value::Positive::try_from(amount).unwrap();
        assert_eq!(
            value_product::<false>(bounded).unwrap(),
            v_base * Fq::from(amount)
        );
        assert_eq!(
            value_product::<true>(bounded).unwrap(),
            -v_base * Fq::from(amount)
        );
    }
}

#[test]
fn tagged_points_preserve_identity_and_exceptional_additions() {
    let point = Ep::from(EpAffine::generator());
    for (left, right) in [
        (Ep::identity(), Ep::identity()),
        (Ep::identity(), point),
        (point, Ep::identity()),
        (point, point),
        (point, -point),
        (point, point.double()),
    ] {
        let (left_carrier, left_tag) = export(left);
        let (right_carrier, right_tag) = export(right);
        let actual =
            decode(left_carrier, left_tag).unwrap() + decode(right_carrier, right_tag).unwrap();
        let (carrier, tag) = export(actual);
        assert_eq!(decode(carrier, tag).unwrap(), left + right);
    }
    assert_eq!(
        decode(Carrier(EpAffine::generator()), IdentityFlag(false)).unwrap(),
        point
    );
    assert_eq!(
        decode(Carrier(EpAffine::generator()), IdentityFlag(true)).unwrap(),
        Ep::identity()
    );
    assert_matches!(
        decode(Carrier(point.double().to_affine()), IdentityFlag(true)),
        Err(_)
    );
    assert_matches!(
        decode(Carrier(EpAffine::identity()), IdentityFlag(false)),
        Err(_)
    );
    assert_matches!(finite(point + -point), Err(_));
    assert_eq!(
        finite(point + Ep::identity()).unwrap(),
        EpAffine::generator()
    );
}

#[test]
fn stages_reject_noncanonical_scalars_and_mismatched_limbs() {
    let rng = &mut StdRng::seed_from_u64(1);
    let mut modulus = scalar_bits(-Fq::ONE);
    modulus[0] = true;
    assert_matches!(canonical(&modulus), Err(_));
    assert_matches!(
        PROOF_SYSTEM
            .seed(rng, ScaleStart::<R>::default(), (modulus,))
            .err(),
        Some(_)
    );

    let bits = scalar_bits(Fq::ONE);
    let (start, ()) = PROOF_SYSTEM
        .seed(rng, ScaleStart::<R>::default(), (bits,))
        .unwrap();
    for bit in [0, 71, 72, 126, 127, 128, 161, 162, 254] {
        let mut changed = bits;
        changed[bit] = !changed[bit];
        assert_matches!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    ScaleMiddle::<R>::default(),
                    (changed,),
                    start.clone(),
                    Proof::bootstrap().carry::<()>(())
                )
                .err(),
            Some(_)
        );
    }
    let (middle, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            ScaleMiddle::<R>::default(),
            (bits,),
            start,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let mut changed_bits = bits;
    changed_bits[128] = true;
    assert_matches!(
        PROOF_SYSTEM
            .fuse(
                rng,
                ScaleEnd::<R>::default(),
                (changed_bits,),
                middle.clone(),
                Proof::bootstrap().carry::<()>(())
            )
            .err(),
        Some(_)
    );
    let invalid_tag = middle.proof().clone().carry::<ScaleState<R, 54>>((
        middle.data().0,
        middle.data().1,
        Carrier(EpAffine::generator().to_projective().double().to_affine()),
        IdentityFlag(true),
    ));
    assert_matches!(
        PROOF_SYSTEM
            .fuse(
                rng,
                ScaleEnd::<R>::default(),
                (bits,),
                invalid_tag,
                Proof::bootstrap().carry::<()>(())
            )
            .err(),
        Some(_)
    );
}

#[test]
fn certificate_headers_authenticate_their_fields_base_and_phase() {
    let rng = &mut StdRng::seed_from_u64(2);
    let bits = scalar_bits(Fq::ONE);
    let (start, ()) = PROOF_SYSTEM
        .seed(rng, ScaleStart::<R>::default(), (bits,))
        .unwrap();
    let (middle, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            ScaleMiddle::<R>::default(),
            (bits,),
            start.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    for data in [
        (
            ScalarLo(Fp::from(2)),
            middle.data().1,
            middle.data().2,
            middle.data().3,
        ),
        (
            middle.data().0,
            ScalarHi(Fp::ONE),
            middle.data().2,
            middle.data().3,
        ),
        (
            middle.data().0,
            middle.data().1,
            middle.data().2,
            IdentityFlag(true),
        ),
        (
            middle.data().0,
            middle.data().1,
            Carrier(middle.data().2.0.to_projective().double().to_affine()),
            middle.data().3,
        ),
    ] {
        let changed = middle.proof().clone().carry::<ScaleState<R, 54>>(data);
        assert!(!PROOF_SYSTEM.verify(&changed, &mut *rng).unwrap());
    }
    let result = super::prove::<R, _>(rng, Fq::ONE).unwrap();
    for proof in [start.proof(), middle.proof(), result.proof()] {
        let wrong_base = proof.clone().carry::<ScaleResult<G>>(*result.data());
        assert!(!PROOF_SYSTEM.verify(&wrong_base, &mut *rng).unwrap());
    }
    let skipped = start
        .proof()
        .clone()
        .carry::<ScaleState<R, 54>>(*start.data());
    assert!(!PROOF_SYSTEM.verify(&skipped, &mut *rng).unwrap());
    let terminal = result.proof().clone().carry::<super::super::stamp::Stamp>((
        ActionSetPoly::from_iter([ActionDigest::from(Fp::ONE)]).commit(),
        TachygramSetPoly::from_iter([Tachygram::from(Fp::ONE)]).commit(),
        Anchor::from(Fp::ONE),
    ));
    assert!(!PROOF_SYSTEM.verify(&terminal, &mut *rng).unwrap());
}

#[test]
fn exact_hash_scalar_comparison_rejects_modular_aliases() {
    let modulus = Fq::from_bytes((-Fp::ONE).to_bytes()).unwrap() + Fq::ONE;
    let (lo, hi) = limbs(&scalar_bits(modulus));
    let radix = (0..128).fold(Fp::ONE, |acc, _| acc.double());
    assert_eq!(lo.0 + radix * hi.0, Fp::ZERO);
    assert_matches!(match_scalar(Fq::ZERO, lo, hi), Err(_));
    let (valid_lo, valid_hi) = limbs(&scalar_bits(Fq::ZERO));
    assert_matches!(match_scalar(Fq::ZERO, valid_lo, ScalarHi(Fp::ONE)), Err(_));
    match_scalar(Fq::ZERO, valid_lo, valid_hi).unwrap();
}
