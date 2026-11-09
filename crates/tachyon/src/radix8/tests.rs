use super::*;

#[test]
fn scalar_reads_signed_odd_radix8_windows() {
    let base = -(Fq::from(8u64).pow_u64(85) - Fq::ONE) * Fq::from(7u64).invert().unwrap();
    assert_eq!(read(Fp::ZERO), base);

    for window in 0..85 {
        for (offset, delta) in [
            (0, Fq::from(2u64)),
            (1, -Fq::from(2u64)),
            (2, -Fq::from(4u64)),
        ] {
            assert_eq!(
                read(Fp::from(2u64).pow_u64(3 * window + offset)),
                base + delta * Fq::from(8u64).pow_u64(window)
            );
        }
    }

    assert_eq!(
        read(Fp::from(2u64).pow_u64(254) - Fp::ONE),
        Fq::from(2u64).pow_u64(254) - Fq::ONE
    );
}
