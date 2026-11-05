use alloc::vec::Vec;

use super::*;

#[test]
fn form_boundary_round_trips() {
    let cases = alloc::vec![
        (0, CompactSize::OneByte(0), [0x00].to_vec()),
        (
            u64::from(MAX_ONE_BYTE),
            CompactSize::OneByte(MAX_ONE_BYTE),
            [MAX_ONE_BYTE].to_vec()
        ),
        (
            u64::from(FLAG_TWO_BYTES),
            CompactSize::TwoBytes(u16::from(FLAG_TWO_BYTES)),
            [
                [FLAG_TWO_BYTES].as_slice(),
                &u16::from(FLAG_TWO_BYTES).to_le_bytes()
            ]
            .concat(),
        ),
        (
            u64::from(u16::MAX),
            CompactSize::TwoBytes(u16::MAX),
            [[FLAG_TWO_BYTES].as_slice(), &u16::MAX.to_le_bytes()].concat(),
        ),
        (
            u64::from(u16::MAX) + 1,
            CompactSize::FourBytes(u32::from(u16::MAX) + 1),
            [
                [FLAG_FOUR_BYTES].as_slice(),
                &(u32::from(u16::MAX) + 1).to_le_bytes()
            ]
            .concat(),
        ),
        (
            u64::from(MAX_COMPACT_SIZE),
            CompactSize::FourBytes(MAX_COMPACT_SIZE),
            [
                [FLAG_FOUR_BYTES].as_slice(),
                &MAX_COMPACT_SIZE.to_le_bytes()
            ]
            .concat(),
        ),
    ];

    let mut buf = Vec::new();
    for (value, expected_variant, expected_bytes) in cases {
        let cs = CompactSize::from(value);
        assert_eq!(cs, expected_variant);
        cs.write(&mut buf).unwrap();
        assert_eq!(buf, expected_bytes);
        assert_eq!(CompactSize::read(buf.as_slice()).unwrap(), expected_variant);
        buf.clear();
    }
}

#[test]
fn constructors_enforce_canonical_form() {
    CompactSize::one_byte(0).unwrap();
    CompactSize::one_byte(MAX_ONE_BYTE).unwrap();
    CompactSize::one_byte(FLAG_TWO_BYTES).unwrap_err();

    CompactSize::two_bytes(u16::from(MAX_ONE_BYTE)).unwrap_err();
    CompactSize::two_bytes(u16::from(FLAG_TWO_BYTES)).unwrap();
    CompactSize::two_bytes(u16::MAX).unwrap();

    CompactSize::four_bytes(u32::from(u16::MAX)).unwrap_err();
    CompactSize::four_bytes(u32::from(u16::MAX) + 1).unwrap();
    CompactSize::four_bytes(u32::MAX).unwrap();

    CompactSize::eight_bytes(u64::from(u32::MAX)).unwrap_err();
    CompactSize::eight_bytes(u64::from(u32::MAX) + 1).unwrap();
}

#[test]
fn enforce_max_rejects_above_consensus() {
    CompactSize::FourBytes(MAX_COMPACT_SIZE + 1)
        .enforce_max()
        .unwrap_err();
    CompactSize::FourBytes(u32::MAX).enforce_max().unwrap_err();
    CompactSize::EightBytes(u64::from(u32::MAX) + 1)
        .enforce_max()
        .unwrap_err();
    CompactSize::FourBytes(MAX_COMPACT_SIZE)
        .enforce_max()
        .unwrap();
}

#[test]
fn enforce_canon_rejects_non_canonical() {
    CompactSize::TwoBytes(u16::from(MAX_ONE_BYTE))
        .enforce_canon()
        .unwrap_err();
    CompactSize::FourBytes(u32::from(u16::MAX))
        .enforce_canon()
        .unwrap_err();
    CompactSize::EightBytes(u64::from(u32::MAX))
        .enforce_canon()
        .unwrap_err();
}

#[test]
fn read_rejects_truncated_input() {
    CompactSize::read([].as_slice()).unwrap_err();
    CompactSize::read([FLAG_TWO_BYTES].as_slice()).unwrap_err();
    CompactSize::read([FLAG_TWO_BYTES, 0x00].as_slice()).unwrap_err();
    CompactSize::read([FLAG_FOUR_BYTES, 0x00, 0x00, 0x00].as_slice()).unwrap_err();
    CompactSize::read([FLAG_EIGHT_BYTES, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].as_slice())
        .unwrap_err();
}

#[test]
fn try_from_usize_round_trip() {
    for n in [
        0usize,
        usize::from(MAX_ONE_BYTE),
        usize::from(FLAG_TWO_BYTES),
        usize::from(u16::MAX) + 1,
    ] {
        let cs = CompactSize::try_from(n).unwrap();
        assert_eq!(usize::try_from(cs).unwrap(), n);
    }
}
