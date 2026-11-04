use alloc::vec::Vec;

use super::*;

const SIZES: [(u64, CompactSize, &[u8], bool); 10] = [
    (0, CompactSize::OneByte(0), &[0x00], true),
    (0xFC, CompactSize::OneByte(0xFC), &[0xFC], true),
    (
        0xFD,
        CompactSize::TwoBytes(0xFD),
        &[FLAG_TWO_BYTES, 0xFD, 0x00],
        true,
    ),
    (
        0xFFFF,
        CompactSize::TwoBytes(0xFFFF),
        &[FLAG_TWO_BYTES, 0xFF, 0xFF],
        true,
    ),
    (
        0x1_0000,
        CompactSize::FourBytes(0x1_0000),
        &[FLAG_FOUR_BYTES, 0x00, 0x00, 0x01, 0x00],
        true,
    ),
    (
        0x0200_0000,
        CompactSize::FourBytes(0x0200_0000),
        &[FLAG_FOUR_BYTES, 0x00, 0x00, 0x00, 0x02],
        true,
    ),
    (
        0x0200_0001,
        CompactSize::FourBytes(0x0200_0001),
        &[FLAG_FOUR_BYTES, 0x01, 0x00, 0x00, 0x02],
        false,
    ),
    (
        0xFFFF_FFFF,
        CompactSize::FourBytes(0xFFFF_FFFF),
        &[FLAG_FOUR_BYTES, 0xFF, 0xFF, 0xFF, 0xFF],
        false,
    ),
    (
        0x1_0000_0000,
        CompactSize::EightBytes(0x1_0000_0000),
        &[
            FLAG_EIGHT_BYTES,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
        ],
        false,
    ),
    (
        u64::MAX,
        CompactSize::EightBytes(u64::MAX),
        &[
            FLAG_EIGHT_BYTES,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
        ],
        false,
    ),
];

#[test]
fn a_value_takes_its_shortest_form() {
    for (value, form, bytes, valid) in SIZES {
        let mut written = Vec::new();
        form.write(&mut written).unwrap();
        assert_eq!(CompactSize::from(value), form, "{value:#x}: its form");
        assert_eq!(u64::from(form), value, "{value:#x}: back to u64");
        assert_eq!(written, bytes, "{value:#x}: its encoding");
        assert_eq!(CompactSize::read(bytes).unwrap(), form, "{value:#x}: read");
        assert_eq!(form.enforce_valid().is_ok(), valid, "{value:#x}: the bound");
        assert_eq!(
            usize::try_from(form),
            usize::try_from(value),
            "{value:#x}: to usize"
        );
        if let Ok(wide) = usize::try_from(value) {
            assert_eq!(
                CompactSize::try_from(wide).unwrap(),
                form,
                "{value:#x}: from usize"
            );
        }
    }
}

#[test]
fn a_constructor_takes_only_its_form() {
    for (constructed, form) in [
        (CompactSize::one_byte(0xFC), CompactSize::OneByte(0xFC)),
        (CompactSize::two_bytes(0xFD), CompactSize::TwoBytes(0xFD)),
        (
            CompactSize::two_bytes(u16::MAX),
            CompactSize::TwoBytes(u16::MAX),
        ),
        (
            CompactSize::four_bytes(0x1_0000),
            CompactSize::FourBytes(0x1_0000),
        ),
        (
            CompactSize::four_bytes(u32::MAX),
            CompactSize::FourBytes(u32::MAX),
        ),
        (
            CompactSize::eight_bytes(0x1_0000_0000),
            CompactSize::EightBytes(0x1_0000_0000),
        ),
        (
            CompactSize::eight_bytes(u64::MAX),
            CompactSize::EightBytes(u64::MAX),
        ),
    ] {
        assert_eq!(constructed.unwrap(), form);
    }
    for (constructed, shortest) in [
        (CompactSize::one_byte(0xFD), CompactSize::TwoBytes(0xFD)),
        (CompactSize::two_bytes(0xFC), CompactSize::OneByte(0xFC)),
        (
            CompactSize::four_bytes(0xFFFF),
            CompactSize::TwoBytes(0xFFFF),
        ),
        (
            CompactSize::eight_bytes(0xFFFF_FFFF),
            CompactSize::FourBytes(0xFFFF_FFFF),
        ),
    ] {
        let Err(CompactSizeError::NonCanonical(reported)) = constructed else {
            panic!("{shortest}: a longer form constructs");
        };
        assert_eq!(reported, shortest);
    }
}

#[test]
fn a_read_form_is_checked_against_its_value() {
    let flag = CompactSize::OneByte(FLAG_TWO_BYTES);
    let Err(CompactSizeError::NonCanonical(flagged)) = flag.enforce_canon() else {
        panic!("a flag byte is a canonical single byte");
    };
    assert_eq!(flagged, flag);
    for bytes in [
        [FLAG_TWO_BYTES, 0xFC, 0x00].as_slice(),
        &[FLAG_FOUR_BYTES, 0xFF, 0xFF, 0x00, 0x00],
        &[
            FLAG_EIGHT_BYTES,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0x00,
            0x00,
            0x00,
            0x00,
        ],
    ] {
        let form = CompactSize::read(bytes).unwrap();
        let Err(CompactSizeError::NonCanonical(reported)) = form.enforce_canon() else {
            panic!("{bytes:02x?}: an over-long form is canonical");
        };
        assert_eq!(reported, form);
    }
    let bound = CompactSize::FourBytes(MAX_COMPACT_SIZE);
    assert_eq!(bound.enforce_max().unwrap(), bound);
    let past = CompactSize::FourBytes(MAX_COMPACT_SIZE + 1);
    let Err(CompactSizeError::ExceedsMaximum(reported)) = past.enforce_max() else {
        panic!("a size past the bound passes enforce_max");
    };
    assert_eq!(reported, past);
}

#[test]
fn read_takes_exactly_one_encoding() {
    let trailings: [&[u8]; 3] = [&[], &[0x00], &[0xFF; 8]];
    for (value, form, bytes, _) in SIZES {
        for trailing in trailings {
            let reader = [bytes, trailing].concat();
            let mut rest = reader.as_slice();
            assert_eq!(
                CompactSize::read(&mut rest).unwrap(),
                form,
                "{value:#x} before {} more bytes",
                trailing.len()
            );
            assert_eq!(
                rest,
                trailing,
                "{value:#x} leaves {} bytes unread",
                trailing.len()
            );
        }
        for cut in 0..bytes.len() {
            assert!(
                CompactSize::read(&bytes[..cut]).is_err(),
                "{value:#x} cut to {cut} bytes"
            );
        }
    }
}
