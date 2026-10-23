#![no_main]

//! Fuzz [`CompactSize::read`] and its consensus checks.
//!
//! The reader itself keeps whatever form it was given, so every accepted input
//! round-trips byte for byte. A value that passes `enforce_valid` must also be
//! the form the constructor picks for its integer.

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::CompactSize;
use zcash_tachyon_fuzz::read_canonical;

fuzz_target!(|data: &[u8]| {
    let Some((size, _)) = read_canonical(
        data,
        |reader| CompactSize::read(reader),
        |size, writer| size.write(writer),
        |_| 0,
    ) else {
        return;
    };
    if let Ok(valid) = size.enforce_valid() {
        assert_eq!(
            CompactSize::from(u64::from(valid)),
            valid,
            "a valid compact size is in its canonical form"
        );
    }
});
