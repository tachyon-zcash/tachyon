#![no_main]

//! Fuzz the typed reader for pointer-stamped bundles,
//! [`Bundle::<PointerStamp>::read`].
//!
//! Reaches the `0x02` state byte, the fee and the nonzero 64-byte
//! `tachyonAggregateId` trailer (the all-zero encoding is rejected). Any input
//! must decode or return a clean `io::Error`, never panic or exhibit UB. An
//! accepted input must be canonical and hold the bundle invariants.

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::{bundle::Bundle, stamp::PointerStamp};
use zcash_tachyon_fuzz::{assert_bundle_invariants, read_canonical};

fuzz_target!(|data: &[u8]| {
    if let Some((bundle, _)) = read_canonical(
        data,
        |reader| Bundle::<PointerStamp>::read(reader),
        |bundle, writer| bundle.write(writer),
        |_| 0,
    ) {
        assert_bundle_invariants(&bundle);
    }
});
