#![no_main]

//! Fuzz the pointer stamp trailer reader, [`PointerStamp::read`], on its own.
//!
//! An accepted input must be canonical, and its 72-byte stamp digest is the
//! encoding itself: the fee followed by the aggregate id.

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::stamp::{PointerStamp, StampState as _};
use zcash_tachyon_fuzz::read_canonical;

fuzz_target!(|data: &[u8]| {
    if let Some((stamp, _)) = read_canonical(
        data,
        |reader| PointerStamp::read(reader),
        |stamp, writer| stamp.write(writer),
        |_| 0,
    ) {
        assert_eq!(
            &stamp.stamp_digest()[..],
            &data[..72],
            "a pointer stamp digests to its encoding"
        );
    }
});
