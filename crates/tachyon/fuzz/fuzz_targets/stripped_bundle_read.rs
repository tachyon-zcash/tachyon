#![no_main]

//! Fuzz the typed reader for pointer-stamped bundles,
//! [`Bundle::<PointerStamp>::read`].
//!
//! Reaches the `0x02` state byte and the nonzero 64-byte `stampWtxid` trailer
//! (the all-zero encoding is rejected). Liveness only: any input must decode or
//! return a clean `io::Error`, never panic or exhibit UB.

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::{bundle::Bundle, stamp::PointerStamp};

fuzz_target!(|data: &[u8]| {
    let _ = Bundle::<PointerStamp>::read(data);
});
