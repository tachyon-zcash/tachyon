#![no_main]

//! Fuzz the top-level consensus-wire dispatcher, [`TachyonBundle::read`].
//!
//! Feeds arbitrary attacker-controlled bytes into the reader that dispatches
//! on the `tachyonBundleState` byte. The reader consumes untrusted network
//! data, so the invariant under test is liveness, not a semantic oracle: any
//! input must either decode or return a clean `io::Error` — never panic, abort,
//! or exhibit UB. Semantic rejection rules (canonical ordering, descriptor
//! uniqueness, etc.) are covered by unit tests, not here.

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::bundle::TachyonBundle;

fuzz_target!(|data: &[u8]| {
    // `&[u8]` implements `Read`; a decode error is a valid outcome, a panic is
    // not. The result is intentionally discarded.
    let _ = TachyonBundle::read(data);
});
