#![no_main]

//! Fuzz the consensus-wire bundle reader, [`TachyonBundle::read`].
//!
//! Arbitrary bytes decode or return a clean `io::Error`, never panic. An
//! accepted bundle is canonical and holds the bundle invariants. Raw bytes
//! cannot carry a valid mock proof, so a proof-stamped input is never accepted
//! here; `wire_mutation` covers that path.
//!
//! [`TachyonBundle::read`]: zcash_tachyon::bundle::TachyonBundle::read

use libfuzzer_sys::fuzz_target;
use zcash_tachyon_fuzz::check_bundle_wire;

fuzz_target!(|data: &[u8]| {
    drop(check_bundle_wire(data));
});
