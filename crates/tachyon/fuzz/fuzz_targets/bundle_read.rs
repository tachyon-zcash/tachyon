#![no_main]

//! Fuzz the consensus-wire bundle reader, [`TachyonBundle::read`].
//!
//! Arbitrary bytes decode or return a clean `io::Error`, never panic. An
//! accepted bundle is canonical and holds the bundle invariants.
//!
//! A proof-stamped bundle ends in a proof blob that raw bytes cannot supply:
//! the blob is longer than libFuzzer's default input limit, and ragu checks a
//! hash over its fields when it decodes it. So this target accepts only
//! pointer-stamped bundles and the no-bundle state, and reaches a proof-stamped
//! bundle's fields only to reject them. `wire_mutation` covers accepted
//! proof-stamped bundles.
//!
//! [`TachyonBundle::read`]: zcash_tachyon::bundle::TachyonBundle::read

use libfuzzer_sys::fuzz_target;
use zcash_tachyon_fuzz::check_bundle_wire;

fuzz_target!(|data: &[u8]| {
    drop(check_bundle_wire(data));
});
