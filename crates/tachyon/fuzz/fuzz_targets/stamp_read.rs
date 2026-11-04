#![no_main]

//! Fuzz the stamp trailer readers, [`ProofStamp::read`] and
//! [`PointerStamp::read`], on every input.
//!
//! The bundle readers reach a trailer only behind a well-formed bundle body;
//! here every input lands on both trailers directly. An accepted pointer stamp
//! is canonical and digests without panicking.
//!
//! A proof stamp ends in a proof blob that raw bytes cannot supply: the blob
//! is longer than libFuzzer's default input limit, and ragu checks a hash over
//! its fields when it decodes it. So `ProofStamp::read` only has to reject
//! every input without panicking. `wire_mutation` covers accepted proof
//! stamps.

use std::hint;

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::stamp::{PointerStamp, ProofStamp, StampState as _};
use zcash_tachyon_fuzz::read_canonical;

fuzz_target!(|data: &[u8]| {
    drop(ProofStamp::read(data));
    if let Some((stamp, _)) = read_canonical(
        data,
        |reader| PointerStamp::read(reader),
        |stamp, writer| stamp.write(writer),
        |_| 0,
    ) {
        hint::black_box(stamp.stamp_digest());
    }
});
