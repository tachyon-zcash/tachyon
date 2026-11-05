#![no_main]

//! Fuzz the stamp trailer readers, [`ProofStamp::read`] and
//! [`PointerStamp::read`], on every input.
//!
//! The bundle readers reach a trailer only behind a well-formed bundle body;
//! here every input lands on both trailers directly. An accepted pointer stamp
//! is canonical.
//!
//! A proof stamp ends in a proof blob that raw bytes cannot supply: the blob
//! is longer than libFuzzer's default input limit, and ragu checks a hash over
//! its fields when it decodes it. So `ProofStamp::read` only has to reject
//! every input without panicking. `wire_mutation` covers accepted proof
//! stamps.

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::stamp::{PointerStamp, ProofStamp};
use zcash_tachyon_fuzz::read_canonical;

fuzz_target!(|data: &[u8]| {
    drop(ProofStamp::read(data));
    read_canonical(
        data,
        |reader| PointerStamp::read(reader),
        |stamp, writer| stamp.write(writer),
        |_| 0,
    );
});
