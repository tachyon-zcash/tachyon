#![no_main]

//! Fuzz the stamp trailer readers, [`ProofStamp::read`] and
//! [`PointerStamp::read`], on every input.
//!
//! The bundle readers reach a trailer only behind a well-formed bundle body;
//! here every input lands on both trailers directly. An accepted proof stamp is
//! canonical up to its proof blob (in particular, its tachygrams strictly
//! increase) and publishes a tachygram. An accepted pointer stamp is
//! canonical. Both digest without panicking.

use std::hint;

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::stamp::{PointerStamp, ProofStamp, StampState as _};
use zcash_tachyon_fuzz::{assert_proof_stamp_invariants, proof_len, read_canonical};

fuzz_target!(|data: &[u8]| {
    if let Some((stamp, _)) = read_canonical(
        data,
        |reader| ProofStamp::read(reader),
        |stamp, writer| stamp.write(writer),
        proof_len,
    ) {
        assert_proof_stamp_invariants(&stamp);
        hint::black_box(stamp.stamp_digest());
    }
    if let Some((stamp, _)) = read_canonical(
        data,
        |reader| PointerStamp::read(reader),
        |stamp, writer| stamp.write(writer),
        |_| 0,
    ) {
        hint::black_box(stamp.stamp_digest());
    }
});
