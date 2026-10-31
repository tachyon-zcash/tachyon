#![no_main]

//! Fuzz the proof stamp trailer reader, [`ProofStamp::read`], on its own.
//!
//! The bundle targets reach this reader only behind a well-formed bundle body;
//! here every input lands on the trailer directly. An accepted input must be
//! canonical (in particular, its tachygrams strictly increasing) and hold the
//! stamp invariants.

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::stamp::{ProofStamp, StampState as _};
use zcash_tachyon_fuzz::{assert_proof_stamp_invariants, proof_len, read_canonical};

fuzz_target!(|data: &[u8]| {
    if let Some((stamp, _)) = read_canonical(
        data,
        |reader| ProofStamp::read(reader),
        |stamp, writer| stamp.write(writer),
        proof_len,
    ) {
        assert_proof_stamp_invariants(&stamp);
        std::hint::black_box(stamp.stamp_digest());
    }
});
