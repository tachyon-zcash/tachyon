#![no_main]

//! Fuzz the typed reader for proof-stamped bundles,
//! [`Bundle::<ProofStamp>::read`].
//!
//! Reaches the full stamp trailer (fee, coverage digest, anchor, tachygram set
//! commitment, tachygram list, proof) behind the `0x01` state byte. Any input
//! must decode or return a clean `io::Error`, never panic or exhibit UB. An
//! accepted input must be canonical and hold the bundle and stamp invariants.

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::{bundle::Bundle, stamp::ProofStamp};
use zcash_tachyon_fuzz::{
    assert_bundle_invariants, assert_proof_stamp_invariants, proof_len, read_canonical,
};

fuzz_target!(|data: &[u8]| {
    if let Some((bundle, _)) = read_canonical(
        data,
        |reader| Bundle::<ProofStamp>::read(reader),
        |bundle, writer| bundle.write(writer),
        |bundle| proof_len(&bundle.stamp),
    ) {
        assert_bundle_invariants(&bundle);
        assert_proof_stamp_invariants(&bundle.stamp);
    }
});
