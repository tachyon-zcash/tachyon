#![no_main]

//! Fuzz the typed reader for proof-stamped bundles,
//! [`Bundle::<ProofStamp>::read`].
//!
//! Reaches the full stamp trailer (action-set commitment, anchor, tachygram
//! list, proof) behind the `0x01` state byte. Liveness only: any input must
//! decode or return a clean `io::Error`, never panic or exhibit UB.

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::{bundle::Bundle, stamp::ProofStamp};

fuzz_target!(|data: &[u8]| {
    let _ = Bundle::<ProofStamp>::read(data);
});
