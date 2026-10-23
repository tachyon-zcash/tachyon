#![no_main]

//! Fuzz the top-level consensus-wire dispatcher, [`TachyonBundle::read`].
//!
//! Feeds arbitrary attacker-controlled bytes into the reader that dispatches
//! on the `tachyonBundleState` byte. Any input must decode or return a clean
//! `io::Error`, never panic, abort, or exhibit UB. An accepted input must be
//! canonical and hold the bundle invariants, and the dispatched digests must
//! agree with the typed bundle's.

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::{bundle::TachyonBundle, digest::blake2b};
use zcash_tachyon_fuzz::{
    assert_bundle_invariants, assert_proof_stamp_invariants, proof_len, read_canonical,
};

fuzz_target!(|data: &[u8]| {
    let Some((bundle, _)) = read_canonical(
        data,
        |reader| TachyonBundle::read(reader),
        |bundle, writer| bundle.write(writer),
        |bundle| match *bundle {
            TachyonBundle::Proven(ref proven) => proof_len(&proven.stamp),
            TachyonBundle::NoBundle | TachyonBundle::Adjunct(_) => 0,
        },
    ) else {
        return;
    };

    let (commitment, auth_digest) = match bundle {
        TachyonBundle::NoBundle => (*blake2b::COMMIT_NO_BUNDLE, *blake2b::AUTH_DIGEST_NO_BUNDLE),
        TachyonBundle::Proven(ref proven) => {
            assert_bundle_invariants(proven);
            assert_proof_stamp_invariants(&proven.stamp);
            (proven.commitment(), proven.auth_digest())
        },
        TachyonBundle::Adjunct(ref adjunct) => {
            assert_bundle_invariants(adjunct);
            (adjunct.commitment(), adjunct.auth_digest())
        },
    };
    assert_eq!(
        bundle.commitment(),
        commitment,
        "the dispatched commitment is the variant's"
    );
    assert_eq!(
        bundle.auth_digest(),
        auth_digest,
        "the dispatched auth digest is the variant's"
    );
});
