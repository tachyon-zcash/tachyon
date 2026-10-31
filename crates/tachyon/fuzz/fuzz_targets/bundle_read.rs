#![no_main]

//! Fuzz the top-level consensus-wire dispatcher, [`TachyonBundle::read`].
//!
//! Feeds arbitrary attacker-controlled bytes into the reader that dispatches
//! on the `tachyonBundleState` byte. Any input must decode or return a clean
//! `io::Error`, never panic, abort, or exhibit UB. An accepted input must be
//! canonical and hold the bundle invariants, and the dispatched digests must
//! agree with the typed bundle's. For a proof- or pointer-stamped state byte,
//! the typed reader for that state must accept and reject the same inputs,
//! consume the same bytes and decode a bundle with the same digests.

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::{
    bundle::{Bundle, StateByte, TachyonBundle},
    digest::blake2b,
    stamp::{PointerStamp, ProofStamp, StampState},
};
use zcash_tachyon_fuzz::{
    assert_bundle_invariants, assert_proof_stamp_invariants, proof_len, read_canonical,
};

/// The bytes consumed and both digests, if the typed reader for `S` accepts.
fn read_typed<S: StampState>(data: &[u8]) -> Option<(usize, [u8; 32], [u8; 32])> {
    let mut rest = data;
    let bundle = Bundle::<S>::read(&mut rest).ok()?;
    Some((
        data.len() - rest.len(),
        bundle.commitment(),
        bundle.auth_digest(),
    ))
}

fuzz_target!(|data: &[u8]| {
    let dispatched = read_canonical(
        data,
        |reader| TachyonBundle::read(reader),
        |bundle, writer| bundle.write(writer),
        |bundle| match *bundle {
            TachyonBundle::Proven(ref proven) => proof_len(&proven.stamp),
            TachyonBundle::NoBundle | TachyonBundle::Adjunct(_) => 0,
        },
    );

    let typed = match data.first().copied() {
        Some(byte) if byte == u8::from(StateByte::ProofStamped) => {
            Some(read_typed::<ProofStamp>(data))
        },
        Some(byte) if byte == u8::from(StateByte::PointerStamped) => {
            Some(read_typed::<PointerStamp>(data))
        },
        _ => None,
    };
    if let Some(typed) = typed {
        assert_eq!(
            dispatched.as_ref().map(|(bundle, rest)| (
                data.len() - rest.len(),
                bundle.commitment(),
                bundle.auth_digest()
            )),
            typed,
            "the dispatcher and the typed reader agree on acceptance, length and digests"
        );
    }

    let Some((bundle, _)) = dispatched else {
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
