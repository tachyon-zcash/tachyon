//! Oracles the fuzz targets share.
//!
//! Every reader under fuzz consumes untrusted bytes. Liveness is the floor: an
//! input decodes or returns an `io::Error`, never panics. On top of that, an
//! accepted input must be the canonical encoding of the value it decodes to,
//! so writing the value back reproduces exactly the bytes the reader consumed.
//! A reader that accepted an over-long count, an unsorted or repeated
//! tachygram, or any other alternative spelling fails that comparison.
//!
//! The one exception is a proof stamp's proof, an opaque blob that ragu's own
//! codec decodes. Mock ragu reads the proof's fields and ignores the padding
//! after them, so a blob is accepted with any padding and written back with
//! zeros. The comparison stops short of the proof and leaves its canonicality
//! to ragu.

use std::{hint, io};

use zcash_tachyon::{
    Bundle,
    stamp::{ProofStamp, StampState},
    value,
};

/// Read a value off the front of `data`. When it decodes, assert `write`
/// reproduces the consumed bytes, all but the last `opaque_tail(&value)` of
/// them, and return the value with the unread tail of `data`.
///
/// # Panics
///
/// Panics if an accepted value fails to re-encode, or re-encodes to bytes
/// other than the ones consumed.
pub fn read_canonical<'data, T>(
    data: &'data [u8],
    read: impl FnOnce(&mut &'data [u8]) -> io::Result<T>,
    write: impl FnOnce(&T, &mut Vec<u8>) -> io::Result<()>,
    opaque_tail: impl FnOnce(&T) -> usize,
) -> Option<(T, &'data [u8])> {
    let mut rest = data;
    let decoded = read(&mut rest).ok()?;
    let consumed = &data[..data.len() - rest.len()];

    let mut encoded = Vec::new();
    write(&decoded, &mut encoded).expect("an accepted value re-encodes");
    assert_eq!(
        encoded.len(),
        consumed.len(),
        "an accepted value re-encodes to the length consumed"
    );
    let compared = consumed.len() - opaque_tail(&decoded);
    if let Some(offset) = encoded[..compared]
        .iter()
        .zip(&consumed[..compared])
        .position(|(re, orig)| re != orig)
    {
        panic!(
            "an accepted encoding is not canonical: {} bytes consumed, first difference at byte {offset}",
            consumed.len(),
        );
    }

    Some((decoded, rest))
}

/// The length of a proof stamp's proof blob, the tail of its encoding.
#[must_use]
pub fn proof_len(stamp: &ProofStamp) -> usize {
    stamp.proof.serialize().len()
}

/// Assert the bundle-body invariants a canonical encoding does not imply, and
/// take both digests over the decoded bundle.
///
/// # Panics
///
/// Panics if a bundle without actions carries a nonzero value balance, or if
/// its max fee commitment is the identity.
pub fn assert_bundle_invariants<S: StampState + 'static>(bundle: &Bundle<S>) {
    if bundle.actions.is_empty() {
        assert_eq!(
            bundle.value_balance,
            value::Balance::ZERO,
            "a bundle without actions has a zero value balance"
        );
    }
    assert_ne!(
        bundle.fee_max_commitment,
        value::Commitment::default(),
        "the max fee commitment is not the identity"
    );

    hint::black_box(bundle.commitment());
    hint::black_box(bundle.auth_digest());
}

/// Assert the proof stamp invariants a canonical encoding does not imply.
///
/// # Panics
///
/// Panics if the stamp publishes no tachygram.
pub fn assert_proof_stamp_invariants(stamp: &ProofStamp) {
    assert!(
        !stamp.tachygrams.is_empty(),
        "a proof stamp publishes at least one tachygram"
    );
}
