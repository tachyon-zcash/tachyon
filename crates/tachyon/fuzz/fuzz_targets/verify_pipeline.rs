#![no_main]

//! Fuzz the digest boundaries a validator crosses between parsing a bundle
//! and verifying its proof.
//!
//! The input is a proof-stamped bundle followed by up to four pointer-stamped
//! adjuncts. Every check that consumes their parsed fields runs: signatures,
//! pointers, coverage, tachygram arity and set, the action and fee digests,
//! the anchor folds over the stamp's set commitment, and the stamp digest.
//! Each check may reject; none may panic. Proof verification is exercised by
//! `verify_reject`, on edits to an honest base.

use std::hint;

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::{
    ActionDigest, ActionDigestError, EpochIndex, action,
    bundle::Bundle,
    fee,
    stamp::{PointerStamp, ProofStamp, StampState},
};
use zcash_tachyon_fuzz::{proof_len, read_canonical};

fuzz_target!(|data: &[u8]| {
    let Some((aggregate, mut rest)) = read_canonical(
        data,
        |reader| Bundle::<ProofStamp>::read(reader),
        |bundle, writer| bundle.write(writer),
        |bundle| proof_len(&bundle.stamp),
    ) else {
        return;
    };
    let mut adjuncts = Vec::new();
    while adjuncts.len() < 4 {
        let Some((adjunct, tail)) = read_canonical(
            rest,
            |reader| Bundle::<PointerStamp>::read(reader),
            |bundle, writer| bundle.write(writer),
            |_| 0,
        ) else {
            break;
        };
        adjuncts.push(adjunct);
        rest = tail;
    }
    let adjunct_refs: Vec<&Bundle<PointerStamp>> = adjuncts.iter().collect();
    let dyn_refs: Vec<&Bundle<dyn StampState>> = adjuncts.iter().map(Bundle::as_dyn).collect();

    let mut wtxid = [0u8; 64];
    wtxid[..32].copy_from_slice(&aggregate.commitment());
    wtxid[32..].copy_from_slice(&aggregate.auth_digest());
    let wtxid = adjuncts
        .first()
        .map_or(wtxid, |adjunct| adjunct.stamp.wtxid.into());

    hint::black_box(aggregate.verify_signatures(&aggregate.commitment()).is_ok());
    hint::black_box(aggregate.is_covering(&dyn_refs));
    hint::black_box(aggregate.stamp.stamp_digest());
    for epoch in [EpochIndex::new(0), EpochIndex::new(1)] {
        hint::black_box(
            aggregate
                .stamp
                .anchor
                .next_stamp(epoch, &aggregate.stamp.tachygram_set)
                .is_ok(),
        );
        hint::black_box(aggregate.stamp.anchor.next_epoch(epoch).is_ok());
    }

    let Ok((adjunct_descs, adjunct_fees)) = aggregate.verify_pointers(&wtxid, &adjunct_refs) else {
        return;
    };
    let Ok((covered_descs, covered_fees)) =
        aggregate.verify_coverage(&adjunct_descs, &adjunct_fees)
    else {
        return;
    };
    hint::black_box(
        aggregate
            .verify_tachygrams(covered_descs.len(), covered_fees.len())
            .is_ok(),
    );
    let digests: Result<Vec<ActionDigest>, ActionDigestError> = covered_descs
        .iter()
        .map(action::Descriptor::digest)
        .chain(covered_fees.iter().map(fee::Descriptor::digest))
        .collect();
    hint::black_box(digests.is_ok());
});
