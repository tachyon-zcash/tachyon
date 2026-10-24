//! The serializer-built fuzz seeds in `fuzz/corpus` still reach the paths they
//! were written for: each decodes completely through its target's reader, and
//! the `verify_pipeline` aggregates verify, the second under the sighash in
//! `fuzz/fixtures` that `verify_reject` reads. The hand-written `regression_*`,
//! `noncanonical_*` and `state_*` seeds are outside this check.

use std::{fs, path::Path};

use corez::io;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionSetCommit, Anchor, CompactSize, Tachygram, TachygramSetCommit, action,
    bundle::{self, Bundle, TachyonBundle},
    stamp::{PointerStamp, ProofStamp},
};

use crate::fixtures::{mock_sighash, mock_wtxid};

fn seed(target: &str, name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/corpus")
        .join(target)
        .join(name);
    fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

#[test]
fn valid_seeds_decode_completely() {
    let seeds: [(&str, &str, fn(&mut &[u8]) -> io::Result<()>); 6] = [
        ("bundle_read", "valid_proof_stamped", |reader| {
            TachyonBundle::read(reader).map(drop)
        }),
        ("bundle_read", "valid_pointer_stamped", |reader| {
            TachyonBundle::read(reader).map(drop)
        }),
        ("stamped_bundle_read", "valid_proof_stamped", |reader| {
            Bundle::<ProofStamp>::read(reader).map(drop)
        }),
        ("stripped_bundle_read", "valid_pointer_stamped", |reader| {
            Bundle::<PointerStamp>::read(reader).map(drop)
        }),
        ("proof_stamp_read", "valid_proof_stamp", |reader| {
            ProofStamp::read(reader).map(drop)
        }),
        ("pointer_stamp_read", "valid_pointer_stamp", |reader| {
            PointerStamp::read(reader).map(drop)
        }),
    ];
    for (target, name, read) in seeds {
        let bytes = seed(target, name);
        let mut rest = bytes.as_slice();
        read(&mut rest).unwrap_or_else(|err| panic!("{target}/{name} decodes: {err}"));
        assert_eq!(rest, [], "{target}/{name} has no trailing bytes");
    }
}

#[test]
fn component_seeds_decode_under_their_selector() {
    let seeds: [(&str, u8, fn(&mut &[u8]) -> io::Result<()>); 7] = [
        ("action_descriptor", 0, |reader| {
            action::Descriptor::read(reader).map(drop)
        }),
        ("action_signature", 1, |reader| {
            action::Signature::read(reader).map(drop)
        }),
        ("binding_signature", 2, |reader| {
            bundle::Signature::read(reader).map(drop)
        }),
        ("anchor", 3, |reader| Anchor::read(reader).map(drop)),
        ("tachygram", 4, |reader| Tachygram::read(reader).map(drop)),
        ("tachygram_set", 5, |reader| {
            TachygramSetCommit::read(reader).map(drop)
        }),
        ("action_set", 6, |reader| {
            ActionSetCommit::read(reader).map(drop)
        }),
    ];
    for (name, selector, read) in seeds {
        let bytes = seed("component_read", name);
        let Some((&first, mut rest)) = bytes.split_first() else {
            panic!("component_read/{name} is empty");
        };
        assert_eq!(first, selector, "component_read/{name} selects its reader");
        read(&mut rest).unwrap_or_else(|err| panic!("component_read/{name} decodes: {err}"));
        assert_eq!(rest, [], "component_read/{name} has no trailing bytes");
    }
}

#[test]
fn compact_size_seeds_decode() {
    for (name, valid) in [
        ("one_byte", true),
        ("two_bytes", true),
        ("four_bytes", true),
        ("eight_bytes", false),
    ] {
        let bytes = seed("compact_size_read", name);
        let mut rest = bytes.as_slice();
        let size = CompactSize::read(&mut rest)
            .unwrap_or_else(|err| panic!("compact_size_read/{name} decodes: {err}"));
        assert_eq!(rest, [], "compact_size_read/{name} has no trailing bytes");
        assert_eq!(
            size.enforce_valid().is_ok(),
            valid,
            "compact_size_read/{name} passes consensus validation: {valid}"
        );
    }
}

#[test]
fn verify_pipeline_seeds_verify() {
    let rng = &mut StdRng::seed_from_u64(0);

    let bytes = seed("verify_pipeline", "autonome");
    let mut rest = bytes.as_slice();
    let autonome = Bundle::<ProofStamp>::read(&mut rest).expect("the autonome decodes");
    assert_eq!(rest, [], "verify_pipeline/autonome has no trailing bytes");
    autonome
        .verify(
            rng,
            &mock_sighash(autonome.commitment()),
            &mock_wtxid(&autonome).into(),
            &[],
        )
        .expect("the autonome verifies");

    let bytes = seed("verify_pipeline", "aggregate_with_adjunct");
    let mut rest = bytes.as_slice();
    let aggregate = Bundle::<ProofStamp>::read(&mut rest).expect("the aggregate decodes");
    let adjunct = Bundle::<PointerStamp>::read(&mut rest).expect("the adjunct decodes");
    assert_eq!(
        rest,
        [],
        "verify_pipeline/aggregate_with_adjunct has no trailing bytes"
    );
    let wtxid = mock_wtxid(&aggregate);
    assert_eq!(
        adjunct.stamp.wtxid, wtxid,
        "the adjunct points to the aggregate"
    );
    let sighash = mock_sighash(aggregate.commitment());
    aggregate
        .verify(rng, &sighash, &wtxid.into(), &[&adjunct])
        .expect("the aggregate verifies against its adjunct");

    let sidecar =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fixtures/aggregate_with_adjunct.sighash");
    assert_eq!(
        fs::read(&sidecar).unwrap_or_else(|err| panic!("read {}: {err}", sidecar.display())),
        sighash,
        "the sighash sidecar is the aggregate's"
    );
}
