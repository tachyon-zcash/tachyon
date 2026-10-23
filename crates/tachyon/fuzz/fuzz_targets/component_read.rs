#![no_main]

//! Fuzz the fixed-width component readers the bundle and stamp readers are
//! built from.
//!
//! The first byte picks the reader and the rest is its input. Each reader
//! decodes a field element, a compressed curve point or a signature, so an
//! accepted input must be the canonical 32- or 64-byte encoding of what it
//! decodes to.

use libfuzzer_sys::fuzz_target;
use zcash_tachyon::{ActionSetCommit, Anchor, Tachygram, TachygramSetCommit, action, bundle};
use zcash_tachyon_fuzz::read_canonical;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    match selector % 7 {
        0 => drop(read_canonical(
            input,
            |reader| action::Descriptor::read(reader),
            |desc, writer| desc.write(writer),
            |_| 0,
        )),
        1 => drop(read_canonical(
            input,
            |reader| action::Signature::read(reader),
            |sig, writer| sig.write(writer),
            |_| 0,
        )),
        2 => drop(read_canonical(
            input,
            |reader| bundle::Signature::read(reader),
            |sig, writer| sig.write(writer),
            |_| 0,
        )),
        3 => drop(read_canonical(
            input,
            |reader| Anchor::read(reader),
            |anchor, writer| anchor.write(writer),
            |_| 0,
        )),
        4 => drop(read_canonical(
            input,
            |reader| Tachygram::read(reader),
            |tachygram, writer| tachygram.write(writer),
            |_| 0,
        )),
        5 => drop(read_canonical(
            input,
            |reader| TachygramSetCommit::read(reader),
            |commit, writer| commit.write(writer),
            |_| 0,
        )),
        _ => drop(read_canonical(
            input,
            |reader| ActionSetCommit::read(reader),
            |commit, writer| commit.write(writer),
            |_| 0,
        )),
    }
});
