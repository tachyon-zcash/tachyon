# Tachyon Fuzz Targets

Every target feeds untrusted bytes to the public consensus readers and checks
two things:
- **Liveness.** The input decodes or returns `io::Error`. It never panics, aborts or hangs.
- **Canonicality.** An accepted input is the one encoding of the value it decodes to: writing the value back reproduces the bytes the reader consumed, and the value holds the invariants the writer relies on.

The proof blob is the exception. It is ragu's encoding, and mock ragu ignores
the padding after the proof's fields, so the comparison stops short of it.

| Target          | Reads |
| --------------- | ----- |
| `bundle_read`   | `TachyonBundle::read` on every input; accepts pointer-stamped bundles and the no-bundle state |
| `stamp_read`    | `PointerStamp::read` on every input, and `ProofStamp::read` for liveness only |
| `wire_mutation` | a consistent aggregate and zero to four adjuncts built from the input, then edited, through `TachyonBundle::read` and `Bundle::verify`; the only target that accepts proof-stamped bundles |

A proof stamp ends in a proof blob that raw bytes cannot supply. The blob is
longer than libFuzzer's default input limit of 4,096 bytes, and ragu checks a
hash over its fields when it decodes it. So `bundle_read` and `stamp_read` reach
a proof stamp's fields only to reject them, and `wire_mutation` covers accepted
proof stamps.

`wire_mutation`'s input is a shape, not wire bytes. It chooses:
- the aggregate's actions, their kinds and wire order, its fees and memo length;
- each adjunct's actions and fees;
- up to four edits: a byte flipped, inserted or deleted outside the memos and the proof blob, or the encoding truncated anywhere.

The built aggregate covers its adjuncts:
- its coverage digests all their descriptors and fees;
- it publishes two tachygrams per covered action and one per covered fee under a commitment to them;
- each adjunct points at its wtxid.

Every bundle signs its own commitment. The aggregate carries the proof of one
action-free stamp, proved once at initialization, so no wire verifies. An
unedited wire must decode completely to the bundles built, and `verify` must
reject it at the proof and nowhere earlier. An edited wire may be rejected at
any stage, but must not panic.

## Running

The recipes call [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) on
the pinned nightly, and install both first, skipping whatever is already
installed. From the repository root:

```sh
just fuzz
```

- `just fuzz` runs every target for five minutes each, one after another, and stops at the first crash. Arguments starting with `-` go to libFuzzer for every target, for example `just fuzz -runs=0` to replay the corpora once.
- `just fuzz TARGET` runs one target on `corpus/TARGET`, also for five minutes unless the arguments say otherwise: `just fuzz bundle_read -max_total_time=0` runs until a crash.
- Crashes land in `artifacts/TARGET`.
- `just fuzz-cmin [TARGET...]` minimizes every corpus, or the named ones. It may drop a committed regression seed; restore it with `git restore`.
- `just fuzz-tmin TARGET INPUT` minimizes a crashing input.
- `just fuzz-lint` checks this crate's formatting, and lints it with clippy's default lints rather than the library's lint table. `just ci_local` runs it.

## CI

The `fuzz` job in `rust.yml` runs on every push to `main`, and on pull
requests that change what the other Rust jobs watch, this crate or the
justfile. It is part of `ci-required`. It lints this crate, then builds every
target and replays its committed corpus once with `just fuzz -runs=0`. It does
not explore, so it fails only on a committed input. The `fmt` job checks this
crate's formatting.

`fuzz-cron.yml` runs a campaign twice a week, or on dispatch, with one job per
`[[bin]]` target in `Cargo.toml`:
- Each job fuzzes its target for an hour, or the dispatched duration.
- Each corpus persists in the Actions cache between campaigns and is minimized at the end of each one.
- Crashes upload as the `fuzz-artifacts-TARGET` artifact.

To keep a crash found by a campaign:
1. Download its `fuzz-artifacts-TARGET` artifact.
2. Minimize the input with `just fuzz-tmin TARGET <crash file>`, with the path given from the repository root.
3. Commit the result as `corpus/TARGET/regression_<name>` with the fix, so every later run replays it.

## Corpus

Only regression seeds are committed. Everything else under `corpus/` is ignored.

| Seeds | Target | Found |
| ----- | ------ | ----- |
| `regression_alloc_near_cap` | `bundle_read` | a proof-stamped bundle header with an action count of `0x01FFFFFF`, under `MAX_COMPACT_SIZE`, that once drove a multi-gigabyte preallocation; it must parse-error cleanly, within libFuzzer's default 2 GB RSS limit |
| `regression_alloc_near_cap_stripped` | `bundle_read` | the same header in the pointer-stamped state |
