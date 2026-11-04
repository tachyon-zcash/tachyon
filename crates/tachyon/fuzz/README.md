# Tachyon Fuzz Targets

Every target feeds untrusted bytes to the public consensus readers and checks
two things:
- **Liveness.** The input decodes or returns `io::Error`. It never panics, aborts or hangs.
- **Canonicality.** An accepted input is the one encoding of the value it decodes to: writing the value back reproduces the bytes the reader consumed, and the value holds the invariants the writer relies on.

The proof blob is the exception. It is ragu's encoding, and mock ragu ignores
the padding after the proof's fields, so the comparison stops short of it.

| Target          | Reads |
| --------------- | ----- |
| `bundle_read`   | `TachyonBundle::read` on every input |
| `stamp_read`    | `ProofStamp::read` and `PointerStamp::read` on every input |
| `wire_mutation` | a consistent aggregate and zero to four adjuncts built from the input, then edited, through `TachyonBundle::read` and `Bundle::verify` |

`wire_mutation`'s input is a shape, not wire bytes. It chooses:
- the aggregate's actions, their kinds and wire order, its fees and memo length;
- each adjunct's actions and fees;
- up to four edits: a byte flipped, inserted or deleted, or the encoding truncated.

The built aggregate covers its adjuncts:
- its coverage digests all their descriptors and fees;
- it publishes two tachygrams per covered action and one per covered fee under a commitment to them;
- each adjunct points at its wtxid.

Every bundle signs its own commitment. The aggregate carries the proof of one
action-free stamp, proved once at initialization, so no wire verifies. An
unedited wire must decode completely to the bundles built, and `verify` must
reject it at the proof and nowhere earlier. An edited wire may be rejected at
any stage, but must not panic.

Raw bytes cannot carry a valid mock proof: the mock binds a proof to its
header. So `bundle_read` and `stamp_read` never accept a proof-stamped input,
and `wire_mutation` covers proof-stamped acceptance.

## Running

The recipes call [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) on
the pinned nightly. From the repository root:

```sh
just fuzz
```

The recipes install the pinned nightly, with `rustfmt`, and cargo-fuzz before they run, and skip whatever is already installed. CI uses the same recipes.

- `just fuzz` runs every target for five minutes each, one after another, and stops at the first crash.
- `just fuzz TARGET` runs one target on `corpus/TARGET`, for example `just fuzz bundle_read -max_total_time=60`. Any further arguments go to libFuzzer.
- Crashes land in `artifacts/TARGET`.
- `just fuzz-cmin TARGET` minimizes `corpus/TARGET`. It may drop a committed regression seed; restore it with `git restore`. The campaign workflow runs it after each campaign.

`just lint` runs clippy on this crate with warnings denied.

## CI

`fuzz.yml` runs on pull requests that touch `zcash_tachyon`'s sources or this
crate. It checks formatting and lints, then builds and replays each target's
committed corpus once with `-runs=0`. It does not explore, so it
fails only on a committed input.

`fuzz-cron.yml` runs a campaign twice a week, or on dispatch, for each target:
- It fuzzes for an hour, or the dispatched duration.
- The corpus persists in the Actions cache between campaigns and is minimized at the end of each one.
- Crashes upload as the `fuzz-artifacts-TARGET` artifact.

To keep a crash found by a campaign:
1. Download its `fuzz-artifacts-TARGET` artifact.
2. Minimize the input with `cargo fuzz tmin TARGET crash-<sha>`, from `crates/tachyon`.
3. Commit the result as `corpus/TARGET/regression_<name>` with the fix, so every later run replays it.

## Corpus

Only regression seeds are committed. Everything else under `corpus/` is ignored.

| Seeds | Target | Found |
| ----- | ------ | ----- |
| `regression_alloc_near_cap`, `regression_alloc_near_cap_stripped` | `bundle_read` | an action count of `0x01FFFFFF`, under `MAX_COMPACT_SIZE`, that once drove a multi-gigabyte preallocation; it must parse-error cleanly, within libFuzzer's default 2 GB RSS limit |
