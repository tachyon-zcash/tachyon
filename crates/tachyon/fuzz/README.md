# Tachyon Fuzz Targets

Install `cargo-fuzz`, then run from this directory. The local toolchain file
pins a nightly new enough for the workspace MSRV:

```sh
cd crates/tachyon/fuzz
cargo fuzz run bundle_read -- -runs=10000 -max_len=32768
cargo fuzz run stamped_bundle_read -- -runs=10000 -max_len=32768
cargo fuzz run stripped_bundle_read -- -runs=10000 -max_len=32768
```

From the repository root, the equivalent form is:

```sh
cargo +nightly-2026-04-11 fuzz run bundle_read \
    --fuzz-dir crates/tachyon/fuzz -- -runs=10000 -max_len=32768
```

These targets fuzz public wire-format readers and assert liveness only:
arbitrary bytes must decode or return `io::Error`, not panic, abort, or hang.
Semantic rejection rules belong in unit/regression tests.

Each typed target has a valid serializer-generated seed that reaches its full
stamp trailer. The top-level target has both valid bundle variants so its
state-byte dispatch reaches both bodies. Keep `-max_len` at least 32768: the
proof-stamped seed is larger than libFuzzer's 4096-byte default.

`regression_alloc_near_cap` pins a past finding: a near-`MAX_COMPACT_SIZE`
action count that once drove a multi-gigabyte preallocation in the reader. The
readers now grow incrementally and fail fast at EOF, so this input must
parse-error cleanly, never OOM.

`noncanonical_action_count` exercises the public readers' rejection of an
over-long CompactSize action count before an action body is consumed.
