# Tachyon Fuzz Targets

Run from repo root:

```sh
just fuzz bundle_read -- -runs=1000
just fuzz stamped_bundle_read -- -runs=1000
just fuzz stripped_bundle_read -- -runs=1000
```

Direct cargo-fuzz form:

```sh
cargo +nightly fuzz run bundle_read --fuzz-dir crates/tachyon/fuzz
```

Requires a nightly toolchain at or above the workspace MSRV (1.90). The default
`+nightly` may be older than that and will fail with an MSRV error — run
`rustup update nightly`, or pin a recent dated nightly explicitly, e.g.
`cargo +nightly-2026-04-11 fuzz run bundle_read --fuzz-dir crates/tachyon/fuzz`.

These targets fuzz public wire-format readers and assert liveness only:
arbitrary bytes must decode or return `io::Error`, not panic, abort, or hang.
Semantic rejection rules belong in unit/regression tests.

The seed corpus is intentionally minimal. Real fixture-derived seeds are
deferred until there is a `testing`/`fixtures` surface usable from this
detached fuzz crate.

`regression_alloc_near_cap` pins a past finding: a near-`MAX_COMPACT_SIZE`
action count that once drove an unbounded `Vec::with_capacity` (multi-GB
allocation) in the reader. The readers now grow incrementally and fail fast at
EOF, so this input must parse-error cleanly, never OOM.
