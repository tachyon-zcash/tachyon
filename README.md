# Tachyon

The Tachyon shielded transaction protocol for Zcash.

This repository holds the reference implementation, the `zcash_tachyon` crate
in [`crates/tachyon`](crates/tachyon), and the protocol's documentation, The
Tachyon Book, in [`book`](book).

## Status

Work in progress. The crate is version `0.0.0` and is not published, and its
API changes without notice.

## The crate

`zcash_tachyon` implements keys, notes, nullifiers, value commitments, fees,
actions, bundles and stamps. Stamps are proven, merged and verified with
[Ragu](https://github.com/tachyon-zcash/ragu) proof-carrying data. Ragu is a
git dependency pinned to a revision, so the first build fetches it from GitHub.

The crate is `no_std`. The default `std` feature enables `std` support in its
dependencies and multicore proving in Ragu.

## Development

Requires stable Rust 1.97 or later and [`just`](https://github.com/casey/just).
Formatting uses the pinned toolchain `nightly-2026-05-23`.

```sh
just test          # unit tests, then integration tests and doctests with --release
just lint          # build the docs, then clippy for no_std and for all targets
just fmt           # format with the pinned nightly
just check         # cargo check for no_std and for all targets
just doc           # rustdoc, with private items and KaTeX
just book serve    # build | serve | watch the book
just ci_local      # the Rust CI gates, without the OS matrix
```

`just test` passes its arguments to libtest. `just book` installs pinned
versions of `mdbook`, `mdbook-katex` and `mdbook-mermaid` with `cargo-binstall`
before it runs.

Unit and integration tests build with the `test-epoch-size` feature, which
shortens an epoch from 4096 blocks to 64. Only `tests/epoch.rs` runs at the
shipped epoch size. `just ci_local` includes it and `just test` does not.

## License

MIT OR Apache-2.0
