# Tachyon

Tachyon is a shielded transaction protocol for Zcash, designed to reduce what
shielded transactions cost the chain.

A Tachyon bundle carries a stamp: a recursive zero-knowledge proof that the
bundle's actions follow the rules. Stamps can be merged, so one stamp covers
many transactions instead of each being verified individually. Notes are
simpler than Orchard's, and viewing keys, diversified addresses and on-chain
note ciphertexts leave the core protocol: wallets exchange payment details out
of band.

This repository holds the reference implementation, the `zcash_tachyon` crate
in [`crates/tachyon`](crates/tachyon), and The Tachyon Book in [`book`](book).
Both are work in progress. The crate is version `0.0.0`, unpublished, and its
API changes without notice.

## Where to go next

- **The protocol:** read the book with `just book serve`, or in place starting
  from [Bundles](book/src/bundle.md), [Proof Tree](book/src/proof-tree.md) and
  [Aggregation](book/src/aggregation.md).
- **The design rationale:** Sean Bowe's
  [Tachyaction at a Distance](https://seanbowe.com/blog/tachyaction-at-a-distance/).
- **The API:** `just doc --open` builds the crate's rustdoc.
- **The proof system:** [Ragu](https://github.com/tachyon-zcash/ragu) and its
  [book](https://tachyon.z.cash/ragu/). The crate proves, merges and verifies
  stamps with Ragu proof-carrying data.
- **The ZIPs:** [Tachyon ZIPs](book/src/zips/tachyon-zips.md) maps the
  specification work.

## Development

Requires stable Rust 1.97 or later and [`just`](https://github.com/casey/just).
Formatting uses the pinned toolchain `nightly-2026-05-23`. Ragu is a git
dependency pinned to a revision, so the first build fetches it from GitHub.

```sh
just test        # unit tests, then integration tests and doctests with --release
just lint        # build the docs, then clippy for no_std and for all targets
just fmt         # format with the pinned nightly
just check       # cargo check for no_std and for all targets
just ci_local    # the Rust CI gates, without the OS matrix
```

`just test` passes its arguments to libtest. `just book` installs pinned
versions of `mdbook`, `mdbook-katex` and `mdbook-mermaid` with `cargo-binstall`
before it runs.

Unit and integration tests build with the `test-epoch-size` feature, which
shortens an epoch from 4096 blocks to 64. Only `tests/epoch.rs` runs at the
shipped epoch size. `just ci_local` includes it and `just test` does not.

The crate is `no_std`; `std` is a default feature.

## License

MIT OR Apache-2.0
