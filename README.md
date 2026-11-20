# Tachyon

Tachyon is a shielded transaction protocol for Zcash. It aims to reduce the
cost of shielded transactions to the chain.

A Tachyon bundle carries a stamp, a recursive zero-knowledge proof that the
bundle's actions follow the rules. Stamps can be merged, so a single stamp can
cover many transactions.

Tachyon notes are simpler than Orchard notes. Viewing keys, diversified
addresses and on-chain note ciphertexts are no longer part of the core
protocol. Wallets exchange payment details out of band instead.

This repository holds two things: the reference implementation, which is the
`zcash_tachyon` crate in [`crates/tachyon`](crates/tachyon), and The Tachyon
Book in [`book`](book). Both are work in progress. The crate is unpublished at
version `0.0.0`, and its API changes without notice.

## Where to go next

- **The protocol:** run `just book serve` to read the book. Its sources start
  with [Bundles](book/src/bundle.md), [Proof Tree](book/src/proof-tree.md) and
  [Aggregation](book/src/aggregation.md).
- **The design rationale:** Sean Bowe's
  [Tachyaction at a Distance](https://seanbowe.com/blog/tachyaction-at-a-distance/).
- **The API:** `just doc --open` builds the crate's rustdoc.
- **The proof system:** the crate proves, merges and verifies stamps with
  [Ragu](https://github.com/tachyon-zcash/ragu) proof-carrying data. Ragu has
  its own [book](https://tachyon.z.cash/ragu/).

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

`just test` passes its arguments to libtest. `just book` first installs pinned
versions of `mdbook`, `mdbook-katex` and `mdbook-mermaid` with `cargo-binstall`.

Unit and integration tests build with the `test-epoch-size` feature. It
shortens an epoch from 4096 blocks to 64. Only `tests/epoch.rs` runs at the
shipped epoch size, and only `just ci_local` runs it.

The crate is `no_std`, with `std` as a default feature.

## License

MIT OR Apache-2.0
