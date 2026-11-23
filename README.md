# Tachyon

Tachyon is a shielded transaction protocol for Zcash. It aims to reduce the
cost of shielded transactions to the chain.

This repository holds the reference implementation, in the `zcash_tachyon`
crate, and [The Tachyon Book](book), which describes the protocol. Both are
work in progress, and the crate's API changes without notice.

## Transaction structure

A bundle holds actions and a stamp. Each action has a signature and a pair of
tachygrams. A tachygram stands for a nullifier or a note commitment, and
consensus treats both alike.

The stamp carries a [Ragu](https://github.com/tachyon-zcash/ragu) proof that
the bundle's actions follow the rules. Stamps can be merged into one stamp that
covers several bundles, and the other bundles are stripped of their stamps.

```mermaid
classDiagram
    direction LR
    class Bundle {
        value_balance: value::Balance
        fee: fee::Descriptor
        binding_sig: Signature
        verify()
        strip()
    }
    class Action {
        cv: value::Commitment
        rk: ActionVerificationKey
        sig: action::Signature
        tachygrams: Tachygram[2]
    }
    class ProofStamp {
        anchor: Anchor
        tachygram_set: TachygramSetCommit
        proof: stamp::Proof
        merge()
        unmerge()
        compress()
    }
    Bundle "1" *-- "0..*" Action : actions
    Bundle "1" *-- "0..1" ProofStamp : stamp
    ProofStamp --> "0..*" Bundle : adjuncts
```

A stamp's adjuncts are the other bundles it covers, listed by transaction id.
`merge` combines two stamps into one, and `unmerge` divides one back out.
`strip` removes the stamp from a bundle that another stamp covers.

`compress` gives the stamp the compressed proof it travels with. An aggregator
is meant to decompress the stamps it receives, merge them, and compress the
result. The crate cannot decompress yet, so as a stopgap `merge` and `unmerge`
take stamps that were never compressed.

In the crate, an action's `cv` and `rk` form an `action::Descriptor`, and its
signature and tachygrams sit beside it in `Bundle::action_auth`. The book's
[Bundles](book/src/bundle.md) chapter explains every field.

## Development

Requires stable Rust 1.97 or later and [`just`](https://github.com/casey/just).
Formatting uses the pinned toolchain `nightly-2026-05-23`.

```sh
just test          # unit tests, then integration tests and doctests with --release
just lint          # build the docs, then clippy for no_std and for all targets
just fmt           # format with the pinned nightly
just check         # cargo check for no_std and for all targets
just doc --open    # build and open the crate's rustdoc
just book serve    # serve the book, after installing mdbook and its plugins
just ci_local      # the Rust CI gates, without the OS matrix
```

Unit and integration tests build with the `test-epoch-size` feature, which shortens an epoch from
4096 blocks to 64. Only `tests/epoch.rs` runs at the shipped epoch size, and
only `just ci_local` runs it.

## License

MIT OR Apache-2.0
