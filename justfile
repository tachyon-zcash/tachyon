default:
    @just --list

# keep in step with .github/actions/rust-nightly-setup/action.yml, the pin the
# `fmt` job checks against
_nightly := "nightly-2026-05-23"

_katex := "--html-in-header " + justfile_directory() / "crates/tachyon/katex-header.html"

fmt:
    cargo +{{_nightly}} fmt --all
    cargo +{{_nightly}} fmt --all --manifest-path {{_fuzz_dir}}/Cargo.toml

lint: doc
    cargo clippy --workspace --lib --no-default-features # no_std
    cargo clippy --workspace --all-targets --all-features
    cargo clippy --manifest-path {{_fuzz_dir}}/Cargo.toml --all-targets --locked -- -D warnings

test *ARGS:
    cargo test --workspace --all-features {{ARGS}}

doc *ARGS:
    RUSTDOCFLAGS="{{_katex}}" cargo doc --workspace --no-deps --document-private-items {{ARGS}}

check:
    cargo check --workspace --lib --no-default-features # no_std
    cargo check --workspace --all-targets --all-features

_fuzz_dir := justfile_directory() / "crates/tachyon/fuzz"

_fuzz_setup: _install_binstall
    rustup toolchain install {{_nightly}} --profile minimal --component rustfmt
    cargo binstall --no-confirm cargo-fuzz@0.13.2

# fuzz every target for 5 minutes each until a crash, or TARGET with libFuzzer ARGS
fuzz TARGET="" *ARGS: _fuzz_setup
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{_fuzz_dir}}/..
    if [ -n "{{TARGET}}" ]; then
        exec cargo +{{_nightly}} fuzz run {{TARGET}} -- {{ARGS}}
    fi
    for target in $(cargo +{{_nightly}} fuzz list); do
        cargo +{{_nightly}} fuzz run "$target" -- -max_total_time=300
    done

# minimize TARGET's corpus
fuzz-cmin TARGET: _fuzz_setup
    cd {{_fuzz_dir}}/.. && cargo +{{_nightly}} fuzz cmin {{TARGET}}

_install_binstall:
    cargo-binstall -V || cargo install cargo-binstall

_book_setup: _install_binstall
    cargo binstall mdbook@0.4.52 mdbook-katex@0.9.4 mdbook-mermaid@0.16.2

# locally [build | serve | watch] the Tachyon book
book COMMAND *ARGS: _book_setup
    mdbook {{COMMAND}} ./book {{ARGS}}

# the gates in .github/workflows/rust.yml, minus the os and 32-bit matrix
ci_local:
    cargo +{{_nightly}} fmt --all -- --check
    cargo clippy --workspace --lib --no-default-features --locked -- -D warnings
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --release --all --locked --lib
    cargo test --release --all --locked --all-features
    RUSTDOCFLAGS="-D warnings {{_katex}}" cargo doc --no-deps --all --locked --document-private-items
