default:
    @just --list

# keep in step with .github/actions/rust-nightly-setup/action.yml, the pin the
# `fmt` job checks against; the fuzz recipes install it too
_nightly := "nightly-2026-05-23"

_katex := "--html-in-header " + justfile_directory() / "crates/tachyon/katex-header.html"

_fuzz_dir := justfile_directory() / "crates/tachyon/fuzz"

fmt:
    cargo +{{_nightly}} fmt --all
    cargo +{{_nightly}} fmt --all --manifest-path {{_fuzz_dir}}/Cargo.toml

lint: doc
    cargo clippy --workspace --lib --no-default-features # no_std
    cargo clippy --workspace --all-targets --all-features

test *ARGS:
    cargo test --workspace --all-features {{ARGS}}

doc *ARGS:
    RUSTDOCFLAGS="{{_katex}}" cargo doc --workspace --no-deps --document-private-items {{ARGS}}

check:
    cargo check --workspace --lib --no-default-features # no_std
    cargo check --workspace --all-targets --all-features

# cargo-fuzz ships no Apple Silicon binary, so it is built from source unless
# this version is already installed; CI installs the release binary first
_fuzz_setup:
    rustup toolchain install {{_nightly}} --profile minimal
    cargo fuzz --version 2>/dev/null | grep -qx 'cargo-fuzz 0.13.2' || cargo install --locked cargo-fuzz@0.13.2

# fuzz every target, or the TARGET given first, with libFuzzer ARGS (default: 5 minutes each)
[positional-arguments]
fuzz *ARGS: _fuzz_setup
    #!/usr/bin/env bash
    set -euo pipefail
    fuzz=(cargo +{{_nightly}} fuzz)
    dir=(--fuzz-dir "{{_fuzz_dir}}")
    targets="$("${fuzz[@]}" list "${dir[@]}")"
    if [ $# -gt 0 ] && [[ $1 != -* ]]; then
        targets=$1
        shift
    fi
    [ $# -gt 0 ] || set -- -max_total_time=300
    for target in $targets; do
        "${fuzz[@]}" run "${dir[@]}" "$target" -- "$@"
    done

# minimize every target's corpus, or the TARGETS'
[positional-arguments]
fuzz-cmin *TARGETS: _fuzz_setup
    #!/usr/bin/env bash
    set -euo pipefail
    fuzz=(cargo +{{_nightly}} fuzz)
    dir=(--fuzz-dir "{{_fuzz_dir}}")
    [ $# -gt 0 ] || set -- $("${fuzz[@]}" list "${dir[@]}")
    for target in "$@"; do
        "${fuzz[@]}" cmin "${dir[@]}" "$target"
    done

# minimize a crashing INPUT to TARGET
[positional-arguments]
fuzz-tmin TARGET INPUT: _fuzz_setup
    cargo +{{_nightly}} fuzz tmin --fuzz-dir "{{_fuzz_dir}}" "$1" "$2"

# check the fuzz crate's formatting and lints as CI does; clippy builds libFuzzer's C++
fuzz-lint:
    cargo +{{_nightly}} fmt --all --manifest-path {{_fuzz_dir}}/Cargo.toml -- --check
    cargo clippy --manifest-path {{_fuzz_dir}}/Cargo.toml --all-targets --locked -- -D warnings

_install_binstall:
    cargo-binstall -V || cargo install cargo-binstall

_book_setup: _install_binstall
    cargo binstall mdbook@0.4.52 mdbook-katex@0.9.4 mdbook-mermaid@0.16.2

# locally [build | serve | watch] the Tachyon book
book COMMAND *ARGS: _book_setup
    mdbook {{COMMAND}} ./book {{ARGS}}

# the gates in .github/workflows/rust.yml, minus the os and 32-bit matrix and the fuzz replay
ci_local: fuzz-lint
    cargo +{{_nightly}} fmt --all -- --check
    cargo clippy --workspace --lib --no-default-features --locked -- -D warnings
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --release --all --locked --lib
    cargo test --release --all --locked --all-features
    RUSTDOCFLAGS="-D warnings {{_katex}}" cargo doc --no-deps --all --locked --document-private-items
