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

test *ARGS:
    cargo test --workspace --all-features {{ARGS}}

doc *ARGS:
    RUSTDOCFLAGS="{{_katex}}" cargo doc --workspace --no-deps --document-private-items {{ARGS}}

check:
    cargo check --workspace --lib --no-default-features # no_std
    cargo check --workspace --all-targets --all-features

_fuzz_dir := justfile_directory() / "crates/tachyon/fuzz"

# cargo-fuzz's libFuzzer instrumentation, applied without cargo-fuzz; keep in
# step with .github/workflows/fuzz.yml
_fuzz_rustflags := "--cfg fuzzing -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares -Cdebug-assertions -Coverflow-checks"

# build every fuzz target
fuzz-build:
    cd {{_fuzz_dir}} && RUSTFLAGS="{{_fuzz_rustflags}}" cargo +{{_nightly}} build --release --locked --bins --target "$(rustc +{{_nightly}} -vV | sed -n 's/^host: //p')"

# fuzz TARGET from its committed corpus, keeping new finds out of the tree;
# ARGS go to libFuzzer, e.g. `just fuzz bundle_read -runs=10000`
fuzz TARGET *ARGS: fuzz-build
    mkdir -p {{_fuzz_dir}}/target/corpus/{{TARGET}} {{_fuzz_dir}}/artifacts/{{TARGET}}
    {{_fuzz_dir}}/target/"$(rustc +{{_nightly}} -vV | sed -n 's/^host: //p')"/release/{{TARGET}} -max_len=32768 -artifact_prefix={{_fuzz_dir}}/artifacts/{{TARGET}}/ {{ARGS}} {{_fuzz_dir}}/target/corpus/{{TARGET}} {{_fuzz_dir}}/corpus/{{TARGET}}

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
