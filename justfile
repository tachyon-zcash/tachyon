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
    {{_fuzz_dir}}/target/"$(rustc +{{_nightly}} -vV | sed -n 's/^host: //p')"/release/{{TARGET}} -max_len=32768 -timeout=10 -rss_limit_mb=2048 -artifact_prefix={{_fuzz_dir}}/artifacts/{{TARGET}}/ {{ARGS}} {{_fuzz_dir}}/target/corpus/{{TARGET}} {{_fuzz_dir}}/corpus/{{TARGET}}

# minimize TARGET's local finds under target/corpus, replacing them only if the
# merge succeeds; the committed corpus is never minimized
fuzz-cmin TARGET: fuzz-build
    rm -rf {{_fuzz_dir}}/target/cmin/{{TARGET}}
    mkdir -p {{_fuzz_dir}}/target/cmin/{{TARGET}} {{_fuzz_dir}}/target/corpus/{{TARGET}}
    {{_fuzz_dir}}/target/"$(rustc +{{_nightly}} -vV | sed -n 's/^host: //p')"/release/{{TARGET}} -merge=1 -max_len=32768 -timeout=30 -rss_limit_mb=2048 {{_fuzz_dir}}/target/cmin/{{TARGET}} {{_fuzz_dir}}/target/corpus/{{TARGET}}
    rm -rf {{_fuzz_dir}}/target/corpus/{{TARGET}}
    mv {{_fuzz_dir}}/target/cmin/{{TARGET}} {{_fuzz_dir}}/target/corpus/{{TARGET}}

# line coverage of zcash_tachyon from replaying TARGET's committed and local
# corpora, or every target's, written to crates/tachyon/fuzz/coverage; needs
# cargo-llvm-cov and the fuzz toolchain's llvm-tools-preview
fuzz-coverage TARGET="":
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{_fuzz_dir}}
    source <(cargo llvm-cov show-env --sh --dep-coverage zcash_tachyon)
    export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing"
    cargo llvm-cov clean --workspace
    cargo build --release --locked --bins
    targets="{{TARGET}}"
    if [ -z "$targets" ]; then
        targets="$(for source in fuzz_targets/*.rs; do basename "$source" .rs; done)"
    fi
    for target in $targets; do
        mkdir -p "target/corpus/$target"
        "target/release/$target" -runs=0 -max_len=32768 -rss_limit_mb=2048 "corpus/$target" "target/corpus/$target"
    done
    mkdir -p coverage
    cargo llvm-cov report --release --dep-coverage zcash_tachyon --lcov --output-path coverage/lcov.info
    cargo llvm-cov report --release --dep-coverage zcash_tachyon

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
