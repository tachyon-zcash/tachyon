default:
    @just --list

# keep in step with .github/actions/rust-nightly-setup/action.yml, the pin the
# `fmt` job checks against
_nightly := "nightly-2026-05-23"

_katex := "--html-in-header " + justfile_directory() / "crates/tachyon/katex-header.html"

# kache remaps the cargo registry to `/kache/.cargo`, outside the default
# cargo-llvm-cov excludes
_cov_ignore := "--ignore-filename-regex '/[.]cargo/registry/'"

fmt:
    cargo +{{_nightly}} fmt --all

lint: doc
    cargo clippy --workspace --lib --no-default-features # no_std
    cargo clippy --workspace --all-targets --all-features

test *ARGS:
    cargo test --workspace --all-features {{ARGS}}

# line coverage of the test suite, written to lcov.info
coverage *ARGS:
    cargo llvm-cov clean --workspace
    cargo llvm-cov --no-report --release --workspace --locked --features test-epoch-size {{ARGS}}
    cargo llvm-cov report --release {{_cov_ignore}} --lcov --output-path lcov.info
    cargo llvm-cov report --release {{_cov_ignore}} --summary-only

# line coverage of the test suite, as an HTML report in coverage-html/html
coverage-html *ARGS: (coverage ARGS)
    cargo llvm-cov report --release {{_cov_ignore}} --html --output-dir coverage-html

doc *ARGS:
    RUSTDOCFLAGS="{{_katex}}" cargo doc --workspace --no-deps --document-private-items {{ARGS}}

check:
    cargo check --workspace --lib --no-default-features # no_std
    cargo check --workspace --all-targets --all-features

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
