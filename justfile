default:
    @just --list

_nightly := "nightly-2026-04-11"

fmt:
    cargo +{{_nightly}} fmt --all

lint:
    cargo +nightly clippy --workspace --lib --no-default-features # no_std
    cargo +nightly clippy --workspace --all-targets --all-features

test *ARGS:
    cargo test --workspace --all-features {{ARGS}}

doc *ARGS:
    RUSTDOCFLAGS="--html-in-header {{justfile_directory()}}/katex-header.html" cargo doc --workspace --no-deps {{ARGS}}

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

# run CI checks locally (formatting, clippy, tests, docs, book)
ci_local: _book_setup
    cargo +{{_nightly}} fmt --all -- --check
    cargo clippy --workspace --lib --no-default-features --locked -- -D warnings
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --release --all --locked --all-features
    RUSTDOCFLAGS="-D warnings --html-in-header {{justfile_directory()}}/katex-header.html" cargo doc --no-deps --all --locked --document-private-items
    mdbook build ./book
