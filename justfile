default:
    @just --list

# keep in step with .github/actions/rust-nightly-setup/action.yml, the pin the
# `fmt` job checks against
_nightly := "nightly-2026-05-23"

_katex := "--html-in-header " + justfile_directory() / "crates/tachyon/katex-header.html"

fmt:
    cargo +{{_nightly}} fmt --all

lint: doc
    cargo clippy --workspace --lib --no-default-features # no_std
    cargo clippy --workspace --all-targets --features test-epoch-size

# unit tests and doctests at the default test profile, then the
# integration tests in release mode; ARGS go to libtest
test *ARGS:
    cargo test --workspace --features test-epoch-size --lib -- {{ARGS}}
    cargo test --workspace --features test-epoch-size --doc -- {{ARGS}}
    cargo test --workspace --release --features test-epoch-size --test integration -- {{ARGS}}

doc *ARGS:
    RUSTDOCFLAGS="{{_katex}}" cargo doc --workspace --no-deps --document-private-items {{ARGS}}

check:
    cargo check --workspace --lib --no-default-features # no_std
    cargo check --workspace --all-targets --features test-epoch-size

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
    cargo clippy --workspace --all-targets --features test-epoch-size --locked -- -D warnings
    cargo test --workspace --locked --features test-epoch-size --lib
    cargo test --workspace --locked --features test-epoch-size --doc
    cargo test --workspace --locked --release --features test-epoch-size --test integration
    RUSTDOCFLAGS="-D warnings {{_katex}}" cargo doc --no-deps --all --locked --document-private-items
