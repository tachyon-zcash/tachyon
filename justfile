default:
    @just --list

fmt:
    cargo +nightly fmt --all

lint:
    cargo +nightly clippy --workspace --all-targets --all-features

test:
    cargo test --workspace --all-features

doc:
    cargo doc --workspace --no-deps

check:
    cargo check --workspace --all-targets --all-features

_install_binstall:
    cargo-binstall -V || cargo install cargo-binstall

_book_setup: _install_binstall
    cargo binstall mdbook@0.4.52 mdbook-katex@0.9.4 mdbook-mermaid@0.16.2

# locally [build | serve | watch] the Tachyon book
book COMMAND: _book_setup
    mdbook {{COMMAND}} ./book --open
