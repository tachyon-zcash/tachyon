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
