default:
    @just --list

fmt:
    cargo +nightly fmt --all

lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --workspace --all-features

doc:
    cargo doc --workspace --no-deps

# Check for unused deps (requires cargo-udeps on nightly)
# udeps:
#     cargo +nightly udeps --workspace --all-targets

check:
    cargo check --workspace --all-targets --all-features

