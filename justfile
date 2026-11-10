default:
    @just --list

# keep in step with .github/actions/rust-nightly-setup/action.yml, the pin the
# `fmt` job checks against
_nightly := "nightly-2026-05-23"

_katex := "--html-in-header " + justfile_directory() / "crates/tachyon/katex-header.html"

# keep in step with .github/workflows/coverage.yml, which fails when either
# lcov report differs from the committed one. `--remap-path-prefix` makes its paths
# workspace-relative. kache remaps the cargo registry to `/kache/.cargo`,
# outside the default cargo-llvm-cov excludes. The lcov reports take
# `--skip-functions`: their function records are keyed by mangled symbols, whose
# crate hashes change with the toolchain and target.
_cov := "--remap-path-prefix --ignore-filename-regex '/[.]cargo/registry/'"

fmt:
    cargo +{{_nightly}} fmt --all

lint: doc
    cargo clippy --workspace --lib --no-default-features # no_std
    cargo clippy --workspace --all-targets --features test-epoch-size

# unit tests, then integration tests and doctests with --release; ARGS go to libtest
test *ARGS:
    cargo test --workspace --features test-epoch-size --lib -- {{ARGS}}
    cargo test --workspace --release --features test-epoch-size --test integration -- {{ARGS}}
    cargo test --workspace --release --features test-epoch-size --doc -- {{ARGS}}

# line coverage with the same profiles as the unit and integration CI jobs
coverage *ARGS:
    just coverage-lib {{ARGS}}
    just coverage-integration {{ARGS}}

# unit-test coverage in debug mode, including overflow and debug assertions
coverage-lib *ARGS:
    cargo llvm-cov {{_cov}} --workspace --locked --features test-epoch-size --lib {{ARGS}}
    cargo llvm-cov report {{_cov}} --lcov --skip-functions --output-path lcov-lib.info

# integration-test coverage in release mode
coverage-integration *ARGS:
    cargo llvm-cov {{_cov}} --release --workspace --locked --features test-epoch-size --test integration {{ARGS}}
    cargo llvm-cov report {{_cov}} --release --lcov --skip-functions --output-path lcov-integration.info

# line coverage of the test suite, as an HTML report
# keep HTML outside target/llvm-cov, which the next coverage pass clears
coverage-html *ARGS:
    just coverage-lib {{ARGS}}
    cargo llvm-cov report {{_cov}} --html --output-dir target/coverage-html/lib
    just coverage-integration {{ARGS}}
    cargo llvm-cov report {{_cov}} --release --html --output-dir target/coverage-html/integration

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
    cargo test --workspace --locked --test epoch
    cargo test --workspace --locked --release --features test-epoch-size --test integration
    RUSTDOCFLAGS="-D warnings {{_katex}}" cargo doc --no-deps --all --locked --document-private-items
    cargo test --workspace --locked --doc
