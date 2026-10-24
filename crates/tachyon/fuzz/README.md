# Tachyon Fuzz Targets

Every target feeds untrusted bytes to a public reader and checks two things.
Liveness: the input decodes or returns `io::Error`, and never panics, aborts or
hangs. Canonicality: an accepted input is the one encoding of the value it
decodes to, so writing the value back reproduces the bytes the reader
consumed, and the value holds the invariants the writer relies on. The proof
blob is the exception: it is ragu's encoding, and mock ragu ignores the
padding after the proof's fields, so the comparison stops short of it.

| Target                 | Reader                                       |
| ---------------------- | -------------------------------------------- |
| `bundle_read`          | `TachyonBundle::read`, dispatching on state, against the typed reader the state selects |
| `stamped_bundle_read`  | `Bundle::<ProofStamp>::read`                 |
| `stripped_bundle_read` | `Bundle::<PointerStamp>::read`               |
| `proof_stamp_read`     | `ProofStamp::read`                           |
| `pointer_stamp_read`   | `PointerStamp::read`                         |
| `compact_size_read`    | `CompactSize::read` and its consensus checks |
| `component_read`       | the fixed-width field and signature readers  |
| `verify_pipeline`      | a parsed aggregate and up to four adjuncts through every pre-proof check and digest |
| `verify_reject`        | `Bundle::verify` on one edit to an honest aggregate and its adjunct |

The input to `verify_reject` is an edit, not wire bytes. It chooses a field, an
index and a mask, and the edit must be rejected at the stage that binds the field
(signatures, pointers, coverage, tachygram arity or tachygram set). Anchor and
proof edits run for liveness only, since mock ragu decides them. Before
fuzzing, the honest base must verify and one fixed edit of every other field
must be rejected at its stage.

## Running

From the repository root, without installing anything beyond the pinned
nightly:

```sh
just fuzz bundle_read -max_total_time=60
```

`just fuzz-build` compiles every target with the same libFuzzer
instrumentation `cargo-fuzz` applies. `just fuzz TARGET` runs one target from
its committed corpus, writes new finds under `target/corpus/TARGET` and crash
artifacts under `artifacts/TARGET`, and passes any further arguments to
libFuzzer. With `cargo-fuzz` installed, `cargo fuzz run TARGET -- -max_len=32768`
from this directory works as well; the local toolchain file pins a nightly new
enough for the workspace MSRV.

To see why a reader rejects an input, replay the input file through the built
target with `DEBUG_INPUT` set, which prints the reader's `io::Error`. From this
directory:

```sh
DEBUG_INPUT=1 target/"$(rustc -vV | sed -n 's/^host: //p')"/release/bundle_read corpus/bundle_read/state_ff
```

Keep `-max_len` at least 32768: the proof-stamped seeds are larger than
libFuzzer's 4096-byte default. The recipe sets it, along with the CI limits:
a 10 s per-input timeout and a 2 GB RSS limit.

`just fuzz-cmin TARGET` minimizes the local finds under `target/corpus/TARGET`
into a scratch directory and replaces them only if the merge succeeds. The
committed corpus is never minimized.

## CI

`fuzz.yml` runs on every pull request: it builds every target and runs each
one for 30 s from its committed corpus. Every target runs even after one
fails, and the job fails at the end. Each target's log tail lands in the job
summary, and failing inputs and logs upload as the `fuzz-artifacts` artifact.

`fuzz-cron.yml` runs a campaign twice a week, or on dispatch with a `duration`
in seconds. Each target fuzzes for an hour with the same limits, except that
the `verify*` targets get a 30 s per-input timeout. The target's corpus
persists in the Actions cache between campaigns and is minimized at the end of
each one. Each target uploads `fuzz-corpus-TARGET` (90 days),
`fuzz-artifacts-TARGET` (30 days) and `fuzz-logs-TARGET`.

After the campaign, a coverage job rebuilds the targets with `cargo llvm-cov`
instrumentation on `zcash_tachyon` alone and replays each one with `-runs=0`
over its committed seeds and this campaign's corpus. It writes one union
report: the line totals go to the job summary, and `lcov.info` and
`summary.json` upload as the 90-day `fuzz-coverage` artifact. The job fails if
no file under `crates/tachyon/src/` is covered, or if a target's campaign
corpus is missing. Locally, `just fuzz-coverage [TARGET]` replays the
committed and local corpora into `coverage/`; it needs `cargo-llvm-cov`, and
this directory's toolchain file brings `llvm-tools-preview`.

`rust.yml` runs the seed guard in `tests/integration/fuzz_seeds.rs` on every
pull request. It fails when a wire or verifier change leaves the
serializer-built seeds unable to reach the paths they were written for.

To keep a crash found by a campaign, download its `fuzz-artifacts-TARGET`
artifact, minimize the input with
`target/<host>/release/TARGET -minimize_crash=1 -runs=10000 crash-<sha>`, and
commit the result as `corpus/TARGET/regression_<name>` with the fix, so every
later run replays it.

## Corpus

Each target has serializer-built seeds that reach its deepest accepting path:
both bundle variants for the dispatcher, a full stamp trailer for the typed
and stamp readers, every compact size form, one seed per component reader, and
for `verify_pipeline` an autonome alone and an aggregate followed by the
adjunct it covers. `verify_reject` has only an empty seed: its base is the
`verify_pipeline/aggregate_with_adjunct` seed, verified under the sighash in
`fixtures/aggregate_with_adjunct.sighash`, which the fuzz crate cannot
recompute. Regenerate the seeds and the sidecar after a wire-format change,
from the repository root:

```sh
just test write_fuzz_seeds -- --ignored
```

`regression_alloc_near_cap` pins a past finding: a near-`MAX_COMPACT_SIZE`
action count that once drove a multi-gigabyte preallocation in the reader. The
readers now grow incrementally and fail fast at EOF, so this input must
parse-error cleanly, never OOM.

`noncanonical_action_count` exercises the public readers' rejection of an
over-long CompactSize action count before an action body is consumed.
