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

Keep `-max_len` at least 32768: the proof-stamped seeds are larger than
libFuzzer's 4096-byte default. The recipe sets it.

## Corpus

Each target has serializer-built seeds that reach its deepest accepting path:
both bundle variants for the dispatcher, a full stamp trailer for the typed
and stamp readers, every compact size form, one seed per component reader, and
for `verify_pipeline` an autonome alone and an aggregate followed by the
adjunct it covers. Regenerate them after a wire-format change, from the
repository root:

```sh
just test write_fuzz_seeds -- --ignored
```

`regression_alloc_near_cap` pins a past finding: a near-`MAX_COMPACT_SIZE`
action count that once drove a multi-gigabyte preallocation in the reader. The
readers now grow incrementally and fail fast at EOF, so this input must
parse-error cleanly, never OOM.

`noncanonical_action_count` exercises the public readers' rejection of an
over-long CompactSize action count before an action body is consumed.
