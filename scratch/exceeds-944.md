# Tachyon steps exceeding ragu #944 limits

This inventory describes the migrated steps against mock revision `62d65d19`.
The subsequent phase can refactor these steps to fit #944. This migration keeps
the step set and its checks intact.

`L0`, `R0`, and `O0` name the first polynomial of the left, right, and output
headers; indices are zero-based. #944 supplies two slots per header, permits one
opening per slot, and therefore permits at most six openings per step. The mock
adds a third slot and permits repeated queries. Bridge digests and staged values
are not polynomial-opening queries.

| Step | #944 limit exceeded | Exact usage | Why needed in this migration |
| --- | --- | --- | --- |
| `QrIntakeSplit` | One opening per slot | Four queries of three distinct polynomials: `O0(ζ)`, `O1(ζ)`, `L0(ζ)` for `O0 · O1 = L0`, then a second query `O0(-R_depth)`; `O0` carries the non-residue side. | The product proves the partition; the exceptional-point nonzero check prevents assigning `-R_depth` to the non-residue class. Both original checks must remain. |
| `QrSideDescend` | Two polynomial slots per header | Five distinct queries, once each at `ζ`: `L0`, `L1`, `O0`, `O1`, `O2`. Output slots hold the selected side, interpolant, and quotient respectively. The staged side bit selects the sibling from `L0/L1`; `O0` is checked against the other side. | The selected polynomial must remain available to descendants, while the sibling-class identity needs both an interpolant and a quotient. `O2` holds that quotient; the fifth opening binds the selected output rather than trusting prover-side slot selection. |

**Exceeding steps: 2 (two table rows).** No step exceeds six opening queries.
`StampMerge`, `ActionMerge`, and `StampUnmerge` each use exactly six distinct
slots; `StampLift` and `ActionLift` each use five. `QrBucketSeal` opens `L0`,
`O0`, and `O1` once each, reusing those values for its copy equalities.

The mock ABI represents three polynomial vectors on every header. Unused slots
contain the constant one; that placeholder alone is not counted as a step's
use of a third polynomial. The only non-placeholder third slot in this migration
is `QrSideDescend::O2`. No additional staged-value or bridge-hash API limit is
exceeded by the steps.
