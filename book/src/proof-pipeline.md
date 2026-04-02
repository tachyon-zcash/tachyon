# Proof Pipeline

Tachyon uses a 13-step PCD (Proof-Carrying Data) pipeline for proof generation and aggregation. Steps are organized into three categories: **seeds** (create proofs from scratch), **transforms** (evolve a single proof), and **fuses** (combine two proofs).

## Anchor

An `Anchor` is a `(BlockHeight, PoolCommit)` pair that should refer to a real consensus block. It appears on every header that carries pool-state context (`SpendableHeader`, `SpendableRolloverHeader`, `StampHeader`).

| Field          | Type          | Description                                               |
| -------------- | ------------- | --------------------------------------------------------- |
| `block_height` | `BlockHeight` | 32-bit block counter; epoch index is `block_height >> 12` |
| `pool_commit`  | `PoolCommit`  | Pedersen commitment to the pool multiset at that block    |

### What an anchor asserts

An anchor is three things bundled together:

1. **A checkpoint.** `pool_commit` is the pool's state at block `block_height`, as blessed by consensus. A proof that binds to `(h, pc)` is claiming "this held at block `h`."
2. **An epoch extent for non-inclusion.** The epoch `E = block_height >> 12` determines which historical epoch's nullifiers the pool multiset has absorbed. A non-inclusion assertion against `pool_commit` is therefore scoped to "nullifier was not yet absorbed as of epoch `E`, block `h`."
3. **A bound on stamp validity.** A stamp bound to anchor `(h, pc)` is only meaningful while `pc` is still a current-or-recent pool state. Once the pool advances past the nullifiers a stamp reveals, later anchors will absorb them and a new stamp at the same `(h, pc)` would be stale.

### Non-inclusion proofs have built-in expiry

Non-inclusion is an assertion against a specific `pool_commit`. The moment the pool absorbs the nullifier in question, that assertion becomes a historical claim about a stale commitment — any downstream spend needs a fresher anchor. This is why `SpendableLift` and `SpendableEpochLift` exist: they let a wallet re-anchor a spendable onto a newer `pool_commit` that still doesn't contain the tracked nullifier.

### Anchors are malleable within an epoch

Because an anchor is just `(height, pool_commit)`, a wallet can replace it with any later anchor in the same epoch whose pool set is a superset of the current one — this is what `SpendableLift` and `StampLift` do. Across an epoch boundary, continuity is proved by `SpendableEpochLift` using `epoch_seed_hash(prev_pool_commit)` (see [Epoch Seed](#epoch-seed)).

## Step Types

### Seeds

| Step             | Output                   | Description                                |
| ---------------- | ------------------------ | ------------------------------------------ |
| `DelegationSeed` | `DelegationMasterHeader` | Initialize GGM tree walk at depth 0        |
| `OutputStamp`    | `StampHeader`            | Create a stamp for a single output action  |

### Transforms

| Step                   | Input → Output                                 | Description                                      |
| ---------------------- | ---------------------------------------------- | ------------------------------------------------ |
| `DelegationMasterStep` | `DelegationMasterHeader` → `DelegationHeader`  | First GGM step: master key → depth-1 prefix key  |
| `DelegationStep`       | `DelegationHeader` → `DelegationHeader`        | Walk one GGM tree level                          |
| `NullifierStep`        | `DelegationHeader` → `NullifierHeader`         | Extract nullifier from completed delegation leaf |

### Fuses

| Step                 | Left × Right → Output                                               | Description                                                      |
| -------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `SpendableInit`      | `NullifierHeader` × `()` → `SpendableHeader`                        | Bootstrap spendable status (cm inclusion + nf non-membership)    |
| `SpendableRollover`  | `NullifierHeader` × `NullifierHeader` → `SpendableRolloverHeader`   | Stage a cross-epoch transition                                   |
| `SpendableLift`      | `SpendableHeader` × `()` → `SpendableHeader`                        | Advance spendable anchor within the same epoch                   |
| `SpendableEpochLift` | `SpendableHeader` × `SpendableRolloverHeader` → `SpendableHeader`   | Cross-epoch spendable transition using the epoch seed            |
| `SpendBind`          | `NullifierHeader` × `NullifierHeader` → `SpendHeader`               | Fuse two epoch-adjacent nullifiers and bind them to an action    |
| `SpendStamp`         | `SpendHeader` × `SpendableHeader` → `StampHeader`                   | Combine a bound spend with a spendable proof into a stamp        |
| `MergeStamp`         | `StampHeader` × `StampHeader` → `StampHeader`                       | Merge two stamps (requires exact anchor equality)                |
| `StampLift`          | `StampHeader` × `()` → `StampHeader`                                | Advance stamp anchor within the same epoch                       |

## Proof Trees

### Output path

```
OutputStamp(rcv, α, note, anchor) → StampHeader
```

### Spend path

A spend requires proving authorization (the GGM walk) and spendable status (cm inclusion + nf non-membership at an anchor in the current epoch). Nullifiers for two consecutive epochs, `E` and `E+1`, are derived from independent GGM walks and fused by `SpendBind`:

```
DelegationSeed(note, pak, trap)
  → DelegationMasterStep(dir)
  → DelegationStep(dir) × (GGM_TREE_DEPTH − 1)
  → NullifierStep                                    // → NullifierHeader @ epoch E

(same walk targeted at epoch E+1)                     // → NullifierHeader @ epoch E+1

SpendableInit(NullifierHeader_E, pool, anchor)
  → SpendableLift × n                                 // advance anchor within epoch E
  (or cross-epoch via SpendableRollover + SpendableEpochLift)

SpendBind(NullifierHeader_E, NullifierHeader_{E+1}, rcv, α, pak, note, trap)
  → SpendStamp(× SpendableHeader) → StampHeader
```

`SpendBind` requires both nullifier headers share a `DelegationId` and that `epoch_{E+1} == epoch_E + 1`, emitting `SpendHeader(action_digest, [nf_E, nf_{E+1}], E, delegation_id)`.

`SpendStamp` enforces:

- `spend.delegation_id == spendable.delegation_id`
- `spend.nullifiers[0] == spendable.nf`
- `spend.epoch == spendable.anchor.block_height.epoch()`

### Overlap: why the anchor must be in the spend's present epoch

`SpendStamp` requires the spendable's anchor epoch to equal the spend's current epoch `E`. Transaction authors therefore need to lift their spendable onto a mid-epoch anchor of the present epoch `E` before calling `SpendStamp`:

- The spendable attests that `nf_E` is not yet in `pool_commit` at some block in epoch `E`. A mid-epoch anchor gives overlap: `nf_E` is still live (consensus has not absorbed it yet) and the cm-inclusion claim is against a current pool.
- The stamp pre-reveals both `nf_E` (matching the spendable) and `nf_{E+1}` (next epoch, committed but not yet usable).
- If the wallet is holding a spendable from an older epoch, `SpendableLift` (same epoch) or `SpendableEpochLift` (across the boundary) is used to re-anchor it into epoch `E` before spend.

This is what "overlap is correct" means in practice: the anchor's epoch matches the spend's epoch `E`, so non-inclusion of `nf_E` and pre-revelation of `nf_{E+1}` are both meaningful at the same checkpoint.

### Aggregation

Before merging, stamps must share the same `Anchor`. Use `StampLift` to advance each stamp within the epoch until they land on a common `(block_height, pool_commit)`:

```
StampLift(StampHeader, pool, delta, new_anchor) → StampHeader
MergeStamp(StampHeader × StampHeader)          → StampHeader
```

`MergeStamp` requires equality on **both** anchor fields (height and pool commitment) and binds each witness accumulator (action, tachygram) to the public commitments on its side before merging. The merged polynomials are recommitted via `Polynomial::commit`; `ActionCommit` and `TachygramCommit` are carried on the header, but the underlying polynomials travel prover-side only and are discarded after the final merge.

## Identity Binding

Every spend-side header carries a `DelegationId` — `H(domain, mk, cm, trapdoor)` via `NullifierKey::derive_delegation_id`. The trapdoor is fresh per delegation, so two delegations of the same note produce unrelated `DelegationId`s, hiding the note's identity from any observer who doesn't hold the trapdoor.

Fuse steps equality-check `DelegationId` across their inputs:

- `SpendBind` compares the two nullifier headers' `DelegationId`s **and** recomputes the id from the note + `DelegationTrapdoor` in its own witness.
- `SpendableInit` recomputes `DelegationId` from its note/trapdoor witness and checks it against the left `NullifierHeader`.
- `SpendableRollover` / `SpendableEpochLift` propagate `DelegationId` from their inputs.
- `SpendStamp` requires `spend.delegation_id == spendable.delegation_id`.

Because the trapdoor never appears in a public header, cross-note proof splicing requires knowing the exact trapdoor that produced the target `DelegationId`.

## Epoch Seed

At each epoch boundary, consensus inserts `epoch_seed_hash(prev_pool_commit)` — a domain-separated Poseidon hash of the previous epoch's final `PoolCommit` — as a root of the new epoch's pool multiset. `SpendableEpochLift` proves cross-epoch continuity by checking that the new pool multiset queries that seed to zero. This replaces the earlier per-block/per-epoch chain hashes with a single inline marker inside the multiset itself.
