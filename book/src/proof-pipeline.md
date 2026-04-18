# Proof Pipeline

Tachyon uses a 17-step PCD (Proof-Carrying Data) pipeline for proof generation and aggregation. Steps are organized into three categories: **seeds** (create proofs from scratch), **transforms** (evolve a single proof), and **fuses** (combine two proofs).

## Anchor

All anchor-bearing headers embed a shared `Anchor` sub-struct representing pool state at a specific block:

| Field | Type | Description |
|-------|------|-------------|
| block_height | BlockHeight | Block height in the pool chain |
| block_commit | BlockCommit | Per-block tachygram set commitment |
| pool_commit | PoolCommit | Cumulative epoch tachygram commitment |
| block_chain | BlockChainHash | `H(prev, block_commit)` every block |
| epoch_chain | EpochChainHash | `H(prev, pool_commit)` at epoch boundaries |

## Step Types

### Seeds

| Step | Output | Description |
|------|--------|-------------|
| DelegationSeed | DelegationHeader | Initialize GGM tree walk for nullifier delegation |
| SpendNullifier | SpendNullifierHeader | Derive nullifier pair (epoch E and E+1) via full GGM walk |
| OutputStamp | StampHeader | Create a stamp for a single output action |
| PoolSeed | PoolHeader | Initialize a pool chain from activation height |

### Transforms

| Step | Input → Output | Description |
|------|----------------|-------------|
| DelegationStep | DelegationHeader → DelegationHeader | Walk one GGM tree level |
| NullifierStep | DelegationHeader → NullifierHeader | Extract nullifier from completed delegation |
| PoolStep | PoolHeader → PoolHeader | Advance pool by one block |
| SpendBind | SpendNullifierHeader → SpendHeader | Bind action digest to spend nullifiers |

### Fuses

| Step | Left × Right → Output | Description |
|------|------------------------|-------------|
| SpendableInit | NullifierHeader × PoolHeader → SpendableHeader | Bootstrap spendable status (cm inclusion + nf non-membership) |
| SpendableRollover | NullifierHeader × PoolHeader → SpendableRolloverHeader | Fresh epoch non-membership for epoch transitions |
| SpendableLift | SpendableHeader × PoolHeader → SpendableHeader | Advance spendable anchor within same epoch |
| SpendableEpochLift | SpendableHeader × SpendableRolloverHeader → SpendableHeader | Cross-epoch spendable transition with chain continuity |
| SpendNullifierFuse | NullifierHeader × NullifierHeader → SpendNullifierHeader | Fuse two nullifiers (E, E+1) from delegation chains |
| SpendStamp | SpendHeader × SpendableHeader → StampHeader | Combine spend with spendable proof into stamp |
| MergeStamp | StampHeader × StampHeader → StampHeader | Merge two stamps (requires exact anchor equality) |
| StampLift | StampHeader × PoolHeader → StampHeader | Advance stamp anchor within same epoch |

## Proof Trees

### Output path

An output action produces a stamp directly via a single seed step:

```
OutputStamp(rcv, α, note, anchor) → StampHeader
```

### Spend path

A spend requires proving both authorization and spendable status:

```
DelegationSeed(note, nk, dir)
  → DelegationStep(dir) × 31     (walk GGM tree to leaf)
  → NullifierStep                 (extract nf)

SpendableInit(NullifierHeader × PoolHeader)   (cm inclusion + nf non-membership)
  → SpendableLift(× PoolHeader)               (advance within epoch)
  → SpendableEpochLift(× SpendableRolloverHeader)  (cross epoch)

SpendNullifier(note, nk, epoch)               (or SpendNullifierFuse)
  → SpendBind(rcv, α, ak, note, nk)
  → SpendStamp(× SpendableHeader) → StampHeader
```

`SpendStamp` enforces `left.nullifiers[0] == right.nf` and `left.epoch == epoch_index(right.anchor.block_height)`, binding the spend to the spendable chain's note and epoch.

### Aggregation

Before merging, stamps must share the same anchor. Use `StampLift` to advance both stamps to a common block within the same epoch:

```
StampLift(StampHeader × PoolHeader) → StampHeader   (align anchors)
MergeStamp(StampHeader × StampHeader) → StampHeader  (exact anchor equality)
```

`MergeStamp` enforces exact anchor equality — all five fields must match. The accumulators merge via $\mathbb{F}_p$ multiplication.

## Identity Binding

All steps in a spend pipeline carry `bind_note = H(mk, cm)` — a hash of the note's master key and commitment. Fuse steps verify that left and right inputs agree on `bind_note`, preventing cross-note proof splicing.

## Chain Hashes

`PoolStep` maintains two running chain hashes:

- **block_chain**: `H(prev, block_commit)` every block. Used by `SpendableLift` and `StampLift` to verify anchor advancement continuity.
- **epoch_chain**: `H(prev, pool_commit)` at epoch boundaries only. Used by `SpendableEpochLift` to verify cross-epoch continuity.
