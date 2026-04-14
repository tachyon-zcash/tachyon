# Proof Pipeline

Tachyon uses a 26-step PCD (Proof-Carrying Data) pipeline for proof generation and aggregation. Steps are organized into three categories: **seeds** (create proofs from scratch), **transforms** (evolve a single proof), and **fuses** (combine two proofs).

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
| CoverageLeaf | CoverageHeader | Commit a prefix-partitioned leaf of tachygrams |
| InclusionLeaf | CoverageHeader | Commit a leaf and assert cm is at a specific index |
| ExclusionLeaf | CoverageHeader | Commit a leaf and assert nf is not among the tachygrams |
| CoverageEmpty | CoverageHeader | Seed an empty coverage subtree for jump-starting sparse trees |

### Transforms

| Step | Input -> Output | Description |
|------|----------------|-------------|
| DelegationStep | DelegationHeader -> DelegationHeader | Walk one GGM tree level |
| NullifierStep | DelegationHeader -> NullifierHeader | Extract nullifier from completed delegation |
| PoolStep | PoolHeader -> PoolHeader | Advance pool by one block |
| SpendBind | SpendNullifierHeader -> SpendHeader | Bind action digest to spend nullifiers |
| ExclusionFinalize | CoverageHeader -> ExclusionHeader | Finalize per-block exclusion proof from root coverage |

### Fuses

| Step | Left x Right -> Output | Description |
|------|------------------------|-------------|
| CoverageFuse | CoverageHeader x CoverageHeader -> CoverageHeader | Merge two sibling coverage subtrees |
| InclusionFinalize | CoverageHeader x PoolHeader -> InclusionBoundHeader | Verify root coverage matches block_commit |
| InclusionBindNullifier | InclusionBoundHeader x NullifierHeader -> SpendableHeader | Bind inclusion proof to nullifier, producing initial spendable status |
| ExclusionFuse | ExclusionHeader x ExclusionHeader -> ExclusionHeader | Merge per-block exclusion proofs across blocks |
| NullifierExclusionFuse | NullifierHeader x ExclusionHeader -> NullifierExclusionHeader | Bind nullifier to exclusion scope |
| SpendableExclusionFuse | SpendableHeader x ExclusionHeader -> SpendableExclusionHeader | Bind spendable status to exclusion scope |
| SpendableRollover | NullifierExclusionHeader x PoolHeader -> SpendableRolloverHeader | Fresh epoch non-membership for epoch transitions |
| SpendableLift | SpendableExclusionHeader x PoolHeader -> SpendableHeader | Advance spendable anchor within same epoch |
| SpendableEpochLift | SpendableHeader x SpendableRolloverHeader -> SpendableHeader | Cross-epoch spendable transition with chain continuity |
| SpendNullifierFuse | NullifierHeader x NullifierHeader -> SpendNullifierHeader | Fuse two nullifiers (E, E+1) from delegation chains |
| SpendStamp | SpendHeader x SpendableHeader -> StampHeader | Combine spend with spendable proof into stamp |
| MergeStamp | StampHeader x StampHeader -> StampHeader | Merge two stamps (requires exact anchor equality) |
| StampLift | StampHeader x PoolHeader -> StampHeader | Advance stamp anchor within same epoch |

## Proof Trees

### Output path

An output action produces a stamp directly via a single seed step:

```
OutputStamp(rcv, alpha, note, anchor) -> StampHeader
```

### Spend path

A spend requires proving both authorization and spendable status:

```
DelegationSeed(note, nk, dir)
  -> DelegationStep(dir) x 31     (walk GGM tree to leaf)
  -> NullifierStep                 (extract nf)

InclusionLeaf(note, nk, prefix, tachygrams)     (cm inclusion in block)
  -> CoverageFuse x n                            (merge prefix subtrees to root)
  -> InclusionFinalize(x PoolHeader)             (verify coverage = block_commit)
  -> InclusionBindNullifier(x NullifierHeader)   (bind nf, produce SpendableHeader)

ExclusionLeaf(nf, prefix, tachygrams)            (nf non-membership per block)
  -> CoverageFuse x n                            (merge prefix subtrees to root)
  -> ExclusionFinalize                            (produce ExclusionHeader)
  -> ExclusionFuse x m                           (merge across blocks in delta)
  -> SpendableExclusionFuse(SpendableHeader x)   (bind to spendable status)
  -> SpendableLift(x PoolHeader)                 (advance within epoch)
  -> SpendableEpochLift(x SpendableRolloverHeader)  (cross epoch)

SpendNullifier(note, nk, epoch)               (or SpendNullifierFuse)
  -> SpendBind(rcv, alpha, ak, note, nk)
  -> SpendStamp(x SpendableHeader) -> StampHeader
```

`SpendStamp` enforces `left.nullifiers[0] == right.nf` and `left.epoch == epoch_index(right.anchor.block_height)`, binding the spend to the spendable chain's note and epoch.

### Aggregation

Before merging, stamps must share the same anchor. Use `StampLift` to advance both stamps to a common block within the same epoch:

```
StampLift(StampHeader x PoolHeader) -> StampHeader   (align anchors)
MergeStamp(StampHeader x StampHeader) -> StampHeader  (exact anchor equality)
```

`MergeStamp` enforces exact anchor equality -- all five fields must match. The accumulators merge via $\mathbb{F}_p$ multiplication.

## Identity Binding

All steps in a spend pipeline carry `note_id = H(mk, cm)` -- a hash of the note's master key and commitment. Fuse steps verify that left and right inputs agree on `note_id`, preventing cross-note proof splicing.

## Chain Hashes

`PoolStep` maintains two running chain hashes:

- **block_chain**: `H(prev, block_commit)` every block. Used by `SpendableLift` and `StampLift` to verify anchor advancement continuity.
- **epoch_chain**: `H(prev, pool_commit)` at epoch boundaries only. Used by `SpendableEpochLift` to verify cross-epoch continuity.
