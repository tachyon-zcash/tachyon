# Anchor

An anchor is an $\mathbb{F}_p$ element produced by a Poseidon hash chain, representing a running commitment to the Tachyon pool state.

Each stamp, empty block, and epoch transition produces a new pool state, but consensus may <!-- should? must? --> only acknowledge pool states that represent the end of a block.

These end-of-block states are anchors.

## Three domains

The chain advances under three domain tags, each used in exactly one situation:

| Domain | When |
| ------ | ---- |
| `Tachyon-StampFld` | Advance one stamp within a block |
| `Tachyon-EmptyBlk` | Advance one block with zero stamps |
| `Tachyon-EpochStp` | Advance over an epoch boundary (never an anchor) |

### Stamp absorption

Each stamp lands at a definite position in a definite block. Its contribution to the pool state is its tachygram-set commitment, a point whose coordinates feed the chain directly:

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}StampFld}(\mathsf{anchor},\ x,\ y)
$$

where $(x, y)$ are the affine coordinates of the stamp's tachygram-set commitment. Absorbing the coordinates directly (rather than the compressed encoding) makes the binding independent of sign-bit recovery, so two parties cannot disagree on which of $\pm y$ produced the chain.

### Empty block

A block with zero stamps still advances the anchor:

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}EmptyBlk}(\mathsf{anchor})
$$

The dedicated domain ensures an empty block at height $h$ produces an anchor distinct from any non-empty configuration. Per-height uniqueness matters because validators acknowledge anchors at heights, not by content.

### Epoch boundary

When the chain crosses from epoch $e$ into epoch $e+1$:

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}EpochStp}(\mathsf{anchor},\ e+1)
$$

This is the only domain that absorbs the new epoch index. Nothing else in the chain references the epoch number, so cross-epoch identity flows through exactly this step.

## Intra-block state vs end-of-block anchor

Within a block, each stamp's absorption produces an intermediate hash value.

Consensus actors should know about intermediate states, but may only acknowledge the anchor state at the end of a block.

A proof such as `SpendableInit` will produce a header that is likely at an intra-block state, and should be lifted to the end of a block by proving state continuity.
