# Anchor

An anchor is an $\mathbb{F}_p$ element produced by a Poseidon hash chain, representing a running commitment to the Tachyon pool state.

Each stamp, empty block, and epoch transition produces a new pool state, but consensus may <!-- should? must? --> only acknowledge pool states that represent the end of a block.

These end-of-block states are anchors.

## Stamp absorption

Each stamp lands at a definite position in a definite block, when the block is accepted by consensus. A stamp's contribution to the pool state is

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}StampFld}(\mathsf{anchor},\ x,\ y)
$$

where $(x, y)$ are coordinates of the stamp's tachygram-set commitment[^tachygrams].
Absorbing the complete coordinates (rather than a compressed encoding) ensures the binding is unambiguous.

[^tachygrams]: [Tachygrams](./tachygrams.md) describes the tachygram commitment are absorbed here

## Empty block

A block with zero stamps still advances the anchor:

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}EmptyBlk}(\mathsf{anchor})
$$

## Epoch boundary

When the chain crosses from epoch $e$ into epoch $e+1$:

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}EpochStp}(\mathsf{anchor},\ e+1)
$$

This is the only domain that absorbs the new epoch index. Nothing else in the chain references the epoch number, so cross-epoch binding relies on this step.

## Intra-block state vs end-of-block anchor

Within a block, each stamp's absorption produces an intermediate hash value.

Consensus actors should know about intermediate states, but may only acknowledge the anchor state at the end of a block.
