# Anchor

An anchor is an $\mathbb{F}_p$ element produced by a Poseidon hash chain, representing a running commitment to the Tachyon pool state.

Each stamp, empty block, and epoch transition produces a new pool state, but consensus may <!-- should? must? --> only acknowledge pool states that represent the end of a block.

These end-of-block states are anchors.

Every link absorbs an epoch index. The stamp and empty-block links absorb the epoch of the block that contains them, which a validator reads off the block height; the epoch link absorbs the epoch being entered. The three use distinct Poseidon domains, so opening a chain reveals each link's role.

## Stamp absorption

Each stamp lands at a definite position in a definite block, when the block is accepted by consensus. A stamp's contribution to the pool state is

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}StampFld}(\mathsf{anchor},\ e,\ \mathsf{tg}_\mathsf{lo},\ \mathsf{tg}_\mathsf{hi})
$$

where $e$ is the containing block's epoch and $(\mathsf{tg}_\mathsf{lo}, \mathsf{tg}_\mathsf{hi})$ are the two 128-bit limbs of the stamp's tachygram-set commitment[^tachygrams] in compressed form. The compressed encoding carries $x$ with the sign of $y$ in its high bit, so the limb pair determines the point.

[^tachygrams]: The [tachygrams](./tachygrams.md) chapter gives the set commitment this absorbs, and the rule that full validation recomputes it from the published tachygrams.

## Empty block

A block with zero stamps still advances the anchor:

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}EmptyBlk}(\mathsf{anchor},\ e)
$$

This is what makes anchors unique per block height. Without it, a run of empty blocks would leave the pool state unchanged and an anchor would no longer identify a single point in the chain.

## Epoch boundary

When the chain crosses from epoch $e$ into epoch $e+1$:

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}EpochStp}(\mathsf{anchor},\ e+1)
$$

All three link types absorb an epoch, so the epoch index alone does not distinguish them. What distinguishes this one is that it absorbs the epoch being *entered* rather than the epoch it sits inside, under its own domain. Reaching a boundary anchor by any other link would therefore be a cross-domain collision, which is what lets a proof pin a lineage to a real epoch boundary.

## Intra-block state vs end-of-block anchor

Within a block, each stamp's absorption produces an intermediate hash value.

Consensus actors should know about intermediate states, but may only acknowledge the anchor state at the end of a block.

A proof such as `SpendableInit` will produce a header that is likely at an intra-block state, and should be lifted to the end of a block by proving state continuity.
