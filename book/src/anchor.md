# Anchor

An anchor is an $\mathbb{F}_p$ element produced by a Poseidon hash chain, representing a running commitment to the Tachyon pool state.

Each stamp and each epoch transition produces a new pool state, but consensus may <!-- should? must? --> only acknowledge pool states that represent the end of a block.

These end-of-block states are anchors.

The anchor advances by two kinds of fold. Both absorb an epoch index. A stamp absorption absorbs the epoch of the block that contains the stamp. A validator reads that epoch from the block height. A boundary digest absorbs the epoch being entered. The two folds hash under different Poseidon domains (`Tachyon-AnchorSt` and `Tachyon-AnchorEp`). The Poseidon domain of a fold identifies it as a stamp absorption or a boundary digest.

A block that publishes no stamp leaves the anchor unchanged, unless the block starts a new epoch. An anchor identifies a position in the sequence of stamp absorptions and boundary digests.

## Stamp absorption

Each stamp lands at a definite position in a definite block, when the block is accepted by consensus. A stamp's contribution to the pool state is

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}AnchorSt}(\mathsf{anchor},\ e,\ \mathsf{tg}_\mathsf{lo},\ \mathsf{tg}_\mathsf{hi})
$$

where $e$ is the containing block's epoch and $(\mathsf{tg}_\mathsf{lo}, \mathsf{tg}_\mathsf{hi})$ are the two 128-bit limbs of the stamp's tachygram-set commitment[^tachygrams] in compressed form. The compressed encoding carries $x$ with the sign of $y$ in its high bit, so the limb pair determines the point.

[^tachygrams]: The [tachygrams](./tachygrams.md) chapter gives the set commitment this absorbs, and the rule that full validation recomputes it from the published tachygrams.

## Epoch boundary

When the chain crosses from epoch $e$ into epoch $e+1$:

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}AnchorEp}(\mathsf{anchor},\ e+1)
$$

The two folds differ in their Poseidon domain and in which epoch they absorb. A stamp absorption absorbs the epoch it sits in. A boundary digest absorbs the epoch being entered. A stamp absorption with the same output as a boundary digest is a Poseidon collision across the two domains. A proof can therefore check that an anchor is a boundary digest. Consensus membership of the eventual spend anchor binds the lineage to published epoch boundaries.

Two positions at the boundary have names. The **entry anchor** of $e$ is the first anchor of $e$ in the accepted chain: $H_\mathsf{ep}(\mathsf{final}(e-1), e)$ for $e \geq 1$, and $H_\mathsf{ep}(0, 0)$ for $e = 0$. The **final anchor** of $e$ is the last anchor inside $e$, which equals the entry anchor when $e$ published no stamp. The **crossing** is the single fold $\mathsf{final}(e) \to \mathsf{entry}(e+1)$ joining them.

$H_\mathsf{ep}(x, e)$ is a boundary digest for any $x$. For $e \geq 1$, the entry anchor of $e$ is the boundary digest of $\mathsf{final}(e-1)$ into $e$. A step that checks that an anchor is a boundary digest into $e$ has not checked that it is the entry anchor of $e$.

## Intra-block state vs end-of-block anchor

Within a block, each stamp's absorption produces an intermediate hash value.

Consensus actors should know about intermediate states, but may only acknowledge the anchor state at the end of a block.

A proof such as `SpendableInit` will produce a header that is likely at an intra-block state, and should be lifted to the end of a block by proving state continuity.
