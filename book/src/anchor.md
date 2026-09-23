# Anchor

An anchor is an $\mathbb{F}_p$ element produced by a Poseidon hash chain, representing a running commitment to the Tachyon pool state.

Each stamp and each epoch transition produces a new pool state, but consensus may <!-- should? must? --> only acknowledge pool states that represent the end of a block.

These end-of-block states are anchors.

Both links absorb an epoch index. The stamp link absorbs the epoch of the block that contains it, which a validator reads off the block height; the epoch link absorbs the epoch being entered. The two use distinct Poseidon domains, so opening a chain reveals each link's role.

A block that publishes no stamp produces no link, so the anchor is constant across a stampless span. An anchor names a position in the sequence of published stamps rather than a block height.

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

Both link types absorb an epoch, so the epoch index alone does not distinguish them. What distinguishes this one is that it absorbs the epoch being *entered* rather than the epoch it sits inside, under its own domain. Reaching an entry anchor by a stamp link would therefore be a cross-domain collision, which is what lets a proof pin a lineage to a real epoch boundary.

Two positions at the boundary have names. The **entry anchor** of $e$ is the first anchor of $e$ in the accepted chain: $H_\mathsf{ep}(\mathsf{terminal}(e-1), e)$ for $e \geq 1$, and $H_\mathsf{ep}(0, 0)$ for $e = 0$. The **terminal anchor** of $e$ is the last anchor inside $e$, which equals the entry anchor when $e$ published no stamp. The single fold joining them, $\mathsf{terminal}(e) \to \mathsf{entry}(e+1)$, is the **crossing**.

Epoch-link form is a property, position is an identity: every $H_\mathsf{ep}(x, e)$ has the form for any $x$, and only the one folded from $\mathsf{terminal}(e-1)$ is the entry anchor. A step that checks the form has not checked the position.

## Intra-block state vs end-of-block anchor

Within a block, each stamp's absorption produces an intermediate hash value.

Consensus actors should know about intermediate states, but may only acknowledge the anchor state at the end of a block.

A proof such as `SpendableInit` will produce a header that is likely at an intra-block state, and should be lifted to the end of a block by proving state continuity.
