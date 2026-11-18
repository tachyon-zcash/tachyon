# Anchor

An anchor is an $\mathbb{F}_p$ element produced by a Poseidon hash chain, representing a running commitment to the Tachyon pool state.

Each stamp and each epoch transition produces a new pool state, but consensus acknowledges only pool states that represent the end of a block.

These end-of-block states are anchors.

The anchor advances by two kinds of transition. Both absorb an epoch index. A stamp absorption absorbs the epoch of the block that contains the stamp. A validator reads that epoch from the block height. A boundary digest absorbs the epoch being entered. The two transitions hash under different Poseidon domains (`Tachyon-AnchorSt` and `Tachyon-AnchorEp`), so the domain identifies a transition as a stamp absorption or a boundary digest.

A block that publishes no stamp leaves the anchor unchanged, unless the block starts a new epoch. An anchor identifies a position in the sequence of stamp absorptions and boundary digests.

## Stamp absorption

Each stamp lands at a definite position in an accepted block. To advance the pool state, the anchor absorbs the containing block's epoch $e$ and the affine coordinates of the bridge hash $B$ of the stamp's tachygram-set commitment[^tachygrams]

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}AnchorSt}\bigl(\mathsf{anchor},\ e,\ x(B),\ y(B)\bigr)
$$

For a Vesta tachygram-set commitment $C$ the bridge hash is the Pallas point

$$
B = [x(C)]G_i + [y(C)]G_j
$$

where $x(C)$ and $y(C)$ are the affine coordinates of $C$ in $\mathbb{F}_q$ (the scalar field of Pallas) and $G_i$ and $G_j$ are Ragu's fixed bridge-stage generators for those two coordinates.

[^tachygrams]: The [tachygrams](./tachygrams.md) chapter gives the set commitment whose bridge hash the anchor absorbs, and the rule that full validation recomputes that commitment from the published tachygrams.

## Epoch boundary

When the chain crosses from epoch $e$ into epoch $e+1$:

$$
\mathsf{anchor}' = \mathsf{Poseidon}_\mathtt{Tachyon\text{-}AnchorEp}(\mathsf{anchor},\ e+1)
$$

The two transitions differ in their Poseidon domain and in which epoch they absorb. A stamp absorption absorbs the epoch it sits in. A boundary digest absorbs the epoch being entered. A stamp absorption producing the same value as a boundary digest is a Poseidon collision across the two domains. A step can therefore check that an anchor is a boundary digest. Consensus membership of the eventual spend anchor binds the lineage to published epoch boundaries.

Two positions at the boundary have names. The **entry anchor** of $e$ is the first anchor of $e$ in the accepted chain: $H_\mathsf{ep}(\mathsf{final}(e-1), e)$ for $e \geq 1$, and $H_\mathsf{ep}(0, 0)$ for $e = 0$. The **final anchor** of $e$ is the last anchor inside $e$, which equals the entry anchor when $e$ published no stamp. The **crossing** is the boundary digest $\mathsf{final}(e) \to \mathsf{entry}(e+1)$ joining them.

$H_\mathsf{ep}(x, e)$ is a boundary digest for any $x$. For $e \geq 1$, the entry anchor of $e$ is the boundary digest of $\mathsf{final}(e-1)$ into $e$. A step that checks that an anchor is a boundary digest into $e$ has not checked that it is the entry anchor of $e$.

## Intra-block state vs end-of-block anchor

Within a block, each stamp's absorption produces an intermediate hash value.

Consensus acknowledges only end-of-block anchors: stamps must anchor to an end-of-block anchor within the present epoch or the immediately previous epoch. That a stamp's anchor is on the canonical chain and satisfies this recency rule is a consensus obligation outside `Bundle::verify`, which checks the stamp proof against the carried anchor without consulting chain history.

A step such as `SpendableInit` may produce a header at an intra-block state: its anchor is the state right after the creation stamp, which is the end-of-block anchor only when that stamp is the block's last.
A spend of that note reaches an end-of-block anchor when its `Actions` are lifted with `ActionLift`, or after the fee its `Stamp` with `StampLift`, along [anchor spans](./proof-tree.md#anchor-segments), which prove state continuity.
