# Anchor

Each block accepted by consensus produces a new pool state, and that pool state may be represented by a 32-byte field element called an **anchor**.

Each anchor commits to its immediate predecessor, its own block's height $h$, and its own block's stamps. This concept should be familiar.

$$\mathsf{anchor}_h = \text{Poseidon}_\text{Tachyon-AnchrFld}(\mathsf{anchor}_{h-1}, h, \mathsf{block\_state}_h)$$

## Block state

The block-state input to the anchor is itself a running Poseidon hash, accumulating each stamp's tachygram set commitment in landing order:

$$\mathsf{block\_state}_i = \text{Poseidon}_\text{Tachyon-PoolFold}(\mathsf{block\_state}_{i-1}, \mathsf{stamp\_commit}_x, \mathsf{stamp\_commit}_y)$$

where $(\mathsf{stamp\_commit}_x, \mathsf{stamp\_commit}_y)$ are the affine coordinates of the $i$-th stamp's [tachygram set commitment](./tachygrams.md). The fold starts from a constant **block-state seed** — a single-input Poseidon hash of the `Tachyon-PoolFold` domain tag — which also stands as the closing block state of any empty block. The final $\mathsf{block\_state}$ is what consensus splices into the next anchor.

The block-state fold is what lets sub-block proofs (per-stamp inclusion or exclusion shards) compose into per-block claims: a wallet seeds at $\mathsf{block\_state}_{i-1}$ and folds forward to $\mathsf{block\_state}_i$ to demonstrate that a particular stamp lands at position $i$. Sentinel-rooted shards (those starting at the empty seed) cover the entire block.
