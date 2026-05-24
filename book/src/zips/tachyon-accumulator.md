# Tachyon Accumulator / Hash Chain

**Tracking:** [#105](https://github.com/tachyon-zcash/tachyon/issues/105)

**('Additive' ZIP, Category 'Consensus')**

The accumulator hierarchy: at the tachystamp-level, we have a tachygram vector commitment (pedersen commitment to a multiset polynomial whose roots are poseidon hashes). At the block-level, we have a block accumulator (poseidon hash-chain that absorbs the coordinates of each stamp's pedersen commitments).
