# Tachyon Shielded Protocol

**Tracking:** [#103](https://github.com/tachyon-zcash/tachyon/issues/103)

**('Additive' ZIP, Category 'Consensus')**

This defines a new shielded pool alongside a simplified key structure. More specifically, the specification will define: note structure, key derivation, note commitments and nullifiers, value commitments, actions, tachygrams, spend authorization signatures, binding signatures, consensus rules (bounded nullifier sets and nullifier pruning, anchors, etc.), authorization.

The pool will cross reference Ragu / Tachyon books (like the [Orchard pool](https://zips.z.cash/zip-0224) references [Halo2](https://zcash.github.io/halo2/)). The ZIP only includes things that touch consensus, not the full proving system.
