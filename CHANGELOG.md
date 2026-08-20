# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ProofStamp::lift`, which advances a stamp's anchor along a reusable
  `AnchorSegment`. `MergeStamp` constrains both sides of a merge to one anchor,
  but wallets stamp against whatever anchor was current when they built, so an
  aggregator collecting stamps from different heights had no way to align
  them. Lifting is the "match/update anchors" step of aggregation.
- `AnchorStep` and `AnchorSegment`, the validated, intra-epoch view of an anchor
  chain. A node supplies one stamp step per absorbed proof stamp, in transaction
  order, or one empty-block step for a block absorbing none. Segment
  construction checks the predicted endpoint against consensus state before
  proving, and the resulting proof can be reused for stamps at the same anchor.

  Both are wrappers over the already-registered `StampLift`, `AnchorSeed`,
  `EmptyBlockSeed`, and `AnchorFuse` steps: no circuit, step registration, or
  proof-system change. A lift cannot cross an epoch boundary, since
  `AnchorChain` has no link for one.

## [0.0.0] - 2026-02-16

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/tachyon/compare/v0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/tachyon/releases/tag/v0.0.0
