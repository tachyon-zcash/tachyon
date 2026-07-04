//! GGM tree PRF for nullifier derivation.
//!
//! A `k`-ary tree of key schedules, `k = GGM_TREE_ARITY`, expanded by a
//! hardened 128-round MiMC child cipher. Every node is a `k`-key cyclic
//! schedule; expanding a node derives one child's full schedule as `k`
//! whitened cipher outputs on the secret affine inputs
//! `s + δ·(base + row)`, where `base = k·chunk` selects the
//! child by a `GGM_CHUNK_SIZE`-bit chunk of the epoch index (MSB-first), so
//! left subtrees cover lower-numbered leaves and contiguous ranges map to
//! sparse prefix covers. A depth-2 node's single expansion (base 0, its own
//! domain) is its nullifier leaf: those outputs are the epochs' nullifiers.
//!
//! The tree is sized to tile the full epoch space exactly:
//! `GGM_ARITY^GGM_DEPTH == GGM_MAX_INDEX + 1`, and to fill exactly one trace
//! polynomial per expansion: `GGM_TREE_ARITY = POLY_LEN_MAX / ROUNDS`.

use alloc::vec::Vec;
use core::{
    array,
    num::{NonZeroU8, NonZeroUsize},
    ops::RangeInclusive,
};

use derive_more::{Debug, Eq as TotalEq, PartialEq};
use pasta_curves::Fp;
use ragu::{Domain, Polynomial};
use zcash_mimc::spec::tachyon::TachyonP5R128;

use crate::{
    constants::{
        EPOCH_MAX, MK_LENGTH, MK_PART_LEN, MK_PARTS, NF_EXPANSION_KEY_PREFIX, POLY_LEN_MAX,
    },
    digest::{mimc, poseidon},
    note::Nullifier,
    primitives::{EpochIndex, NfLeafPoly, NfPrefixPoly, NfPrefixTracePoly},
};

/// Maximum leaf index. Equal to [`EPOCH_MAX`] so every epoch maps to a
/// distinct leaf.
pub const GGM_MAX_INDEX: u32 = EPOCH_MAX;

/// Children per non-leaf node. Must be a power of two >= 2.
///
/// Also a node's key-schedule width (one key per child) and the row count of
/// one expansion trace: sized so one node expansion exactly fills one
/// committed trace polynomial.
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "const arithmetic"
)]
pub const GGM_TREE_ARITY: usize = POLY_LEN_MAX / TachyonP5R128::ROUNDS;

/// Bits of the leaf index absorbed per GGM step.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "const arithmetic"
)]
pub const GGM_CHUNK_SIZE: u8 = GGM_TREE_ARITY.trailing_zeros() as u8;

/// Mask covering exactly one chunk: low `GGM_CHUNK_SIZE` bits set.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "const arithmetic"
)]
pub const GGM_CHUNK_MASK: u8 = (GGM_TREE_ARITY - 1) as u8;

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "const arithmetic"
)]
/// Tree depth such that `ARITY ** DEPTH == MAX_INDEX + 1`.
pub const GGM_TREE_DEPTH: u8 = GGM_MAX_INDEX.trailing_ones() as u8 / GGM_CHUNK_SIZE;

// The depth formula's division truncates silently; require the exact tiling
// it assumes, so the tree and the epoch space cannot drift apart.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "const arithmetic"
)]
const _: () = assert!(
    (GGM_TREE_ARITY as u32).pow(GGM_TREE_DEPTH as u32) == GGM_MAX_INDEX + 1,
    "GGM tree must tile the epoch space exactly"
);

/// A GGM node's child-cipher input parameters `(s, δ, w)`.
///
/// Squeezed from the node's schedule prefix by a domain-separated sponge: the
/// secret input salt `s`, the input stride `δ`, and the whitening key `w`.
/// Internal nodes derive under `Tachyon-NfExpand`; a depth-2 node's nullifier
/// leaf derives under `Tachyon-NfLeaf__`.
///
/// The child cipher runs on the affine inputs `s + δ·(base + row)`, so both
/// the inputs and their pairwise differences are node secrets rather than
/// public constants (a leaked output yields no known plaintext/ciphertext
/// pair for its siblings), and outputs are whitened by the dedicated `w`
/// rather than a reused schedule key.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct ExpansionParams {
    /// The secret input salt `s`: the cipher input at row 0 of chunk 0.
    #[debug(skip)]
    pub(crate) salt: Fp,
    /// The secret input stride `δ` between consecutive rows' inputs.
    #[debug(skip)]
    pub(crate) stride: Fp,
    /// The dedicated whitening key `w`, added to every output.
    #[debug(skip)]
    pub(crate) whitening: Fp,
}

impl ExpansionParams {
    /// The cipher input at the given schedule position: `s + δ·index`.
    #[must_use]
    pub fn input(&self, index: Fp) -> Fp {
        self.salt + self.stride * index
    }

    const fn from_squeeze((salt, stride, whitening): (Fp, Fp, Fp)) -> Self {
        Self {
            salt,
            stride,
            whitening,
        }
    }
}

/// Per-note master root key: the `MK_LENGTH`-key cyclic schedule keying the
/// root expansion, assembled from `MK_PARTS` Poseidon-derived parts.
///
/// ## Delegation chain
///
/// ```text
/// nk + psi → mk (per-note root schedule, user device)
///              ├── nf = F_mk(flavor)     nullifier for a specific epoch
///              └── S_t = GGM(mk, t)      node schedule covering a window (OSS)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct NoteMasterKey(#[debug(skip)] pub(crate) [Fp; MK_LENGTH]);

impl NoteMasterKey {
    /// Assemble the full master key by concatenating its `MK_PARTS` parts, in
    /// order. Each part is one `NfMasterSeed` step's `nf_master_part` output;
    /// part `i` occupies `mk[i·MK_PART_LEN .. (i+1)·MK_PART_LEN]`.
    #[must_use]
    pub fn from_parts(parts: &[[Fp; MK_PART_LEN]; MK_PARTS]) -> Self {
        Self(array::from_fn(|index| {
            #[expect(
                clippy::indexing_slicing,
                clippy::integer_division,
                clippy::integer_division_remainder_used,
                reason = "index < MK_LENGTH = MK_PARTS*MK_PART_LEN"
            )]
            let key = parts[index / MK_PART_LEN][index % MK_PART_LEN];
            key
        }))
    }

    /// Get the round key at the given index (cyclic).
    #[must_use]
    pub const fn round_key(&self, index: usize) -> Fp {
        #[expect(clippy::integer_division_remainder_used, reason = "cyclic schedule")]
        self.0[index % self.0.len()]
    }

    /// The root expansion's input parameters `(s, δ, w)`, squeezed from the
    /// master key's schedule prefix under `Tachyon-NfExpand`. The root
    /// expansion step derives these in-step from the header-carried parts; a
    /// witnessed tuple would be the free-witness trap.
    #[must_use]
    pub fn expansion_params(&self) -> ExpansionParams {
        ExpansionParams::from_squeeze(poseidon::nf_expansion_params(schedule_prefix(&self.0)))
    }

    /// Descend one level from the root: derive child `chunk`'s schedule.
    #[must_use]
    pub fn step(&self, chunk: u8) -> NotePrefixedKey {
        assert!(
            usize::from(chunk) < GGM_TREE_ARITY,
            "chunk must be less than arity"
        );
        #[expect(clippy::expect_used, reason = "depth 1 is always valid")]
        NotePrefixedKey {
            schedule: expand_child(&self.0, &self.expansion_params(), chunk),
            depth: NonZeroU8::new(1).expect("1 != 0"),
            index: u32::from(chunk),
        }
    }

    /// Derive a nullifier for the given epoch: the leaf value itself.
    ///
    /// # Panics
    ///
    /// Panics if the epoch exceeds the epoch space.
    #[must_use]
    pub fn derive_nullifier(&self, flavor: EpochIndex) -> Nullifier {
        assert!(
            flavor.0 <= GGM_MAX_INDEX,
            "epoch exceeds epoch space {:?}",
            0u32..=GGM_MAX_INDEX,
        );
        let chunks = walk_chunks(flavor.0);
        self.step(chunks[0]).step(chunks[1]).leaf_nullifier(flavor)
    }

    /// Child `chunk`'s expansion with its full state grid: the trace cells,
    /// the child key, and the child's eval-form schedule polynomial.
    #[must_use]
    pub(crate) fn expand_child_trace(
        &self,
        chunk: u8,
    ) -> (NodeStates, NotePrefixedKey, NfPrefixPoly) {
        let (states, outputs) = expand_rows_trace(
            &self.0,
            &self.expansion_params(),
            u64::from(chunk) << GGM_CHUNK_SIZE,
        );
        let child = NotePrefixedKey {
            schedule: outputs,
            #[expect(clippy::expect_used, reason = "depth 1 is always valid")]
            depth: NonZeroU8::new(1).expect("1 != 0"),
            index: u32::from(chunk),
        };
        (states, child, NfPrefixPoly(column_interpolant(&outputs)))
    }

    /// Derive window-restricted node schedules covering the specified range.
    ///
    /// Recursively descends the tree, emitting fully-covered nodes and only
    /// expanding children that overlap the range. The finest delegation grain
    /// is a depth-2 node (one nullifier leaf), so the range must be
    /// leaf-aligned.
    ///
    /// # Panics
    ///
    /// Panics if the range exceeds the epoch space or is not aligned to
    /// [`GGM_TREE_ARITY`]-epoch leafs.
    #[must_use]
    pub fn derive_note_delegates(&self, range: RangeInclusive<u32>) -> Vec<NotePrefixedKey> {
        assert!(
            *range.end() <= GGM_MAX_INDEX,
            "range {range:?} exceeds epoch space {:?}",
            0u32..=GGM_MAX_INDEX,
        );
        assert_leaf_aligned(&range);

        let child_size = 1u32 << ((GGM_TREE_DEPTH - 1) * GGM_CHUNK_SIZE);
        let mut result = Vec::new();
        for chunk in 0u8..=GGM_CHUNK_MASK {
            let child_lo = u32::from(chunk) * child_size;
            let child_hi = child_lo + child_size - 1;
            if *range.start() <= child_hi && *range.end() >= child_lo {
                let clamped = (*range.start()).max(child_lo)..=(*range.end()).min(child_hi);
                result.extend(self.step(chunk).derive_note_delegates(clamped));
            }
        }
        result
    }
}

/// A Tachyon node schedule for window-restricted nullifier delegation.
///
/// At depth `d` there are `GGM_ARITY^d` nodes. Node `i` covers the contiguous
/// epoch range of size `GGM_ARITY^(GGM_DEPTH - d)`. At depth
/// `GGM_TREE_DEPTH - 1`, a node's own expansion is its nullifier leaf: one
/// nullifier per covered epoch.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct NotePrefixedKey {
    /// The node's key schedule.
    #[debug(skip)]
    pub(crate) schedule: [Fp; GGM_TREE_ARITY],
    /// The number of levels already descended.
    pub(crate) depth: NonZeroU8,
    /// Node index at this depth.
    pub(crate) index: u32,
}

impl NotePrefixedKey {
    /// The node's child-expansion input parameters `(s, δ, w)`, squeezed
    /// from its schedule prefix under `Tachyon-NfExpand`. The expansion
    /// steps derive these in-step from the commitment-bound schedule.
    #[must_use]
    pub fn expansion_params(&self) -> ExpansionParams {
        ExpansionParams::from_squeeze(poseidon::nf_expansion_params(schedule_prefix(
            &self.schedule,
        )))
    }

    /// The depth-2 node's nullifier-leaf parameters `(s, δ, w)`, squeezed
    /// from its schedule prefix under the leaf domain `Tachyon-NfLeaf__`.
    #[must_use]
    pub fn leaf_params(&self) -> ExpansionParams {
        ExpansionParams::from_squeeze(poseidon::nf_leaf_params(schedule_prefix(&self.schedule)))
    }

    /// The epoch range covered by this key.
    #[must_use]
    pub fn range(self) -> RangeInclusive<u32> {
        let levels_remaining = GGM_TREE_DEPTH - self.depth.get();
        let span_bits = levels_remaining * GGM_CHUNK_SIZE;
        let first = self.index << span_bits;
        let mask = 1u32
            .checked_shl(u32::from(span_bits))
            .map_or(u32::MAX, |size| size - 1u32);
        let last = first | mask;
        first..=last
    }

    /// Descend one level: derive child `chunk`'s schedule.
    ///
    /// # Panics
    ///
    /// Panics if already at the deepest schedule level
    /// (depth == `GGM_TREE_DEPTH - 1`; the level below is the nullifier
    /// leaf, not a schedule).
    #[must_use]
    pub fn step(&self, chunk: u8) -> Self {
        assert!(
            self.depth.get() < GGM_TREE_DEPTH - 1,
            "must not step beyond the deepest schedule level"
        );
        assert!(
            usize::from(chunk) < GGM_TREE_ARITY,
            "chunk must be less than arity"
        );
        Self {
            schedule: expand_child(&self.schedule, &self.expansion_params(), chunk),
            #[expect(clippy::expect_used, reason = "nonzero plus one is not zero")]
            depth: NonZeroU8::new(self.depth.get() + 1).expect("not zero"),
            index: (self.index << GGM_CHUNK_SIZE) | u32::from(chunk),
        }
    }

    /// The depth-2 node's nullifier leaf: one nullifier per covered epoch,
    /// in epoch order.
    ///
    /// # Panics
    ///
    /// Panics unless at the deepest schedule level
    /// (depth == `GGM_TREE_DEPTH - 1`).
    #[must_use]
    pub fn leaf_nullifiers(&self) -> [Fp; GGM_TREE_ARITY] {
        assert!(
            self.depth.get() == GGM_TREE_DEPTH - 1,
            "only the deepest schedule level expands into a nullifier leaf"
        );
        expand_rows(&self.schedule, &self.leaf_params(), 0)
    }

    /// Derive window-restricted node schedules covering the specified range
    /// within this key's range.
    ///
    /// Recursively descends the tree, emitting fully-covered nodes and only
    /// expanding children that overlap the range. The finest delegation
    /// grain is a depth-2 node (one nullifier leaf), so the range must be
    /// leaf-aligned.
    ///
    /// # Panics
    ///
    /// Panics if `range` is not a leaf-aligned subset of [`Self::range`].
    #[must_use]
    pub fn derive_note_delegates(&self, range: RangeInclusive<u32>) -> Vec<Self> {
        assert!(
            self.range().contains(range.start()) && self.range().contains(range.end()),
            "prefix key for {:?} does not cover requested range {:?}",
            self.range(),
            range,
        );
        assert_leaf_aligned(&range);

        if range == self.range() {
            alloc::vec![*self]
        } else {
            let next_depth = self.depth.get() + 1;
            let child_span_bits = (GGM_TREE_DEPTH - next_depth) * GGM_CHUNK_SIZE;
            let child_size = 1u32 << child_span_bits;
            let base = *self.range().start();

            let mut result = Vec::new();
            for chunk in 0u8..=GGM_CHUNK_MASK {
                let child_lo = base + u32::from(chunk) * child_size;
                let child_hi = child_lo + child_size - 1;
                if *range.start() <= child_hi && *range.end() >= child_lo {
                    let clamped = (*range.start()).max(child_lo)..=(*range.end()).min(child_hi);
                    result.extend(self.step(chunk).derive_note_delegates(clamped));
                }
            }
            result
        }
    }

    /// This node's own eval-form schedule polynomial over `⟨ζ⟩`: the operand
    /// an expansion step witnesses and binds to the input header's
    /// commitment.
    #[must_use]
    pub(crate) fn key_poly(&self) -> NfPrefixPoly {
        NfPrefixPoly(column_interpolant(&self.schedule))
    }

    /// Child `chunk`'s expansion with its full state grid, matching
    /// [`Self::step`].
    #[must_use]
    pub(crate) fn expand_child_trace(&self, chunk: u8) -> (NodeStates, Self, NfPrefixPoly) {
        let (states, outputs) = expand_rows_trace(
            &self.schedule,
            &self.expansion_params(),
            u64::from(chunk) << GGM_CHUNK_SIZE,
        );
        let child = Self {
            schedule: outputs,
            #[expect(clippy::expect_used, reason = "depth below the leaf level")]
            depth: NonZeroU8::new(self.depth.get() + 1).expect("not zero"),
            index: (self.index << GGM_CHUNK_SIZE) | u32::from(chunk),
        };
        (states, child, NfPrefixPoly(column_interpolant(&outputs)))
    }

    /// The depth-2 node's nullifier-leaf expansion with its full state grid,
    /// matching [`Self::leaf_nullifiers`].
    #[must_use]
    pub(crate) fn leaf_nullifier_trace(&self) -> (NodeStates, [Fp; GGM_TREE_ARITY], NfLeafPoly) {
        assert!(
            self.depth.get() == GGM_TREE_DEPTH - 1,
            "only the deepest schedule level expands into a nullifier leaf"
        );
        let (states, outputs) = expand_rows_trace(&self.schedule, &self.leaf_params(), 0);
        let leaf_poly = NfLeafPoly(column_interpolant(&outputs));
        (states, outputs, leaf_poly)
    }

    /// Derive a nullifier for the given epoch.
    ///
    /// # Panics
    ///
    /// Panics if the epoch is outside this key's authorized range.
    #[must_use]
    pub fn derive_nullifier(&self, flavor: EpochIndex) -> Nullifier {
        assert!(self.range().contains(&flavor.0), "epoch out of range");
        if self.depth.get() == GGM_TREE_DEPTH - 1 {
            self.leaf_nullifier(flavor)
        } else {
            let chunks = walk_chunks(flavor.0);
            #[expect(clippy::indexing_slicing, reason = "depth < GGM_TREE_DEPTH - 1")]
            self.step(chunks[NonZeroUsize::from(self.depth).get()])
                .leaf_nullifier(flavor)
        }
    }

    /// Read one nullifier out of this depth-2 node's leaf.
    fn leaf_nullifier(&self, flavor: EpochIndex) -> Nullifier {
        debug_assert!(self.range().contains(&flavor.0), "epoch out of range");
        let position = flavor.0 & u32::from(GGM_CHUNK_MASK);
        #[expect(
            clippy::indexing_slicing,
            clippy::as_conversions,
            reason = "position < GGM_TREE_ARITY by mask"
        )]
        Nullifier::from(self.leaf_nullifiers()[position as usize])
    }
}

/// One node expansion's raw internal cipher states.
///
/// Row-major `GGM_TREE_ARITY × ROUNDS = POLY_LEN_MAX` cells, row `r`'s
/// columns being that row's per-round states. Distinct from the expansion
/// outputs (the per-row whitened final cells only): this is the full state
/// grid a trace interpolates over.
///
/// Wallet-only secret material.
#[derive(Clone, Debug)]
pub struct NodeStates(#[debug(skip)] pub(crate) Vec<Fp>);

impl NodeStates {
    /// Interpolate this expansion's committed trace `T` over `⟨ω⟩`
    /// (`T(ω^{ROUNDS·r + c})` is row `r`'s `c`-th cipher state). `T` is only
    /// ever the interpolant, so the inverse FFT lives here with its producer.
    #[must_use]
    pub(crate) fn spectrum(&self) -> NfPrefixTracePoly {
        let mut coeffs = self.0.clone();
        Domain::new(coeffs.len().ilog2()).ifft(&mut coeffs);
        NfPrefixTracePoly(Polynomial::from_coeffs(&coeffs))
    }
}

/// The eval-form interpolant of one expansion's outputs over the
/// order-`GGM_TREE_ARITY` subgroup `⟨ζ⟩` (`interpolant(ζ^r) = outputs[r]`).
fn column_interpolant(outputs: &[Fp; GGM_TREE_ARITY]) -> Polynomial {
    let mut coeffs = outputs.to_vec();
    Domain::new(GGM_TREE_ARITY.ilog2()).ifft(&mut coeffs);
    Polynomial::from_coeffs(&coeffs)
}

/// One expansion window with its full state grid: the trace cells and the
/// whitened outputs, matching [`expand_rows`].
fn expand_rows_trace(
    keys: &[Fp],
    params: &ExpansionParams,
    base: u64,
) -> (NodeStates, [Fp; GGM_TREE_ARITY]) {
    let mut cells: Vec<Fp> = Vec::with_capacity(POLY_LEN_MAX);
    #[expect(clippy::as_conversions, reason = "row < GGM_TREE_ARITY fits u64")]
    let outputs = array::from_fn(|row| {
        let (states, output) = mimc::schedule_key_trace(
            keys,
            params.input(Fp::from(base + row as u64)),
            params.whitening,
        );
        cells.extend_from_slice(&states);
        output
    });
    (NodeStates(cells), outputs)
}

/// Candidate starts for a cover of `[start..=end]`.
///
/// Rounded down to `GGM_ARITY^j`-boundaries for `j >= 1` (the leaf grain
/// and coarser). Sorted by overage descending (`[0..=end]` first, the
/// leaf-aligned rounding of `start` last), duplicates collapsed.
///
/// The caller picks based on its own effort/privacy trade-off; see the book's
/// "Delegation window" section for rationale.
///
/// # Panics
///
/// Panics if the range is empty or `end > GGM_MAX_INDEX`.
#[must_use]
pub fn cover_candidates(range: RangeInclusive<u32>) -> Vec<RangeInclusive<u32>> {
    assert!(!range.is_empty(), "range must not be empty");
    assert!(*range.end() <= GGM_MAX_INDEX, "end exceeds epoch space");

    let mut candidates: Vec<RangeInclusive<u32>> = Vec::new();
    for level in 1u8..=GGM_TREE_DEPTH {
        let alignment_bits = level * GGM_CHUNK_SIZE;
        let start = 1u32
            .checked_shl(u32::from(alignment_bits))
            .map_or(0u32, |alignment| range.start() & !(alignment - 1u32));
        if candidates.last().is_some_and(|prev| *prev.start() == start) {
            continue;
        }
        candidates.push(start..=*range.end());
    }
    candidates.reverse();
    candidates
}

/// The MSB-first 6-bit chunks of an epoch index, one per tree level.
#[expect(clippy::as_conversions, reason = "const array length from a u8 depth")]
fn walk_chunks(leaf: u32) -> [u8; GGM_TREE_DEPTH as usize] {
    array::from_fn(|level| {
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "level < GGM_TREE_DEPTH fits u8"
        )]
        let shift = (GGM_TREE_DEPTH - 1 - level as u8) * GGM_CHUNK_SIZE;
        #[expect(
            clippy::expect_used,
            reason = "chunk bits fit in u8 because GGM_CHUNK_SIZE <= u8::BITS"
        )]
        u8::try_from((leaf >> shift) & u32::from(GGM_CHUNK_MASK)).expect("chunk fits in u8")
    })
}

/// Derive child `chunk`'s schedule from a node's cyclic key schedule: rows
/// `GGM_TREE_ARITY·chunk ..` of the expansion.
fn expand_child(keys: &[Fp], params: &ExpansionParams, chunk: u8) -> [Fp; GGM_TREE_ARITY] {
    debug_assert!(
        usize::from(chunk) < GGM_TREE_ARITY,
        "chunk must be less than arity"
    );
    expand_rows(keys, params, u64::from(chunk) << GGM_CHUNK_SIZE)
}

/// One expansion window: `GGM_TREE_ARITY` whitened cipher outputs at the
/// affine inputs `s + δ·(base + row)`.
#[expect(clippy::as_conversions, reason = "row < GGM_TREE_ARITY fits u64")]
fn expand_rows(keys: &[Fp], params: &ExpansionParams, base: u64) -> [Fp; GGM_TREE_ARITY] {
    array::from_fn(|row| {
        mimc::schedule_key(
            keys,
            params.input(Fp::from(base + row as u64)),
            params.whitening,
        )
    })
}

/// The schedule prefix absorbed by the parameter sponges.
fn schedule_prefix(keys: &[Fp]) -> [Fp; NF_EXPANSION_KEY_PREFIX] {
    array::from_fn(|index| {
        #[expect(
            clippy::indexing_slicing,
            reason = "NF_EXPANSION_KEY_PREFIX <= every schedule width"
        )]
        keys[index]
    })
}

/// Block-grain alignment for delegation windows: start and end+1 must be
/// multiples of the leaf width [`GGM_TREE_ARITY`].
fn assert_leaf_aligned(range: &RangeInclusive<u32>) {
    let width = 1u32 << GGM_CHUNK_SIZE;
    assert!(
        range.start().is_multiple_of(width) && (range.end() + 1).is_multiple_of(width),
        "delegation windows are leaf-aligned: {range:?} is not"
    );
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

    use super::*;

    const LEAF: u32 = 1 << GGM_CHUNK_SIZE;

    fn random_master(rng: &mut StdRng) -> NoteMasterKey {
        NoteMasterKey(array::from_fn(|_| Fp::random(&mut *rng)))
    }

    #[test]
    fn distinct_leaves() {
        let rng = &mut StdRng::seed_from_u64(0);
        let key = random_master(rng);

        assert_ne!(
            key.derive_nullifier(EpochIndex(0)),
            key.derive_nullifier(EpochIndex(1)),
        );
    }

    /// A leaf entry is the epoch's nullifier, with no further
    /// transformation.
    #[test]
    fn leaf_entry_is_nullifier() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = random_master(rng);
        // 4290 = (1, 3, 2) in MSB-first 6-bit chunks.
        let epoch = EpochIndex(4290);

        let leaf_key = root.step(1).step(3);
        assert_eq!(leaf_key.depth.get(), GGM_TREE_DEPTH - 1);
        assert_eq!(leaf_key.index, 64 + 3, "walked to the epoch's leaf");
        assert_eq!(
            Nullifier::from(leaf_key.leaf_nullifiers()[2]),
            root.derive_nullifier(epoch),
            "leaf entry must be the nullifier"
        );
    }

    /// The whole leaf agrees with per-epoch derivation.
    #[test]
    fn leaf_matches_per_epoch_derivation() {
        let rng = &mut StdRng::seed_from_u64(1);
        let root = random_master(rng);
        let leaf_key = root.step(2).step(5);
        let base = *leaf_key.range().start();

        for (position, &value) in leaf_key.leaf_nullifiers().iter().enumerate() {
            let epoch = EpochIndex(base + u32::try_from(position).expect("fits"));
            assert_eq!(
                Nullifier::from(value),
                root.derive_nullifier(epoch),
                "mismatch at position {position}"
            );
        }
    }

    /// Delegate covering epoch 0 produces the same nullifier as the root.
    #[test]
    fn delegate_matches_root() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = random_master(rng);
        let cover_end = LEAF * LEAF - 1;
        for delegate in root.derive_note_delegates(0..=cover_end) {
            assert_eq!(
                delegate.derive_nullifier(EpochIndex(0)),
                root.derive_nullifier(EpochIndex(0)),
                "mismatch at depth {:?}",
                delegate.depth.get()
            );
        }
    }

    #[test]
    fn tight_cover() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = random_master(rng);
        let delegates = root.derive_note_delegates(0..=(6 * LEAF - 1));
        assert!(!delegates.is_empty());
        let union_end = delegates
            .iter()
            .map(|dk| *dk.range().end())
            .max()
            .expect("non-empty delegates");
        assert_eq!(union_end, 6 * LEAF - 1);
        let union_start = delegates
            .iter()
            .map(|dk| *dk.range().start())
            .min()
            .expect("non-empty delegates");
        assert_eq!(union_start, 0);
    }

    #[test]
    fn single_leaf_delegate() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = random_master(rng);
        let delegates = root.derive_note_delegates((42 * LEAF)..=(43 * LEAF - 1));
        assert_eq!(delegates.len(), 1);
        assert_eq!(delegates[0].range(), (42 * LEAF)..=(43 * LEAF - 1));
        assert_eq!(delegates[0].depth.get(), GGM_TREE_DEPTH - 1);
    }

    #[test]
    #[should_panic(expected = "leaf-aligned")]
    fn sub_leaf_delegation_panics() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = random_master(rng);
        let _delegates = root.derive_note_delegates(0..=5);
    }

    #[test]
    #[should_panic(expected = "must not step beyond the deepest schedule level")]
    fn step_beyond_leaf_level_panics() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = random_master(rng);
        let mut key = root.step(0);
        for _ in 1..GGM_TREE_DEPTH {
            key = key.step(0);
        }
    }

    #[test]
    fn full_range_from_master() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = random_master(rng);
        let delegates = root.derive_note_delegates(0..=GGM_MAX_INDEX);
        assert_eq!(delegates.len(), GGM_TREE_ARITY);
        for (idx, delegate) in delegates.iter().enumerate() {
            assert_eq!(delegate.depth.get(), 1);
            let idx_u32 = u32::try_from(idx).unwrap();
            assert_eq!(delegate.index, idx_u32);
        }
        assert_eq!(*delegates[0].range().start(), 0);
        assert_eq!(*delegates[GGM_TREE_ARITY - 1].range().end(), GGM_MAX_INDEX);
    }

    #[test]
    fn last_leaf_delegate() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = random_master(rng);
        let last_leaf_start = GGM_MAX_INDEX + 1 - LEAF;
        let delegates = root.derive_note_delegates(last_leaf_start..=GGM_MAX_INDEX);
        assert_eq!(delegates.len(), 1);
        assert_eq!(delegates[0].range(), last_leaf_start..=GGM_MAX_INDEX);
        assert_eq!(delegates[0].depth.get(), GGM_TREE_DEPTH - 1);
    }

    #[test]
    #[should_panic(expected = "does not cover requested range")]
    fn disjoint_range_panics() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = random_master(rng);
        // Depth-2 node rooted at chunks (0, 0) covers the first leaf.
        let prefix = root.step(0).step(0);
        let outside = *prefix.range().end() + 1;
        let _delegates = prefix.derive_note_delegates(outside..=(outside + LEAF - 1));
    }

    #[test]
    #[should_panic(expected = "does not cover requested range")]
    fn partial_overlap_panics() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = random_master(rng);
        let prefix = root.step(0).step(0);
        let partial_hi = *prefix.range().end() + LEAF;
        let _delegates = prefix.derive_note_delegates(0..=partial_hi);
    }

    /// Distinct domains keep a leaf from reading as a child schedule: the
    /// nullifier leaf differs from child 0's schedule of the same node.
    #[test]
    fn leaf_nullifiers_is_not_child_zero_schedule() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = random_master(rng);
        let leaf_key = root.step(0).step(0);
        let leaf = leaf_key.leaf_nullifiers();
        let child_zero = expand_child(&leaf_key.schedule, &leaf_key.expansion_params(), 0);
        assert_ne!(leaf, child_zero, "leaf domain must separate the leaf");
    }

    #[test]
    fn cover_candidates_start_zero_is_singleton() {
        let candidates = cover_candidates(0..=100);
        assert_eq!(candidates, alloc::vec![0..=100]);
    }

    #[test]
    fn cover_candidates_concrete_k64() {
        // At GGM_CHUNK_SIZE=6, start=23*64 rounds down to: 23*64 (64^1), then
        // 0 (64^2 through epoch top, duplicates collapsed).
        // Effort-descending order after reverse:
        let start = 23 * LEAF;
        let end = 48 * LEAF - 1;
        let candidates = cover_candidates(start..=end);
        assert_eq!(candidates, alloc::vec![0..=end, start..=end]);
    }

    #[test]
    fn cover_candidates_last_is_leaf_rounding() {
        for (start, end) in [(0u32, 0u32), (5, 10), (42, 42), (100, 200)] {
            let candidates = cover_candidates(start..=end);
            assert_eq!(
                *candidates.last().expect("non-empty").start(),
                start & !(LEAF - 1),
                "last entry must start at the leaf rounding of start",
            );
        }
    }

    #[test]
    fn cover_candidates_first_has_smallest_start() {
        for (start, end) in [(1u32, 10u32), (23, 47), (123, 200)] {
            let candidates = cover_candidates(start..=end);
            let first_start = *candidates.first().expect("non-empty").start();
            for candidate in &candidates {
                assert!(
                    first_start <= *candidate.start(),
                    "first candidate must have smallest start",
                );
            }
        }
    }

    #[test]
    fn cover_candidates_epoch_max_no_panic() {
        let max = GGM_MAX_INDEX;
        assert!(!cover_candidates(0..=max).is_empty());
        assert!(!cover_candidates(max..=max).is_empty());
        assert!(!cover_candidates(42u32..=max).is_empty());
    }

    /// Delegation is deterministic in the key material.
    #[test]
    fn expansion_is_deterministic() {
        let rng = &mut StdRng::seed_from_u64(7);
        let root = random_master(rng);
        let chunk = rng.gen_range(0..=GGM_CHUNK_MASK);
        assert_eq!(root.step(chunk), root.step(chunk));
    }

    #[test]
    fn debug_master_key_redacts_value() {
        let key = NoteMasterKey([Fp::from(0xDEAD_BEEFu64); MK_LENGTH]);
        let dbg = alloc::format!("{key:?}");
        assert!(dbg.contains("NoteMasterKey"), "must name the type");
        assert!(!dbg.contains("DEAD"), "must not leak field element");
        assert!(!dbg.contains("dead"), "must not leak field element");
    }

    #[test]
    fn debug_prefixed_key_shows_coordinates_hides_schedule() {
        let root = NoteMasterKey([Fp::from(1u64); MK_LENGTH]);
        let prefix = root.step(0);
        let dbg = alloc::format!("{prefix:?}");
        assert!(dbg.contains("NotePrefixedKey"), "must name the type");
        assert!(dbg.contains("depth"), "must show depth");
        assert!(dbg.contains("index"), "must show index");
    }
}
