use core::ops::{Div, DivAssign, Mul, MulAssign};

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use pasta_curves::{Eq, Fp};

use super::{EpochIndex, FactoredPoly, factored::impl_factored_poly};
use crate::{collections::indexed_multiset::IndexedMultiset, nullifier::Nullifier};

/// Pedersen commitment to a nullifier sequence.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfSeqCommit(Eq);

/// Witness for a nullifier sequence, held in indexed-multiset form.
///
/// The sequence polynomial is the product of its members' encodings, one per
/// member, realized into coefficient form lazily and memoized alongside its
/// commitment. Coefficients stay internal: a step reaches the sequence
/// through [`commit`](Self::commit) and [`FactoredPoly`], whose `*` and `/`
/// concatenate and excise runs without polynomial arithmetic.
#[derive(Clone, Debug, Default, PartialEq, TotalEq)]
pub struct NfSeqPoly(IndexedMultiset);

impl NfSeqPoly {
    /// Build the sequence for one contiguous run: the members of the
    /// consecutive epochs starting at `epoch_start`.
    #[must_use]
    pub fn new(epoch_start: EpochIndex, nfs: &[Nullifier]) -> Self {
        Self(
            (epoch_start.into()..)
                .zip(nfs.iter().copied().map(Fp::from))
                .collect(),
        )
    }

    /// Deterministic (untrapdoored) commitment to the sequence polynomial,
    /// memoized until the sequence changes.
    #[must_use]
    pub fn commit(&self) -> NfSeqCommit {
        NfSeqCommit(self.0.commit())
    }
}

impl_factored_poly!(NfSeqPoly);
