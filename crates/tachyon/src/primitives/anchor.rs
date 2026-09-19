use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, From, Into, PartialEq};
use ff::Field as _;
use group::{Curve as _, Group as _};
use lazy_static::lazy_static;
use pasta_curves::{Eq, Fp};

use super::{EpochIndex, TachygramSetCommit};
use crate::{digest::poseidon, serialization};

lazy_static! {
    static ref ANCHOR_GENESIS: Fp = poseidon::anchor_next_epoch(Fp::ZERO, Fp::ZERO);
}

/// Errors that can occur when advancing an anchor.
#[derive(Debug, Display, Error, PartialEq, TotalEq)]
pub enum AnchorError {
    /// The provided tachygram set is the identity point.
    #[display("next stamp cannot be the identity point")]
    NextStampZero,
    /// The provided tachygram set is empty.
    #[display("next stamp cannot be empty")]
    NextStampEmpty,
    /// The provided epoch index is zero.
    #[display("next epoch cannot be zero")]
    NextEpochZero,
}

/// Running anchor over the consensus state.
#[derive(Clone, Copy, Debug, From, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct Anchor(pub Fp);

impl Anchor {
    /// Advance the anchor by one stamp link, absorbing the containing epoch.
    ///
    /// The containing epoch index may be zero, within the genesis epoch.
    ///
    /// # Errors
    ///
    /// Fails if `stamp_commit` is the identity point or a commitment to an
    /// empty set.
    pub fn next_stamp(
        self,
        epoch: EpochIndex,
        &stamp_commit: &TachygramSetCommit,
    ) -> Result<Self, AnchorError> {
        if *stamp_commit.as_ref() == Eq::identity() {
            Err(AnchorError::NextStampZero)
        } else if stamp_commit == TachygramSetCommit::default() {
            Err(AnchorError::NextStampEmpty)
        } else {
            Ok(Self(poseidon::anchor_next_stamp(
                self.0,
                epoch.into(),
                stamp_commit.as_ref().to_affine(),
            )))
        }
    }

    /// Advance the anchor by one epoch link, absorbing `epoch`.
    ///
    /// # Errors
    ///
    /// Fails if `epoch` is zero.
    pub fn next_epoch(self, epoch: EpochIndex) -> Result<Self, AnchorError> {
        if epoch == EpochIndex::new(0) {
            Err(AnchorError::NextEpochZero)
        } else {
            Ok(Self(poseidon::anchor_next_epoch(self.0, epoch.into())))
        }
    }

    /// Read a 32-byte anchor.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or the bytes are not a canonical
    /// field element.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        serialization::read_fp(&mut reader).map(Self)
    }

    /// Write a 32-byte anchor.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_fp(&mut writer, &self.0)
    }
}

impl Default for Anchor {
    /// The entry anchor of epoch zero, `H_epoch(0, 0)`. Its fold input is
    /// zero, which is no chain vertex; [`Anchor::next_epoch`] rejects index
    /// zero, so no crossing produces it.
    fn default() -> Self {
        Self(*ANCHOR_GENESIS)
    }
}

#[cfg(test)]
mod tests {
    use pasta_curves::Eq;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{Tachygram, TachygramSetPoly};

    #[test]
    fn order_matters() {
        let rng = &mut StdRng::seed_from_u64(0);
        let first = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
        let second = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();

        let forward = Anchor::default()
            .next_stamp(EpochIndex::new(7), &first)
            .unwrap()
            .next_stamp(EpochIndex::new(7), &second)
            .unwrap();

        let reverse = Anchor::default()
            .next_stamp(EpochIndex::new(7), &second)
            .unwrap()
            .next_stamp(EpochIndex::new(7), &first)
            .unwrap();

        assert_ne!(forward, reverse);
    }

    #[test]
    fn next_stamp_rejects_invalid_sets() {
        let rng = &mut StdRng::seed_from_u64(0);

        // The identity commitment is not a valid set
        {
            let anchor = Anchor(Fp::random(&mut *rng));
            let zero_set = TachygramSetCommit::from(Eq::identity());

            let Err(AnchorError::NextStampZero) = anchor.next_stamp(EpochIndex::new(7), &zero_set)
            else {
                panic!("should not be able to advance with an identity stamp");
            };
        }

        // An empty set commits to a constant polynomial
        {
            let anchor = Anchor(Fp::random(&mut *rng));
            let one_set = TachygramSetCommit::default();

            let Err(AnchorError::NextStampEmpty) = anchor.next_stamp(EpochIndex::new(1), &one_set)
            else {
                panic!("should not be able to advance with an empty stamp");
            };
        }
    }

    #[test]
    fn next_epoch_rejects_epoch_zero() {
        let rng = &mut StdRng::seed_from_u64(0);

        let anchor = Anchor(Fp::random(rng));

        let Err(AnchorError::NextEpochZero) = anchor.next_epoch(EpochIndex::new(0)) else {
            panic!("should not be able to advance to epoch zero");
        };
    }
}
