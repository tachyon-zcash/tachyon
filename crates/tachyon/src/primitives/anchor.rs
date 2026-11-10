use core::cmp::Ordering;

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, From, Into, PartialEq};
use lazy_static::lazy_static;
use rand_core::CryptoRng;
use udon::{curve::Projective as _, field::Field as _};

use super::{EpochIndex, TachygramSetCommit};
use crate::{
    digest::poseidon,
    pasta::{Eq, Fp},
    serialization,
};

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
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct Anchor(pub Fp);

impl PartialOrd for Anchor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Anchor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_inner().reduce().cmp(&other.0.as_inner().reduce())
    }
}

impl Anchor {
    /// Sample a uniformly random anchor.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fp::random(|bytes| rng.fill_bytes(bytes)))
    }

    /// Advance the anchor by absorbing one stamp and the epoch of the block
    /// that contains it.
    ///
    /// The containing epoch index may be zero, within the genesis epoch.
    ///
    /// # Errors
    ///
    /// Fails if the commitment is the identity, or if the tachygram set is
    /// empty.
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
            let stamp_hash = stamp_commit
                .bridge()
                .map_err(|_err| AnchorError::NextStampZero)?;
            Ok(Self(poseidon::anchor_next_stamp(
                self.0,
                epoch.into(),
                stamp_hash.into(),
            )))
        }
    }

    /// Advance the anchor into `epoch` with a boundary digest.
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
    /// The entry anchor of epoch zero is `H_epoch(0, 0)`. Its fold input is
    /// zero, which is no chain vertex; [`Anchor::next_epoch`] rejects index
    /// zero, so no crossing produces it.
    fn default() -> Self {
        Self(*ANCHOR_GENESIS)
    }
}

#[cfg(test)]
mod tests;
