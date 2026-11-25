use core::cmp::Ordering;

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, From, Into, PartialEq};
use lazy_static::lazy_static;
use ragu::udon::{curve::Affine as _, field::Field as _};
use rand_core::CryptoRng;

use super::{EpochIndex, TachygramSetCommit};
use crate::{bridge_hash::bridge_hash, digest::poseidon, pasta::Fp, serialization};

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
///
/// A pool history starts at [`Anchor::default`], $\mathsf{ep}(0,0)$. Each
/// entry advances its anchor $a$ by one digest:
///
/// - Publishing a stamp in epoch $e$ [absorbs](poseidon::anchor_next_stamp)
///   $a$, $e$ and both coordinates of the stamp accumulator's canonical
///   wallet-rank [bridge hash](super::TachygramSetBridge) $B$, giving
///   $\mathsf{st}(a,e,B)$.
/// - At the boundary into $e\ge1$, the previous epoch's final anchor $a$ gives
///   the new entry anchor $\mathsf{ep}(a,e)$ via
///   [`anchor_next_epoch`](poseidon::anchor_next_epoch).
///
/// # Injectivity
///
/// [Poseidon](poseidon#injectivity) binds the entry kind, predecessor and
/// integer epoch (at most `EPOCH_MAX`). For a stamp it also binds the absorbed
/// point, in a pool history the canonical wallet-rank bridge hash, which
/// determines the accumulator and polynomial. A step can absorb a point that
/// is no bridge hash into an anchor outside any pool history
/// ([`AnchorSpan`](crate::stamp::proof::pool::AnchorSpan)). Walking back from
/// a shared anchor thus matches ordered entries to genesis. No later entry
/// equals genesis: stamp absorptions use another tag and
/// [`next_epoch`](Self::next_epoch) rejects epoch zero. Hence matching anchors
/// have identical histories and no history repeats an anchor.
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
        if stamp_commit.as_ref().is_identity() {
            Err(AnchorError::NextStampZero)
        } else if stamp_commit == TachygramSetCommit::default() {
            Err(AnchorError::NextStampEmpty)
        } else {
            Ok(Self(poseidon::anchor_next_stamp(
                self.0,
                epoch.into(),
                bridge_hash(stamp_commit.into()),
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
    /// The genesis value $\mathsf{ep}(0, 0)$, the entry anchor of epoch zero.
    ///
    /// No other anchor of a pool history equals it. See
    /// [Injectivity](Anchor#injectivity).
    fn default() -> Self {
        Self(*ANCHOR_GENESIS)
    }
}

#[cfg(test)]
mod tests;
