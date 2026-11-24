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
/// An anchor heads a hash chain over a pool history starting at the genesis
/// value [`Anchor::default`], $\mathsf{ep}(0, 0)$. Each entry advances $a$ by
/// one digest.
///
/// - Publishing a stamp in epoch $e$ yields the stamp absorption
///   $\mathsf{st}(a, e, B)$, the
///   [`anchor_next_stamp`](poseidon::anchor_next_stamp) digest of $a$, $e$ and
///   the two coordinates of $B$, the canonical [bridge
///   hash](super::TachygramSetBridge) of the stamp's tachygram accumulator.
/// - Crossing into epoch $e \geq 1$ yields the boundary digest $\mathsf{ep}(a,
///   e)$, the [`anchor_next_epoch`](poseidon::anchor_next_epoch) digest of $a$
///   into $e$. In a history, $a$ is the previous epoch's final anchor and the
///   digest is the entry anchor of $e$.
///
/// # Injectivity
///
/// An anchor determines the ordered entries of its pool history. Because a
/// digest determines its function and absorbed elements
/// ([Poseidon](poseidon#injectivity)), an anchor determines its last entry and
/// predecessor anchor. A stamp absorption determines its epoch and bridge hash,
/// and the bridge hash determines the accumulator and its polynomial
/// ([`TachygramSetBridge`](super::TachygramSetBridge)). Epochs enter as
/// integers at most `EPOCH_MAX`.
///
/// Walking two histories back from a shared anchor matches one entry per step
/// down to genesis, so matching anchors imply identical histories and no
/// history repeats an anchor. No later history anchor equals genesis because
/// stamp absorptions use a distinct tag and [`next_epoch`](Self::next_epoch)
/// rejects epoch zero.
///
/// # Chains in a step
///
/// Steps compute the same digests on wires, sometimes taking the predecessor
/// anchor or epoch from the prover. Satisfying such a step proves that a digest
/// chain exists without tying it to a pool history.
///
/// A *stamp chain* of $k$ absorptions from $a_0$ to $a_k$ consists of an epoch
/// $e_i \leq \text{EPOCH\_MAX}$, a polynomial $P_i \notin \{0, 1\}$ and a
/// bridge hash $B_i$ of $P_i$'s accumulator at each $i \in 1..=k$, with
/// $a_i = \mathsf{st}(a_{i-1}, e_i, B_i)$. The chain is *in epoch* $e$ when
/// every $e_i$ equals $e$, and $k = 0$ sets $a_k = a_0$.
///
/// `anchor_next_stamp` absorbs an anchor wire, an
/// [`EpochIndex`](crate::gadgets::epoch::EpochIndex) and two bridge hash wires
/// tied by [Recursion](crate::stamp::proof#assumptions) to the last output
/// slot's accumulator. Its polynomial is nonzero: the zero polynomial commits
/// to the identity, which lacks affine coordinates for a bridge hash. Each step
/// also rules out the constant one, as [`next_stamp`](Self::next_stamp) rejects
/// the empty set. Only
/// [`AnchorSpanSeed`](crate::stamp::proof::pool::AnchorSpanSeed) evaluates an
/// absorption inside a challenge identity.
///
/// If $a_k$ belongs to a pool history, backward injectivity matches the $k$
/// absorptions to its last $k$ entries behind $a_k$, including each stamp's
/// epoch $e_i$, canonical bridge hash $B_i$ and polynomial $P_i$. A non-genesis
/// $\mathsf{ep}(a,e)$ in that history is its boundary into $e$ from $a$.
/// Genesis $\mathsf{ep}(0,0)$ is no entry and does not make zero a history
/// anchor.
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
