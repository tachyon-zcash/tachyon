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
/// An anchor is the head of a hash chain over a pool history. The history
/// starts at the genesis value [`Anchor::default`], and each entry advances
/// the anchor $a$ by one digest.
///
/// - A stamp published in epoch $e$ gives $\mathsf{st}(a, e, B)$, the
///   [`anchor_next_stamp`](poseidon::anchor_next_stamp) digest of $a$, $e$ and
///   the two coordinates of $B$. $B$ is the canonical [bridge
///   hash](super::TachygramSetBridge) of the stamp's tachygram accumulator.
///   This digest is a stamp absorption.
/// - A boundary into epoch $e \geq 1$ gives $\mathsf{ep}(a, e)$, the
///   [`anchor_next_epoch`](poseidon::anchor_next_epoch) digest. It is the
///   boundary digest of $a$ into $e$. In a history, $a$ is the final anchor of
///   the epoch before $e$ and the digest is the entry anchor of $e$.
///
/// The genesis value is $\mathsf{ep}(0, 0)$.
///
/// # Injectivity
///
/// An anchor stands for the pool history that produced it. A history is its
/// entries in order. A stamp entry is an epoch and a tachygram accumulator,
/// and a boundary entry is the epoch it enters.
///
/// Under the [Poseidon assumption](crate::stamp::proof#assumptions) a digest
/// determines its function and the elements it absorbed. The two functions
/// have different tags. An anchor is therefore the digest of one kind of
/// entry, and it determines that entry and the anchor before it. A stamp
/// absorption determines the epoch and the bridge hash, and the bridge hash
/// determines the accumulator and its polynomial
/// ([`TachygramSetBridge`](super::TachygramSetBridge)). An epoch is an
/// integer at most `EPOCH_MAX` and is absorbed as that integer.
///
/// No later anchor of a history equals the genesis value. A stamp absorption
/// has the other tag. [`next_epoch`](Self::next_epoch) rejects epoch zero, so a
/// boundary digest of a history absorbs an epoch the genesis value does not.
///
/// Walking back from an anchor of a history therefore finds one entry at each
/// step, and it reaches the genesis value only at the history's start. Two
/// histories with one anchor have the same entries, and no history holds an
/// anchor twice.
///
/// # Chains in a step
///
/// A step computes the same digests on wires. Several steps take the anchor
/// that a digest absorbs, or the epoch, as a wire of the prover's choice.
/// Such a step shows that a chain of digests exists. It does not show that
/// the chain is part of a pool history.
///
/// A *stamp chain* of $k$ absorptions from $a_0$ to $a_k$ is, for each $i$
/// from 1 to $k$, an epoch $e_i$ at most `EPOCH_MAX`, a polynomial $P_i$ and
/// a bridge hash $B_i$ of the accumulator of $P_i$, with
/// $a_i = \mathsf{st}(a_{i-1}, e_i, B_i)$. The chain is *in epoch* $e$ when
/// every $e_i$ is $e$. A chain of no absorptions has $a_k = a_0$.
///
/// No $P_i$ is the constant one. Each step that computes a stamp absorption
/// shows this of its polynomial, as [`next_stamp`](Self::next_stamp) rejects
/// the empty set. No $P_i$ is zero either. The accumulator of the zero
/// polynomial is the identity, and a bridge hash commits to the two affine
/// coordinates of an accumulator, which the identity does not have.
///
/// Each $a_i$ after $a_0$ determines $a_{i-1}$, $e_i$, $B_i$ and $P_i$, as
/// above. When $a_k$ is an anchor of a pool history, the $k$ absorptions are
/// the last $k$ entries behind $a_k$ in that history. Each is a stamp entry,
/// $e_i$ is its epoch, $B_i$ is the canonical bridge hash of its accumulator
/// and $P_i$ is the polynomial that accumulator commits to.
///
/// A boundary digest $\mathsf{ep}(a, e)$ that is a later anchor of a pool
/// history is likewise that history's boundary entry into $e$, and $a$ is the
/// anchor behind it. A boundary digest that is the genesis value is no entry.
/// It has $a$ and $e$ both zero, it is the history's start, and nothing shows
/// that zero is an anchor.
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
