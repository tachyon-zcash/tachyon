//! Proving.

use alloc::{collections::BTreeSet, vec::Vec};
use core::mem;

use derive_more::{Display, Error, From};
use ragu::{ProductionRank, pasta::Pasta};
use rand_core::CryptoRng;

use super::{Bundle, Partial, Slot};
use crate::{
    action,
    keys::{ProofAuthorizingKey, public},
    primitives::Anchor,
    stamp::{
        ActionsPlan, ProofStamp, ProveError,
        proof::{App, delegation, pool, spendable},
    },
    value,
};

/// Errors from the prover role.
#[derive(Debug, Display, Error, From)]
#[non_exhaustive]
pub enum ProverError {
    /// No action has this index.
    #[display("no {_0}")]
    #[from(skip)]
    NoAction(#[error(not(source))] Slot),
    /// A note opening is incomplete.
    #[display("{_0} has an incomplete note")]
    #[from(skip)]
    MissingNote(#[error(not(source))] Slot),
    /// An action has no `theta` or `rcv`.
    #[display("{_0} has no theta or rcv")]
    #[from(skip)]
    MissingEntropy(#[error(not(source))] Slot),
    /// An action has no `cv` or `rk`.
    #[display("{_0} has no value commitment or verification key")]
    #[from(skip)]
    MissingEffect(#[error(not(source))] Slot),
    /// Partials to merge cover a common action.
    #[display("partials overlap")]
    Overlap,
    /// No partial covers every action exactly once.
    #[display("no partial covers every action")]
    Incomplete,
    /// The bundle has actions, so it cannot be stamped by `FeeSeed`.
    #[display("bundle has actions")]
    HasActions,
    /// The fee exceeds the max fee note's value, or a bundle with no actions
    /// has a nonzero max fee.
    #[display("fee exceeds the max fee")]
    FeeAboveMax,
    /// A proof step failed.
    #[display("proving failed: {_0}")]
    Prove(ProveError),
}

#[expect(clippy::multiple_inherent_impl, reason = "one impl block per role")]
impl Bundle {
    /// Prove the spends and outputs at the given indices as one [`Partial`] at
    /// `anchor`, and add it to [`Self::partials`].
    ///
    /// Each spend comes with its note's secret, its spendable and the anchor
    /// spans that carry it to `anchor`, as [`ActionsPlan::prove`] takes them.
    /// `pak` is read only by spends.
    ///
    /// # Errors
    ///
    /// Returns [`ProverError`] if an index names no action, an action lacks
    /// `theta`, `rcv`, `cv` or `rk`, an output's note is incomplete, an
    /// index repeats, or a proof step fails.
    #[expect(
        clippy::type_complexity,
        reason = "each spend's index, secret, spendable and anchor spans"
    )]
    pub fn prove_partial<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        app: &App<'_>,
        anchor: Anchor,
        pak: Option<&ProofAuthorizingKey>,
        spends: Vec<(
            usize,
            ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
            Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
        )>,
        outputs: BTreeSet<usize>,
    ) -> Result<(), ProverError> {
        let mut spend_indices = BTreeSet::new();
        let mut planned_spends = Vec::with_capacity(spends.len());
        let mut spend_pcds = Vec::with_capacity(spends.len());
        for (index, secret, spendable, spans) in spends {
            let slot = Slot::Spend(index);
            let spend = self.spends.get(index).ok_or(ProverError::NoAction(slot))?;
            if !spend_indices.insert(index) {
                return Err(ProverError::Overlap);
            }
            planned_spends.push((
                descriptor(spend.cv, spend.rk, slot)?,
                spend.theta.ok_or(ProverError::MissingEntropy(slot))?,
                spend.rcv.ok_or(ProverError::MissingEntropy(slot))?,
            ));
            spend_pcds.push((secret, spendable, spans));
        }

        let mut planned_outputs = Vec::with_capacity(outputs.len());
        for &index in &outputs {
            let slot = Slot::Output(index);
            let output = self.outputs.get(index).ok_or(ProverError::NoAction(slot))?;
            planned_outputs.push((
                descriptor(output.cv, output.rk, slot)?,
                output.theta.ok_or(ProverError::MissingEntropy(slot))?,
                output.note.note().ok_or(ProverError::MissingNote(slot))?,
                output.rcv.ok_or(ProverError::MissingEntropy(slot))?,
            ));
        }

        let proof = ActionsPlan::new(planned_spends, planned_outputs, anchor)
            .prove(rng, app, pak, spend_pcds)?;
        self.partials.push(Partial {
            spends: spend_indices,
            outputs,
            proof,
        });
        Ok(())
    }

    /// Merge every partial into one.
    ///
    /// # Errors
    ///
    /// Returns [`ProverError::Overlap`] if two partials cover a common
    /// action, [`ProverError::Incomplete`] if there are no partials, or
    /// [`ProverError::Prove`] if a proof step fails.
    pub fn merge_partials<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        app: &App<'_>,
    ) -> Result<(), ProverError> {
        let mut partials = mem::take(&mut self.partials).into_iter();
        let Some(mut merged) = partials.next() else {
            return Err(ProverError::Incomplete);
        };
        for partial in partials {
            if merged.overlaps(&partial) {
                return Err(ProverError::Overlap);
            }
            merged = Partial {
                spends: merged.spends.union(&partial.spends).copied().collect(),
                outputs: merged.outputs.union(&partial.outputs).copied().collect(),
                proof: merged.proof.merge(rng, app, partial.proof)?,
            };
        }
        self.partials.push(merged);
        Ok(())
    }

    /// Apply `fee` to the partial covering every action, replacing any prior
    /// stamp and its authorization data. The partial is kept for restamping.
    ///
    /// # Errors
    ///
    /// Returns [`ProverError`] if no single partial covers every action, the
    /// max fee note is incomplete, the fee exceeds it, or a proof step fails.
    pub fn stamp<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        app: &App<'_>,
        fee: value::Positive,
    ) -> Result<(), ProverError> {
        let (Some(partial), 1) = (self.partials.first(), self.partials.len()) else {
            return Err(ProverError::Incomplete);
        };
        let covers_spends = partial.spends.iter().copied().eq(0..self.spends.len());
        let covers_outputs = partial.outputs.iter().copied().eq(0..self.outputs.len());
        let has_actions = !self.spends.is_empty() || !self.outputs.is_empty();
        if !(covers_spends && covers_outputs && has_actions) {
            return Err(ProverError::Incomplete);
        }
        let max_fee_note = self
            .max_fee_note
            .note()
            .ok_or(ProverError::MissingNote(Slot::MaxFee))?;
        if fee > max_fee_note.value {
            return Err(ProverError::FeeAboveMax);
        }

        self.stamp = Some(partial.proof.clone().fee(rng, app, max_fee_note, fee)?);
        Ok(())
    }

    /// Stamp a bundle with no actions at `anchor`, at a zero fee, replacing
    /// any prior stamp and its authorization data.
    ///
    /// # Errors
    ///
    /// Returns [`ProverError`] if the bundle has actions, the max fee note is
    /// incomplete or nonzero, or a proof step fails.
    pub fn seed_stamp<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        app: &App<'_>,
        anchor: Anchor,
    ) -> Result<(), ProverError> {
        if !self.spends.is_empty() || !self.outputs.is_empty() {
            return Err(ProverError::HasActions);
        }
        let max_fee_note = self
            .max_fee_note
            .note()
            .ok_or(ProverError::MissingNote(Slot::MaxFee))?;
        if max_fee_note.value != value::Positive::ZERO {
            return Err(ProverError::FeeAboveMax);
        }

        self.stamp = Some(ProofStamp::seed(rng, app, max_fee_note, anchor)?);
        Ok(())
    }
}

/// An action's stored descriptor.
fn descriptor(
    cv: Option<value::Commitment>,
    rk: Option<public::ActionVerificationKey>,
    slot: Slot,
) -> Result<action::Descriptor, ProverError> {
    Ok(action::Descriptor {
        cv: cv.ok_or(ProverError::MissingEffect(slot))?,
        rk: rk.ok_or(ProverError::MissingEffect(slot))?,
    })
}
