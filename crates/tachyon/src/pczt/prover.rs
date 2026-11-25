use alloc::{collections::BTreeSet, vec, vec::Vec};

use derive_more::{Display, Error};
use ragu::{Pcd, WalletRank, pasta::Pasta};
use rand_core::CryptoRng;

use super::{
    ActionWitness, Bundle, MaxFeeOpeningReason, NoteField, Opening, OpeningCheckError,
    OpeningDataField, signing::FeeOpeningError,
};
use crate::{
    primitives::effect,
    stamp::{
        self,
        proof::{App, pool},
    },
    value,
};

/// A missing input to action proving.
#[derive(Clone, Copy, Debug, Display)]
pub enum ProveField {
    /// The proving target.
    Anchor,
    /// A required field of the selected action.
    #[display("action {_0} {_1}")]
    Action(usize, ProveActionField),
}

/// A field required to prove an action.
#[derive(Clone, Copy, Debug, Display)]
pub enum ProveActionField {
    /// The action's witness tag.
    Witness,
    /// A delegated proof authorizing key.
    Pak,
    /// The spend's predecessor proofs.
    Lineage,
    /// A preimage of the action descriptor.
    #[display("{_0}")]
    Opening(OpeningDataField),
}

/// Failure to prove the selected actions.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ProveActionsError {
    /// The selected action randomness is not representable.
    #[display("unrepresentable randomness at action {_0}")]
    UnrepresentableActionRandomness(#[error(not(source))] usize),
    /// The selected note's commitment trapdoor is zero.
    #[display("zero rcm at action {_0}")]
    ZeroRcm(#[error(not(source))] usize),
    /// The index is out of range.
    #[display("invalid action index {_0}")]
    InvalidIndex(#[error(not(source))] usize),
    /// The index occurs twice in the selection.
    #[display("repeated action index {_0}")]
    RepeatedIndex(#[error(not(source))] usize),
    /// A stored proof already covers the index.
    #[display("already covered action {_0}")]
    AlreadyCovered(#[error(not(source))] usize),
    /// A proving input is absent.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] ProveField),
    /// The opening does not derive the descriptor.
    #[display("opening mismatch at action {_0}")]
    OpeningMismatch(#[error(not(source))] usize),
    /// Proof construction failed.
    #[display("cannot prove selected actions")]
    Prove(stamp::ActionsProveError),
}

/// Failure to lift an action proof.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum LiftActionsProofError {
    /// The index is outside `actions_proofs`.
    #[display("invalid proof index {_0}")]
    InvalidIndex(#[error(not(source))] usize),
    /// Proof lifting failed.
    #[display("cannot lift action proof")]
    Lift(ragu::Error),
}

/// A missing input to the fee step.
#[derive(Clone, Copy, Debug, Display)]
pub enum ApplyFeeField {
    /// The proving target of an actionless section.
    Anchor,
    /// A field of the maximum fee opening.
    #[display("max fee {_0}")]
    MaxFee(NoteField),
}

/// Failure to apply a fee.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ApplyFeeError {
    /// The maximum fee note's commitment trapdoor is zero.
    #[display("zero maximum fee rcm")]
    ZeroMaxFeeRcm,
    /// A required field is missing.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] ApplyFeeField),
    /// The opening does not derive the maximum fee commitment.
    #[display("max fee opening mismatch")]
    MaxFeeOpeningMismatch,
    /// The proofs do not cover every action.
    #[display("incomplete proof coverage")]
    IncompleteCoverage,
    /// An actionless section cannot pay a nonzero fee.
    #[display("nonzero fee for actionless section")]
    NonzeroSeedFee,
    /// Merging action proofs failed.
    #[display("cannot merge action proofs")]
    Merge(stamp::MergeError),
    /// Applying the fee to proven actions failed.
    #[display("cannot apply fee to action proof")]
    Fee(stamp::FeeError),
    /// Seeding a stamp without actions failed.
    #[display("cannot seed actionless stamp")]
    Seed(stamp::SeedError),
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "proving entry points are defined together"
)]
impl Bundle {
    /// Prove the selected actions and append an `ActionsProof`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid selection, unavailable or inconsistent
    /// openings, or failed proving.
    #[expect(clippy::ref_patterns, reason = "borrow the spend witness")]
    pub fn prove_actions<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        app: &App<'_>,
        indices: &[usize],
    ) -> Result<(), ProveActionsError> {
        let anchor = self
            .anchor
            .ok_or(ProveActionsError::Missing(ProveField::Anchor))?;
        let mut selected = BTreeSet::new();
        for &index in indices {
            if !selected.insert(index) {
                return Err(ProveActionsError::RepeatedIndex(index));
            }
        }
        let mut spends = Vec::new();
        let mut outputs = Vec::new();
        let mut pcds = Vec::new();
        for index in selected {
            let action = self
                .actions
                .get(index)
                .ok_or(ProveActionsError::InvalidIndex(index))?;
            let desc = action.descriptor;
            if self
                .actions_proofs
                .iter()
                .any(|proof| proof.pairs.contains_key(&desc))
            {
                return Err(ProveActionsError::AlreadyCovered(index));
            }
            let missing = |field| ProveActionsError::Missing(ProveField::Action(index, field));
            let theta = action
                .theta
                .ok_or_else(|| missing(ProveActionField::Opening(OpeningDataField::Theta)))?;
            let rcv = action
                .rcv
                .ok_or_else(|| missing(ProveActionField::Opening(OpeningDataField::Rcv)))?;
            let check = |result: Result<_, OpeningCheckError>| {
                let derived = result.map_err(|err| match err {
                    OpeningCheckError::ZeroRcm => ProveActionsError::ZeroRcm(index),
                    OpeningCheckError::Randomness => {
                        ProveActionsError::UnrepresentableActionRandomness(index)
                    },
                })?;
                if derived != desc {
                    return Err(ProveActionsError::OpeningMismatch(index));
                }
                Ok(())
            };
            match *action
                .witness
                .as_ref()
                .ok_or_else(|| missing(ProveActionField::Witness))?
            {
                ActionWitness::Spend(ref spend) => {
                    let pak = spend.pak().ok_or_else(|| missing(ProveActionField::Pak))?;
                    let lineage = spend
                        .lineage
                        .as_ref()
                        .ok_or_else(|| missing(ProveActionField::Lineage))?;
                    let (_, note, _) = *lineage.secret.data();
                    check(
                        Opening::<effect::Spend> {
                            note,
                            theta,
                            rcv,
                            authority: pak.ak,
                        }
                        .check()
                        .map(|checked| checked.descriptor),
                    )?;
                    spends.push((desc, theta, rcv));
                    pcds.push((
                        pak,
                        lineage.secret().clone(),
                        lineage.spendable().clone(),
                        lineage.spans.clone(),
                    ));
                },
                ActionWitness::Output(_) => {
                    let opening = action
                        .opening::<effect::Output>(())
                        .map_err(|field| missing(ProveActionField::Opening(field)))?;
                    check(opening.check().map(|checked| checked.descriptor))?;
                    outputs.push((desc, theta, opening.note, rcv));
                },
            }
        }
        let proof = stamp::ActionsPlan::new(spends, outputs, anchor)
            .prove(rng, app, pcds)
            .map_err(ProveActionsError::Prove)?;
        self.actions_proofs.push(proof);
        Self::sort_actions_proofs(&mut self.actions_proofs);
        Ok(())
    }

    /// Advance one entry of `actions_proofs` to a later anchor.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid index or failed lifting.
    pub fn lift_actions_proof<RNG: CryptoRng>(
        &mut self,
        index: usize,
        rng: &mut RNG,
        app: &App<'_>,
        spans: Vec<Pcd<Pasta, WalletRank, pool::AnchorSpan>>,
    ) -> Result<(), LiftActionsProofError> {
        let proof = self
            .actions_proofs
            .get_mut(index)
            .ok_or(LiftActionsProofError::InvalidIndex(index))?;
        *proof = proof
            .clone()
            .lift(rng, app, spans)
            .map_err(LiftActionsProofError::Lift)?;
        Ok(())
    }

    /// Apply the fee and retain one `ActionsProof` for later fee changes.
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete coverage, invalid fee opening or failed
    /// proving.
    pub fn apply_fee<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        app: &App<'_>,
        fee: value::Positive,
    ) -> Result<(), ApplyFeeError> {
        let actionless = self.actions.is_empty();
        let note = self.checked_fee_opening().map_err(|err| match err {
            FeeOpeningError::Missing(field) => ApplyFeeError::Missing(ApplyFeeField::MaxFee(field)),
            FeeOpeningError::Invalid(MaxFeeOpeningReason::CommitmentMismatch) => {
                ApplyFeeError::MaxFeeOpeningMismatch
            },
            FeeOpeningError::Invalid(MaxFeeOpeningReason::ZeroRcm) => ApplyFeeError::ZeroMaxFeeRcm,
        })?;
        if actionless {
            if fee != value::Positive::ZERO {
                return Err(ApplyFeeError::NonzeroSeedFee);
            }
            let anchor = self
                .anchor
                .ok_or(ApplyFeeError::Missing(ApplyFeeField::Anchor))?;
            let parts =
                stamp::AutonomeParts::seed(rng, app, note, anchor).map_err(ApplyFeeError::Seed)?;
            self.autonome_parts = Some(parts);
            return Ok(());
        }
        let Some((first, rest)) = self.actions_proofs.split_first() else {
            return Err(ApplyFeeError::IncompleteCoverage);
        };
        if first.pairs.len() + rest.iter().map(|proof| proof.pairs.len()).sum::<usize>()
            != self.actions.len()
        {
            return Err(ApplyFeeError::IncompleteCoverage);
        }
        let merged = rest
            .iter()
            .cloned()
            .try_fold(first.clone(), |left, right| left.merge(rng, app, right))
            .map_err(ApplyFeeError::Merge)?;
        let parts = merged
            .clone()
            .fee(rng, app, note, fee)
            .map_err(ApplyFeeError::Fee)?;
        self.actions_proofs = vec![merged];
        self.autonome_parts = Some(parts);
        Ok(())
    }
}
