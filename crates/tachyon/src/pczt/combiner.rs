//! Combining copies of one bundle.

use alloc::vec::Vec;

use derive_more::{Display, Eq as TotalEq, Error, PartialEq};
use udon::field::Field as _;

use super::{Action, Bundle, NoteOpening, Partial, Slot};
use crate::{
    pasta::{Fp, Fq},
    primitives::Effect,
    stamp::StampState as _,
};

/// Errors from the combiner role.
#[derive(Clone, Copy, Debug, Display, Error, PartialEq, TotalEq)]
#[non_exhaustive]
pub enum CombineError {
    /// The copies differ in a field that is never absent, so they are not
    /// copies of one bundle.
    #[display("copies differ in {_0}")]
    Mismatch(#[error(not(source))] &'static str),
    /// The copies hold different values for a field of this action or of the
    /// max fee note.
    #[display("copies conflict in {_0}")]
    Conflict(#[error(not(source))] Slot),
    /// The copies hold different values for a bundle field.
    #[display("copies conflict in {_0}")]
    BundleConflict(#[error(not(source))] &'static str),
    /// A partial overlaps another without either covering the other, or two
    /// different partials cover the same actions.
    #[display("partials conflict")]
    PartialConflict,
}

impl Bundle {
    /// Combine two copies of this bundle.
    ///
    /// The copies must hold the same actions, memo and value balance. Each
    /// optional field takes the present value, and two different present
    /// values conflict. A partial that covers another's actions supersedes
    /// it.
    ///
    /// # Errors
    ///
    /// Returns [`CombineError`] if the copies are of different bundles or hold
    /// conflicting values.
    pub fn combine(self, other: Self) -> Result<Self, CombineError> {
        if self.spends.len() != other.spends.len() || self.outputs.len() != other.outputs.len() {
            return Err(CombineError::Mismatch("actions"));
        }
        if self.memo != other.memo {
            return Err(CombineError::Mismatch("memo"));
        }
        if self.value_balance != other.value_balance {
            return Err(CombineError::Mismatch("value balance"));
        }

        let spends = self
            .spends
            .into_iter()
            .zip(other.spends)
            .enumerate()
            .map(|(index, (ours, theirs))| combine_action(Slot::Spend(index), &ours, &theirs))
            .collect::<Result<_, _>>()?;
        let outputs = self
            .outputs
            .into_iter()
            .zip(other.outputs)
            .enumerate()
            .map(|(index, (ours, theirs))| combine_action(Slot::Output(index), &ours, &theirs))
            .collect::<Result<_, _>>()?;

        let max_fee_conflict = CombineError::Conflict(Slot::MaxFee);
        Ok(Self {
            spends,
            outputs,
            value_balance: self.value_balance,
            max_fee_note: combine_opening(self.max_fee_note, other.max_fee_note, max_fee_conflict)?,
            max_fee_owner: merge(
                self.max_fee_owner,
                other.max_fee_owner,
                PartialEq::eq,
                max_fee_conflict,
            )?,
            cv_feemax: merge(
                self.cv_feemax,
                other.cv_feemax,
                PartialEq::eq,
                max_fee_conflict,
            )?,
            memo: self.memo,
            binding_sig: merge(
                self.binding_sig,
                other.binding_sig,
                PartialEq::eq,
                CombineError::BundleConflict("binding signature"),
            )?,
            partials: combine_partials(self.partials, other.partials)?,
            stamp: merge(
                self.stamp,
                other.stamp,
                |ours, theirs| ours.stamp_digest() == theirs.stamp_digest(),
                CombineError::BundleConflict("stamp"),
            )?,
        })
    }
}

/// Take the present value, failing with `conflict` if both are present and
/// differ.
fn merge<T>(
    left: Option<T>,
    right: Option<T>,
    same: impl FnOnce(&T, &T) -> bool,
    conflict: CombineError,
) -> Result<Option<T>, CombineError> {
    match (left, right) {
        (Some(ours), Some(theirs)) if !same(&ours, &theirs) => Err(conflict),
        (ours, theirs) => Ok(ours.or(theirs)),
    }
}

fn combine_opening(
    left: NoteOpening,
    right: NoteOpening,
    conflict: CombineError,
) -> Result<NoteOpening, CombineError> {
    Ok(NoteOpening {
        pk: merge(
            left.pk,
            right.pk,
            |ours, theirs| Fp::from(*ours) == Fp::from(*theirs),
            conflict,
        )?,
        value: merge(left.value, right.value, PartialEq::eq, conflict)?,
        psi: merge(left.psi, right.psi, PartialEq::eq, conflict)?,
        rcm: merge(
            left.rcm,
            right.rcm,
            |ours, theirs| Fp::from(*ours) == Fp::from(*theirs),
            conflict,
        )?,
    })
}

fn combine_action<E: Effect>(
    slot: Slot,
    left: &Action<E>,
    right: &Action<E>,
) -> Result<Action<E>, CombineError> {
    let conflict = CombineError::Conflict(slot);
    Ok(Action {
        note: combine_opening(left.note, right.note, conflict)?,
        owner: merge(left.owner, right.owner, PartialEq::eq, conflict)?,
        theta: merge(
            left.theta,
            right.theta,
            |ours, theirs| ours.to_bytes() == theirs.to_bytes(),
            conflict,
        )?,
        rcv: merge(
            left.rcv,
            right.rcv,
            |ours, theirs| Fq::from(*ours).to_bytes() == Fq::from(*theirs).to_bytes(),
            conflict,
        )?,
        cv: merge(left.cv, right.cv, PartialEq::eq, conflict)?,
        rk: merge(left.rk, right.rk, PartialEq::eq, conflict)?,
        sig: merge(left.sig, right.sig, PartialEq::eq, conflict)?,
        _effect: left._effect,
    })
}

/// Add each of `right`'s partials that no partial of `left` covers,
/// replacing every partial of `left` it covers.
fn combine_partials(
    mut left: Vec<Partial>,
    right: Vec<Partial>,
) -> Result<Vec<Partial>, CombineError> {
    for partial in right {
        if let Some(kept) = left.iter().find(|kept| kept.covers(&partial)) {
            if partial.covers(kept) && !same_proof(kept, &partial) {
                return Err(CombineError::PartialConflict);
            }
            continue;
        }
        if left
            .iter()
            .any(|kept| kept.overlaps(&partial) && !partial.covers(kept))
        {
            return Err(CombineError::PartialConflict);
        }
        left.retain(|kept| !partial.covers(kept));
        left.push(partial);
    }
    Ok(left)
}

fn same_proof(left: &Partial, right: &Partial) -> bool {
    left.proof.descriptors == right.proof.descriptors
        && left.proof.digests == right.proof.digests
        && left.proof.tachygrams == right.proof.tachygrams
        && left.proof.anchor == right.proof.anchor
        && matches!(
            (left.proof.proof.to_bytes(), right.proof.proof.to_bytes()),
            (Ok(left_bytes), Ok(right_bytes)) if left_bytes == right_bytes
        )
}
