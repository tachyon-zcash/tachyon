//! Transaction extraction.

use alloc::vec::Vec;

use derive_more::{Display, Error};
use rand_core::CryptoRng;

use super::{Bundle, Slot};
use crate::{
    action::Action,
    bundle::{self, VerificationError},
    stamp::{ProofStamp, Uncompressed},
};

/// Errors from the transaction extractor role.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ExtractError {
    /// An action has no `cv` or `rk`, or the max fee note no `cv_feemax`.
    #[display("{_0} has no value commitment or verification key")]
    MissingEffect(#[error(not(source))] Slot),
    /// An action has no signature.
    #[display("{_0} has no signature")]
    MissingSignature(#[error(not(source))] Slot),
    /// The bundle has no binding signature.
    #[display("no binding signature")]
    MissingBindingSignature,
    /// The bundle has no stamp.
    #[display("no stamp")]
    MissingStamp,
    /// The note values do not sum to the value balance.
    #[display("note values do not sum to the value balance")]
    BalanceMismatch,
    /// The extracted bundle does not verify.
    #[display("extracted bundle does not verify: {_0}")]
    Verification(VerificationError),
}

#[expect(clippy::multiple_inherent_impl, reason = "one impl block per role")]
impl Bundle {
    /// Extract a verified uncompressed bundle, with actions in sorted descriptor
    /// order.
    ///
    /// When every note value is present, they must sum to the value balance.
    /// The extracted bundle is verified as an autonome against `sighash`:
    /// signatures, coverage, tachygrams and proof. Its anchor's membership in
    /// the chain is not checked.
    ///
    /// # Errors
    ///
    /// Returns [`ExtractError`] if a published field is absent, the note
    /// values do not balance, or the bundle does not verify.
    pub fn extract<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        sighash: &[u8; 32],
    ) -> Result<bundle::Bundle<ProofStamp<Uncompressed>>, ExtractError> {
        let values = self
            .spends
            .iter()
            .map(|spend| spend.note.value.map(i128::from))
            .chain(
                self.outputs
                    .iter()
                    .map(|output| output.note.value.map(|value| -i128::from(value))),
            )
            .chain([self.max_fee_note.value.map(|value| -i128::from(value))])
            .collect::<Option<Vec<i128>>>();
        if values.is_some_and(|amounts| {
            amounts.into_iter().sum::<i128>() != i128::from(self.value_balance)
        }) {
            return Err(ExtractError::BalanceMismatch);
        }

        let mut actions = Vec::with_capacity(self.spends.len() + self.outputs.len());
        for (slot, cv, rk, sig) in
            self.spends
                .iter()
                .enumerate()
                .map(|(index, spend)| (Slot::Spend(index), spend.cv, spend.rk, spend.sig))
                .chain(
                    self.outputs.iter().enumerate().map(|(index, output)| {
                        (Slot::Output(index), output.cv, output.rk, output.sig)
                    }),
                )
        {
            actions.push(Action {
                cv: cv.ok_or(ExtractError::MissingEffect(slot))?,
                rk: rk.ok_or(ExtractError::MissingEffect(slot))?,
                sig: sig.ok_or(ExtractError::MissingSignature(slot))?,
            });
        }
        actions.sort();

        let extracted = bundle::Bundle {
            value_balance: self.value_balance,
            actions,
            cv_feemax: self
                .cv_feemax
                .ok_or(ExtractError::MissingEffect(Slot::MaxFee))?,
            binding_sig: self
                .binding_sig
                .ok_or(ExtractError::MissingBindingSignature)?,
            memo: self.memo,
            stamp: self.stamp.ok_or(ExtractError::MissingStamp)?,
        };

        extracted
            .verify_autonome(rng, sighash)
            .map_err(ExtractError::Verification)?;
        Ok(extracted)
    }
}
