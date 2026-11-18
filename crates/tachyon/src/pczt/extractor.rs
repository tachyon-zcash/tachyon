//! Transaction extraction.

use alloc::{collections::BTreeMap, vec::Vec};

use derive_more::{Display, Error};
use rand_core::CryptoRng;
use udon::curve::Affine as _;

use super::{Bundle, Slot};
use crate::{
    action,
    bundle::{self, VerificationError},
    fee,
    pasta::EpAffine,
    stamp::{ProofStamp, Uncompressed, proof::App},
    value::Balance,
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
    /// The stamp lists adjuncts, which PCZT extraction does not support.
    #[display("stamp lists adjuncts")]
    UnexpectedAdjuncts,
    /// Descriptors are not unique or do not match the stamp's pairs.
    #[display("action descriptors do not match the stamped pairs")]
    ActionMismatch,
    /// A pair is not in the prover's ascending order.
    #[display("tachygram pair is not in ascending order")]
    TachygramOrder,
    /// An action or fee descriptor contains an identity point.
    #[display("{_0} has an identity commitment or verification key")]
    IdentityEffect(#[error(not(source))] Slot),
    /// The note values do not sum to the value balance, or a bundle with no
    /// actions has a nonzero balance.
    #[display("invalid value balance")]
    BalanceMismatch,
    /// The extracted bundle does not verify.
    #[display("extracted bundle does not verify: {_0}")]
    Verification(VerificationError),
}

#[expect(clippy::multiple_inherent_impl, reason = "one impl block per role")]
impl Bundle {
    /// Extract a verified uncompressed bundle, with actions in sorted
    /// descriptor order.
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
        app: &App<'_>,
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
        if (self.spends.is_empty()
            && self.outputs.is_empty()
            && self.value_balance != Balance::ZERO)
            || values.is_some_and(|amounts| {
                amounts.into_iter().sum::<i128>() != i128::from(self.value_balance)
            })
        {
            return Err(ExtractError::BalanceMismatch);
        }

        let mut action_sigs = BTreeMap::new();
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
            let descriptor = action::Descriptor {
                cv: cv.ok_or(ExtractError::MissingEffect(slot))?,
                rk: rk.ok_or(ExtractError::MissingEffect(slot))?,
            };
            if EpAffine::from(descriptor.cv).is_identity()
                || EpAffine::from(descriptor.rk).is_identity()
            {
                return Err(ExtractError::IdentityEffect(slot));
            }
            if action_sigs
                .insert(descriptor, sig.ok_or(ExtractError::MissingSignature(slot))?)
                .is_some()
            {
                return Err(ExtractError::ActionMismatch);
            }
        }

        let cv_feemax = self
            .cv_feemax
            .ok_or(ExtractError::MissingEffect(Slot::MaxFee))?;
        if EpAffine::from(cv_feemax).is_identity() {
            return Err(ExtractError::IdentityEffect(Slot::MaxFee));
        }
        let binding_sig = self
            .binding_sig
            .ok_or(ExtractError::MissingBindingSignature)?;
        let (stamp, pairs, fee_auth, v_fee) = self.stamp.ok_or(ExtractError::MissingStamp)?;
        if !stamp.adjuncts.is_empty() {
            return Err(ExtractError::UnexpectedAdjuncts);
        }
        if !action_sigs.keys().eq(pairs.keys()) {
            return Err(ExtractError::ActionMismatch);
        }
        if pairs.values().any(|&(first, second)| first >= second) {
            return Err(ExtractError::TachygramOrder);
        }
        let (actions, action_auth) = action_sigs
            .into_iter()
            .zip(pairs)
            .map(|((desc, sig), (_, pair))| (desc, (sig, pair)))
            .unzip();
        let extracted = bundle::Bundle {
            value_balance: self.value_balance,
            actions,
            action_auth,
            fee: fee::Descriptor { cv_feemax, v_fee },
            fee_auth,
            binding_sig,
            memo: self.memo,
            stamp,
        };

        extracted
            .verify(rng, app, sighash, &[])
            .map_err(ExtractError::Verification)?;
        Ok(extracted)
    }
}
