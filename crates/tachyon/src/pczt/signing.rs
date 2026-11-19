use alloc::vec::Vec;

use derive_more::{Debug, Display, Eq as TotalEq, Error, PartialEq};
use rand_core::CryptoRng;
use udon::field::Field as _;

use super::{ActionWitness, Bundle, NoteField, OpeningCheckError, OpeningDataField};
use crate::{
    Note, action,
    keys::{private, public},
    pasta::Fp,
    primitives::effect,
};

/// A missing input to IO finalization.
#[derive(Clone, Copy, Debug, Display)]
pub enum IoFinalizerField {
    /// A field of the maximum fee note.
    #[display("maximum fee note {_0}")]
    MaxFee(NoteField),
    /// An action's witness tag.
    #[display("witness at action {_0}")]
    Witness(usize),
    /// A field of an action opening.
    #[display("{_1} at action {_0}")]
    Action(usize, OpeningDataField),
}

/// An invalid output opening.
#[derive(Clone, Copy, Debug, Display)]
pub enum OpeningReason {
    /// The action randomness is not representable.
    UnrepresentableActionRandomness,
    /// The note commitment trapdoor is zero.
    ZeroRcm,
    /// The opening does not derive the stored effect.
    Mismatch,
}

/// An invalid maximum fee opening.
#[derive(Clone, Copy, Debug, Display)]
pub enum MaxFeeOpeningReason {
    /// The note commitment trapdoor is zero.
    ZeroRcm,
    /// The opening does not derive the stored maximum fee commitment.
    CommitmentMismatch,
}

/// The IO Finalizer cannot derive consistent authorizing data.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum IoFinalizerError {
    /// A required input is absent.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] IoFinalizerField),
    /// An output opening is invalid.
    #[display("invalid opening for action {_0}: {_1}")]
    Opening(
        #[error(not(source))] usize,
        #[error(not(source))] OpeningReason,
    ),
    /// The maximum fee opening is invalid.
    #[display("invalid maximum fee opening: {_0}")]
    MaxFeeOpening(#[error(not(source))] MaxFeeOpeningReason),
    /// The trapdoor sum does not match the effects.
    #[display("binding key mismatch")]
    BindingKeyMismatch,
    /// A stored signature does not verify.
    #[display("invalid stored signature at action {_0}")]
    InvalidStoredSignature(#[error(not(source))] usize),
}

/// A missing spend witness or validating key.
#[derive(Clone, Copy, Debug, Display, PartialEq, TotalEq)]
pub enum SignField {
    /// The action's witness tag.
    Witness,
    /// The spend's validating key.
    Ak,
}

/// An incomplete or inconsistent spend opening.
#[derive(Clone, Copy, Debug, Display, Error, PartialEq, TotalEq)]
#[non_exhaustive]
pub enum SignOpeningError {
    /// A needed preimage is absent.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] OpeningDataField),
    /// The note commitment trapdoor is zero.
    #[display("zero note commitment trapdoor")]
    ZeroRcm,
    /// The action randomness exceeds the circuit field's capacity.
    #[display("unrepresentable action randomness")]
    UnrepresentableActionRandomness,
    /// The opening does not derive the stored descriptor.
    #[display("action descriptor mismatch")]
    DescriptorMismatch,
}

/// An action cannot accept a signature.
#[derive(Clone, Copy, Debug, Display, Error, PartialEq, TotalEq)]
#[non_exhaustive]
pub enum SignError {
    /// The action index is out of range.
    #[display("invalid action index {_0}")]
    InvalidIndex(#[error(not(source))] usize),
    /// The witness or owner is absent.
    #[display("missing {_1} at action {_0}")]
    Missing(#[error(not(source))] usize, #[error(not(source))] SignField),
    /// The action is not a spend.
    #[display("action is not a spend")]
    NotSpend,
    /// The key does not own the action.
    #[display("wrong spend owner")]
    WrongOwner,
    /// Opening verification failed.
    #[display("invalid spend opening")]
    Opening(SignOpeningError),
    /// The stored signature does not verify.
    #[display("invalid stored signature")]
    InvalidStoredSignature,
}

/// Failure to import a signature.
#[derive(Clone, Copy, Debug, Display, Error, PartialEq, TotalEq)]
#[non_exhaustive]
pub enum ApplySignatureError {
    /// The action index is out of range.
    #[display("invalid action index {_0}")]
    InvalidIndex(#[error(not(source))] usize),
    /// The supplied signature does not verify.
    #[display("invalid signature")]
    InvalidSignature,
    /// A different signature already occupies the slot.
    #[display("conflicting signature")]
    Conflict,
}

pub(super) enum FeeOpeningError {
    Missing(NoteField),
    Invalid(MaxFeeOpeningReason),
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "signing roles are defined together"
)]
impl Bundle {
    pub(super) fn checked_fee_opening(&self) -> Result<Note, FeeOpeningError> {
        let note = self
            .max_fee
            .note
            .complete()
            .map_err(FeeOpeningError::Missing)?;
        if Fp::from(note.rcm) == Fp::ZERO {
            return Err(FeeOpeningError::Invalid(MaxFeeOpeningReason::ZeroRcm));
        }
        if note.cv_feemax() != self.max_fee.cv_feemax {
            return Err(FeeOpeningError::Invalid(
                MaxFeeOpeningReason::CommitmentMismatch,
            ));
        }
        Ok(note)
    }

    pub(super) fn binding_key_matches(&self, bsk: &private::BindingSigningKey) -> bool {
        bsk.derive_binding_public()
            == public::BindingVerificationKey::derive(
                self.actions
                    .iter()
                    .map(|action| action.descriptor.cv)
                    .chain([self.max_fee.cv_feemax]),
                self.value_balance,
            )
    }

    /// Establish the binding key and authorize the outputs.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or inconsistent input data.
    pub fn finalize_io<RNG: CryptoRng>(
        &mut self,
        sighash: [u8; 32],
        rng: &mut RNG,
    ) -> Result<(), IoFinalizerError> {
        let fee_note = self.checked_fee_opening().map_err(|err| match err {
            FeeOpeningError::Missing(field) => {
                IoFinalizerError::Missing(IoFinalizerField::MaxFee(field))
            },
            FeeOpeningError::Invalid(reason) => IoFinalizerError::MaxFeeOpening(reason),
        })?;
        let mut blinds = Vec::with_capacity(self.actions.len() + 1);
        for (index, action) in self.actions.iter().enumerate() {
            blinds.push(
                action
                    .rcv
                    .ok_or(IoFinalizerError::Missing(IoFinalizerField::Action(
                        index,
                        OpeningDataField::Rcv,
                    )))?,
            );
        }
        blinds.push(fee_note.derive_feemax_blind());
        let bsk = private::BindingSigningKey::from(blinds);
        if !self.binding_key_matches(&bsk)
            || self.bsk.is_some_and(|key| key.to_bytes() != bsk.to_bytes())
        {
            return Err(IoFinalizerError::BindingKeyMismatch);
        }
        let mut sigs = Vec::with_capacity(self.actions.len());
        for (index, action) in self.actions.iter().enumerate() {
            let missing = |field| IoFinalizerError::Missing(IoFinalizerField::Action(index, field));
            let witness = action
                .witness
                .as_ref()
                .ok_or(IoFinalizerError::Missing(IoFinalizerField::Witness(index)))?;
            let sig = match *witness {
                ActionWitness::Spend(_) => None,
                ActionWitness::Output(_) => {
                    let opening = action.opening::<effect::Output>(()).map_err(missing)?;
                    let checked = opening.check().map_err(|err| {
                        IoFinalizerError::Opening(
                            index,
                            match err {
                                OpeningCheckError::ZeroRcm => OpeningReason::ZeroRcm,
                                OpeningCheckError::Randomness => {
                                    OpeningReason::UnrepresentableActionRandomness
                                },
                            },
                        )
                    })?;
                    if checked.descriptor != action.descriptor {
                        return Err(IoFinalizerError::Opening(index, OpeningReason::Mismatch));
                    }
                    if let Some(stored) = action.sig {
                        action
                            .descriptor
                            .rk
                            .verify(&sighash, &stored)
                            .map_err(|_err| IoFinalizerError::InvalidStoredSignature(index))?;
                        sigs.push(None);
                        continue;
                    }
                    Some(private::ActionSigningKey::new(&checked.alpha).sign(rng, &sighash))
                },
            };
            sigs.push(sig);
        }
        for (action, sig) in self.actions.iter_mut().zip(sigs) {
            if sig.is_some() {
                action.sig = sig;
            }
        }
        self.bsk = Some(bsk);
        Ok(())
    }

    /// Sign one owned spend. For full bundle review, use [`Self::plan`] first.
    ///
    /// # Errors
    ///
    /// Returns an error if the indexed action is not a fully opened spend of
    /// `ask`, or if its descriptor does not match.
    #[expect(clippy::ref_patterns, reason = "borrow the spend witness")]
    pub fn sign_at<RNG: CryptoRng>(
        &mut self,
        index: usize,
        sighash: [u8; 32],
        ask: &private::SpendAuthorizingKey,
        rng: &mut RNG,
    ) -> Result<(), SignError> {
        let action = self
            .actions
            .get_mut(index)
            .ok_or(SignError::InvalidIndex(index))?;
        let Some(ref witness) = action.witness else {
            return Err(SignError::Missing(index, SignField::Witness));
        };
        let ActionWitness::Spend(ref spend) = *witness else {
            return Err(SignError::NotSpend);
        };
        let ak = ask.derive_auth_public();
        let owner = spend.ak.ok_or(SignError::Missing(index, SignField::Ak))?;
        if <[u8; 32]>::from(owner.0) != <[u8; 32]>::from(ak.0) {
            return Err(SignError::WrongOwner);
        }
        let opening = action
            .opening::<effect::Spend>(ak)
            .map_err(|field| SignError::Opening(SignOpeningError::Missing(field)))?;
        let checked = opening.check().map_err(|err| {
            SignError::Opening(match err {
                OpeningCheckError::ZeroRcm => SignOpeningError::ZeroRcm,
                OpeningCheckError::Randomness => SignOpeningError::UnrepresentableActionRandomness,
            })
        })?;
        if checked.descriptor != action.descriptor {
            return Err(SignError::Opening(SignOpeningError::DescriptorMismatch));
        }
        if let Some(stored) = action.sig {
            return action
                .descriptor
                .rk
                .verify(&sighash, &stored)
                .map_err(|_err| SignError::InvalidStoredSignature);
        }
        action.sig = Some(
            ask.derive_action_private(&checked.alpha)
                .sign(rng, &sighash),
        );
        Ok(())
    }

    /// Import a signature under the indexed descriptor's verification key.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid index, invalid signature or conflict
    /// with the stored signature.
    pub fn apply_signature_at(
        &mut self,
        index: usize,
        sighash: [u8; 32],
        sig: action::Signature,
    ) -> Result<(), ApplySignatureError> {
        let action = self
            .actions
            .get_mut(index)
            .ok_or(ApplySignatureError::InvalidIndex(index))?;
        action
            .descriptor
            .rk
            .verify(&sighash, &sig)
            .map_err(|_err| ApplySignatureError::InvalidSignature)?;
        if action.sig.is_some_and(|stored| stored != sig) {
            return Err(ApplySignatureError::Conflict);
        }
        action.sig = Some(sig);
        Ok(())
    }
}
