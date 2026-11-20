use alloc::{boxed::Box, string::String, vec::Vec};

use derive_more::{Display, Error};

use super::{ActionWitness, Bundle, SpendLineage, SpendWitness, Zip32Derivation};
use crate::{Anchor, keys::ProofAuthorizingKey};

/// The specified action index is outside the section.
#[derive(Clone, Copy, Debug, Display, Error)]
#[display("invalid action index {_0}")]
pub struct InvalidIndex(#[error(not(source))] pub usize);

/// The indexed action witness is unavailable.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum WitnessAccessError {
    /// The index is invalid.
    #[display("cannot locate action")]
    InvalidIndex(InvalidIndex),
    /// The witness is absent.
    #[display("missing witness at action {_0}")]
    MissingWitness(#[error(not(source))] usize),
}

/// Failure to update a kind-specific action witness.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum WitnessUpdateError {
    /// The witness could not be reached.
    #[display("cannot locate witness")]
    Witness(WitnessAccessError),
    /// The witness has the wrong action kind.
    #[display("wrong witness kind at action {_0}")]
    WrongKind(#[error(not(source))] usize),
}

/// Failure to attach a proof authorizing key.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum SetPakError {
    /// The spend witness could not be reached.
    #[display("cannot locate spend witness")]
    Witness(WitnessUpdateError),
    /// The proof authorizing key names a different owner.
    #[display("owner mismatch")]
    OwnerMismatch,
}

/// Updates metadata and proving inputs without changing effects or openings.
#[derive(Debug)]
pub struct Updater<'bundle>(&'bundle mut Bundle);

#[expect(
    clippy::multiple_inherent_impl,
    reason = "updater entry point is defined with its role"
)]
impl Bundle {
    /// Apply updates in the order requested by `update`.
    ///
    /// # Errors
    ///
    /// Propagates errors returned by `update`; earlier updates are retained.
    pub fn update_with<F, E>(&mut self, update: F) -> Result<(), E>
    where
        F: FnOnce(Updater<'_>) -> Result<(), E>,
    {
        update(Updater(self))
    }
}

impl Updater<'_> {
    fn witness(&mut self, index: usize) -> Result<&mut ActionWitness, WitnessAccessError> {
        self.0
            .actions
            .get_mut(index)
            .ok_or(WitnessAccessError::InvalidIndex(InvalidIndex(index)))?
            .witness
            .as_mut()
            .ok_or(WitnessAccessError::MissingWitness(index))
    }

    fn spend(&mut self, index: usize) -> Result<&mut SpendWitness, WitnessUpdateError> {
        let ActionWitness::Spend(ref mut spend) =
            *self.witness(index).map_err(WitnessUpdateError::Witness)?
        else {
            return Err(WitnessUpdateError::WrongKind(index));
        };
        Ok(spend)
    }

    /// Set the target for subsequent proofs.
    pub const fn set_anchor(&mut self, anchor: Anchor) {
        self.0.anchor = Some(anchor);
    }

    /// Attach a delegated proving key to a spend.
    ///
    /// # Errors
    ///
    /// Returns an error if the index does not have a spend witness or the key
    /// disagrees with the recorded owner.
    pub fn set_pak(&mut self, index: usize, pak: ProofAuthorizingKey) -> Result<(), SetPakError> {
        let spend = self.spend(index).map_err(SetPakError::Witness)?;
        if !SpendWitness::keys_match(spend.ak, Some(pak)) {
            return Err(SetPakError::OwnerMismatch);
        }
        spend.pak = Some(Box::new(pak));
        Ok(())
    }

    /// Attach predecessor proofs to a spend.
    ///
    /// # Errors
    ///
    /// Returns an error if the index does not have a spend witness.
    pub fn set_lineage(
        &mut self,
        index: usize,
        lineage: SpendLineage,
    ) -> Result<(), WitnessUpdateError> {
        self.spend(index)?.lineage = Some(lineage);
        Ok(())
    }

    /// Attach an action's key locator.
    ///
    /// # Errors
    ///
    /// Returns an error if the index does not have a witness.
    pub fn set_zip32_derivation(
        &mut self,
        index: usize,
        derivation: Zip32Derivation,
    ) -> Result<(), WitnessAccessError> {
        match *self.witness(index)? {
            ActionWitness::Spend(ref mut spend) => spend.zip32_derivation = Some(derivation),
            ActionWitness::Output(ref mut output) => output.zip32_derivation = Some(derivation),
        }
        Ok(())
    }

    /// Attach the fee change recipient's key locator.
    pub fn set_max_fee_zip32_derivation(&mut self, derivation: Zip32Derivation) {
        self.0.max_fee.zip32_derivation = Some(derivation);
    }

    /// Attach an address for display.
    ///
    /// # Errors
    ///
    /// Returns an error if the index does not have an output witness.
    pub fn set_user_address(
        &mut self,
        index: usize,
        address: String,
    ) -> Result<(), WitnessUpdateError> {
        let ActionWitness::Output(ref mut output) =
            *self.witness(index).map_err(WitnessUpdateError::Witness)?
        else {
            return Err(WitnessUpdateError::WrongKind(index));
        };
        output.user_address = Some(address);
        Ok(())
    }

    /// Set a bundle metadata entry.
    pub fn set_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.proprietary.insert(key, value);
    }

    /// Set an action metadata entry.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid action index.
    pub fn set_action_proprietary(
        &mut self,
        index: usize,
        key: String,
        value: Vec<u8>,
    ) -> Result<(), InvalidIndex> {
        self.0
            .actions
            .get_mut(index)
            .ok_or(InvalidIndex(index))?
            .proprietary
            .insert(key, value);
        Ok(())
    }

    /// Set a max fee metadata entry.
    pub fn set_max_fee_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.max_fee.proprietary.insert(key, value);
    }
}
