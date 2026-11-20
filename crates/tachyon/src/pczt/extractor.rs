use alloc::vec::Vec;

use derive_more::{Debug, Display, Eq as TotalEq, Error, PartialEq};
use rand_core::CryptoRng;

use super::{Bundle, Effects};
use crate::{Tachygram, action, fee, keys::private, stamp};

/// An absent field required for extraction.
#[derive(Clone, Copy, Debug, Display, PartialEq, TotalEq)]
pub enum ExtractionField {
    /// The binding signing key.
    #[display("binding key")]
    BindingKey,
    /// The fee-applied proof.
    #[display("fee-applied proof")]
    AutonomeParts,
    /// An indexed action's signature.
    #[display("signature at action {_0}")]
    Signature(usize),
}

/// How the stored stamp coverage differs from this section.
#[derive(Clone, Copy, Debug, Display, PartialEq, TotalEq)]
pub enum ExtractionCoverage {
    /// The pair keys differ from the section's descriptors.
    PairKeys,
    /// The stamp names adjunct transactions.
    Adjuncts,
}

/// The section cannot be extracted.
#[derive(Clone, Copy, Debug, Display, Error, PartialEq, TotalEq)]
#[non_exhaustive]
pub enum TxExtractorError {
    /// Required authorization is absent.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] ExtractionField),
    /// The binding key does not match the effects.
    #[display("binding key mismatch")]
    BindingKeyMismatch,
    /// The stamp does not cover exactly this section's actions.
    #[display("invalid stamp coverage: {_0}")]
    Coverage(#[error(not(source))] ExtractionCoverage),
}

/// Complete authorizing data awaiting the transaction sighash.
#[derive(Debug)]
pub struct Unbound {
    effects: Effects,
    action_auth: Vec<(action::Signature, (Tachygram, Tachygram))>,
    parts: stamp::AutonomeParts,
    bsk: private::BindingSigningKey,
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "extractor entry point is defined with its role"
)]
impl Bundle {
    /// Drop construction data and retain the effects and authorization.
    ///
    /// # Errors
    ///
    /// Returns an error for missing authorization, mismatched pair coverage,
    /// an aggregate stamp or a mismatched binding key.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the coverage check guarantees a pair for every descriptor"
    )]
    pub fn extract(self) -> Result<Unbound, TxExtractorError> {
        let bsk = self
            .bsk
            .ok_or(TxExtractorError::Missing(ExtractionField::BindingKey))?;
        if !self.binding_key_matches(&bsk) {
            return Err(TxExtractorError::BindingKeyMismatch);
        }
        let parts = self
            .autonome_parts
            .ok_or(TxExtractorError::Missing(ExtractionField::AutonomeParts))?;
        if !parts.stamp.adjuncts.is_empty() {
            return Err(TxExtractorError::Coverage(ExtractionCoverage::Adjuncts));
        }
        if !parts
            .pairs
            .keys()
            .copied()
            .eq(self.actions.iter().map(|action| action.descriptor))
        {
            return Err(TxExtractorError::Coverage(ExtractionCoverage::PairKeys));
        }
        let mut actions = Vec::with_capacity(self.actions.len());
        let mut action_auth = Vec::with_capacity(self.actions.len());
        for (index, action) in self.actions.into_iter().enumerate() {
            let signature = action
                .sig
                .ok_or(TxExtractorError::Missing(ExtractionField::Signature(index)))?;
            #[expect(
                clippy::expect_used,
                reason = "the coverage check establishes every descriptor key"
            )]
            let pair = parts
                .pairs
                .get(&action.descriptor)
                .expect("pair keys match the section's descriptors");
            actions.push(action.descriptor);
            action_auth.push((signature, *pair));
        }
        Ok(Unbound {
            effects: Effects {
                actions,
                value_balance: self.value_balance,
                cv_feemax: self.max_fee.cv_feemax,
                memo: self.memo,
            },
            action_auth,
            parts,
            bsk,
        })
    }
}

impl Unbound {
    /// Bind the bundle to the transaction. The caller verifies the result.
    pub fn apply_binding_signature<RNG: CryptoRng>(
        self,
        sighash: [u8; 32],
        rng: &mut RNG,
    ) -> crate::Bundle<stamp::ProofStamp<stamp::Uncompressed>> {
        crate::Bundle {
            value_balance: self.effects.value_balance,
            actions: self.effects.actions,
            action_auth: self.action_auth,
            fee: fee::Descriptor {
                cv_feemax: self.effects.cv_feemax,
                v_fee: self.parts.fee,
            },
            fee_auth: self.parts.cm_change,
            memo: self.effects.memo,
            stamp: self.parts.stamp,
            binding_sig: self.bsk.sign(rng, &sighash),
        }
    }
}
