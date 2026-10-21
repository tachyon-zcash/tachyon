//! Max fee notes and fee descriptors.

use core::cmp;

use derive_more::{Debug, Eq as TotalEq, PartialEq};
use ff::{Field as _, PrimeField as _};
use group::GroupEncoding as _;
use pasta_curves::{EpAffine, Fp, Fq, arithmetic::CurveAffine as _};

use crate::{
    Note,
    digest::poseidon,
    primitives::{ActionDigest, ActionDigestError, Tachygram},
    value,
};

/// A planned max fee note, not yet authorized.
#[derive(Clone, Copy, Debug)]
pub struct Plan {
    /// The max fee note, whose value is the maximum fee.
    pub note: Note,
}

impl Plan {
    /// Assemble a max fee note plan.
    #[must_use]
    pub const fn new(note: Note) -> Self {
        Self { note }
    }

    /// Derive the max fee note's blind $r$.
    #[expect(
        clippy::expect_used,
        reason = "p < q, so every Fp repr is canonical in Fq"
    )]
    pub(crate) fn blind(&self) -> value::Trapdoor {
        value::Trapdoor::from_scalar(
            Option::from(Fq::from_repr(
                poseidon::fee_blind(
                    Fp::from(self.note.pk),
                    Fp::from(self.note.psi),
                    Fp::from(self.note.rcm),
                )
                .to_repr(),
            ))
            .expect("p < q"),
        )
    }

    /// Derive the max fee note's value commitment.
    ///
    /// # Panics
    ///
    /// Panics if the blind is zero.
    #[must_use]
    pub fn max_commitment(&self) -> value::Commitment {
        let trapdoor = self.blind();
        assert_ne!(
            Fq::from(trapdoor),
            Fq::ZERO,
            "max fee note blind should not be zero"
        );
        trapdoor.commit(-self.note.value)
    }

    /// Obtain the fee descriptor for this max fee note at `fee`.
    #[must_use]
    pub fn descriptor(&self, fee: value::Positive) -> Descriptor {
        Descriptor {
            max_commitment: self.max_commitment(),
            value: fee,
        }
    }

    /// Derive the commitment `cmChange` of the fee change note that `fee`
    /// leaves of the max fee note.
    pub(crate) fn change_commitment(&self, fee: value::Positive) -> Tachygram {
        #[expect(
            clippy::expect_used,
            reason = "the saturated change never exceeds the max fee note's value"
        )]
        let fee_change_note = Note {
            value: value::Positive::try_from(
                u64::from(self.note.value).saturating_sub(u64::from(fee)),
            )
            .expect("change within the max fee note's value"),
            ..self.note
        };
        Tachygram::from(fee_change_note.commitment())
    }
}

/// A bundle's fee descriptor: the max fee note's value commitment and the fee.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct Descriptor {
    /// The max fee note's value commitment.
    pub max_commitment: value::Commitment,

    /// The fee.
    pub value: value::Positive,
}

impl Descriptor {
    /// The fee digest [`poseidon::fee_digest`], a member of the action set.
    ///
    /// # Errors
    ///
    /// Returns [`ActionDigestError`] if the commitment is the identity.
    pub fn digest(&self) -> Result<ActionDigest, ActionDigestError> {
        let cv_max_fee = EpAffine::from(self.max_commitment)
            .coordinates()
            .into_option()
            .ok_or(ActionDigestError::IdentityCv)?;
        Ok(ActionDigest::from(poseidon::fee_digest(
            cv_max_fee,
            u64::from(self.value),
        )))
    }
}

impl PartialOrd for Descriptor {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Descriptor {
    /// Orders fee descriptors by their coverage entries.
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        <[u8; 40]>::from(*self).cmp(&<[u8; 40]>::from(*other))
    }
}

impl From<Descriptor> for [u8; 40] {
    /// The fee descriptor's coverage entry, `cv_maxfee || LE64(fee)`.
    fn from(descriptor: Descriptor) -> Self {
        let mut entry = [0u8; 40];
        entry[..32].copy_from_slice(&EpAffine::from(descriptor.max_commitment).to_bytes());
        entry[32..].copy_from_slice(&u64::from(descriptor.value).to_le_bytes());
        entry
    }
}
