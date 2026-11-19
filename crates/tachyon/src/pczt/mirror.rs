//! Byte fields for a transaction container to carry and redact independently.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use corez::io;
use derive_more::{Debug, Display, Eq as TotalEq, Error, PartialEq};
use udon::{curve::Affine as _, field::Field as _};

use super::{NoteField, Zip32Derivation};
use crate::{
    action,
    entropy::ActionEntropy,
    keys::{private, public},
    pasta::{EpAffine, Fp, Fq},
    pczt, serialization, value,
};

/// The section's mirror. Absent effects require sufficient opening fields.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("Bundle(..)")]
pub struct Bundle {
    /// Actions in commitment order.
    pub actions: Vec<Action>,
    /// The signed balance in zatoshis.
    pub value_balance: Option<i64>,
    /// Maximum fee data.
    pub max_fee: MaxFee,
    /// The memo.
    pub memo: Vec<u8>,
    /// Canonical binding signing scalar.
    pub bsk: Option<[u8; 32]>,
    /// Bundle metadata.
    pub proprietary: BTreeMap<String, Vec<u8>>,
}

/// The per-action byte fields.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("Action(..)")]
pub struct Action {
    /// The action descriptor in its canonical encoding.
    pub descriptor: Option<[u8; 64]>,
    /// Authorization signature.
    pub sig: Option<[u8; 64]>,
    /// Independently redactable note fields.
    pub note: NoteOpening,
    /// Canonical action entropy.
    pub theta: Option<[u8; 32]>,
    /// Canonical value commitment trapdoor.
    pub rcv: Option<[u8; 32]>,
    /// Action metadata.
    pub proprietary: BTreeMap<String, Vec<u8>>,
}

/// A note opening's byte fields.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
#[debug("NoteOpening(..)")]
pub struct NoteOpening {
    /// The payment key.
    pub pk: Option<[u8; 32]>,
    /// The value in zatoshis.
    pub value: Option<u64>,
    /// The nullifier trapdoor.
    pub psi: Option<[u8; 32]>,
    /// The commitment trapdoor.
    pub rcm: Option<[u8; 32]>,
}

/// Maximum fee byte fields.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("MaxFee(..)")]
pub struct MaxFee {
    /// The canonical value commitment.
    pub cv_feemax: Option<[u8; 32]>,
    /// Independently redactable note fields.
    pub note: NoteOpening,
    /// The change recipient's key locator.
    pub zip32_derivation: Option<Zip32Derivation>,
    /// Fee metadata.
    pub proprietary: BTreeMap<String, Vec<u8>>,
}

/// A field of the byte mirror.
#[derive(Clone, Copy, Debug, Display)]
pub enum Field {
    /// Action list.
    Actions,
    /// Memo.
    Memo,
    /// Bundle balance.
    ValueBalance,
    /// Binding signing key.
    Bsk,
    /// Action descriptor.
    #[display("descriptor at action {_0}")]
    Descriptor(usize),
    /// Action entropy.
    #[display("theta at action {_0}")]
    Theta(usize),
    /// Value commitment trapdoor.
    #[display("rcv at action {_0}")]
    Rcv(usize),
    /// Action signature.
    #[display("signature at action {_0}")]
    Signature(usize),
    /// Maximum fee commitment.
    MaxFee,
    /// A field in an action's note.
    #[display("note {_1} at action {_0}")]
    ActionNote(usize, NoteField),
    /// A field in the maximum fee note.
    #[display("maximum fee note {_0}")]
    MaxFeeNote(NoteField),
}

/// A decoded value violates an invariant.
#[derive(Clone, Copy, Debug, Display)]
pub enum ValueReason {
    /// Identity key or point.
    Identity,
    /// Value is out of range.
    Range,
    /// A section without actions must have zero balance.
    NonzeroActionlessBalance,
}

/// The cause of a mirror decoding failure.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum EncodingCause {
    /// The bytes are not canonical.
    #[display("noncanonical encoding")]
    Noncanonical,
    /// A field reader rejected the input.
    #[display("field reader rejected the input")]
    Read(io::Error),
}

/// A malformed or insufficient byte mirror.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Field decoding failed.
    #[display("invalid encoding for {_0}")]
    InvalidEncoding(#[error(not(source))] Field, #[error(source)] EncodingCause),
    /// A field is required to derive an omitted effect.
    #[display("missing {_0} for compact effect")]
    MissingForEffect(#[error(not(source))] MissingEffectField),
    /// A value violates a field invariant.
    #[display("invalid {_0}: {_1}")]
    InvalidValue(
        #[error(not(source))] Field,
        #[error(not(source))] ValueReason,
    ),
    /// Section exceeds a size bound.
    #[display("limit exceeded for {_0}")]
    Limit(#[error(not(source))] Field),
    /// Descriptors are not strictly ascending.
    #[display("descriptors are not strictly ascending in {_0}")]
    DescriptorOrder(#[error(not(source))] DescriptorOrderLocation),
}

/// A mirror field required to resolve an effect.
#[derive(Clone, Copy, Debug, Display)]
#[expect(
    variant_size_differences,
    reason = "only a missing descriptor needs an action index"
)]
pub enum MissingEffectField {
    /// The section's balance.
    ValueBalance,
    /// The indexed action's descriptor.
    #[display("descriptor at action {_0}")]
    Descriptor(usize),
    /// A field of the maximum fee opening.
    #[display("maximum fee note {_0}")]
    MaxFeeNote(NoteField),
}

/// A list whose descriptors must be strictly ascending.
#[derive(Clone, Copy, Debug, Display)]
pub enum DescriptorOrderLocation {
    /// The section's action list.
    #[display("actions")]
    Actions,
}

impl ParseError {
    const fn noncanonical(field: Field) -> Self {
        Self::InvalidEncoding(field, EncodingCause::Noncanonical)
    }
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "mirror conversion is separate from section construction"
)]
impl pczt::Bundle {
    /// Parse the effect, note, entropy, trapdoor, signature and metadata
    /// fields. Derive an omitted `cv_feemax` from a complete fee note.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or missing effect fields.
    pub fn parse(mirror: Bundle) -> Result<Self, ParseError> {
        if mirror.actions.len() > pczt::max_actions() {
            return Err(ParseError::Limit(Field::Actions));
        }
        if !pczt::memo_fits(mirror.memo.len()) {
            return Err(ParseError::Limit(Field::Memo));
        }
        let actions = mirror
            .actions
            .into_iter()
            .enumerate()
            .map(|(index, action)| action.parse(index))
            .collect::<Result<Vec<_>, _>>()?;
        if actions
            .iter()
            .map(|action| action.descriptor)
            .zip(actions.iter().skip(1).map(|action| action.descriptor))
            .any(|(left, right)| left >= right)
        {
            return Err(ParseError::DescriptorOrder(
                DescriptorOrderLocation::Actions,
            ));
        }
        let max_fee = mirror.max_fee.parse()?;
        let balance = mirror.value_balance.ok_or(ParseError::MissingForEffect(
            MissingEffectField::ValueBalance,
        ))?;
        let value_balance = value::Balance::try_from(balance)
            .map_err(|_err| ParseError::InvalidValue(Field::ValueBalance, ValueReason::Range))?;
        if actions.is_empty() && value_balance != value::Balance::ZERO {
            return Err(ParseError::InvalidValue(
                Field::ValueBalance,
                ValueReason::NonzeroActionlessBalance,
            ));
        }
        Ok(Self {
            actions,
            value_balance,
            max_fee,
            memo: mirror.memo,
            anchor: None,
            actions_proofs: Vec::new(),
            autonome_parts: None,
            bsk: mirror
                .bsk
                .map(|bytes| {
                    Fq::from_bytes(bytes)
                        .map(|scalar| {
                            private::BindingSigningKey::from([value::ValueTrapdoor(scalar)])
                        })
                        .ok_or_else(|| ParseError::noncanonical(Field::Bsk))
                })
                .transpose()?,
            proprietary: mirror.proprietary,
        })
    }

    /// Encode the effect, note, entropy, trapdoor, signature and metadata
    /// fields.
    ///
    /// # Panics
    ///
    /// Panics if an action descriptor cannot be written to its fixed-width
    /// buffer.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "action descriptors fit their fixed-width buffers"
    )]
    pub fn to_mirror(&self) -> Bundle {
        Bundle {
            actions: self
                .actions
                .iter()
                .map(Action::serialize)
                .collect::<Result<_, _>>()
                .expect("action fields are encodable"),
            value_balance: Some(self.value_balance.into()),
            max_fee: MaxFee {
                cv_feemax: Some(self.max_fee.cv_feemax.into()),
                note: NoteOpening::from_opening(self.max_fee.note),
                zip32_derivation: self.max_fee.zip32_derivation.clone(),
                proprietary: self.max_fee.proprietary.clone(),
            },
            memo: self.memo.clone(),
            bsk: self.bsk.map(private::BindingSigningKey::to_bytes),
            proprietary: self.proprietary.clone(),
        }
    }
}

impl Action {
    fn parse(self, index: usize) -> Result<pczt::Action, ParseError> {
        let descriptor_bytes = self.descriptor.ok_or(ParseError::MissingForEffect(
            MissingEffectField::Descriptor(index),
        ))?;
        let descriptor = parse_descriptor(descriptor_bytes, Field::Descriptor(index))?;
        let note = self.note.parse(|field| Field::ActionNote(index, field))?;
        let theta = self
            .theta
            .map(|bytes| {
                ActionEntropy::from_bytes(bytes)
                    .ok_or_else(|| ParseError::noncanonical(Field::Theta(index)))
            })
            .transpose()?;
        let rcv = self
            .rcv
            .map(|bytes| {
                Fq::from_bytes(bytes)
                    .map(value::ValueTrapdoor)
                    .ok_or_else(|| ParseError::noncanonical(Field::Rcv(index)))
            })
            .transpose()?;
        let sig = self
            .sig
            .map(|bytes| {
                action::Signature::read(bytes.as_slice()).map_err(|cause| {
                    ParseError::InvalidEncoding(Field::Signature(index), EncodingCause::Read(cause))
                })
            })
            .transpose()?;
        Ok(pczt::Action {
            descriptor,
            sig,
            note,
            theta,
            rcv,
            witness: None,
            proprietary: self.proprietary,
        })
    }

    fn serialize(action: &pczt::Action) -> io::Result<Self> {
        Ok(Self {
            descriptor: Some(encode_descriptor(action.descriptor)?),
            sig: action.sig.map(|sig| sig.0.into()),
            note: NoteOpening::from_opening(action.note),
            theta: action.theta.map(|entropy| entropy.0.to_bytes()),
            rcv: action.rcv.map(|rcv| Fq::from(rcv).to_bytes()),
            proprietary: action.proprietary.clone(),
        })
    }
}

impl MaxFee {
    fn parse(self) -> Result<pczt::MaxFee, ParseError> {
        let note = self.note.parse(Field::MaxFeeNote)?;
        let cv_feemax = match self.cv_feemax {
            Some(bytes) => EpAffine::from_bytes(bytes)
                .map(value::Commitment::from)
                .ok_or_else(|| ParseError::noncanonical(Field::MaxFee))?,
            None => note
                .complete()
                .map_err(|field| {
                    ParseError::MissingForEffect(MissingEffectField::MaxFeeNote(field))
                })?
                .cv_feemax(),
        };
        if EpAffine::from(cv_feemax).is_identity() {
            return Err(ParseError::InvalidValue(
                Field::MaxFee,
                ValueReason::Identity,
            ));
        }
        Ok(pczt::MaxFee {
            cv_feemax,
            note,
            zip32_derivation: self.zip32_derivation,
            proprietary: self.proprietary,
        })
    }
}

impl NoteOpening {
    fn from_opening(note: pczt::NoteOpening) -> Self {
        Self {
            pk: note.pk.map(|pk| Fp::from(pk).to_bytes()),
            value: note.value.map(u64::from),
            psi: note.psi.map(|psi| Fp::from(psi).to_bytes()),
            rcm: note.rcm.map(|rcm| Fp::from(rcm).to_bytes()),
        }
    }

    fn parse(self, field: impl Fn(NoteField) -> Field) -> Result<pczt::NoteOpening, ParseError> {
        Ok(pczt::NoteOpening {
            pk: self
                .pk
                .map(|bytes| {
                    Fp::from_bytes(bytes)
                        .map(Into::into)
                        .ok_or_else(|| ParseError::noncanonical(field(NoteField::Pk)))
                })
                .transpose()?,
            value: self
                .value
                .map(|amount| {
                    value::Positive::try_from(amount).map_err(|_err| {
                        ParseError::InvalidValue(field(NoteField::Value), ValueReason::Range)
                    })
                })
                .transpose()?,
            psi: self
                .psi
                .map(|bytes| {
                    Fp::from_bytes(bytes)
                        .map(Into::into)
                        .ok_or_else(|| ParseError::noncanonical(field(NoteField::Psi)))
                })
                .transpose()?,
            rcm: self
                .rcm
                .map(|bytes| {
                    Fp::from_bytes(bytes)
                        .map(Into::into)
                        .ok_or_else(|| ParseError::noncanonical(field(NoteField::Rcm)))
                })
                .transpose()?,
        })
    }
}

fn parse_descriptor(bytes: [u8; 64], field: Field) -> Result<action::Descriptor, ParseError> {
    let mut reader = bytes.as_slice();
    let read_error = |cause| ParseError::InvalidEncoding(field, EncodingCause::Read(cause));
    let cv = serialization::read_ep_affine(&mut reader).map_err(read_error)?;
    let rk =
        public::ActionVerificationKey(serialization::read_action_vk(reader).map_err(read_error)?);
    checked_descriptor(action::Descriptor { cv: cv.into(), rk }, field)
}

fn checked_descriptor(
    descriptor: action::Descriptor,
    field: Field,
) -> Result<action::Descriptor, ParseError> {
    if EpAffine::from(descriptor.cv).is_identity() || EpAffine::from(descriptor.rk).is_identity() {
        return Err(ParseError::InvalidValue(field, ValueReason::Identity));
    }
    Ok(descriptor)
}

fn encode_descriptor(descriptor: action::Descriptor) -> io::Result<[u8; 64]> {
    let mut bytes = [0; 64];
    descriptor.write(bytes.as_mut_slice())?;
    Ok(bytes)
}
