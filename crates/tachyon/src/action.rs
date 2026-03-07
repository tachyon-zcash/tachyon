//! Tachyon Action descriptions.

use pasta_curves::{
    EpAffine,
    group::{GroupEncoding as _, prime::PrimeCurveAffine as _},
};
use reddsa::orchard::SpendAuth;

use crate::{
    entropy::ActionEntropy,
    keys::{SpendValidatingKey, private, public},
    note::Note,
    value,
};

/// Whether an action plan represents a spend or an output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Effect {
    /// Spend — signed with
    /// [`SpendAuthorizingKey::derive_action_private`](private::SpendAuthorizingKey::derive_action_private).
    Spend,
    /// Output — signed via
    /// [`ActionSigningKey<Output>::sign`](private::ActionSigningKey::sign).
    Output,
}

/// A planned Tachyon action, not yet authorized.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Plan {
    /// Randomized action verification key.
    pub rk: public::ActionVerificationKey,
    /// The note being spent or created.
    pub note: Note,
    /// Per-action entropy for alpha derivation.
    pub theta: ActionEntropy,
    /// Value commitment trapdoor.
    pub rcv: value::CommitmentTrapdoor,
    /// Spend or output.
    pub effect: Effect,
}

impl Plan {
    /// Assemble a spend action plan.
    ///
    /// $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$.
    #[must_use]
    pub fn spend(
        note: Note,
        theta: ActionEntropy,
        rcv: value::CommitmentTrapdoor,
        ak: &SpendValidatingKey,
    ) -> Self {
        let cm = note.commitment();
        let alpha = theta.spend_randomizer(&cm);
        let rk = ak.derive_action_public(&alpha);

        Self {
            rk,
            note,
            theta,
            rcv,
            effect: Effect::Spend,
        }
    }

    /// Assemble an output action plan.
    ///
    /// $\mathsf{rk} = [\alpha]\,\mathcal{G}$.
    #[must_use]
    pub fn output(note: Note, theta: ActionEntropy, rcv: value::CommitmentTrapdoor) -> Self {
        let cm = note.commitment();
        let alpha = theta.output_randomizer(&cm);
        let rsk = private::ActionSigningKey::new(alpha);
        let rk = rsk.derive_action_public();

        Self {
            rk,
            note,
            theta,
            rcv,
            effect: Effect::Output,
        }
    }

    /// Derive the value commitment of this action plan.
    ///
    /// $$\mathsf{cv} = [\pm v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$$
    #[must_use]
    pub fn cv(&self) -> value::Commitment {
        match self.effect {
            | Effect::Spend => self.rcv.commit_spend(self.note),
            | Effect::Output => self.rcv.commit_output(self.note),
        }
    }
}

/// An authorized Tachyon action.
///
/// - `cv`: Commitment to a value effect
/// - `rk`: Public key (randomized counterpart to `rsk`)
/// - `sig`: Signature (by single-use `rsk`) over transaction sighash
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Action {
    /// Value commitment $\mathsf{cv} = [v]\,\mathcal{V}
    /// + [\mathsf{rcv}]\,\mathcal{R}$ (EpAffine).
    pub cv: value::Commitment,

    /// Randomized action verification key $\mathsf{rk}$ (EpAffine).
    pub rk: public::ActionVerificationKey,

    /// RedPallas spend auth signature over the transaction sighash.
    pub sig: Signature,
}

/// A spend authorization signature (RedPallas over SpendAuth).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Signature(pub(crate) reddsa::Signature<SpendAuth>);

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(reddsa::Signature::<SpendAuth>::from(bytes))
    }
}

impl From<Signature> for [u8; 64] {
    fn from(sig: Signature) -> [u8; 64] {
        <[u8; 64]>::from(sig.0)
    }
}

/// Errors from action deserialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeserializeError {
    /// `cv` bytes are not a valid curve point.
    InvalidCv,
    /// `cv` is the identity point.
    IdentityCv,
    /// `rk` bytes are not a valid verification key.
    InvalidRk,
    /// `rk` is the identity point.
    IdentityRk,
}

impl From<&Action> for [u8; 128] {
    fn from(action: &Action) -> Self {
        let mut out = [0u8; 128];
        let cv_bytes: [u8; 32] = action.cv.into();
        let rk_bytes: [u8; 32] = action.rk.into();
        let sig_bytes: [u8; 64] = action.sig.into();
        out[..32].copy_from_slice(&cv_bytes);
        out[32..64].copy_from_slice(&rk_bytes);
        out[64..].copy_from_slice(&sig_bytes);
        out
    }
}

impl TryFrom<&[u8; 128]> for Action {
    type Error = DeserializeError;

    /// Deserialize an action from `cv (32) || rk (32) || sig (64)`.
    ///
    /// Rejects identity points for `cv` and `rk`, which would panic
    /// in [`ActionDigest`](crate::ActionDigest) computation.
    fn try_from(bytes: &[u8; 128]) -> Result<Self, Self::Error> {
        let cv_raw: &[u8; 32] = &bytes[..32]
            .try_into()
            .map_err(|_err| DeserializeError::InvalidCv)?;
        let rk_raw: [u8; 32] = bytes[32..64]
            .try_into()
            .map_err(|_err| DeserializeError::InvalidRk)?;
        let sig_raw: [u8; 64] = bytes[64..]
            .try_into()
            .map_err(|_err| DeserializeError::InvalidCv)?;

        let cv_point = EpAffine::from_bytes(cv_raw)
            .into_option()
            .ok_or(DeserializeError::InvalidCv)?;

        if bool::from(cv_point.is_identity()) {
            return Err(DeserializeError::IdentityCv);
        }

        let rk = public::ActionVerificationKey::try_from(rk_raw)
            .map_err(|_reddsa_err| DeserializeError::InvalidRk)?;

        if bool::from(EpAffine::from(rk).is_identity()) {
            return Err(DeserializeError::IdentityRk);
        }

        Ok(Self {
            cv: value::Commitment::from(cv_point),
            rk,
            sig: Signature::from(sig_raw),
        })
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        entropy::ActionEntropy,
        keys::private,
        note::{self, CommitmentTrapdoor, Note, NullifierTrapdoor},
        value,
    };

    /// Build a valid serialized action (128 bytes).
    fn make_valid_action_bytes() -> [u8; 128] {
        let mut rng = StdRng::seed_from_u64(300);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fp::ZERO),
        };
        let rcv = value::CommitmentTrapdoor::random(&mut rng);
        let cv = rcv.commit_spend(note);
        let theta = ActionEntropy::random(&mut rng);
        let alpha = theta.output_randomizer(&note.commitment());
        let rsk = private::ActionSigningKey::new(alpha);
        let rk = rsk.derive_action_public();
        let sig = rsk.sign(&mut rng, &[0u8; 32]);
        let action = Action { cv, rk, sig };
        <[u8; 128]>::from(&action)
    }

    /// Valid bytes round-trip through deserialization.
    #[test]
    fn deserialize_valid_round_trips() {
        let bytes = make_valid_action_bytes();
        Action::try_from(&bytes).unwrap();
    }

    /// All-zero cv (identity point) is rejected.
    #[test]
    fn deserialize_rejects_identity_cv() {
        let mut bytes = make_valid_action_bytes();
        bytes[..32].fill(0);
        assert_eq!(
            Action::try_from(&bytes).unwrap_err(),
            DeserializeError::IdentityCv
        );
    }

    /// Invalid cv bytes are rejected.
    #[test]
    fn deserialize_rejects_invalid_cv() {
        let mut bytes = make_valid_action_bytes();
        bytes[..32].fill(0xFF);
        assert_eq!(
            Action::try_from(&bytes).unwrap_err(),
            DeserializeError::InvalidCv
        );
    }

    /// Invalid rk bytes are rejected.
    #[test]
    fn deserialize_rejects_invalid_rk() {
        let mut bytes = make_valid_action_bytes();
        bytes[32..64].fill(0xFF);
        assert_eq!(
            Action::try_from(&bytes).unwrap_err(),
            DeserializeError::InvalidRk
        );
    }
}
