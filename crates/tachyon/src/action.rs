//! Tachyon Action descriptions.

use reddsa::orchard::SpendAuth;

use crate::{
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{SpendValidatingKey, private, public},
    note::Note,
    value,
    witness::ActionPrivate,
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
    /// Assemble a spend action plan with given entropy and trapdoor.
    #[must_use]
    pub fn spend_with(
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

    /// Assemble an output action plan with given entropy and trapdoor.
    #[must_use]
    pub fn output_with(note: Note, theta: ActionEntropy, rcv: value::CommitmentTrapdoor) -> Self {
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

    /// Assemble a spend action plan with random entropy and trapdoor.
    pub fn spend(
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
        note: Note,
        ak: &SpendValidatingKey,
    ) -> Self {
        Self::spend_with(
            note,
            ActionEntropy::random(&mut *rng),
            value::CommitmentTrapdoor::random(rng),
            ak,
        )
    }

    /// Assemble an output action plan with random entropy and trapdoor.
    pub fn output(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng), note: Note) -> Self {
        Self::output_with(
            note,
            ActionEntropy::random(&mut *rng),
            value::CommitmentTrapdoor::random(rng),
        )
    }

    /// Assemble the proof witness for this action plan.
    #[must_use]
    pub fn witness(&self) -> ActionPrivate {
        let cm = self.note.commitment();
        let alpha = match self.effect {
            | Effect::Spend => ActionRandomizer::from(self.theta.spend_randomizer(&cm)),
            | Effect::Output => ActionRandomizer::from(self.theta.output_randomizer(&cm)),
        };
        ActionPrivate {
            alpha,
            note: self.note,
            rcv: self.rcv,
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
