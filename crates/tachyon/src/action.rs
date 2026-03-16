//! Tachyon Action descriptions.

use core::marker::PhantomData;

use reddsa::orchard::SpendAuth;

pub use crate::primitives::{Effect, Output, Spend};
use crate::{
    entropy::ActionEntropy,
    keys::{SpendValidatingKey, private, public},
    note::Note,
    value,
    witness::ActionPrivate,
};

/// A planned Tachyon action, not yet authorized.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct Plan<E: Effect> {
    /// Randomized action verification key.
    pub rk: public::ActionVerificationKey,
    /// The note being spent or created.
    pub note: Note,
    /// Per-action entropy for alpha derivation.
    pub theta: ActionEntropy,
    /// Value commitment trapdoor.
    pub rcv: value::CommitmentTrapdoor,
    _effect: PhantomData<E>,
}

impl Plan<Spend> {
    /// Derive the value commitment: $\mathsf{cv} = [+v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$.
    #[must_use]
    pub fn cv(&self) -> value::Commitment {
        let value: i64 = self.note.value.into();
        self.rcv.commit(value)
    }

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
            _effect: PhantomData,
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

    /// Assemble the proof witness for this action plan.
    #[must_use]
    pub fn witness(&self) -> ActionPrivate<Spend> {
        let cm = self.note.commitment();
        ActionPrivate {
            alpha: self.theta.spend_randomizer(&cm),
            note: self.note,
            rcv: self.rcv,
        }
    }
}

impl Plan<Output> {
    /// Derive the value commitment: $\mathsf{cv} = [-v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$.
    #[must_use]
    pub fn cv(&self) -> value::Commitment {
        let value: i64 = self.note.value.into();
        self.rcv.commit(-value)
    }

    /// Assemble an output action plan with given entropy and trapdoor.
    #[must_use]
    pub fn output_with(note: Note, theta: ActionEntropy, rcv: value::CommitmentTrapdoor) -> Self {
        let cm = note.commitment();
        let alpha = theta.output_randomizer(&cm);
        let rsk = private::ActionSigningKey::new(&alpha);
        let rk = rsk.derive_action_public();

        Self {
            rk,
            note,
            theta,
            rcv,
            _effect: PhantomData,
        }
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
    pub fn witness(&self) -> ActionPrivate<Output> {
        let cm = self.note.commitment();
        ActionPrivate {
            alpha: self.theta.output_randomizer(&cm),
            note: self.note,
            rcv: self.rcv,
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
