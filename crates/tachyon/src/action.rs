//! Tachyon Action descriptions.

use core::{any::TypeId, marker::PhantomData};

use crate::{
    entropy::ActionEntropy,
    keys::{SpendValidatingKey, private, public},
    note::Note,
    primitives::{Effect, effect},
    reddsa, value,
    witness::ActionPrivate,
};

/// A planned Tachyon action, not yet authorized.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Plan<E: Effect> {
    /// Randomized action verification key.
    pub rk: public::ActionVerificationKey,
    /// The note being spent or created.
    pub note: Note,
    /// Per-action entropy for alpha derivation.
    pub theta: ActionEntropy,
    /// Value commitment trapdoor.
    pub rcv: value::CommitmentTrapdoor,
    /// Effect marker (zero-sized).
    pub _effect: PhantomData<E>,
}

impl Plan<effect::Spend> {
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
        let alpha = theta.randomizer::<effect::Spend>(&cm);
        let rk = ak.derive_action_public(&alpha);

        Self {
            rk,
            note,
            theta,
            rcv,
            _effect: PhantomData,
        }
    }

    /// Assemble the proof witness for this spend plan.
    #[must_use]
    pub fn witness(&self) -> ActionPrivate {
        let cm = self.note.commitment();
        ActionPrivate {
            alpha: self.theta.randomizer::<effect::Spend>(&cm).into(),
            note: self.note,
            rcv: self.rcv,
        }
    }
}

impl Plan<effect::Output> {
    /// Assemble an output action plan.
    ///
    /// $\mathsf{rk} = [\alpha]\,\mathcal{G}$.
    #[must_use]
    pub fn output(note: Note, theta: ActionEntropy, rcv: value::CommitmentTrapdoor) -> Self {
        let cm = note.commitment();
        let alpha = theta.randomizer::<effect::Output>(&cm);
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

    /// Assemble the proof witness for this output plan.
    #[must_use]
    pub fn witness(&self) -> ActionPrivate {
        let cm = self.note.commitment();
        ActionPrivate {
            alpha: self.theta.randomizer::<effect::Output>(&cm).into(),
            note: self.note,
            rcv: self.rcv,
        }
    }
}

impl<E: Effect> Plan<E> {
    /// Derive the value commitment of this action plan.
    ///
    /// $$\mathsf{cv} = [\pm v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$$
    #[must_use]
    #[expect(clippy::unreachable, reason = "Effect is sealed to Spend and Output")]
    pub fn cv(&self) -> value::Commitment {
        let value: i64 = self.note.value.into();
        if TypeId::of::<E>() == TypeId::of::<effect::Spend>() {
            return self.rcv.commit(value);
        }
        if TypeId::of::<E>() == TypeId::of::<effect::Output>() {
            return self.rcv.commit(-value);
        }
        unreachable!("Effect is sealed to Spend and Output")
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

/// A spend authorization signature (RedPallas over reddsa::ActionAuth).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Signature(pub(crate) reddsa::Signature<reddsa::ActionAuth>);

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(reddsa::Signature::<reddsa::ActionAuth>::from(bytes))
    }
}

impl From<Signature> for [u8; 64] {
    fn from(sig: Signature) -> [u8; 64] {
        <[u8; 64]>::from(sig.0)
    }
}
