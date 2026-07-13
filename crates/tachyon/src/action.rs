//! Tachyon Action descriptions.

use core::{cmp, marker::PhantomData};

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, PartialEq};
use pasta_curves::{EpAffine, group::GroupEncoding as _};

use crate::{
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{private, public},
    note::Note,
    primitives::{ActionDigest, ActionDigestError, Effect, effect},
    reddsa, serialization, value,
};

/// The simple fields of an action, without the signature.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct Descriptor {
    /// Value commitment $\mathsf{cv} = [v]\,\mathcal{V}
    /// + [\mathsf{rcv}]\,\mathcal{R}$ (EpAffine).
    pub cv: value::Commitment,

    /// Randomized action verification key $\mathsf{rk}$ (EpAffine).
    pub rk: public::ActionVerificationKey,
}

impl Descriptor {
    /// Derive the action digest.
    pub fn digest(&self) -> Result<ActionDigest, ActionDigestError> {
        ActionDigest::new(self.cv, self.rk)
    }

    /// Read an action descriptor from the consensus wire format.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let cv = value::Commitment::from(serialization::read_ep_affine(&mut reader)?);
        let rk = public::ActionVerificationKey(serialization::read_action_vk(&mut reader)?);
        Ok(Self { cv, rk })
    }

    /// Write an action descriptor in the consensus wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_ep_affine(&mut writer, &EpAffine::from(self.cv))?;
        serialization::write_action_vk(&mut writer, &self.rk.0)?;
        Ok(())
    }
}

impl From<Descriptor> for [u8; 64] {
    fn from(desc: Descriptor) -> Self {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&EpAffine::from(desc.cv).to_bytes());
        bytes[32..].copy_from_slice(&<[u8; 32]>::from(desc.rk));
        bytes
    }
}

impl PartialOrd for Descriptor {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Descriptor {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        EpAffine::from(self.cv)
            .to_bytes()
            .cmp(&EpAffine::from(other.cv).to_bytes())
            .then(<[u8; 32]>::from(self.rk).cmp(&<[u8; 32]>::from(other.rk)))
    }
}

/// A planned Tachyon action, not yet authorized.
#[derive(Clone, Copy, Debug)]
pub struct Plan<E: Effect> {
    /// Randomized action verification key.
    pub rk: public::ActionVerificationKey,
    /// The note being spent or created.
    pub note: Note,
    /// Per-action entropy for alpha derivation.
    pub theta: ActionEntropy,
    /// Value commitment trapdoor.
    pub rcv: value::Trapdoor,
    /// Effect marker (zero-sized).
    pub _effect: PhantomData<E>,
}

impl Plan<effect::Spend> {
    /// Assemble a spend action plan.
    ///
    /// $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$
    #[must_use]
    pub fn spend(
        note: Note,
        theta: ActionEntropy,
        rcv: value::Trapdoor,
        derive_rk: impl FnOnce(ActionRandomizer<effect::Spend>) -> public::ActionVerificationKey,
    ) -> Self {
        let cm = note.commitment();
        let alpha = theta.randomizer::<effect::Spend>(cm);

        Self {
            rk: derive_rk(alpha),
            note,
            theta,
            rcv,
            _effect: PhantomData,
        }
    }
}

impl Plan<effect::Output> {
    /// Assemble an output action plan.
    ///
    /// $\mathsf{rk} = [\alpha]\,\mathcal{G}$.
    #[must_use]
    pub fn output(note: Note, theta: ActionEntropy, rcv: value::Trapdoor) -> Self {
        let cm = note.commitment();
        let alpha = theta.randomizer::<effect::Output>(cm);
        let rsk = private::ActionSigningKey::new(&alpha);

        Self {
            rk: rsk.derive_action_public(),
            note,
            theta,
            rcv,
            _effect: PhantomData,
        }
    }
}

impl<E: Effect> Plan<E> {
    /// Derive the value commitment of this action plan.
    ///
    /// $$\mathsf{cv} = [\pm v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$$
    #[must_use]
    pub fn cv(&self) -> value::Commitment {
        E::commit_value(self.rcv, self.note.value)
    }

    /// Derive the action digest.
    pub fn digest(&self) -> Result<ActionDigest, ActionDigestError> {
        ActionDigest::new(self.cv(), self.rk)
    }

    /// Obtain a descriptor for this planned action.
    #[must_use]
    pub fn descriptor(&self) -> Descriptor {
        Descriptor {
            cv: self.cv(),
            rk: self.rk,
        }
    }
}

/// An authorized Tachyon action.
///
/// - `cv`: Commitment to a value effect
/// - `rk`: Public key (randomized counterpart to `rsk`)
/// - `sig`: Signature (by single-use `rsk`) over transaction sighash
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct Action {
    /// Value commitment.
    ///
    /// $$ \mathsf{cv} = \[v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R} $$
    pub cv: value::Commitment,

    /// Randomized action verification key $\mathsf{rk}$.
    pub rk: public::ActionVerificationKey,

    /// RedPallas spend auth signature over the transaction sighash.
    pub sig: Signature,
}

impl Action {
    /// Construct an action from a descriptor and signature.
    #[must_use]
    pub const fn from_parts(desc: Descriptor, sig: Signature) -> Self {
        Self {
            cv: desc.cv,
            rk: desc.rk,
            sig,
        }
    }

    /// Derive the action digest.
    pub fn digest(&self) -> Result<ActionDigest, ActionDigestError> {
        ActionDigest::new(self.cv, self.rk)
    }

    /// Obtain a descriptor for this action.
    #[must_use]
    pub fn descriptor(&self) -> Descriptor {
        Descriptor::from(*self)
    }
}

impl PartialOrd for Action {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Action {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.descriptor()
            .cmp(&other.descriptor())
            .then_with(|| <[u8; 64]>::from(self.sig).cmp(&<[u8; 64]>::from(other.sig)))
    }
}

impl From<Action> for Descriptor {
    fn from(action: Action) -> Self {
        Self {
            cv: action.cv,
            rk: action.rk,
        }
    }
}

/// A spend authorization signature (RedPallas over reddsa::ActionAuth).
#[derive(Clone, Copy, Debug, Display, PartialEq, TotalEq)]
#[display("Signature({:?})", self.0)]
pub struct Signature(pub(crate) reddsa::Signature<reddsa::ActionAuth>);

impl Signature {
    /// Read an action signature from the consensus wire format.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let sig = serialization::read_action_sig(&mut reader)?;
        Ok(Self(sig))
    }

    /// Write an action signature in the consensus wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_action_sig(&mut writer, &self.0)?;
        Ok(())
    }
}

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
