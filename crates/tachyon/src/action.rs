//! Tachyon Action descriptions.

use alloc::vec::Vec;
use core::cmp::{Ord, Ordering};
use core::marker::PhantomData;

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, PartialEq};
use pasta_curves::EpAffine;
use pasta_curves::group::GroupEncoding as _;

use crate::entropy::{ActionEntropy, ActionRandomizer};
use crate::keys::{private, public};
use crate::note::Note;
use crate::primitives::{ActionDigest, ActionDigestError, Effect, effect};
use crate::reddsa::{self, ActionAuth, VerificationKey};
use crate::{serialization, value};

/// The simple fields of an action, without the signature.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct Descriptor {
    /// Value commitment (EpAffine).
    ///
    /// $$
    ///   \mathsf{cv} =
    ///     \lbrack v \rbrack\mathcal{V}
    ///     + \lbrack \mathsf{rcv} \rbrack\mathcal{R}
    /// $$
    pub cv: value::Commitment,

    /// Randomized action verification key $\mathsf{rk}$ (EpAffine).
    pub rk: public::ActionVerificationKey,
}

impl Descriptor {
    /// Derive the action digest.
    ///
    /// # Errors
    ///
    /// Returns [`ActionDigestError`] if `cv` or `rk` is the identity point.
    pub fn digest(&self) -> Result<ActionDigest, ActionDigestError> {
        ActionDigest::try_new(self.cv, self.rk)
    }

    /// Read an action descriptor from the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or either component is not a
    /// canonical encoding.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let cv = value::Commitment::from(serialization::read_ep_affine(&mut reader)?);
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        let rk = public::ActionVerificationKey(
            VerificationKey::<ActionAuth>::try_from(bytes).map_err(|_err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid action verification key",
                )
            })?,
        );
        Ok(Self { cv, rk })
    }

    /// Write an action descriptor in the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_ep_affine(&mut writer, &self.cv.into())?;
        let bytes: [u8; 32] = self.rk.0.into();
        writer.write_all(&bytes)
    }
}

impl PartialOrd for Descriptor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Descriptor {
    fn cmp(&self, other: &Self) -> Ordering {
        {
            EpAffine::from(self.cv)
                .to_bytes()
                .cmp(&EpAffine::from(other.cv).to_bytes())
        }
        .then({
            EpAffine::from(self.rk)
                .to_bytes()
                .cmp(&EpAffine::from(other.rk).to_bytes())
        })
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

impl<E: Effect> PartialEq for Plan<E> {
    fn eq(&self, other: &Self) -> bool {
        self.descriptor() == other.descriptor()
    }
}

impl<E: Effect> PartialOrd for Plan<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.descriptor().partial_cmp(&other.descriptor())
    }
}

impl Plan<effect::Spend> {
    /// Assemble a spend action plan.
    ///
    /// $\mathsf{rk} = \mathsf{ak} + [\alpha]\mathcal{G}$
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
    /// $\mathsf{rk} = [\alpha]\mathcal{G}$.
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
    /// $$
    ///   \mathsf{cv} = [\pm v]\mathcal{V} + [\mathsf{rcv}]\mathcal{R}
    /// $$
    #[must_use]
    pub fn cv(&self) -> value::Commitment {
        E::commit_value(self.rcv, self.note.value)
    }

    /// Derive the action digest.
    ///
    /// # Errors
    ///
    /// Returns [`ActionDigestError`] if `cv` or `rk` is the identity point.
    pub fn digest(&self) -> Result<ActionDigest, ActionDigestError> {
        ActionDigest::try_new(self.cv(), self.rk)
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
    /// $$
    ///   \mathsf{cv} = \[v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R}
    /// $$
    pub cv: value::Commitment,

    /// Randomized action verification key $\mathsf{rk}$.
    pub rk: public::ActionVerificationKey,

    /// RedPallas spend auth signature over the transaction sighash.
    pub sig: Signature,
}

impl From<(Descriptor, Signature)> for Action {
    fn from((desc, sig): (Descriptor, Signature)) -> Self {
        Self {
            cv: desc.cv,
            rk: desc.rk,
            sig,
        }
    }
}

impl Action {
    /// Derive the action digest.
    ///
    /// # Errors
    ///
    /// Returns [`ActionDigestError`] if `cv` or `rk` is the identity point.
    pub fn digest(&self) -> Result<ActionDigest, ActionDigestError> {
        ActionDigest::try_new(self.cv, self.rk)
    }

    /// Obtain a descriptor for this action.
    #[must_use]
    pub const fn descriptor(&self) -> Descriptor {
        Descriptor {
            cv: self.cv,
            rk: self.rk,
        }
    }
}

impl PartialOrd for Action {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Action {
    fn cmp(&self, other: &Self) -> Ordering {
        self.descriptor()
            .cmp(&other.descriptor())
            .then(self.sig.cmp(&other.sig))
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

/// A spend authorization signature (RedPallas over ActionAuth).
#[derive(Clone, Copy, Debug, Display, PartialEq, TotalEq)]
#[display("Signature({:?})", self.0)]
pub struct Signature(pub(crate) reddsa::Signature<ActionAuth>);

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> Ordering {
        let bytes: [u8; 64] = self.0.into();
        let other_bytes: [u8; 64] = other.0.into();
        bytes.cmp(&other_bytes)
    }
}

impl Signature {
    /// Read an action signature from the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 64];
        reader.read_exact(&mut bytes)?;
        Ok(Self(reddsa::Signature::<ActionAuth>::from(bytes)))
    }

    /// Write an action signature in the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        let bytes: [u8; 64] = self.0.into();
        writer.write_all(&bytes)
    }
}

impl FromIterator<Descriptor> for Vec<[u8; 64]> {
    fn from_iter<I: IntoIterator<Item = Descriptor>>(iter: I) -> Self {
        iter.into_iter()
            .map(|desc| {
                let mut desc_bytes = [0u8; 64];
                desc_bytes[0..32].copy_from_slice(&EpAffine::from(desc.cv).to_bytes());
                desc_bytes[32..64].copy_from_slice(&EpAffine::from(desc.rk).to_bytes());
                desc_bytes
            })
            .collect()
    }
}

impl FromIterator<Signature> for Vec<[u8; 64]> {
    fn from_iter<I: IntoIterator<Item = Signature>>(iter: I) -> Self {
        iter.into_iter()
            .map(|sig| <[u8; 64]>::from(sig.0))
            .collect()
    }
}
