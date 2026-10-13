//! Tachyon Action descriptions.

use alloc::vec::Vec;
use core::{cmp, cmp::Ord};

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, PartialEq};
use pasta_curves::{EpAffine, group::GroupEncoding as _};

use crate::{
    keys::public,
    primitives::{ActionDigest, ActionDigestError},
    reddsa, serialization, value,
};

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
        ActionDigest::new(self.cv, self.rk)
    }

    /// Read an action descriptor from the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or either component is not a
    /// canonical encoding.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let cv = value::Commitment::from(serialization::read_ep_affine(&mut reader)?);
        let rk = public::ActionVerificationKey(serialization::read_action_vk(&mut reader)?);
        Ok(Self { cv, rk })
    }

    /// Write an action descriptor in the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_ep_affine(&mut writer, &self.cv.into())?;
        serialization::write_action_vk(&mut writer, &self.rk.0)?;
        Ok(())
    }
}

impl PartialOrd for Descriptor {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Descriptor {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
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
        ActionDigest::new(self.cv, self.rk)
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
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Action {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
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

/// A spend authorization signature (RedPallas over reddsa::ActionAuth).
#[derive(Clone, Copy, Debug, Display, PartialEq, TotalEq)]
#[display("Signature({:?})", self.0)]
pub struct Signature(pub(crate) reddsa::Signature<reddsa::ActionAuth>);

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
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
        let sig = serialization::read_action_sig(&mut reader)?;
        Ok(Self(sig))
    }

    /// Write an action signature in the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_action_sig(&mut writer, &self.0)?;
        Ok(())
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
