//! Tachyon Action descriptions.

use alloc::vec::Vec;
use core::{cmp, cmp::Ord, marker::PhantomData};

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, PartialEq};
use rand_core::CryptoRng;
use udon::{curve::Affine as _, field::Field as _};

use crate::{
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{private, public},
    note::Note,
    pasta::{EpAffine, Fp, Fq},
    primitives::{ActionDigest, Effect, Tachygram, effect},
    reddsa, serialization, value,
};

/// The effecting fields of an action, without its signature or tachygram pair.
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
    /// # Panics
    ///
    /// Panics if `cv` or `rk` is the identity point. Descriptor reading rejects
    /// both identities; hand-built descriptors must uphold this requirement.
    #[must_use]
    pub fn digest(&self, tachygrams: (Tachygram, Tachygram)) -> ActionDigest {
        ActionDigest::new(self.cv, self.rk, tachygrams)
    }

    /// Read an action descriptor from the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or either component is not a
    /// canonical encoding of a non-identity point.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let cv = value::Commitment::from(serialization::read_ep_affine(&mut reader)?);
        if EpAffine::from(cv).is_identity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "action commitment is the identity",
            ));
        }
        let rk = public::ActionVerificationKey(serialization::read_action_vk(&mut reader)?);
        if EpAffine::from(rk).is_identity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "action verification key is the identity",
            ));
        }
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
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.descriptor().partial_cmp(&other.descriptor())
    }
}

impl Plan<effect::Spend> {
    /// Plan a spend of `note` with fresh $\theta$ and $\mathsf{rcv}$, selecting
    /// each again while it, or $\alpha$ for $\theta$, exceeds the
    /// `Fp::CAPACITY` bits the stamp steps read
    /// it from.
    ///
    /// $\mathsf{rk} = \mathsf{ak} + [\alpha]\mathcal{G}$
    #[must_use]
    pub fn spend(
        rng: &mut impl CryptoRng,
        note: Note,
        derive_rk: impl FnOnce(ActionRandomizer<effect::Spend>) -> public::ActionVerificationKey,
    ) -> Self {
        Self::sample(rng, note, derive_rk)
    }
}

impl Plan<effect::Output> {
    /// Plan an output of `note` with fresh $\theta$ and $\mathsf{rcv}$,
    /// selecting each again while it, or $\alpha$ for $\theta$, exceeds the
    /// `Fp::CAPACITY` bits the stamp steps read
    /// it from.
    ///
    /// $\mathsf{rk} = [\alpha]\mathcal{G}$.
    #[must_use]
    pub fn output(rng: &mut impl CryptoRng, note: Note) -> Self {
        Self::sample(rng, note, |alpha| {
            private::ActionSigningKey::new(&alpha).derive_action_public()
        })
    }
}

#[expect(clippy::as_conversions, reason = "constant value")]
fn fits_base_field_capacity(scalar: Fq) -> bool {
    !scalar
        .to_le_bits()
        .as_ref()
        .iter()
        .skip(Fp::CAPACITY as usize)
        .any(|&bit| bit)
}

impl<E: Effect> Plan<E> {
    fn sample(
        rng: &mut impl CryptoRng,
        note: Note,
        derive_rk: impl FnOnce(ActionRandomizer<E>) -> public::ActionVerificationKey,
    ) -> Self {
        let cm = note.commitment();
        let (theta, alpha) = loop {
            let theta = ActionEntropy::random(rng);
            let alpha = theta.randomizer::<E>(cm);
            if fits_base_field_capacity(Fq::from(alpha)) {
                break (theta, alpha);
            }
        };
        let rcv = loop {
            let rcv = value::Trapdoor::random(rng);
            if fits_base_field_capacity(Fq::from(rcv)) {
                break rcv;
            }
        };
        Self {
            rk: derive_rk(alpha),
            note,
            theta,
            rcv,
            _effect: PhantomData,
        }
    }

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
    /// # Panics
    ///
    /// Panics if this plan's value commitment or `rk` is the identity point.
    /// Callers constructing plans must ensure both points are non-identity.
    #[must_use]
    pub fn digest(&self, tachygrams: (Tachygram, Tachygram)) -> ActionDigest {
        ActionDigest::new(self.cv(), self.rk, tachygrams)
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
