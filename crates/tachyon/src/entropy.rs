//! Per-action randomizers and entropy.
//!
//! [`ActionEntropy`] ($\theta$) is per-action randomness chosen by the signer.
//! Combined with a note commitment it deterministically derives an
//! [`ActionRandomizer`].

use core::{any::type_name, marker::PhantomData};

use derive_more::{Debug, Into};
use rand_core::CryptoRng;
use udon::field::Field as _;

use crate::{
    note,
    pasta::{Fp, Fq},
    primitives::Effect,
};

/// Per-action entropy $\theta$ chosen by the signer (e.g. hardware wallet).
///
/// A random field element combined with a note commitment to
/// deterministically derive $\alpha$ via
/// [`randomizer`](Self::randomizer).
/// The signer picks $\theta$ once; any device with $\theta$ and the
/// note can independently reconstruct $\alpha$.
///
/// This separation enables **hardware wallet signing without proof
/// construction**: the hardware wallet holds $\mathsf{ask}$ and $\theta$,
/// signs with $\mathsf{rsk} = \mathsf{ask} + \alpha$, and a separate
/// (possibly untrusted) device constructs the proof later using $\theta$
/// and $\mathsf{cm}$ to recover $\alpha$
/// ("Tachyaction at a Distance", Bowe 2025).
#[derive(Clone, Copy, Debug)]
#[expect(clippy::module_name_repetitions, reason = "intentional name")]
pub struct ActionEntropy(#[debug(skip)] pub(crate) Fp);

impl ActionEntropy {
    /// Parse action entropy from its canonical 32-byte encoding.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        Fp::from_bytes(bytes).map(Self)
    }

    /// Sample fresh entropy for an action of effect `E` on the note committing
    /// to `cm`, selecting again while its randomizer exceeds the
    /// [`Fp::CAPACITY`] bits the stamp steps read it from.
    ///
    /// Entropy obtained another way, such as [`from_bytes`](Self::from_bytes),
    /// whose randomizer lands there yields a proof that doesn't verify.
    #[expect(clippy::as_conversions, reason = "constant value")]
    pub fn random<E: Effect>(rng: &mut impl CryptoRng, cm: note::Commitment) -> Self {
        loop {
            let theta = Self(Fp::random(|bytes| rng.fill_bytes(bytes)));
            let alpha_fits_base_field_capacity = !E::derive_alpha(theta, cm)
                .to_le_bits()
                .as_ref()
                .iter()
                .skip(Fp::CAPACITY as usize)
                .any(|&bit| bit);
            if alpha_fits_base_field_capacity {
                return theta;
            }
        }
    }

    /// Derive the action randomizer $\alpha$ for effect `E`.
    ///
    /// Spend and output use distinct Poseidon domains, so the two randomizers
    /// are independent.
    #[must_use]
    pub fn randomizer<E: Effect>(&self, cm: note::Commitment) -> ActionRandomizer<E> {
        ActionRandomizer(E::derive_alpha(*self, cm), PhantomData)
    }
}

mod sealed {
    use crate::primitives::Effect;

    pub trait RandomizerState: Copy {}
    impl<T: Effect> RandomizerState for T {}
}

/// Per-action randomizer $\alpha$, parameterized by effect state.
///
/// - [`ActionRandomizer<Spend>`]: $\mathsf{rsk} = \mathsf{ask} + \alpha$,
///   $\mathsf{rk} = \mathsf{ak} + [\alpha]\mathcal{G}$.
/// - [`ActionRandomizer<Output>`]: $\mathsf{rsk} = \alpha$.
#[derive(Clone, Copy, Debug, Into)]
#[debug("ActionRandomizer<{}>", type_name::<S>())]
pub struct ActionRandomizer<S: sealed::RandomizerState>(
    pub(crate) Fq,
    #[into(skip)] pub(crate) PhantomData<S>,
);

#[cfg(test)]
mod tests;
