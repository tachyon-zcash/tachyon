//! Tachyon Action descriptions.

use core::ops::Neg as _;

use rand::{CryptoRng, RngCore};
use reddsa::orchard::SpendAuth;

use crate::{
    constants::SPEND_AUTH_PERSONALIZATION,
    custody::Custody,
    keys::{private, public},
    note::Note,
    value,
    witness::ActionPrivate,
};

/// A Tachyon Action description.
///
/// ## Fields
///
/// - `cv`: Commitment to a net value effect
/// - `rk`: Public key (randomized counterpart to `rsk`)
/// - `sig`: Signature by private key (single-use `rsk`)
///
/// ## Note
///
/// The tachygram (nullifier or note commitment) is NOT part of the action.
/// Tachygrams are collected separately in the [`Stamp`](crate::Stamp).
/// However, `rk` is not a direct input to the Ragu proof -- each `rk` is
/// cryptographically bound to its corresponding tachygram, which *is* a proof
/// input, so the proof validates `rk` transitively.
///
/// This separation allows the stamp to be stripped during aggregation
/// while the action (with its authorization) remains in the transaction.
#[derive(Clone, Copy, Debug)]
pub struct Action {
    /// Value commitment $\mathsf{cv} = [v]\,\mathcal{V}
    /// + [\mathsf{rcv}]\,\mathcal{R}$ (EpAffine).
    pub cv: value::Commitment,

    /// Randomized action verification key $\mathsf{rk}$ (EpAffine).
    pub rk: public::ActionVerificationKey,

    /// RedPallas spend auth signature over
    /// $H(\text{"Tachyon-SpendSig"},\; \mathsf{cv} \| \mathsf{rk})$.
    pub sig: Signature,
}

/// A BLAKE2b-512 hash of the spend auth signing message.
#[derive(Clone, Copy, Debug)]
pub struct SigHash([u8; 64]);

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 64]> for SigHash {
    fn into(self) -> [u8; 64] {
        self.0
    }
}

/// Compute the spend auth signing/verification message.
///
/// $$\text{msg} = H(\text{"Tachyon-SpendSig"},\;
///   \mathsf{cv} \| \mathsf{rk})$$
///
/// Domain-separated BLAKE2b-512 over the value commitment and
/// randomized verification key. This binds the signature to the
/// specific (`cv`, `rk`) pair.
#[must_use]
pub fn sighash(cv: value::Commitment, rk: public::ActionVerificationKey) -> SigHash {
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(SPEND_AUTH_PERSONALIZATION)
        .to_state();
    let cv_bytes: [u8; 32] = cv.into();
    state.update(&cv_bytes);
    let rk_bytes: [u8; 32] = rk.into();
    state.update(&rk_bytes);
    SigHash(*state.finalize().as_array())
}

impl Action {
    /// Compute the spend auth signing/verification message.
    /// See [`sighash`] for more details.
    #[must_use]
    pub fn sighash(&self) -> SigHash {
        sighash(self.cv, self.rk)
    }

    /// Consume a note.
    ///
    /// Convenience wrapper composing individual steps for the
    /// single-device case. Each step is independently callable for
    /// delegation (see [composable steps](crate::bundle)):
    ///
    /// 1. Note commitment: [`Note::commitment`]
    /// 2. Value commitment: [`value::Commitment::new`]
    /// 3. Alpha derivation: [`ActionEntropy::spend_randomizer`](private::ActionEntropy::spend_randomizer)
    /// 4. Spend authorization: [`Custody::authorize_spend`](crate::custody::Custody::authorize_spend)
    /// 5. Assembly: `Action { cv, rk, sig }` +
    ///    [`ActionPrivate`](crate::witness::ActionPrivate)
    pub fn spend<R: RngCore + CryptoRng, C: Custody>(
        custody: &C,
        note: Note,
        theta: &private::ActionEntropy,
        rng: &mut R,
    ) -> Result<(Self, ActionPrivate), C::Error> {
        // 1. Note commitment
        let cmx = note.commitment();

        // 2. Value commitment (signer picks rcv)
        let value: i64 = note.value.into();
        let rcv = value::CommitmentTrapdoor::random(&mut *rng);
        let cv = value::Commitment::new(value, rcv);

        // 3. Alpha (user device derives for proof witness)
        let alpha = theta.spend_randomizer(&cmx);

        // 4. Spend authorization (custody derives alpha independently)
        let (rk, sig) = custody.authorize_spend(cv, theta, &cmx, rng)?;

        Ok((
            Self { cv, rk, sig },
            ActionPrivate {
                alpha: alpha.into(),
                note,
                rcv,
            },
        ))
    }

    /// Create a note.
    ///
    /// Convenience wrapper composing individual steps for the
    /// single-device case. Each step is independently callable for
    /// delegation — see [`spend`](Self::spend) for the composable
    /// steps.
    pub fn output<R: RngCore + CryptoRng>(
        note: Note,
        theta: &private::ActionEntropy,
        rng: &mut R,
    ) -> (Self, ActionPrivate) {
        // 1. Note commitment
        let cmx = note.commitment();

        // 2. Value commitment (signer picks rcv; negative for outputs)
        let value: i64 = note.value.into();
        let rcv = value::CommitmentTrapdoor::random(&mut *rng);
        let cv = value::Commitment::new(value.neg(), rcv);

        // 3. Alpha (for proof witness and output signing key)
        let alpha = theta.output_randomizer(&cmx);

        // 4. Output authorization (rsk = alpha, no custody)
        let (rk, sig) = alpha.authorize(cv, rng);

        (
            Self { cv, rk, sig },
            ActionPrivate {
                alpha: alpha.into(),
                note,
                rcv,
            },
        )
    }
}

/// A spend authorization signature (RedPallas over SpendAuth).
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
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

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::{Fp, Fq};
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        custody,
        keys::private,
        note::{self, CommitmentTrapdoor, NullifierTrapdoor},
    };

    /// A spend action's signature must verify against its own rk.
    #[test]
    fn spend_sig_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let local = custody::Local::new(sk.derive_auth_private());
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let theta = private::ActionEntropy::random(&mut rng);

        let (action, _witness) =
            Action::spend(&local, note, &theta, &mut rng).unwrap();

        action
            .rk
            .verify(sighash(action.cv, action.rk), &action.sig)
            .unwrap();
    }

    /// An output action's signature must verify against its own rk.
    #[test]
    fn output_sig_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let theta = private::ActionEntropy::random(&mut rng);

        let (action, _witness) = Action::output(note, &theta, &mut rng);

        action
            .rk
            .verify(sighash(action.cv, action.rk), &action.sig)
            .unwrap();
    }
}
