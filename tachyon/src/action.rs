//! Tachyon Action descriptions.

use core::ops::Neg as _;

use rand::{CryptoRng, RngCore};
use reddsa::orchard::SpendAuth;

use crate::{
    constants::SPEND_AUTH_PERSONALIZATION,
    keys::{private, public},
    note::{self, Note},
    primitives::Epoch,
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

    fn new<R: RngCore + CryptoRng>(
        rsk: &private::ActionSigningKey,
        cv: value::Commitment,
        rng: &mut R,
    ) -> Self {
        let rk = rsk.derive_action_public();
        Self {
            cv,
            rk,
            sig: rsk.sign(rng, sighash(cv, rk)),
        }
    }

    /// Consume a note.
    // TODO: Epoch-boundary transactions may require TWO nullifiers per note.
    // The stamp's tachygram list already supports count > actions, but this API
    // needs a variant or additional flavor parameter to produce the second
    // nullifier.
    pub fn spend<R: RngCore + CryptoRng>(
        ask: &private::SpendAuthorizingKey,
        note: Note,
        nf: note::Nullifier,
        flavor: Epoch,
        theta: &private::ActionEntropy,
        rng: &mut R,
    ) -> (Self, ActionPrivate) {
        let cmx = note.commitment();
        let (alpha, rsk) = theta.authorize_spend(ask, &cmx);
        let value: i64 = note.value.into();
        let (rcv, cv) = value::Commitment::commit(value, rng);

        (
            Self::new(&rsk, cv, rng),
            ActionPrivate {
                tachygram: nf.into(),
                alpha,
                flavor,
                note,
                rcv,
            },
        )
    }

    /// Create a note.
    pub fn output<R: RngCore + CryptoRng>(
        note: Note,
        flavor: Epoch,
        theta: &private::ActionEntropy,
        rng: &mut R,
    ) -> (Self, ActionPrivate) {
        let cmx = note.commitment();
        let (alpha, rsk) = theta.authorize_output(&cmx);
        let value: i64 = note.value.into();
        let (rcv, cv) = value::Commitment::commit(value.neg(), rng);

        (
            Self::new(&rsk, cv, rng),
            ActionPrivate {
                tachygram: cmx.into(),
                alpha,
                flavor,
                rcv,
                note,
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
        keys::private,
        note::{CommitmentTrapdoor, NullifierTrapdoor},
    };

    /// A spend action's signature must verify against its own rk.
    #[test]
    fn spend_sig_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let nk = sk.derive_nullifier_key();
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let flavor = Epoch::from(Fp::ONE);
        let nf = note.nullifier(&nk, flavor);
        let theta = private::ActionEntropy::random(&mut rng);

        let (action, _witness) = Action::spend(&ask, note, nf, flavor, &theta, &mut rng);

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
        let flavor = Epoch::from(Fp::ONE);
        let theta = private::ActionEntropy::random(&mut rng);

        let (action, _witness) = Action::output(note, flavor, &theta, &mut rng);

        action
            .rk
            .verify(sighash(action.cv, action.rk), &action.sig)
            .unwrap();
    }
}
