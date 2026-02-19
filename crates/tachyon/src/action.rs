//! Tachyon Action descriptions.

use core::ops::Neg as _;

use rand::{CryptoRng, RngCore};

use crate::{
    constants::SPEND_AUTH_PERSONALIZATION,
    keys::{
        RandomizedSigningKey, RandomizedVerificationKey, SpendAuthSignature, SpendAuthorizingKey,
    },
    note::{self, Note},
    primitives::{Epoch, SpendAuthEntropy, SpendAuthRandomizer},
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Action {
    /// Value commitment $\mathsf{cv} = [v]\,\mathcal{V}
    /// + [\mathsf{rcv}]\,\mathcal{R}$ (EpAffine).
    pub cv: value::Commitment,

    /// Randomized spend authorization key
    /// $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$ (EpAffine).
    pub rk: RandomizedVerificationKey,

    /// RedPallas spend auth signature over
    /// $H(\text{"Tachyon-SpendSig"},\; \mathsf{cv} \| \mathsf{rk})$.
    pub sig: SpendAuthSignature,
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
pub fn spend_auth_message(cv: &value::Commitment, rk: &RandomizedVerificationKey) -> [u8; 64] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(SPEND_AUTH_PERSONALIZATION)
        .to_state();
    let cv_bytes: [u8; 32] = (*cv).into();
    state.update(&cv_bytes);
    let rk_bytes: [u8; 32] = (*rk).into();
    state.update(&rk_bytes);
    *state.finalize().as_array()
}

impl Action {
    /// The spend auth message for this action's `(cv, rk)` pair.
    #[must_use]
    pub fn sig_message(&self) -> [u8; 64] {
        spend_auth_message(&self.cv, &self.rk)
    }

    fn new<R: RngCore + CryptoRng>(
        rsk: &RandomizedSigningKey,
        cv: value::Commitment,
        rng: &mut R,
    ) -> Self {
        let rk = rsk.public();
        let msg = spend_auth_message(&cv, &rk);

        Self {
            cv,
            rk,
            sig: rsk.sign(rng, &msg),
        }
    }

    /// Consume a note.
    // TODO: Epoch-boundary transactions may require TWO nullifiers per note.
    // The stamp's tachygram list already supports count > actions, but this API
    // needs a variant or additional flavor parameter to produce the second
    // nullifier.
    pub fn spend<R: RngCore + CryptoRng>(
        ask: &SpendAuthorizingKey,
        note: Note,
        nf: note::Nullifier,
        flavor: Epoch,
        theta: &SpendAuthEntropy,
        rng: &mut R,
    ) -> (Self, ActionPrivate) {
        let cmx = note.commitment();
        let alpha = SpendAuthRandomizer::derive(theta, &cmx);
        let rsk = ask.derive_action_private(&alpha);
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
        theta: &SpendAuthEntropy,
        rng: &mut R,
    ) -> (Self, ActionPrivate) {
        let cmx = note.commitment();
        let alpha = SpendAuthRandomizer::derive(theta, &cmx);
        let rsk = RandomizedSigningKey::for_output(&alpha);
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

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::{Fp, Fq};
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        keys::SpendingKey,
        note::{CommitmentTrapdoor, NullifierTrapdoor},
    };

    /// A spend action's signature must verify against its own rk.
    #[test]
    fn spend_sig_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = SpendingKey::from([0x42u8; 32]);
        let ask = sk.spend_authorizing_key();
        let nk = sk.nullifier_key();
        let note = Note {
            pk: sk.payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let flavor = Epoch::from(Fp::ONE);
        let nf = note.nullifier(&nk, flavor);
        let theta = SpendAuthEntropy::random(&mut rng);

        let (action, _witness) = Action::spend(&ask, note, nf, flavor, &theta, &mut rng);

        let msg = action.sig_message();
        action.rk.verify(&msg, &action.sig).unwrap();
    }

    /// An output action's signature must verify against its own rk.
    #[test]
    fn output_sig_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = SpendingKey::from([0x42u8; 32]);
        let note = Note {
            pk: sk.payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let flavor = Epoch::from(Fp::ONE);
        let theta = SpendAuthEntropy::random(&mut rng);

        let (action, _witness) = Action::output(note, flavor, &theta, &mut rng);

        let msg = action.sig_message();
        action.rk.verify(&msg, &action.sig).unwrap();
    }
}
