//! Tachyon Action descriptions.

use core::marker::PhantomData;

use crate::{
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{private, public},
    note::Note,
    primitives::{Effect, effect},
    reddsa, value,
};

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
    pub rcv: value::CommitmentTrapdoor,
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
        rcv: value::CommitmentTrapdoor,
        derive_rk: impl FnOnce(ActionRandomizer<effect::Spend>) -> public::ActionVerificationKey,
    ) -> Self {
        let cm = note.commitment();
        let alpha = theta.randomizer::<effect::Spend>(&cm);

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
    pub fn output(note: Note, theta: ActionEntropy, rcv: value::CommitmentTrapdoor) -> Self {
        let cm = note.commitment();
        let alpha = theta.randomizer::<effect::Output>(&cm);
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
}

/// An authorized Tachyon action.
///
/// - `cv`: Commitment to a value effect
/// - `rk`: Public key (randomized counterpart to `rsk`)
/// - `sig`: Signature (by single-use `rsk`) over transaction sighash
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::{SeedableRng as _, rngs::StdRng};

    use crate::{
        entropy::ActionEntropy,
        keys::private,
        primitives::{Effect as _, effect},
        testing::{arb_note, arb_value},
        value,
    };

    proptest! {
        /// Spend sign-then-verify succeeds for any valid key/note/sighash.
        #[test]
        fn spend_sign_verify(
            sk_bytes in any::<[u8; 32]>(),
            theta_bytes in any::<[u8; 32]>(),
            sighash in any::<[u8; 32]>(),
            note in arb_note(),
        ) {
            let sk = private::SpendingKey::from(sk_bytes);
            let ask = sk.derive_auth_private();
            let theta = ActionEntropy::from_bytes(theta_bytes);
            let cm = note.commitment();
            let alpha = theta.randomizer::<effect::Spend>(&cm);
            let rsk = ask.derive_action_private(&alpha);
            let rk = rsk.derive_action_public();

            let mut rng = StdRng::seed_from_u64(0);
            let sig = rsk.sign(&mut rng, &sighash);
            prop_assert!(rk.verify(&sighash, &sig).is_ok());
        }

        /// Output sign-then-verify succeeds.
        #[test]
        fn output_sign_verify(
            theta_bytes in any::<[u8; 32]>(),
            sighash in any::<[u8; 32]>(),
            note in arb_note(),
        ) {
            let theta = ActionEntropy::from_bytes(theta_bytes);
            let cm = note.commitment();
            let alpha = theta.randomizer::<effect::Output>(&cm);
            let rsk = private::ActionSigningKey::new(&alpha);
            let rk = rsk.derive_action_public();

            let mut rng = StdRng::seed_from_u64(0);
            let sig = rsk.sign(&mut rng, &sighash);
            prop_assert!(rk.verify(&sighash, &sig).is_ok());
        }

        /// Signature rejects wrong sighash.
        #[test]
        fn wrong_sighash_rejects(
            sk_bytes in any::<[u8; 32]>(),
            theta_bytes in any::<[u8; 32]>(),
            sighash_a in any::<[u8; 32]>(),
            sighash_b in any::<[u8; 32]>(),
            note in arb_note(),
        ) {
            prop_assume!(sighash_a != sighash_b);
            let sk = private::SpendingKey::from(sk_bytes);
            let ask = sk.derive_auth_private();
            let theta = ActionEntropy::from_bytes(theta_bytes);
            let cm = note.commitment();
            let alpha = theta.randomizer::<effect::Spend>(&cm);
            let rsk = ask.derive_action_private(&alpha);
            let rk = rsk.derive_action_public();

            let mut rng = StdRng::seed_from_u64(0);
            let sig = rsk.sign(&mut rng, &sighash_a);
            prop_assert!(rk.verify(&sighash_b, &sig).is_err());
        }

        /// Wrong key rejects: sign with one rsk, verify with a different rk.
        #[test]
        fn wrong_key_rejects(
            sk_a_bytes in any::<[u8; 32]>(),
            sk_b_bytes in any::<[u8; 32]>(),
            theta_bytes in any::<[u8; 32]>(),
            sighash in any::<[u8; 32]>(),
            note in arb_note(),
        ) {
            prop_assume!(sk_a_bytes != sk_b_bytes);
            let theta = ActionEntropy::from_bytes(theta_bytes);
            let cm = note.commitment();
            let alpha = theta.randomizer::<effect::Spend>(&cm);

            let ask_a = private::SpendingKey::from(sk_a_bytes).derive_auth_private();
            let rsk_a = ask_a.derive_action_private(&alpha);

            let ask_b = private::SpendingKey::from(sk_b_bytes).derive_auth_private();
            let rk_b = ask_b.derive_action_private(&alpha).derive_action_public();

            let mut rng = StdRng::seed_from_u64(0);
            let sig = rsk_a.sign(&mut rng, &sighash);
            prop_assert!(rk_b.verify(&sighash, &sig).is_err());
        }

        /// Spend and output commit_value with the same (rcv, value) differ.
        #[test]
        fn spend_output_cv_differ(
            seed in any::<u64>(),
            val in arb_value(),
        ) {
            let mut rng = StdRng::seed_from_u64(seed);
            let rcv = value::CommitmentTrapdoor::random(&mut rng);
            let cv_spend = effect::Spend::commit_value(rcv, val);
            let cv_output = effect::Output::commit_value(rcv, val);
            prop_assert_ne!(cv_spend, cv_output);
        }
    }
}
