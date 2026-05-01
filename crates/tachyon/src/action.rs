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
    use ff::Field as _;
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use crate::{
        entropy::ActionEntropy,
        keys::{private, public},
        note::{self, Note},
        primitives::effect,
        value,
    };

    use super::*;

    fn test_note(rng: &mut impl rand::RngCore) -> Note {
        let sk = private::SpendingKey::from([0x42u8; 32]);
        Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut *rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut *rng)),
        }
    }

    /// Spend plan rk must equal ask.derive_action_private(alpha).derive_action_public().
    #[test]
    fn spend_plan_rk_matches_derivation() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let note = test_note(&mut rng);
        let theta = ActionEntropy::random(&mut rng);
        let rcv = value::CommitmentTrapdoor::random(&mut rng);

        let plan = Plan::spend(note, theta, rcv, |alpha| {
            ask.derive_action_private(&alpha).derive_action_public()
        });

        // Independently derive the expected rk.
        let cm = note.commitment();
        let alpha = theta.randomizer::<effect::Spend>(&cm);
        let expected_rk = ask.derive_action_private(&alpha).derive_action_public();

        assert_eq!(plan.rk, expected_rk);
    }

    /// Output plan rk must equal [alpha]G (no ask involved).
    #[test]
    fn output_plan_rk_is_alpha_g() {
        let mut rng = StdRng::seed_from_u64(42);
        let note = test_note(&mut rng);
        let theta = ActionEntropy::random(&mut rng);
        let rcv = value::CommitmentTrapdoor::random(&mut rng);

        let plan = Plan::output(note, theta, rcv);

        // Independently derive the expected rk.
        let cm = note.commitment();
        let alpha = theta.randomizer::<effect::Output>(&cm);
        let expected_rk =
            private::ActionSigningKey::<effect::Output>::new(&alpha).derive_action_public();

        assert_eq!(plan.rk, expected_rk);
    }

    /// Spend cv must be positive; output cv must be negative. Their sum
    /// with matching values and value_balance=0 should equal [rcv_a + rcv_b]R.
    #[test]
    fn spend_output_cv_binding() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let rcv_spend = value::CommitmentTrapdoor::random(&mut rng);
        let rcv_output = value::CommitmentTrapdoor::random(&mut rng);

        let spend_note = test_note(&mut rng);
        let output_note = Note {
            value: spend_note.value,
            ..test_note(&mut rng)
        };

        let spend_plan = Plan::spend(
            spend_note,
            ActionEntropy::random(&mut rng),
            rcv_spend,
            |alpha| ask.derive_action_private(&alpha).derive_action_public(),
        );
        let output_plan = Plan::output(output_note, ActionEntropy::random(&mut rng), rcv_output);

        // Verify via binding key agreement.
        let bsk = private::BindingSigningKey::from([rcv_spend, rcv_output].as_slice());
        let bvk_signer = bsk.derive_binding_public();
        let bvk_verifier = public::BindingVerificationKey::from(public::derive_bvk(
            [spend_plan.cv(), output_plan.cv()].into_iter(),
            0,
        ));
        assert_eq!(bvk_signer, bvk_verifier);
    }

    /// Signature serialization round-trip: sig → bytes → sig.
    #[test]
    fn signature_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let note = test_note(&mut rng);
        let theta = ActionEntropy::random(&mut rng);
        let alpha = theta.randomizer::<effect::Spend>(&note.commitment());
        let rsk = ask.derive_action_private(&alpha);
        let rk = rsk.derive_action_public();

        let sighash = [0xABu8; 32];
        let sig = rsk.sign(&mut rng, &sighash);
        let bytes: [u8; 64] = sig.into();
        let recovered = Signature::from(bytes);

        // Recovered signature must still verify.
        rk.verify(&sighash, &recovered).unwrap();
    }
}
