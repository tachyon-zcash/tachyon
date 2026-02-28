//! Tachyon Action descriptions.

use reddsa::orchard::SpendAuth;

use crate::{
    keys::{SpendValidatingKey, private::OutputSigningKey, public, randomizer::ActionEntropy},
    note::Note,
    value,
};

/// Whether an action plan represents a spend or an output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Spend — signed via custody with
    /// [`SpendRandomizer::sign`](crate::keys::randomizer::SpendRandomizer::sign).
    Spend,
    /// Output — signed via
    /// [`OutputSigningKey::sign`](crate::keys::private::OutputSigningKey::sign).
    Output,
}

/// A planned Tachyon action — assembled but not yet authorized.
///
/// Carries the per-action randomized verification key `rk`, the note,
/// per-action entropy `theta`, and an [`Effect`] discriminant.
///
/// Value commitments (`cv`, `rcv`) are deferred to build time — the plan
/// captures only spending authority (`rk`) and the note.
///
/// The tachygram (nullifier or note commitment) is NOT part of the
/// action. Tachygrams are collected separately in the
/// [`Stamp`](crate::Stamp).
#[derive(Clone, Copy, Debug)]
pub struct Plan {
    /// Randomized action verification key.
    pub rk: public::ActionVerificationKey,
    /// The note being spent or created.
    pub note: Note,
    /// Per-action entropy for alpha derivation.
    pub theta: ActionEntropy,
    /// Spend or output.
    pub effect: Effect,
}

impl Plan {
    /// Assemble a spend action plan.
    ///
    /// Derives `rk` from the spend validating key `ak` and the per-action
    /// randomizer. No signing key (`ask`) is needed — `rk` is derived from
    /// the public key:
    /// $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$.
    #[must_use]
    pub fn spend(note: Note, theta: ActionEntropy, ak: &SpendValidatingKey) -> Self {
        let cm = note.commitment();
        let alpha = theta.spend_randomizer(&cm);
        let rk = ak.derive_action_public(&alpha);

        Self {
            rk,
            note,
            theta,
            effect: Effect::Spend,
        }
    }

    /// Assemble an output action plan.
    ///
    /// Derives $\mathsf{rk} = [\alpha]\,\mathcal{G}$ (no spending authority).
    #[must_use]
    pub fn output(note: Note, theta: ActionEntropy) -> Self {
        let cm = note.commitment();
        let alpha = theta.output_randomizer(&cm);
        let rsk = OutputSigningKey::from(alpha);
        let rk = rsk.derive_action_public();

        Self {
            rk,
            note,
            theta,
            effect: Effect::Output,
        }
    }
}

/// A signed Tachyon Action description.
///
/// ## Fields
///
/// - `cv`: Commitment to a net value effect
/// - `rk`: Public key (randomized counterpart to `rsk`)
/// - `sig`: Signature by private key (single-use `rsk`) over the bundle
///   [`SigHash`](crate::bundle::SigHash)
#[derive(Clone, Copy, Debug)]
pub struct Action {
    /// Value commitment $\mathsf{cv} = [v]\,\mathcal{V}
    /// + [\mathsf{rcv}]\,\mathcal{R}$ (EpAffine).
    pub cv: value::Commitment,

    /// Randomized action verification key $\mathsf{rk}$ (EpAffine).
    pub rk: public::ActionVerificationKey,

    /// RedPallas spend auth signature over the bundle
    /// [`SigHash`](crate::bundle::SigHash).
    pub sig: Signature,
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
        bundle,
        custody::{self, Custody as _},
        keys::private,
        note::{self, CommitmentTrapdoor, NullifierTrapdoor},
    };

    /// A spend action's signature must verify against the bundle
    /// sighash using its own rk.
    #[test]
    fn spend_sig_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let theta = ActionEntropy::random(&mut rng);
        let spend = Plan::spend(note, theta, pak.ak());

        let plan = bundle::Plan::new(vec![spend], 1000);
        let local = custody::Local::new(sk.derive_auth_private());
        let auth = local.authorize(&plan, &mut rng).unwrap();

        let sighash = plan.sighash(&auth.commitments);
        plan.actions[0].rk.verify(sighash, &auth.sigs[0]).unwrap();
    }

    /// An output action's signature must verify against the bundle
    /// sighash using its own rk.
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
        let theta = ActionEntropy::random(&mut rng);
        let output = Plan::output(note, theta);

        let plan = bundle::Plan::new(vec![output], -1000);
        let local = custody::Local::new(sk.derive_auth_private());
        let auth = local.authorize(&plan, &mut rng).unwrap();

        let sighash = plan.sighash(&auth.commitments);
        plan.actions[0].rk.verify(sighash, &auth.sigs[0]).unwrap();
    }
}
