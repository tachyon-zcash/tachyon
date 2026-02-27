//! Tachyon Action descriptions.

use core::{marker::PhantomData, ops::Neg as _};

use rand::{CryptoRng, RngCore};
use reddsa::orchard::SpendAuth;

use crate::{
    keys::{
        ProofAuthorizingKey, public,
        randomizer::{ActionEntropy, ActionRandomizer, Output, Spend, Witness},
    },
    note::Note,
    value,
    witness::ActionPrivate,
};

/// A planned Tachyon action — assembled but not yet authorized.
///
/// Parameterized by kind ([`Spend`] or [`Output`]) to enforce that
/// spends and outputs have different signing requirements:
///
/// - `ActionPlan<Spend>` — signed via custody with
///   [`ActionRandomizer<Spend>::sign`]
/// - `ActionPlan<Output>` — signed directly with
///   [`ActionRandomizer<Output>::sign`]
///
/// Carries the full per-action material: public effecting data
/// (`cv`, `rk`), the note, per-action entropy (`theta`), and the
/// value commitment trapdoor (`rcv`).
///
/// The tachygram (nullifier or note commitment) is NOT part of the
/// action. Tachygrams are collected separately in the
/// [`Stamp`](crate::Stamp).
#[derive(Clone, Copy, Debug)]
#[expect(
    clippy::module_name_repetitions,
    reason = "ActionPlan is the natural name for action plans"
)]
#[expect(
    clippy::partial_pub_fields,
    reason = "PhantomData kind marker is an implementation detail"
)]
pub struct ActionPlan<Kind> {
    /// Value commitment.
    pub cv: value::Commitment,

    /// Randomized action verification key.
    pub rk: public::ActionVerificationKey,

    /// The note being spent or created.
    pub note: Note,

    /// Per-action entropy for alpha derivation.
    pub theta: ActionEntropy,

    /// Value commitment trapdoor.
    pub rcv: value::CommitmentTrapdoor,

    /// Kind marker (zero-sized).
    _kind: PhantomData<Kind>,
}

impl<Kind> ActionPlan<Kind> {
    /// The effecting data pair `(cv, rk)` for sighash computation.
    #[must_use]
    pub const fn effecting_data(&self) -> (value::Commitment, public::ActionVerificationKey) {
        (self.cv, self.rk)
    }

    /// Convert into a proof witness, erasing the spend/output kind.
    ///
    /// The caller supplies the alpha (as [`ActionRandomizer<Witness>`])
    /// obtained by erasing the kind-specific randomizer.
    #[must_use]
    pub const fn into_witness(self, alpha: ActionRandomizer<Witness>) -> ActionPrivate {
        ActionPrivate {
            alpha,
            note: self.note,
            rcv: self.rcv,
        }
    }
}

impl ActionPlan<Spend> {
    /// Assemble a spend action plan.
    ///
    /// Computes the value commitment and derives `rk` from the spend
    /// validating key `ak` and the per-action randomizer. No signing
    /// key (`ask`) is needed — `rk` is derived from the public key:
    /// $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$.
    pub fn new<R: RngCore + CryptoRng>(
        note: Note,
        theta: ActionEntropy,
        pak: &ProofAuthorizingKey,
        rng: &mut R,
    ) -> Self {
        let cm = note.commitment();
        let value: i64 = note.value.into();
        let rcv = value::CommitmentTrapdoor::random(&mut *rng);
        let cv = rcv.commit(value);
        let alpha = theta.spend_randomizer(&cm);
        let rk = pak.ak().derive_action_public(&alpha);

        Self {
            cv,
            rk,
            note,
            theta,
            rcv,
            _kind: PhantomData,
        }
    }
}

impl ActionPlan<Output> {
    /// Assemble an output action plan.
    ///
    /// Computes the value commitment (negated for outputs) and derives
    /// $\mathsf{rk} = [\alpha]\,\mathcal{G}$ (no spending authority).
    pub fn new<R: RngCore + CryptoRng>(note: Note, theta: ActionEntropy, rng: &mut R) -> Self {
        let cm = note.commitment();
        let value: i64 = note.value.into();
        let rcv = value::CommitmentTrapdoor::random(&mut *rng);
        let cv = rcv.commit(value.neg());
        let alpha = theta.output_randomizer(&cm);
        let rk = alpha.derive_rk();

        Self {
            cv,
            rk,
            note,
            theta,
            rcv,
            _kind: PhantomData,
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
        bundle::BundlePlan,
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
        let unsigned = ActionPlan::<Spend>::new(note, theta, &pak, &mut rng);

        let plan = BundlePlan::new(vec![unsigned], vec![], 1000);
        let sighash = plan.sighash();
        let local = custody::Local::new(sk.derive_auth_private());
        let auth = local.authorize(&plan, &mut rng).unwrap();

        plan.spends[0].rk.verify(sighash, &auth.sigs[0]).unwrap();
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
        let unsigned = ActionPlan::<Output>::new(note, theta, &mut rng);

        let plan = BundlePlan::new(vec![], vec![unsigned], -1000);
        let sighash = plan.sighash();
        let local = custody::Local::new(sk.derive_auth_private());
        let auth = local.authorize(&plan, &mut rng).unwrap();

        plan.outputs[0].rk.verify(sighash, &auth.sigs[0]).unwrap();
    }
}
