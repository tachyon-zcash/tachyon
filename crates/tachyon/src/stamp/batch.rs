//! Batch validation for Tachyon stamps.

extern crate alloc;

use alloc::vec::Vec;

use rand_core::CryptoRng;

use super::Stamp;
use crate::{ActionDigest, primitives::multiset::Multiset};

/// Batch validation context for Tachyon stamps.
///
/// This batch-validates Ragu PCD proofs. This is a **mock** implementation:
/// the real batch validator will exploit proof-system–level batching for
/// amortized cost. The mock iterates and delegates to [`Stamp::verify`].
#[derive(Debug, Default)]
pub struct BatchValidator {
    items: Vec<(Stamp, Multiset<ActionDigest>)>,
}

impl BatchValidator {
    /// Constructs a new batch validation context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the stamp and its actions from the given bundle to the validator.
    pub fn add_bundle(&mut self, stamp: Stamp, actions: Multiset<ActionDigest>) {
        self.items.push((stamp, actions));
    }

    /// Batch-validates the accumulated bundles.
    ///
    /// Returns `true` if every proof in every bundle added to the batch
    /// validator is valid, or `false` if one or more are invalid. No attempt
    /// is made to figure out which of the accumulated bundles might be
    /// invalid; if that information is desired, construct separate
    /// [`BatchValidator`]s for sub-batches of the bundles.
    pub fn validate<R: CryptoRng>(self, mut rng: R) -> bool {
        if self.items.is_empty() {
            return true;
        }

        for (stamp, actions) in &self.items {
            if stamp.verify(actions, &mut rng).is_err() {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        Anchor, Epoch, Multiset,
        action::{self, Action, Effect},
        entropy::{ActionEntropy, ActionRandomizer},
        keys::private,
        note::{self, Note},
        stamp::Stamp,
        value,
        witness::ActionPrivate,
    };

    fn make_action_and_witness(
        rng: &mut StdRng,
        sk: &private::SpendingKey,
        value_amount: u64,
        effect: Effect,
    ) -> (Action, ActionPrivate) {
        let pak = sk.derive_proof_private();
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(value_amount),
            psi: note::NullifierTrapdoor::from(Fp::ZERO),
            rcm: note::CommitmentTrapdoor::from(Fp::ZERO),
        };
        let rcv = value::CommitmentTrapdoor::random(rng);
        let theta = ActionEntropy::random(rng);

        let plan = match effect {
            | Effect::Spend => action::Plan::spend(note, theta, rcv, pak.ak()),
            | Effect::Output => action::Plan::output(note, theta, rcv),
        };

        let action = Action {
            cv: plan.cv(),
            rk: plan.rk,
            sig: action::Signature::from([0u8; 64]),
        };

        let witness = ActionPrivate {
            alpha: ActionRandomizer::from(theta.spend_randomizer(&note.commitment())),
            note,
            rcv,
        };

        (action, witness)
    }

    #[test]
    fn batch_validate_empty() {
        let rng = StdRng::seed_from_u64(100);
        let batch = BatchValidator::new();
        assert!(batch.validate(rng), "empty batch should succeed");
    }

    #[test]
    fn batch_validate_single() {
        let mut rng = StdRng::seed_from_u64(101);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let (action, witness) = make_action_and_witness(&mut rng, &sk, 500, Effect::Spend);
        let (stamp, _accs) = Stamp::prove_action(
            &mut rng, &witness, &action, Effect::Spend, anchor, epoch, &pak,
        )
        .expect("prove_action");

        let mut batch = BatchValidator::new();
        batch.add_bundle(
            stamp,
            Multiset::try_from([action].as_slice()).expect("valid"),
        );
        assert!(batch.validate(&mut rng), "single-item batch should succeed");
    }

    #[test]
    fn batch_validate_multiple() {
        let mut rng = StdRng::seed_from_u64(102);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let (action_a, witness_a) = make_action_and_witness(&mut rng, &sk, 500, Effect::Spend);
        let (stamp_a, _) = Stamp::prove_action(
            &mut rng, &witness_a, &action_a, Effect::Spend, anchor, epoch, &pak,
        )
        .expect("prove_action a");

        let (action_b, witness_b) = make_action_and_witness(&mut rng, &sk, 200, Effect::Output);
        let (stamp_b, _) = Stamp::prove_action(
            &mut rng, &witness_b, &action_b, Effect::Output, anchor, epoch, &pak,
        )
        .expect("prove_action b");

        let mut batch = BatchValidator::new();
        batch.add_bundle(
            stamp_a,
            Multiset::try_from([action_a].as_slice()).expect("valid"),
        );
        batch.add_bundle(
            stamp_b,
            Multiset::try_from([action_b].as_slice()).expect("valid"),
        );
        assert!(batch.validate(&mut rng), "multi-item batch should succeed");
    }

    #[test]
    fn batch_validate_returns_false_on_bad_stamp() {
        let mut rng = StdRng::seed_from_u64(103);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let (action_a, witness_a) = make_action_and_witness(&mut rng, &sk, 500, Effect::Spend);
        let (stamp_a, _) = Stamp::prove_action(
            &mut rng, &witness_a, &action_a, Effect::Spend, anchor, epoch, &pak,
        )
        .expect("prove_action a");

        let (action_b, witness_b) = make_action_and_witness(&mut rng, &sk, 200, Effect::Output);
        let (stamp_b, _) = Stamp::prove_action(
            &mut rng, &witness_b, &action_b, Effect::Output, anchor, epoch, &pak,
        )
        .expect("prove_action b");

        // Valid stamp, then stamp verified against the wrong actions.
        let mut batch = BatchValidator::new();
        batch.add_bundle(
            stamp_a,
            Multiset::try_from([action_a].as_slice()).expect("valid"),
        );
        batch.add_bundle(
            stamp_b,
            Multiset::try_from([action_a].as_slice()).expect("valid"), // wrong actions
        );

        assert!(!batch.validate(&mut rng), "batch with bad stamp should fail");
    }
}
