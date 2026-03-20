//! Stamps and anchors.
//!
//! A stamp carries the tachygram list, the epoch anchor, and the proof:
//!
//! - **Tachygrams**: Listed individually
//! - **Anchor**: Accumulator state reference (epoch)
//! - **Proof**: The Ragu PCD proof (rerandomized)
//!
//! The PCD header data `(action_commitment, tachygram_commitment, anchor)`
//! is **not serialized** on the stamp — the verifier reconstructs polynomial
//! commitments from public data and passes them as the header to Ragu
//! `verify()`.

extern crate alloc;

pub mod proof;

use alloc::vec::Vec;
use core::{error::Error, fmt};

use lazy_static::lazy_static;
use mock_ragu::{Application, ApplicationBuilder};
pub use proof::Proof;
use rand_core::CryptoRng;

use self::proof::{ActionStep, ActionWitness, MergeStep, MergeWitness, StampHeader};
use crate::{
    ActionDigest, Epoch,
    action::{Action, Effect},
    keys::ProofAuthorizingKey,
    primitives::{ActionDigestError, Anchor, Tachygram, multiset::Multiset},
    witness::ActionPrivate,
};

/// Marker for the absence of a stamp.
#[derive(Clone, Copy, Debug)]
pub struct Stampless;

/// Error during stamp verification.
#[derive(Clone, Debug)]
pub enum VerificationError {
    /// An action's cv or rk is the identity point.
    ActionDigest(ActionDigestError),
    /// The proof system returned an error.
    ProofSystem,
    /// The proof did not verify against the reconstructed header.
    Disproved,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | &Self::ActionDigest(err) => write!(f, "action digest error: {err}"),
            | &Self::ProofSystem => write!(f, "proof system error"),
            | &Self::Disproved => write!(f, "proof did not verify"),
        }
    }
}

impl Error for VerificationError {}

/// A stamp carrying tachygrams, anchor, and proof.
///
/// Present in [`Stamped`](crate::Stamped) bundles.
/// Stripped during aggregation and merged into the aggregate's stamp.
///
/// The PCD header `(action_acc, tachygram_acc, anchor)` is not stored
/// here — the verifier reconstructs it from public data and passes it as
/// the header to Ragu `verify()`.
#[derive(Clone, Debug)]
pub struct Stamp {
    /// Tachygrams (nullifiers and note commitments) for data availability.
    ///
    /// The number of tachygrams can be greater than the number of actions.
    pub tachygrams: Vec<Tachygram>,

    /// Reference to tachyon accumulator state (epoch).
    pub anchor: Anchor,

    /// The Ragu proof bytes.
    pub proof: Proof,
}

impl Stamp {
    /// Creates a leaf stamp for a single action (ACTION STEP).
    ///
    /// The circuit derives the tachygram and returns it through `Aux` for
    /// data availability on the stamp. The proof is rerandomized before
    /// returning.
    ///
    /// Leaf stamps are combined via [`prove_merge`](Self::prove_merge).
    #[expect(clippy::type_complexity, reason = "deal with it")]
    pub fn prove_action<RNG: CryptoRng>(
        rng: &mut RNG,
        witness: &ActionPrivate,
        action: &Action,
        effect: Effect,
        anchor: Anchor,
        epoch: Epoch,
        pak: &ProofAuthorizingKey,
    ) -> Result<(Self, (Multiset<ActionDigest>, Multiset<Tachygram>)), mock_ragu::Error> {
        let app = &PROOF_SYSTEM;
        let (proof, (tachygram, action_acc, tachygram_acc)) = app.seed(
            rng,
            &ActionStep,
            ActionWitness {
                action,
                witness,
                effect,
                anchor,
                epoch,
                pak,
            },
        )?;

        let pcd = proof.carry::<StampHeader>((action_acc.commit(), tachygram_acc.commit(), anchor));

        let rerand = app.rerandomize(pcd, rng)?;

        Ok((
            Self {
                tachygrams: alloc::vec![tachygram],
                anchor,
                proof: rerand.proof,
            },
            (action_acc, tachygram_acc),
        ))
    }

    /// Merges this stamp with another, combining tachygrams and proofs.
    ///
    /// Assuming the anchor is an append-only accumulator, a later anchor should
    /// be a superset of an earlier anchor.
    ///
    /// The accumulators (`action_acc`, `tachygram_acc`) are merged inside the
    /// circuit via polynomial multiplication. [`MergeStep`] multiplies the
    /// polynomials, recommits, and takes the max anchor.
    #[expect(clippy::type_complexity, reason = "deal with it")]
    pub fn prove_merge<RNG: CryptoRng>(
        rng: &mut RNG,
        left: Self,
        left_actions: Multiset<ActionDigest>,
        right: Self,
        right_actions: Multiset<ActionDigest>,
    ) -> Result<(Self, (Multiset<ActionDigest>, Multiset<Tachygram>)), mock_ragu::Error> {
        let app = &PROOF_SYSTEM;

        let left_tachygrams = Multiset::<Tachygram>::from(left.tachygrams.as_slice());
        let right_tachygrams = Multiset::<Tachygram>::from(right.tachygrams.as_slice());

        let left_pcd = left.proof.carry::<StampHeader>((
            left_actions.commit(),
            left_tachygrams.commit(),
            left.anchor,
        ));

        let right_pcd = right.proof.carry::<StampHeader>((
            right_actions.commit(),
            right_tachygrams.commit(),
            right.anchor,
        ));

        let merge_witness = MergeWitness {
            left_action_acc: left_actions,
            left_tachygram_acc: left_tachygrams,
            right_action_acc: right_actions,
            right_tachygram_acc: right_tachygrams,
        };

        let (proof, (merged_action_acc, merged_tachygram_acc)) =
            app.fuse(rng, &MergeStep, merge_witness, left_pcd, right_pcd)?;

        let merged_anchor = left.anchor.max(right.anchor);
        let merged_tachygrams = [left.tachygrams, right.tachygrams].concat();

        let merged_header = (
            merged_action_acc.commit(),
            merged_tachygram_acc.commit(),
            merged_anchor,
        );
        let carried = proof.carry::<StampHeader>(merged_header);
        let rerand = app.rerandomize(carried, rng)?;

        Ok((
            Self {
                tachygrams: merged_tachygrams,
                anchor: merged_anchor,
                proof: rerand.proof,
            },
            (merged_action_acc, merged_tachygram_acc),
        ))
    }

    /// Verifies this stamp's proof by reconstructing the PCD header from public
    /// data.
    ///
    /// The verifier recomputes the action and tachygram polynomial commitments
    /// from the public actions and tachygrams, constructs the PCD header,
    /// and calls Ragu `verify(Pcd { proof, data: header })`. The proof
    /// only verifies against the header that matches the circuit's honest
    /// execution — a mismatched header causes verification failure.
    pub fn verify(
        &self,
        actions: &Multiset<ActionDigest>,
        rng: &mut impl CryptoRng,
    ) -> Result<(), VerificationError> {
        let app = &PROOF_SYSTEM;

        let action_commitment = actions.commit();

        let tachygram_commitment = <Multiset<Tachygram>>::from(self.tachygrams.as_slice()).commit();

        let pcd = self.proof.clone().carry::<StampHeader>((
            action_commitment,
            tachygram_commitment,
            self.anchor,
        ));

        let valid = app
            .verify(&pcd, rng)
            .map_err(|_err| VerificationError::ProofSystem)?;

        if valid {
            Ok(())
        } else {
            Err(VerificationError::Disproved)
        }
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        action,
        entropy::{ActionEntropy, ActionRandomizer},
        keys::private,
        note::{self, Note},
        value,
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
    fn prove_action_then_verify() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let (action, witness) = make_action_and_witness(&mut rng, &sk, 500, Effect::Spend);
        let (stamp, _accs) = Stamp::prove_action(
            &mut rng,
            &witness,
            &action,
            Effect::Spend,
            anchor,
            epoch,
            &pak,
        )
        .expect("prove_action");

        stamp
            .verify(
                &Multiset::try_from([action].as_slice()).expect("valid"),
                &mut rng,
            )
            .expect("verify should succeed");
    }

    #[test]
    fn verify_rejects_wrong_action() {
        let mut rng = StdRng::seed_from_u64(1);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let (action_a, witness_a) = make_action_and_witness(&mut rng, &sk, 500, Effect::Spend);
        let (stamp, _accs) = Stamp::prove_action(
            &mut rng,
            &witness_a,
            &action_a,
            Effect::Spend,
            anchor,
            epoch,
            &pak,
        )
        .expect("prove_action");

        let (action_b, _witness_b) = make_action_and_witness(&mut rng, &sk, 200, Effect::Output);

        assert!(
            stamp
                .verify(
                    &Multiset::try_from([action_b].as_slice()).expect("valid"),
                    &mut rng
                )
                .is_err(),
            "verify with wrong action must fail"
        );
    }

    #[test]
    fn prove_merge_then_verify() {
        let mut rng = StdRng::seed_from_u64(2);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let (action_a, witness_a) = make_action_and_witness(&mut rng, &sk, 500, Effect::Spend);
        let (stamp_a, accs_a) = Stamp::prove_action(
            &mut rng,
            &witness_a,
            &action_a,
            Effect::Spend,
            anchor,
            epoch,
            &pak,
        )
        .expect("prove_action a");

        let (action_b, witness_b) = make_action_and_witness(&mut rng, &sk, 200, Effect::Output);
        let (stamp_b, accs_b) = Stamp::prove_action(
            &mut rng,
            &witness_b,
            &action_b,
            Effect::Output,
            anchor,
            epoch,
            &pak,
        )
        .expect("prove_action b");

        let (merged, _merged_accs) =
            Stamp::prove_merge(&mut rng, stamp_a, accs_a.0, stamp_b, accs_b.0)
                .expect("prove_merge");

        merged
            .verify(
                &Multiset::try_from([action_a, action_b].as_slice()).expect("valid"),
                &mut rng,
            )
            .expect("merged stamp should verify");
    }

    #[test]
    fn merged_stamp_rejects_partial_actions() {
        let mut rng = StdRng::seed_from_u64(3);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let (action_a, witness_a) = make_action_and_witness(&mut rng, &sk, 500, Effect::Spend);
        let (stamp_a, accs_a) = Stamp::prove_action(
            &mut rng,
            &witness_a,
            &action_a,
            Effect::Spend,
            anchor,
            epoch,
            &pak,
        )
        .expect("prove_action a");

        let (action_b, witness_b) = make_action_and_witness(&mut rng, &sk, 200, Effect::Output);
        let (stamp_b, accs_b) = Stamp::prove_action(
            &mut rng,
            &witness_b,
            &action_b,
            Effect::Output,
            anchor,
            epoch,
            &pak,
        )
        .expect("prove_action b");

        let (merged, _merged_accs) =
            Stamp::prove_merge(&mut rng, stamp_a, accs_a.0, stamp_b, accs_b.0)
                .expect("prove_merge");

        assert!(
            merged
                .verify(
                    &Multiset::try_from([action_a].as_slice()).expect("valid"),
                    &mut rng
                )
                .is_err(),
            "verify with partial actions must fail"
        );
    }
}

lazy_static! {
    static ref PROOF_SYSTEM: Application = {
        #[expect(clippy::expect_used, reason = "mock registration is infallible")]
        ApplicationBuilder::new()
            .register(ActionStep)
            .expect("register ActionStep")
            .register(MergeStep)
            .expect("register MergeStep")
            .finalize()
            .expect("finalize")
    };
}
