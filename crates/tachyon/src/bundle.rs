//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by stamp state `S: StampState`.
//! Actions are constant through state transitions; only the stamp changes.
//!
//! - [`Stamped`] — self-contained bundle with a stamp
//! - [`Stripped`] — stamp removed, depends on an aggregate
//! - `Bundle<Option<Stamp>>` — erased stamp state for mixed contexts

use alloc::vec::Vec;

use lazy_static::lazy_static;

use crate::{
    action::{self, Action},
    constants::BUNDLE_COMMITMENT_PERSONALIZATION,
    keys::{private, public},
    primitives::{ActionDigest, ActionDigestError, effect, multiset::Multiset},
    reddsa,
    stamp::{Stamp, Stampless},
};

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Stamp {}
    impl Sealed for super::Stampless {}
    impl Sealed for Option<super::Stamp> {}
}

/// Sealed trait constraining stamp state types.
pub trait StampState: sealed::Sealed {}
impl<T: sealed::Sealed> StampState for T {}

/// A Tachyon transaction bundle parameterized by stamp state `S`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bundle<S: StampState> {
    /// Actions (cv, rk, sig).
    pub actions: Vec<Action>,

    /// Net value of spends minus outputs (plaintext integer).
    pub value_balance: i64,

    /// Binding signature over the transaction sighash.
    pub binding_sig: Signature,

    /// Stamp state: `Stamp` when present, `Stampless` when stripped.
    pub stamp: S,
}

/// A bundle with a stamp — can stand alone or cover adjunct bundles.
pub type Stamped = Bundle<Stamp>;

impl From<Stamped> for Bundle<Option<Stamp>> {
    fn from(bundle: Stamped) -> Self {
        Self {
            actions: bundle.actions,
            value_balance: bundle.value_balance,
            binding_sig: bundle.binding_sig,
            stamp: Some(bundle.stamp),
        }
    }
}

impl TryFrom<Bundle<Option<Stamp>>> for Stripped {
    type Error = Stamped;

    fn try_from(bundle: Bundle<Option<Stamp>>) -> Result<Self, Self::Error> {
        match bundle.stamp {
            | None => {
                Ok(Self {
                    actions: bundle.actions,
                    value_balance: bundle.value_balance,
                    binding_sig: bundle.binding_sig,
                    stamp: Stampless,
                })
            },
            | Some(stamp) => {
                Err(Stamped {
                    actions: bundle.actions,
                    value_balance: bundle.value_balance,
                    binding_sig: bundle.binding_sig,
                    stamp,
                })
            },
        }
    }
}

/// A bundle whose stamp has been stripped — depends on a stamped bundle.
pub type Stripped = Bundle<Stampless>;

impl From<Stripped> for Bundle<Option<Stamp>> {
    fn from(bundle: Stripped) -> Self {
        Self {
            actions: bundle.actions,
            value_balance: bundle.value_balance,
            binding_sig: bundle.binding_sig,
            stamp: None,
        }
    }
}

impl TryFrom<Bundle<Option<Stamp>>> for Stamped {
    type Error = Stripped;

    fn try_from(bundle: Bundle<Option<Stamp>>) -> Result<Self, Self::Error> {
        match bundle.stamp {
            | Some(stamp) => {
                Ok(Self {
                    actions: bundle.actions,
                    value_balance: bundle.value_balance,
                    binding_sig: bundle.binding_sig,
                    stamp,
                })
            },
            | None => {
                Err(Stripped {
                    actions: bundle.actions,
                    value_balance: bundle.value_balance,
                    binding_sig: bundle.binding_sig,
                    stamp: Stampless,
                })
            },
        }
    }
}

/// Errors during bundle construction.
#[derive(Clone, Copy, Debug)]
pub enum BuildError {
    /// Ragu proof verification failed
    ProofInvalid,

    /// BSK/BVK mismatch (see Protocol §4.14)
    BalanceKeyMismatch,
}

/// Compute a digest of all the bundle's effecting data.
///
/// This contributes to the transaction sighash.
///
/// $$ \mathsf{bundle\_commitment} = \text{BLAKE2b-512}(
/// \text{"Tachyon-BndlHash"},\; \mathsf{action\_commitment} \|
/// \mathsf{value\_balance}) $$
///
/// where $\mathsf{action\_commitment}$ is the multiset polynomial commitment
/// over all action digests — order-independent by construction.
///
/// The stamp is excluded because it is stripped during aggregation.
#[expect(clippy::module_name_repetitions, reason = "consistent naming")]
pub fn digest_bundle(
    action_acc: &Multiset<ActionDigest>,
    value_balance: i64,
) -> Result<[u8; 64], ActionDigestError> {
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(BUNDLE_COMMITMENT_PERSONALIZATION)
        .to_state();

    state.update(&<[u8; 32]>::from(action_acc.commit()));

    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    state.update(&value_balance.to_le_bytes());

    Ok(*state.finalize().as_array())
}

lazy_static! {
    /// Commitment for the absence of a Tachyon bundle in a transaction.
    ///
    /// Personalized BLAKE2b-512 finalized with no data, distinct from the
    /// commitment of an empty bundle (which hashes the identity accumulator
    /// commitment and a zero value balance).
    ///
    /// Follows ZIP-244's pattern for absent pool commitments.
    static ref COMMIT_NO_BUNDLE: [u8; 64] = *blake2b_simd::Params::new()
        .hash_length(64)
        .personal(BUNDLE_COMMITMENT_PERSONALIZATION)
        .to_state()
        .finalize()
        .as_array();
}

/// A complete bundle plan, awaiting authorization.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Plan {
    /// Spend action plans.
    pub spends: Vec<action::Plan<effect::Spend>>,

    /// Output action plans.
    pub outputs: Vec<action::Plan<effect::Output>>,

    /// Net value of spends minus outputs (plaintext integer).
    pub value_balance: i64,
}

impl Plan {
    /// Create a new bundle plan from assembled action plans.
    #[must_use]
    pub const fn new(
        spends: Vec<action::Plan<effect::Spend>>,
        outputs: Vec<action::Plan<effect::Output>>,
        value_balance: i64,
    ) -> Self {
        Self {
            spends,
            outputs,
            value_balance,
        }
    }

    /// Compute the bundle commitment.
    /// See [`digest_bundle`].
    #[must_use]
    pub fn commitment(&self) -> [u8; 64] {
        let actions: Vec<Action> = self
            .spends
            .iter()
            .map(|plan| {
                Action {
                    cv: plan.cv(),
                    rk: plan.rk,
                    sig: action::Signature::from([0u8; 64]),
                }
            })
            .chain(self.outputs.iter().map(|plan| {
                Action {
                    cv: plan.cv(),
                    rk: plan.rk,
                    sig: action::Signature::from([0u8; 64]),
                }
            }))
            .collect();
        #[expect(clippy::expect_used, reason = "don't plan invalid actions")]
        Multiset::try_from(actions.as_slice())
            .and_then(|action_acc| digest_bundle(&action_acc, self.value_balance))
            .expect("don't plan invalid actions")
    }

    /// Derive the binding signing key, which is the scalar sum of value
    /// commitment trapdoors.
    ///
    /// $\mathsf{bsk} = \boxplus_i \mathsf{rcv}_i$.
    #[must_use]
    pub fn derive_bsk_private(&self) -> private::BindingSigningKey {
        let trapdoors: Vec<_> = self
            .spends
            .iter()
            .map(|plan| plan.rcv)
            .chain(self.outputs.iter().map(|plan| plan.rcv))
            .collect();
        private::BindingSigningKey::from(trapdoors.as_slice())
    }
}

impl Stamped {
    /// Strips the stamp, producing a stripped bundle and the extracted stamp.
    ///
    /// The stamp should be merged into an aggregate's stamped bundle.
    #[must_use]
    pub fn strip(self) -> (Stripped, Stamp) {
        (
            Bundle {
                actions: self.actions,
                value_balance: self.value_balance,
                binding_sig: self.binding_sig,
                stamp: Stampless,
            },
            self.stamp,
        )
    }
}

impl<S: StampState> Bundle<S> {
    /// See [`digest_bundle`].
    pub fn commitment(&self) -> Result<[u8; 64], ActionDigestError> {
        let action_acc = Multiset::try_from(self.actions.as_slice())?;
        digest_bundle(&action_acc, self.value_balance)
    }

    /// Verify the bundle's binding signature and all action signatures.
    pub fn verify_signatures(&self, sighash: &[u8; 32]) -> Result<(), reddsa::Error> {
        // 1. Derive bvk from public data (validator-side, §4.14)
        let bvk = public::BindingVerificationKey::derive(&self.actions, self.value_balance);

        // 2. Verify binding signature
        bvk.verify(sighash, &self.binding_sig)?;

        // 3. Verify each action signature against the SAME sighash
        for action in &self.actions {
            action.rk.verify(sighash, &action.sig)?;
        }

        Ok(())
    }
}

/// A binding signature (RedPallas over the Binding group).
///
/// Proves the signer knew the opening $\mathsf{bsk}$ of the Pedersen
/// commitment $\mathsf{bvk}$ to value 0. By the **binding property**
/// of the commitment scheme, it is infeasible to find
/// $(v^*, \mathsf{bsk}')$ such that
/// $\mathsf{bvk} = \text{ValueCommit}_{\mathsf{bsk}'}(v^*)$ for
/// $v^* \neq 0$ — so value balance is enforced.
///
/// The signed message is the transaction sighash — a transaction-wide
/// digest computed at the transaction layer. The validator checks:
/// $\text{BindingSig.Validate}_{\mathsf{bvk}}(\mathsf{sighash},
///   \text{bindingSig}) = 1$
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Signature(pub(crate) reddsa::Signature<reddsa::BindingAuth>);

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes.into())
    }
}

impl From<Signature> for [u8; 64] {
    fn from(sig: Signature) -> Self {
        sig.0.into()
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::Fp;
    use rand::{CryptoRng, RngCore, SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        action,
        entropy::ActionEntropy,
        keys::private,
        note::{self, Note},
        primitives::{Anchor, Epoch},
        stamp::Stamp,
        value,
    };

    /// Normally, data from other parts of the transaction is included in the
    /// sighash, not just the bundle commitment.
    fn mock_sighash(bundle_digest: [u8; 64]) -> [u8; 32] {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"pretend sighash")
            .to_state()
            .update(&bundle_digest)
            .finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }

    /// A wrong value_balance makes binding sig verification fail.
    #[test]
    fn wrong_value_balance_fails_verification() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut bundle = build_autonome(&mut rng, 1000, 700);
        let sighash = mock_sighash(bundle.commitment().unwrap());

        bundle.value_balance = 999;
        assert!(bundle.verify_signatures(&sighash).is_err());
    }

    /// Stripping preserves the binding signature and action signatures.
    #[test]
    fn stripped_bundle_retains_signatures() {
        let mut rng = StdRng::seed_from_u64(0);
        let bundle = build_autonome(&mut rng, 1000, 700);
        let sighash = mock_sighash(bundle.commitment().unwrap());

        let (stripped, _stamp) = bundle.strip();
        stripped.verify_signatures(&sighash).unwrap();
    }

    /// The plan commitment and the built bundle commitment must agree.
    #[test]
    fn plan_commitment_matches_bundle_commitment() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();

        let spend_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(500u64),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
        };
        let output_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(200u64),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
        };

        let spend_rcv = value::CommitmentTrapdoor::random(&mut rng);
        let output_rcv = value::CommitmentTrapdoor::random(&mut rng);
        let theta_spend = ActionEntropy::random(&mut rng);
        let theta_output = ActionEntropy::random(&mut rng);

        let spend_plan = action::Plan::spend(spend_note, theta_spend, spend_rcv, pak.ak());
        let output_plan = action::Plan::output(output_note, theta_output, output_rcv);

        let bundle_plan = Plan::new(alloc::vec![spend_plan], alloc::vec![output_plan], 300);
        let sighash = mock_sighash(bundle_plan.commitment());
        let ask = sk.derive_auth_private();

        let spend_alpha = theta_spend.randomizer::<effect::Spend>(&spend_note.commitment());
        let spend_rsk = ask.derive_action_private(&spend_alpha);
        let spend_action = Action {
            cv: spend_plan.cv(),
            rk: spend_plan.rk,
            sig: spend_rsk.sign(&mut rng, &sighash),
        };

        let output_alpha = theta_output.randomizer::<effect::Output>(&output_note.commitment());
        let output_rsk = private::ActionSigningKey::new(&output_alpha);
        let output_action = Action {
            cv: output_plan.cv(),
            rk: output_plan.rk,
            sig: output_rsk.sign(&mut rng, &sighash),
        };

        let bundle: Stamped = Bundle {
            actions: alloc::vec![spend_action, output_action],
            value_balance: 300,
            binding_sig: bundle_plan.derive_bsk_private().sign(&mut rng, &sighash),
            stamp: {
                let (stamp, _) = Stamp::prove_action(
                    &mut rng,
                    &spend_plan.witness(),
                    &spend_action,
                    Anchor::from(Fp::ZERO),
                    Epoch::from(0u32),
                    &pak,
                )
                .expect("prove_action");
                stamp
            },
        };

        assert_eq!(bundle_plan.commitment(), bundle.commitment().unwrap());
    }

    /// The "no bundle" commitment must differ from an empty bundle's
    /// commitment (identity accumulator + zero balance).
    #[test]
    fn no_bundle_commitment_differs_from_empty_bundle() {
        let empty_plan = Plan::new(alloc::vec![], alloc::vec![], 0);
        assert_ne!(
            *COMMIT_NO_BUNDLE,
            empty_plan.commitment(),
            "absent bundle must differ from empty bundle"
        );
    }

    /// A zero-action bundle with zero balance must verify correctly.
    ///
    /// This exercises the edge case where `BindingVerificationKey::derive`
    /// receives an empty action slice and value_balance = 0, producing the
    /// identity point as `bvk`.
    #[test]
    fn zero_action_bundle_is_valid() {
        let mut rng = StdRng::seed_from_u64(0xdead);
        let plan = Plan::new(alloc::vec![], alloc::vec![], 0);
        let sighash = mock_sighash(plan.commitment());

        let bundle: Stripped = Bundle {
            actions: alloc::vec![],
            value_balance: 0,
            binding_sig: plan.derive_bsk_private().sign(&mut rng, &sighash),
            stamp: Stampless,
        };

        bundle.verify_signatures(&sighash).unwrap();
    }

    /// Build an autonome bundle for testing.
    fn build_autonome(
        rng: &mut (impl RngCore + CryptoRng),
        spend_value: u64,
        output_value: u64,
    ) -> Stamped {
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let spend_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(spend_value),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut *rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut *rng)),
        };
        let output_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(output_value),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut *rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut *rng)),
        };

        let theta_spend = ActionEntropy::random(&mut *rng);
        let theta_output = ActionEntropy::random(&mut *rng);
        let spend_rcv = value::CommitmentTrapdoor::random(&mut *rng);
        let output_rcv = value::CommitmentTrapdoor::random(&mut *rng);

        let spend_plan = action::Plan::spend(spend_note, theta_spend, spend_rcv, pak.ak());
        let output_plan = action::Plan::output(output_note, theta_output, output_rcv);
        let value_balance =
            i64::try_from(spend_value).expect("fits") - i64::try_from(output_value).expect("fits");

        let bundle_plan = Plan::new(
            alloc::vec![spend_plan],
            alloc::vec![output_plan],
            value_balance,
        );
        let sighash = mock_sighash(bundle_plan.commitment());

        // Sign each action
        let spend_alpha = theta_spend.randomizer::<effect::Spend>(&spend_note.commitment());
        let spend_sig = ask
            .derive_action_private(&spend_alpha)
            .sign(&mut *rng, &sighash);
        let output_alpha = theta_output.randomizer::<effect::Output>(&output_note.commitment());
        let output_rsk = private::ActionSigningKey::new(&output_alpha);
        let output_sig = output_rsk.sign(&mut *rng, &sighash);

        // Materialize actions
        let spend_action = Action {
            cv: spend_plan.cv(),
            rk: spend_plan.rk,
            sig: spend_sig,
        };
        let output_action = Action {
            cv: output_plan.cv(),
            rk: output_plan.rk,
            sig: output_sig,
        };

        // Build witnesses and prove leaf stamps
        let (spend_stamp, (spend_acc, _)) = Stamp::prove_action(
            &mut *rng,
            &spend_plan.witness(),
            &spend_action,
            anchor,
            epoch,
            &pak,
        )
        .expect("prove_action (spend)");

        let (output_stamp, (output_acc, _)) = Stamp::prove_action(
            &mut *rng,
            &output_plan.witness(),
            &output_action,
            anchor,
            epoch,
            &pak,
        )
        .expect("prove_action (output)");

        let bundle: Stamped = {
            let (stamp, _accs) =
                Stamp::prove_merge(&mut *rng, spend_stamp, spend_acc, output_stamp, output_acc)
                    .expect("prove_merge");

            Bundle {
                actions: alloc::vec![spend_action, output_action],
                value_balance,
                binding_sig: bundle_plan.derive_bsk_private().sign(&mut *rng, &sighash),
                stamp,
            }
        };

        bundle.verify_signatures(&sighash).unwrap();
        bundle
    }

    /// An innocent aggregate merges stamps from two autonomes.
    ///
    /// Two autonomes are built, their stamps merged via `prove_merge`,
    /// and the result placed in a new bundle with no actions and zero
    /// balance. The merged stamp verifies against actions collected from
    /// both autonomes (which become adjuncts once stripped).
    #[test]
    fn innocent_aggregate_from_two_autonomes() {
        let mut rng = StdRng::seed_from_u64(0xCAFE);

        let autonome_a = build_autonome(&mut rng, 1000, 700);
        let autonome_b = build_autonome(&mut rng, 500, 200);
        let acc_a = Multiset::try_from(autonome_a.actions.as_slice()).expect("valid");
        let acc_b = Multiset::try_from(autonome_b.actions.as_slice()).expect("valid");

        let (adjunct_a, stamp_a) = autonome_a.strip();
        let (adjunct_b, stamp_b) = autonome_b.strip();

        let innocent: Stamped = {
            let innocent_plan = Plan::new(alloc::vec![], alloc::vec![], 0);
            let innocent_sighash = mock_sighash(innocent_plan.commitment());

            let (stamp, _accs) =
                Stamp::prove_merge(&mut rng, stamp_a, acc_a, stamp_b, acc_b).expect("prove_merge");

            Bundle {
                actions: alloc::vec![],
                value_balance: 0,
                binding_sig: innocent_plan
                    .derive_bsk_private()
                    .sign(&mut rng, &innocent_sighash),
                stamp,
            }
        };

        innocent
            .verify_signatures(&mock_sighash(innocent.commitment().unwrap()))
            .expect("innocent binding sig should verify");

        let adjunct_actions: Vec<Action> = [adjunct_a.actions, adjunct_b.actions].concat();
        innocent
            .stamp
            .verify(
                &Multiset::try_from(adjunct_actions.as_slice()).expect("valid"),
                &mut rng,
            )
            .expect("innocent stamp should verify against adjunct actions");
    }

    /// A based aggregate proves its own actions and covers two adjuncts.
    ///
    /// The two contributing autonomes are first merged into an innocent
    /// aggregate, which is then aggregated into the based autonome.
    /// After stripping, the innocent's binding signature still holds.
    #[test]
    fn based_aggregate_with_two_adjuncts() {
        let mut rng = StdRng::seed_from_u64(0xBEEF);

        let mut becomes_based = build_autonome(&mut rng, 800, 400);
        let autonome_a = build_autonome(&mut rng, 1000, 700);
        let autonome_b = build_autonome(&mut rng, 500, 200);

        let acc_a = Multiset::try_from(autonome_a.actions.as_slice()).expect("valid");
        let acc_b = Multiset::try_from(autonome_b.actions.as_slice()).expect("valid");

        let sighash = mock_sighash(becomes_based.commitment().unwrap());

        let (adjunct_a, stamp_a) = autonome_a.strip();
        let (adjunct_b, stamp_b) = autonome_b.strip();

        // Build the innocent aggregate as a full stamped bundle.
        let (innocent, innocent_accs) = {
            let innocent_plan = Plan::new(alloc::vec![], alloc::vec![], 0);
            let innocent_sighash = mock_sighash(innocent_plan.commitment());

            let (stamp, accs) = Stamp::prove_merge(&mut rng, stamp_a, acc_a, stamp_b, acc_b)
                .expect("innocent merge");

            let innocent: Stamped = Bundle {
                actions: alloc::vec![],
                value_balance: 0,
                binding_sig: innocent_plan
                    .derive_bsk_private()
                    .sign(&mut rng, &innocent_sighash),
                stamp,
            };

            (innocent, accs)
        };

        innocent
            .verify_signatures(&mock_sighash(innocent.commitment().unwrap()))
            .expect("innocent aggregate binding sig should verify before stripping");

        // Strip the innocent — its stamp merges into the based aggregate.
        let (stripped_innocent, stripped_innocent_stamp) = innocent.strip();

        stripped_innocent
            .verify_signatures(&mock_sighash(stripped_innocent.commitment().unwrap()))
            .expect("stripped innocent binding sig should still verify");

        // Merge own stamp with innocent stamp → based aggregate.
        let (based_stamp, based_accs) = Stamp::prove_merge(
            &mut rng,
            becomes_based.stamp,
            Multiset::try_from(becomes_based.actions.as_slice()).expect("valid"),
            stripped_innocent_stamp,
            innocent_accs.0,
        )
        .expect("based merge");

        becomes_based.stamp = based_stamp;

        becomes_based
            .verify_signatures(&sighash)
            .expect("based aggregate binding sig should verify");

        // Stamp covers all six actions.
        let all_actions: Vec<Action> = [
            becomes_based.actions.clone(),
            adjunct_a.actions,
            adjunct_b.actions,
        ]
        .concat();

        let all_actions_acc =
            <Multiset<ActionDigest>>::try_from(all_actions.as_slice()).expect("valid");

        assert_eq!(
            all_actions_acc.commit(),
            based_accs.0.commit(),
            "all actions acc should match"
        );

        becomes_based
            .stamp
            .verify(&all_actions_acc, &mut rng)
            .expect("based aggregate stamp should verify against all actions");
    }

    /// A tampered action signature must cause verification to fail.
    #[test]
    fn invalid_action_sig_fails_verification() {
        let mut rng = StdRng::seed_from_u64(11);
        let mut bundle = build_autonome(&mut rng, 1000, 700);
        let sighash = mock_sighash(bundle.commitment().unwrap());

        let mut sig_bytes: [u8; 64] = bundle.actions[0].sig.into();
        sig_bytes[0] ^= 0xFF;
        bundle.actions[0].sig = action::Signature::from(sig_bytes);

        assert!(bundle.verify_signatures(&sighash).is_err());
    }
}
