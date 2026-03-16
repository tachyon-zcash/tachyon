//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by stamp state `S: StampState`.
//! Actions are constant through state transitions; only the stamp changes.
//!
//! - [`Stamped`] — self-contained bundle with a stamp
//! - [`Stripped`] — stamp removed, depends on an aggregate
//! - `Bundle<Option<Stamp>>` — erased stamp state for mixed contexts

use alloc::vec::Vec;

use crate::{
    action::{self, Action},
    constants::BUNDLE_COMMITMENT_PERSONALIZATION,
    keys::{planner, public},
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
#[must_use]
#[expect(clippy::module_name_repetitions, reason = "consistent naming")]
pub fn digest_bundle(action_digests: &[ActionDigest], value_balance: i64) -> [u8; 64] {
    let action_acc = Multiset::from(action_digests).commit();

    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(BUNDLE_COMMITMENT_PERSONALIZATION)
        .to_state();

    state.update(&<[u8; 32]>::from(action_acc));

    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    state.update(&value_balance.to_le_bytes());

    *state.finalize().as_array()
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
    /// Create a new bundle plan from segregated action plans.
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
        let spend_digests = self.spends.iter().map(ActionDigest::try_from);
        let output_digests = self.outputs.iter().map(ActionDigest::try_from);

        #[expect(clippy::expect_used, reason = "don't plan invalid actions")]
        let action_digests: Vec<ActionDigest> = spend_digests
            .chain(output_digests)
            .collect::<Result<_, _>>()
            .expect("don't plan invalid actions");

        digest_bundle(&action_digests, self.value_balance)
    }

    /// Derive the binding signing key, which is the scalar sum of value
    /// commitment trapdoors.
    ///
    /// $\mathsf{bsk} = \boxplus_i \mathsf{rcv}_i$.
    #[must_use]
    pub fn derive_bsk_private(&self) -> planner::BindingSigningKey {
        let trapdoors: Vec<_> = self
            .spends
            .iter()
            .map(|plan| plan.rcv)
            .chain(self.outputs.iter().map(|plan| plan.rcv))
            .collect();
        planner::BindingSigningKey::from(trapdoors.as_slice())
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
        let action_digests: Vec<ActionDigest> = self
            .actions
            .iter()
            .map(ActionDigest::try_from)
            .collect::<Result<_, _>>()?;
        Ok(digest_bundle(&action_digests, self.value_balance))
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
        keys::{custody, delegate::ProofAuthorizingKey},
        note::{self, Note},
        primitives::{Anchor, Epoch},
        stamp::Stamp,
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

    /// Build a test bundle using the new Plan<E> API.
    fn build_test_bundle(rng: &mut (impl RngCore + CryptoRng)) -> Stamped {
        let sk = custody::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let ak = ask.derive_auth_public();
        let nk = sk.derive_nullifier_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let spend_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: note::NullifierTrapdoor::from(Fp::ZERO),
            rcm: note::CommitmentTrapdoor::from(Fp::ZERO),
        };
        let output_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(700u64),
            psi: note::NullifierTrapdoor::from(Fp::ONE),
            rcm: note::CommitmentTrapdoor::from(Fp::ONE),
        };

        let spend_leaf = ProofAuthorizingKey {
            ak,
            node: nk.derive_note_private(&spend_note.psi).derive_leaf(epoch),
        };
        let output_leaf = ProofAuthorizingKey {
            ak,
            node: nk.derive_note_private(&output_note.psi).derive_leaf(epoch),
        };

        let spend_plan = action::Plan::spend(&mut *rng, spend_note, &ak);
        let output_plan = action::Plan::output(&mut *rng, output_note);
        let value_balance: i64 = 300;

        let bundle_plan = Plan::new(
            alloc::vec![spend_plan],
            alloc::vec![output_plan],
            value_balance,
        );
        let sighash = mock_sighash(bundle_plan.commitment());

        // Sign each action
        let spend_alpha = spend_plan
            .theta
            .randomizer::<effect::Spend>(&spend_note.commitment());
        let spend_rsk = ask.derive_action_private(&spend_alpha);
        let spend_action = Action {
            cv: spend_plan.cv(),
            rk: spend_plan.rk,
            sig: spend_rsk.sign(&mut *rng, &sighash),
        };

        let output_alpha = output_plan
            .theta
            .randomizer::<effect::Output>(&output_note.commitment());
        let output_rsk = planner::ActionSigningKey::new(&output_alpha);
        let output_action = Action {
            cv: output_plan.cv(),
            rk: output_plan.rk,
            sig: output_rsk.sign(&mut *rng, &sighash),
        };

        // Prove stamps
        let (spend_stamp, (spend_acc, _)) = Stamp::prove_action(
            &mut *rng,
            &spend_plan.witness(),
            &spend_action,
            anchor,
            epoch,
            &spend_leaf,
        )
        .expect("prove_action (spend)");
        let (output_stamp, (output_acc, _)) = Stamp::prove_action(
            &mut *rng,
            &output_plan.witness(),
            &output_action,
            anchor,
            epoch,
            &output_leaf,
        )
        .expect("prove_action (output)");
        let (stamp, _) =
            Stamp::prove_merge(&mut *rng, spend_stamp, spend_acc, output_stamp, output_acc)
                .expect("prove_merge");

        let bundle: Stamped = Bundle {
            actions: alloc::vec![spend_action, output_action],
            value_balance,
            binding_sig: bundle_plan.derive_bsk_private().sign(&mut *rng, &sighash),
            stamp,
        };

        bundle.verify_signatures(&sighash).unwrap();
        bundle
    }

    /// A wrong value_balance makes binding sig verification fail.
    #[test]
    fn wrong_value_balance_fails_verification() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut bundle = build_test_bundle(&mut rng);
        let sighash = mock_sighash(bundle.commitment().unwrap());

        bundle.value_balance = 999;
        assert!(bundle.verify_signatures(&sighash).is_err());
    }

    /// Stripping preserves the binding signature and action signatures.
    #[test]
    fn stripped_bundle_retains_signatures() {
        let mut rng = StdRng::seed_from_u64(0);
        let bundle = build_test_bundle(&mut rng);
        let sighash = mock_sighash(bundle.commitment().unwrap());

        let (stripped, _stamp) = bundle.strip();
        stripped.verify_signatures(&sighash).unwrap();
    }

    /// The plan commitment and the built bundle commitment must agree.
    #[test]
    fn plan_commitment_matches_bundle_commitment() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = custody::SpendingKey::from([0x42u8; 32]);
        let ak = sk.derive_auth_private().derive_auth_public();
        let nk = sk.derive_nullifier_private();

        let spend_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(500u64),
            psi: note::NullifierTrapdoor::from(Fp::ZERO),
            rcm: note::CommitmentTrapdoor::from(Fp::ZERO),
        };
        let output_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(200u64),
            psi: note::NullifierTrapdoor::from(Fp::ONE),
            rcm: note::CommitmentTrapdoor::from(Fp::ONE),
        };

        let epoch = Epoch::from(0u32);
        let spend_leaf = ProofAuthorizingKey {
            ak,
            node: nk.derive_note_private(&spend_note.psi).derive_leaf(epoch),
        };

        let spend_plan = action::Plan::spend(&mut rng, spend_note, &ak);
        let output_plan = action::Plan::output(&mut rng, output_note);

        let bundle_plan = Plan::new(alloc::vec![spend_plan], alloc::vec![output_plan], 300);
        let plan_commitment = bundle_plan.commitment();

        let spend_action = Action {
            cv: spend_plan.cv(),
            rk: spend_plan.rk,
            sig: action::Signature::from([0u8; 64]),
        };

        let bundle: Stamped = Bundle {
            actions: alloc::vec![
                spend_action,
                Action {
                    cv: output_plan.cv(),
                    rk: output_plan.rk,
                    sig: action::Signature::from([0u8; 64]),
                },
            ],
            value_balance: 300,
            binding_sig: Signature::from([0u8; 64]),
            stamp: {
                let (stamp, _) = Stamp::prove_action(
                    &mut rng,
                    &spend_plan.witness(),
                    &spend_action,
                    Anchor::from(Fp::ZERO),
                    epoch,
                    &spend_leaf,
                )
                .expect("prove_action");
                stamp
            },
        };

        assert_eq!(plan_commitment, bundle.commitment().unwrap());
    }

    /// A tampered action signature must cause verification to fail.
    #[test]
    fn invalid_action_sig_fails_verification() {
        let mut rng = StdRng::seed_from_u64(11);
        let mut bundle = build_test_bundle(&mut rng);
        let sighash = mock_sighash(bundle.commitment().unwrap());

        let mut sig_bytes: [u8; 64] = bundle.actions[0].sig.into();
        sig_bytes[0] ^= 0xFF;
        bundle.actions[0].sig = action::Signature::from(sig_bytes);

        assert!(bundle.verify_signatures(&sighash).is_err());
    }
}
