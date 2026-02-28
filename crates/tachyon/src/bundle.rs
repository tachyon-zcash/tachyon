//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by its stamp state. Actions are constant through
//! state transitions; only the stamp is stripped or merged.

use ff::Field as _;
use pasta_curves::Fq;
use rand::{CryptoRng, RngCore};
use reddsa::orchard::Binding;

use crate::{
    action::{self, Action},
    constants::SIGHASH_PERSONALIZATION,
    keys::{
        ProofAuthorizingKey, private::BindingSigningKey, public, public::BindingVerificationKey,
    },
    primitives::Anchor,
    stamp::{Stamp, Stampless},
    value,
    witness::ActionPrivate,
};

/// A Tachyon transaction bundle parameterized by stamp state `S` and value
/// balance type `V` representing the net pool effect.
#[derive(Clone, Debug)]
pub struct Bundle<S, V> {
    /// Actions (cv, rk, sig).
    pub actions: Vec<Action>,

    /// Net value of spends minus outputs (plaintext integer).
    pub value_balance: V,

    /// Binding signature over the transaction-wide sighash.
    pub binding_sig: Signature,

    /// Stamp state: `Stamp` when present, `Stampless` when stripped.
    pub stamp: S,
}

/// A bundle with a stamp — can stand alone or cover adjunct bundles.
pub type Stamped<V> = Bundle<Stamp, V>;

/// A bundle whose stamp has been stripped — depends on a stamped bundle.
pub type Stripped<V> = Bundle<Stampless, V>;

/// A BLAKE2b-512 hash committing to the bundle's observable effect.
///
/// All signatures (action and binding) sign this same digest. Commits to all
/// `(cv, rk)` pairs and `value_balance`, binding signatures to the bundle's
/// full effect.
#[derive(Clone, Copy, Debug)]
pub struct SigHash([u8; 64]);

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 64]> for SigHash {
    fn into(self) -> [u8; 64] {
        self.0
    }
}

/// Errors during bundle construction.
///
/// Covers both value balance failures (binding key derivation) and stamp
/// verification failures (Ragu proof mismatch).
#[derive(Clone, Copy, Debug)]
pub enum BuildError {
    /// The sum of value commitment trapdoors produced an invalid binding
    /// signing key (e.g. the zero scalar).
    BalanceKey,

    /// Ragu proof verification failed against expected accumulators.
    ///
    /// The verifier reconstructed `(tachygram_acc, action_acc, anchor)`
    /// from public data and the proof did not verify against them.
    ProofInvalid,
}

/// Verifies the stamp by reconstructing the expected accumulators and
/// checking the Ragu proof against them.
///
/// Reconstruction (same logic as consensus verification):
/// 1. `tachygram_acc = sum[H(tg_i)] * G_acc`
/// 2. `action_acc = sum[action_digest_i] * G_acc`  where `action_digest_i =
///    H(cv_i, rk_i)`
/// 3. `anchor` — already known
/// 4. Verify Ragu proof against `(tachygram_acc, action_acc, anchor)`
pub fn verify_stamp(stamp: &Stamp, actions: &[Action]) -> Result<(), BuildError> {
    stamp
        .proof
        .verify(actions, &stamp.tachygrams, stamp.anchor)
        .map_err(|_err| BuildError::ProofInvalid)
}

/// Compute the Tachyon bundle sighash.
///
/// $$\text{sighash} = \text{BLAKE2b-512}(
///   \text{"Tachyon-BndlHash"},\;
///   \mathsf{cv}_1 \| \mathsf{rk}_1 \| \cdots \|
///   \mathsf{cv}_n \| \mathsf{rk}_n \|
///   \mathsf{v\_balance})$$
///
/// All signatures (action and binding) sign this same digest.
/// The stamp is excluded because it is stripped during aggregation.
///
/// Accepts `(cv, rk)` pairs from any source — [`Plan::commit`] data
/// or signed [`Action`]s.
#[must_use]
pub fn sighash(
    effecting_data: &[(value::Commitment, public::ActionVerificationKey)],
    value_balance: i64,
) -> SigHash {
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(SIGHASH_PERSONALIZATION)
        .to_state();

    for &(cv, rk) in effecting_data {
        let cv_bytes: [u8; 32] = cv.into();
        state.update(&cv_bytes);
        let rk_bytes: [u8; 32] = rk.into();
        state.update(&rk_bytes);
    }

    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    state.update(&value_balance.to_le_bytes());

    SigHash(*state.finalize().as_array())
}

/// A bundle plan — all actions assembled, awaiting authorization.
///
/// Collects [`action::Plan`]s (spend and output), then the plan is
/// authorized by a [`Custody`](crate::custody::Custody) device to
/// produce [`AuthorizationData`]. Finally, [`build`](Self::build)
/// consumes the plan and auth data to produce a [`Stamped`] bundle.
///
/// ```text
/// let plan = bundle::Plan::new(vec![spend, output], value_balance);
/// let auth = custody.authorize(&plan, rng)?;
/// let stamped = plan.build(auth, anchor, &pak, rng)?;
/// ```
///
/// For full manual control over each step, use the composable primitives
/// directly: [`SpendRandomizer::sign`](crate::keys::randomizer::SpendRandomizer::sign),
/// [`OutputSigningKey::sign`](crate::keys::private::OutputSigningKey::sign),
/// [`Stamped::build`].
#[derive(Clone, Debug)]
pub struct Plan {
    /// Action plans (spends and outputs, in order).
    pub actions: Vec<action::Plan>,

    /// Net value of spends minus outputs (plaintext integer).
    pub value_balance: i64,
}

impl Plan {
    /// Create a new bundle plan from assembled action plans.
    #[must_use]
    pub const fn new(actions: Vec<action::Plan>, value_balance: i64) -> Self {
        Self {
            actions,
            value_balance,
        }
    }

    /// Generate value commitments for all actions.
    ///
    /// Returns `(cv, rcv)` per action: the value commitment and its
    /// trapdoor. Spends commit to positive value, outputs to negated
    /// value.
    ///
    /// The custody device calls this to produce the `cv` values that
    /// enter the sighash before signing.
    pub fn commit<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Vec<(value::Commitment, value::CommitmentTrapdoor)> {
        self.actions
            .iter()
            .map(|action| {
                let rcv = value::CommitmentTrapdoor::random(&mut *rng);
                let cv = match action.effect {
                    | action::Effect::Spend => rcv.commit_spend(action.note),
                    | action::Effect::Output => rcv.commit_output(action.note),
                };
                (cv, rcv)
            })
            .collect()
    }

    /// The bundle sighash — the digest that all signatures cover.
    ///
    /// `commitments` must be the `(cv, rcv)` pairs from
    /// [`commit`](Self::commit), in the same order as the plan's actions.
    #[must_use]
    pub fn sighash(
        &self,
        commitments: &[(value::Commitment, value::CommitmentTrapdoor)],
    ) -> SigHash {
        let effecting_data: Vec<(value::Commitment, public::ActionVerificationKey)> = self
            .actions
            .iter()
            .zip(commitments)
            .map(|(action, &(cv, _rcv))| (cv, action.rk))
            .collect();
        sighash(&effecting_data, self.value_balance)
    }

    /// Build a stamped bundle from the plan and authorization data.
    ///
    /// Pairs each action plan with its signature and commitment,
    /// builds witnesses (re-deriving alpha from theta + cm via
    /// [`action::Plan::into_witness`]), then delegates to
    /// [`Stamped::build`] for proving and the binding signature.
    pub fn build<R: RngCore + CryptoRng>(
        self,
        auth: AuthorizationData,
        anchor: Anchor,
        pak: &ProofAuthorizingKey,
        rng: &mut R,
    ) -> Result<Stamped<i64>, BuildError> {
        let actions_witnesses: Vec<_> = self
            .actions
            .into_iter()
            .zip(auth.sigs)
            .zip(auth.commitments)
            .map(|((planned, sig), (cv, rcv))| {
                let rk = planned.rk;
                let witness = ActionPrivate {
                    rcv,
                    note: planned.note,
                    alpha: match planned.effect {
                        | action::Effect::Spend => planned
                            .theta
                            .spend_randomizer(&planned.note.commitment())
                            .into(),
                        | action::Effect::Output => planned
                            .theta
                            .output_randomizer(&planned.note.commitment())
                            .into(),
                    },
                };
                (Action { cv, rk, sig }, witness)
            })
            .collect();

        Stamped::build(actions_witnesses, self.value_balance, anchor, pak, rng)
    }
}

/// Authorization data produced by a [`Custody`](crate::custody::Custody)
/// device.
///
/// Contains one signature and one `(cv, rcv)` commitment pair per action,
/// in the same order as the plan.
#[derive(Clone, Debug)]
pub struct AuthorizationData {
    /// One signature per action, in plan order.
    pub sigs: Vec<action::Signature>,

    /// Value commitments and trapdoors, in plan order.
    ///
    /// Produced by [`Plan::commit`] during authorization.
    pub commitments: Vec<(value::Commitment, value::CommitmentTrapdoor)>,
}

impl<V> Stamped<V> {
    /// Strips the stamp, producing a stripped bundle and the extracted stamp.
    ///
    /// The stamp should be merged into an aggregate's stamped bundle.
    pub fn strip(self) -> (Stripped<V>, Stamp) {
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

impl Stamped<i64> {
    /// Builds a stamped bundle from signed action pairs.
    ///
    /// ## Build order: stamp before binding signature
    ///
    /// The stamp is created and verified **before** the binding signature.
    /// This ensures the signer withholds authorization until confirming
    /// the stamp correctly reflects the expected tachygrams and actions.
    /// Without the binding signature, no valid transaction can be broadcast.
    ///
    /// 1. Prove: `Stamp::prove` runs the ACTION STEP per action
    /// 2. Verify: reconstruct expected accumulators, check Ragu proof
    /// 3. Sign: create binding signature over the sighash
    ///
    /// ## Sighash
    ///
    /// All signatures (action and binding) sign the same transaction-wide
    /// digest:
    ///
    /// $$\text{sighash} = \text{BLAKE2b-512}(\text{"Tachyon-BndlHash"},\;
    ///   \mathsf{cv}_1 \| \mathsf{rk}_1 \| \cdots \|
    ///   \mathsf{cv}_n \| \mathsf{rk}_n \|
    ///   \mathsf{v\_balance})$$
    ///
    /// The caller is responsible for computing the sighash during the
    /// authorization phase and signing all actions before calling `build`.
    /// The binding signature is computed here using the same sighash.
    pub fn build<R: RngCore + CryptoRng>(
        actions_witnesses: Vec<(Action, ActionPrivate)>,
        value_balance: i64,
        anchor: Anchor,
        pak: &ProofAuthorizingKey,
        rng: &mut R,
    ) -> Result<Self, BuildError> {
        let mut actions = Vec::new();
        let mut witnesses = Vec::new();

        // bsk = ⊞ᵢ rcvᵢ  (Fq scalar sum)
        let mut rcv_sum: Fq = Fq::ZERO;

        for (action, witness) in actions_witnesses {
            rcv_sum += &Into::<Fq>::into(witness.rcv);
            actions.push(action);
            witnesses.push(witness);
        }

        let bsk = BindingSigningKey::try_from(rcv_sum).map_err(|_err| BuildError::BalanceKey)?;

        // §4.14 implementation fault check:
        // DerivePublic(bsk) == bvk
        //
        // The signer-derived bvk ([bsk]R) must equal the validator-derived
        // bvk (Σcvᵢ - ValueCommit₀(v_balance)). A mismatch indicates a
        // bug in value commitment or trapdoor accumulation.
        debug_assert_eq!(
            bsk.derive_binding_public(),
            BindingVerificationKey::derive(&actions, value_balance),
            "BSK/BVK mismatch: binding key derivation is inconsistent"
        );

        // 1. Create stamp FIRST (ACTION STEP per action, then merge)
        let mut stamps: Vec<Stamp> = actions
            .iter()
            .zip(&witnesses)
            .map(|(action, witness)| Stamp::prove_action(witness, action, anchor, pak))
            .collect();
        while stamps.len() > 1 {
            let right = stamps.pop();
            let left = stamps.pop();
            // Both unwraps are safe: len > 1 guarantees two elements.
            #[expect(clippy::expect_used, reason = "len > 1 guarantees two elements")]
            let merged = left
                .expect("left stamp")
                .prove_merge(right.expect("right stamp"));
            stamps.push(merged);
        }
        #[expect(clippy::expect_used, reason = "at least one action")]
        let stamp = stamps.pop().expect("at least one action");

        // 2. Verify stamp against expected accumulators
        verify_stamp(&stamp, &actions)?;

        // 3. THEN create binding signature (signer withholds until stamp verified).
        //    Uses the same sighash that action sigs signed.
        let pairs: Vec<_> = actions.iter().map(|act| (act.cv, act.rk)).collect();
        let sh = sighash(&pairs, value_balance);
        let binding_sig = bsk.sign(rng, sh);

        Ok(Self {
            actions,
            value_balance,
            binding_sig,
            stamp,
        })
    }
}

impl<S> Bundle<S, i64> {
    /// Compute the bundle sighash.
    /// See [`sighash`] for more details.
    #[must_use]
    pub fn sighash(&self) -> SigHash {
        let pairs: Vec<_> = self.actions.iter().map(|act| (act.cv, act.rk)).collect();
        sighash(&pairs, self.value_balance)
    }

    /// Verify the bundle's binding signature and all action signatures.
    ///
    /// All signatures are verified against the same sighash:
    ///
    /// 1. Recompute $\mathsf{bvk}$ from public action data (§4.14):
    ///    $\mathsf{bvk} = (\bigoplus_i \mathsf{cv}_i) \ominus
    ///    \text{ValueCommit}_0(\mathsf{v\_{balance}})$
    /// 2. Compute the sighash
    /// 3. Verify $\text{BindingSig.Validate}_{\mathsf{bvk}}(\text{sighash},
    ///    \text{bindingSig}) = 1$
    /// 4. Verify each action's spend auth signature against the same sighash:
    ///    $\text{SpendAuthSig.Validate}_{\mathsf{rk}}(\text{sighash}, \sigma) =
    ///    1$
    ///
    /// Full bundle verification also requires Ragu PCD proof
    /// verification (currently stubbed) and consensus-layer anchor
    /// range checks.
    pub fn verify_signatures(&self) -> Result<(), reddsa::Error> {
        // 1. Derive bvk from public data (validator-side, §4.14)
        let bvk = BindingVerificationKey::derive(&self.actions, self.value_balance);

        // 2. Compute sighash
        let sighash = self.sighash();

        // 3. Verify binding signature against sighash
        bvk.verify(sighash, &self.binding_sig)?;

        // 4. Verify each action's spend auth signature against the SAME sighash
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
/// In Tachyon, the signed message is the bundle sighash:
/// `BLAKE2b-512("Tachyon-BndlHash", cv_1 || rk_1 || ... || cv_n || rk_n ||
/// value_balance)`
///
/// The validator checks:
/// $\text{BindingSig.Validate}_{\mathsf{bvk}}(\text{sighash},
///   \text{bindingSig}) = 1$
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct Signature(pub(crate) reddsa::Signature<Binding>);

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
    use pasta_curves::{Fp, Fq};
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        action,
        custody::{self, Custody as _},
        keys::{
            private::{self, OutputSigningKey},
            randomizer::{ActionEntropy, ActionRandomizer},
        },
        note::{self, CommitmentTrapdoor, Note, NullifierTrapdoor},
    };

    /// Build a test bundle using `bundle::Plan` + `Custody` for authorization.
    fn build_test_bundle(rng: &mut (impl RngCore + CryptoRng)) -> Stamped<i64> {
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);

        let spend_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let output_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(700u64),
            psi: NullifierTrapdoor::from(Fp::ONE),
            rcm: CommitmentTrapdoor::from(Fq::ONE),
        };

        let theta_spend = ActionEntropy::random(&mut *rng);
        let theta_output = ActionEntropy::random(&mut *rng);

        let spend = action::Plan::spend(spend_note, theta_spend, pak.ak());
        let output = action::Plan::output(output_note, theta_output);

        let plan = Plan::new(vec![spend, output], 300);
        let local = custody::Local::new(sk.derive_auth_private());
        let auth = local.authorize(&plan, rng).unwrap();

        plan.build(auth, anchor, &pak, rng).unwrap()
    }

    /// A correctly built bundle must pass signature verification.
    #[test]
    fn build_and_verify_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let bundle = build_test_bundle(&mut rng);
        bundle.verify_signatures().unwrap();
    }

    /// A wrong value_balance makes binding sig verification fail.
    #[test]
    fn wrong_value_balance_fails_verification() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut bundle = build_test_bundle(&mut rng);

        bundle.value_balance = 999;
        assert!(bundle.verify_signatures().is_err());
    }

    /// Stripping preserves the binding signature and action signatures.
    #[test]
    fn stripped_bundle_retains_signatures() {
        let mut rng = StdRng::seed_from_u64(0);
        let bundle = build_test_bundle(&mut rng);

        let (stripped, _stamp) = bundle.strip();
        stripped.verify_signatures().unwrap();
    }

    /// Composable flow: construct actions and bundle step-by-step,
    /// exercising each delegation boundary independently.
    ///
    /// This uses no convenience wrappers (`action::Plan::spend`,
    /// `Stamped::build`). Every step is called individually, matching
    /// the custody-delegated flow from the protocol spec.
    #[test]
    #[expect(
        clippy::similar_names,
        reason = "protocol variable names: cv/rcv, rk/rsk"
    )]
    fn composable_delegation_flow() {
        let mut rng = StdRng::seed_from_u64(1);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);

        let spend_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let output_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(700u64),
            psi: NullifierTrapdoor::from(Fp::ONE),
            rcm: CommitmentTrapdoor::from(Fq::ONE),
        };

        // === Phase 1: Assemble all action plans ===

        // Spend action assembly (user device)
        let spend_cm = spend_note.commitment();
        let spend_rcv = value::CommitmentTrapdoor::random(&mut rng);
        let spend_cv = spend_rcv.commit_spend(spend_note);
        let spend_theta = ActionEntropy::random(&mut rng);
        let spend_alpha = spend_theta.spend_randomizer(&spend_cm);
        let spend_rk = pak.ak().derive_action_public(&spend_alpha);

        // Output action assembly (user device, no custody)
        let output_cm = output_note.commitment();
        let output_rcv = value::CommitmentTrapdoor::random(&mut rng);
        let output_cv = output_rcv.commit_output(output_note);
        let output_theta = ActionEntropy::random(&mut rng);
        let output_alpha = output_theta.output_randomizer(&output_cm);
        let output_rsk = OutputSigningKey::from(output_alpha);
        let output_rk = output_rsk.derive_action_public();

        let value_balance: i64 = 300;

        // === Phase 2: Compute sighash and sign all actions ===

        let pairs = [(spend_cv, spend_rk), (output_cv, output_rk)];
        let sh = sighash(&pairs, value_balance);

        // Spend: sign with rsk = ask + alpha
        let spend_sig = spend_alpha.sign(&ask, sh, &mut rng);
        let spend_action = Action {
            cv: spend_cv,
            rk: spend_rk,
            sig: spend_sig,
        };

        // Output: sign with rsk = alpha
        let output_sig = output_rsk.sign(&mut rng, sh);
        let output_action = Action {
            cv: output_cv,
            rk: output_rk,
            sig: output_sig,
        };

        let actions = vec![spend_action, output_action];

        // Witnesses for stamp construction
        let spend_witness = ActionPrivate {
            alpha: ActionRandomizer::from(spend_alpha),
            note: spend_note,
            rcv: spend_rcv,
        };
        let output_witness = ActionPrivate {
            alpha: ActionRandomizer::from(output_alpha),
            note: output_note,
            rcv: output_rcv,
        };

        // === Bundle assembly (composable steps) ===

        // Binding key (user device: accumulate rcv trapdoors)
        let bsk: BindingSigningKey = [spend_witness.rcv, output_witness.rcv].into_iter().sum();
        debug_assert_eq!(
            bsk.derive_binding_public(),
            BindingVerificationKey::derive(&actions, value_balance),
        );

        // Stamp (per-action proofs, then merge)
        let spend_stamp = Stamp::prove_action(&spend_witness, &spend_action, anchor, &pak);
        let output_stamp = Stamp::prove_action(&output_witness, &output_action, anchor, &pak);
        let stamp = spend_stamp.prove_merge(output_stamp);
        verify_stamp(&stamp, &actions).unwrap();

        // Binding signature (user device: withheld until stamp verified)
        let binding_sig = bsk.sign(&mut rng, sh);

        // Assemble bundle
        let bundle: Stamped<i64> = Bundle {
            actions,
            value_balance,
            binding_sig,
            stamp,
        };

        bundle.verify_signatures().unwrap();
    }
}
