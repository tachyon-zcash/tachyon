//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by its stamp state. Actions are constant through
//! state transitions; only the stamp is stripped or merged.

use ff::Field as _;
use pasta_curves::Fq;
use rand::{CryptoRng, RngCore};
use reddsa::orchard::Binding;

use crate::{
    action::Action,
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

/// A BLAKE2b-512 hash of the unified transaction sighash.
///
/// All signatures (action and binding) sign this same digest.
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
/// Signatures are excluded because the sighash is what gets signed.
///
/// Accepts `(cv, rk)` pairs from any source — unsigned actions (typed
/// by [`Spend`](crate::keys::randomizer::Spend) or
/// [`Output`](crate::keys::randomizer::Output)) or signed [`Action`]s.
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

/// Compute the sighash from signed actions (extracts `cv`/`rk` pairs).
///
/// Convenience for verification paths and `build` where signed actions
/// are already available.
#[must_use]
pub fn sighash_from_actions(actions: &[Action], value_balance: i64) -> SigHash {
    let pairs: Vec<(value::Commitment, public::ActionVerificationKey)> =
        actions.iter().map(|act| (act.cv, act.rk)).collect();
    sighash(&pairs, value_balance)
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
    /// 3. Sign: create binding signature over the unified sighash
    ///
    /// ## Unified sighash
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
        tachyactions: Vec<(Action, ActionPrivate)>,
        value_balance: i64,
        anchor: Anchor,
        pak: &ProofAuthorizingKey,
        rng: &mut R,
    ) -> Result<Self, BuildError> {
        let mut actions = Vec::new();
        let mut witnesses = Vec::new();

        // bsk = ⊞ᵢ rcvᵢ  (Fq scalar sum)
        let mut rcv_sum: Fq = Fq::ZERO;

        for (action, witness) in tachyactions {
            rcv_sum += &witness.rcv.into();
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

        // 3. THEN create binding signature (signer withholds until stamp verified) Uses
        //    the same unified sighash that action sigs signed.
        let sh = sighash_from_actions(&actions, value_balance);
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
    /// Compute the unified Tachyon transaction sighash.
    /// See [`sighash`] for more details.
    #[must_use]
    pub fn sighash(&self) -> SigHash {
        sighash_from_actions(&self.actions, self.value_balance)
    }

    /// Verify the bundle's binding signature and all action signatures.
    ///
    /// All signatures are verified against the same transaction-wide
    /// sighash:
    ///
    /// 1. Recompute $\mathsf{bvk}$ from public action data (§4.14):
    ///    $\mathsf{bvk} = (\bigoplus_i \mathsf{cv}_i) \ominus
    ///    \text{ValueCommit}_0(\mathsf{v\_{balance}})$
    /// 2. Compute the unified sighash
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

        // 2. Compute unified sighash
        let sh = self.sighash();

        // 3. Verify binding signature against sighash
        bvk.verify(sh, &self.binding_sig)?;

        // 4. Verify each action's spend auth signature against the SAME sighash
        for action in &self.actions {
            action.rk.verify(sh, &action.sig)?;
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
/// In Tachyon, the signed message is the unified transaction sighash:
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
        action::UnsignedAction,
        custody::{self, Custody as _},
        keys::{
            private,
            randomizer::{ActionEntropy, Output, Spend},
        },
        note::{self, CommitmentTrapdoor, Note, NullifierTrapdoor},
    };

    /// Build a test bundle using the custody trait for spend signing.
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

        // Phase 1: assemble unsigned actions
        let spend = UnsignedAction::<Spend>::new(spend_note, theta_spend, &pak, &mut *rng);
        let output = UnsignedAction::<Output>::new(output_note, theta_output, &mut *rng);

        // Collect effecting data for sighash
        let value_balance: i64 = 300;
        let pairs = [spend.effecting_data(), output.effecting_data()];

        // Phase 2: sign via custody (spends) and randomizer (outputs)
        let local = custody::Local::new(sk.derive_auth_private());
        let spend_actions = local
            .authorize(&pairs, value_balance, &[spend], rng)
            .unwrap();

        let output_cm = output_note.commitment();
        let output_alpha = theta_output.output_randomizer(&output_cm);
        let sh = sighash(&pairs, value_balance);
        let output_action = output_alpha.sign(output.cv, output.rk, sh, &mut *rng);

        // Witnesses for stamp construction
        let spend_alpha = theta_spend.spend_randomizer(&spend_note.commitment());
        let spend_witness = spend.into_witness(spend_alpha.into());
        let output_witness = output.into_witness(output_alpha.into());

        Stamped::build(
            vec![
                (spend_actions[0], spend_witness),
                (output_action, output_witness),
            ],
            value_balance,
            anchor,
            &pak,
            rng,
        )
        .unwrap()
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
    /// This uses no convenience wrappers (`UnsignedAction::new`,
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

        // === Phase 1: Assemble all unsigned actions ===

        // Spend action assembly (user device)
        let spend_cm = spend_note.commitment();
        let spend_value: i64 = spend_note.value.into();
        let spend_rcv = value::CommitmentTrapdoor::random(&mut rng);
        let spend_cv = spend_rcv.commit(spend_value);
        let spend_theta = ActionEntropy::random(&mut rng);
        let spend_alpha = spend_theta.spend_randomizer(&spend_cm);
        let spend_rk = pak.ak().derive_action_public(&spend_alpha);

        // Output action assembly (user device, no custody)
        let output_cm = output_note.commitment();
        let output_value: i64 = output_note.value.into();
        let output_rcv = value::CommitmentTrapdoor::random(&mut rng);
        let output_cv = output_rcv.commit(-output_value);
        let output_theta = ActionEntropy::random(&mut rng);
        let output_alpha = output_theta.output_randomizer(&output_cm);
        let output_rk = output_alpha.derive_rk();

        let value_balance: i64 = 300;

        // === Phase 2: Compute SigHash and sign all actions ===

        let pairs = [(spend_cv, spend_rk), (output_cv, output_rk)];
        let sh = sighash(&pairs, value_balance);

        // Spend: sign with rsk = ask + alpha
        let spend_action = spend_alpha.sign(&ask, spend_cv, spend_rk, sh, &mut rng);

        // Output: sign with rsk = alpha
        let output_action = output_alpha.sign(output_cv, output_rk, sh, &mut rng);

        let actions = vec![spend_action, output_action];

        // Witnesses for stamp construction
        let spend_witness = ActionPrivate {
            alpha: spend_alpha.into(),
            note: spend_note,
            rcv: spend_rcv,
        };
        let output_witness = ActionPrivate {
            alpha: output_alpha.into(),
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
