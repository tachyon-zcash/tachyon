//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by its stamp state. Actions are constant through
//! state transitions; only the stamp is stripped or merged.

use ff::Field as _;
use pasta_curves::Fq;
use rand::{CryptoRng, RngCore};

use crate::{
    Proof,
    action::Action,
    constants::BINDING_SIGHASH_PERSONALIZATION,
    keys::{ProvingKey, private::BindingSigningKey, public::BindingVerificationKey},
    primitives::Anchor,
    stamp::{Stamp, Stampless},
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

    /// Binding signature over actions and value balance.
    pub binding_sig: Signature,

    /// Stamp state: `Stamp` when present, `Stampless` when stripped.
    pub stamp: S,
}

/// A bundle with a stamp — can stand alone or cover adjunct bundles.
pub type Stamped<V> = Bundle<Stamp, V>;

/// A bundle whose stamp has been stripped — depends on a stamped bundle.
pub type Stripped<V> = Bundle<Stampless, V>;

/// A BLAKE2b-512 hash of the binding sighash message.
#[derive(Clone, Copy, Debug)]
pub struct SigHash([u8; 64]);

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 64]> for SigHash {
    fn into(self) -> [u8; 64] {
        self.0
    }
}

/// Compute the Tachyon binding sighash.
///
/// $$\text{sighash} = \text{BLAKE2b-512}(
///   \text{"Tachyon-BindHash"},\;
///   \mathsf{v\_\{balance\}} \| \sigma_1 \| \cdots \| \sigma_n)$$
///
/// This is Tachyon-specific and differs from Orchard's `SIGHASH_ALL`:
/// - Each $\sigma_i$ already binds its $\mathsf{cv}$ and $\mathsf{rk}$ via
///   $H(\text{"Tachyon-SpendSig"},\; \mathsf{cv} \| \mathsf{rk})$, so they are
///   not repeated here.
/// - The binding sig must be computable without the full transaction.
/// - The stamp is excluded because it is stripped during aggregation.
#[must_use]
pub fn sighash(value_balance: i64, action_sigs: &[[u8; 64]]) -> SigHash {
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(BINDING_SIGHASH_PERSONALIZATION)
        .to_state();

    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    state.update(&value_balance.to_le_bytes());

    for sig in action_sigs {
        state.update(sig);
    }

    SigHash(*state.finalize().as_array())
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
    /// Builds a stamped bundle from action pairs.
    ///
    /// ## Binding signature scheme
    ///
    /// The binding signature enforces value balance (§4.14). The signer:
    ///
    /// 1. Computes $\mathsf{bsk} = \boxplus_i \mathsf{rcv}_i$ (scalar sum of
    ///    all value commitment trapdoors in $\mathbb{F}_q$)
    /// 2. Computes the binding sighash (Tachyon-specific):
    ///    $\text{BLAKE2b-512}(\text{"Tachyon-BindHash"},\;
    ///    \mathsf{v\_{balance}} \| \sigma_1 \| \cdots \| \sigma_n)$
    /// 3. Signs the sighash with $\mathsf{bsk}$
    /// 4. Checks $\text{DerivePublic}(\mathsf{bsk}) = \mathsf{bvk}$
    ///    (implementation fault check)
    ///
    /// Action sigs sign
    /// $H(\text{"Tachyon-SpendSig"},\; \mathsf{cv} \| \mathsf{rk})$
    /// at construction time (not the transaction sighash), so the
    /// binding sig can cover fully-signed actions with no circular
    /// dependency. The stamp is excluded from the sighash because it
    /// is stripped during aggregation.
    pub fn build<R: RngCore + CryptoRng>(
        tachyactions: Vec<(Action, ActionPrivate)>,
        value_balance: i64,
        anchor: Anchor,
        pak: &ProvingKey,
        rng: &mut R,
    ) -> Self {
        let mut actions = Vec::new();
        let mut witnesses = Vec::new();

        // bsk = ⊞ᵢ rcvᵢ  (Fq scalar sum)
        let mut rcv_sum: Fq = Fq::ZERO;

        for (action, witness) in tachyactions {
            rcv_sum += &witness.rcv.into();
            actions.push(action);
            witnesses.push(witness);
        }

        #[expect(clippy::expect_used, reason = "specified behavior")]
        let bsk =
            BindingSigningKey::try_from(rcv_sum).expect("sum of trapdoors is a valid signing key");

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

        let action_sigs = actions
            .iter()
            .map(|action| <[u8; 64]>::from(action.sig))
            .collect::<Vec<[u8; 64]>>();
        let binding_sig = bsk.sign(rng, sighash(value_balance, &action_sigs));

        let (proof, tachygrams) = Proof::create(&actions, &witnesses, &anchor, pak);

        Self {
            actions,
            value_balance,
            binding_sig,
            stamp: Stamp {
                tachygrams,
                anchor,
                proof,
            },
        }
    }
}

impl<S> Bundle<S, i64> {
    /// Compute the Tachyon binding sighash.
    /// See [`sighash`] for more details.
    #[must_use]
    pub fn sighash(&self) -> SigHash {
        let action_sigs = self
            .actions
            .iter()
            .map(|action| <[u8; 64]>::from(action.sig))
            .collect::<Vec<[u8; 64]>>();
        sighash(self.value_balance, &action_sigs)
    }

    /// Verify the bundle's binding signature and all action signatures.
    ///
    /// This checks:
    /// 1. Recompute $\mathsf{bvk}$ from public action data (§4.14):
    ///    $\mathsf{bvk} = (\bigoplus_i \mathsf{cv}_i) \ominus
    ///    \text{ValueCommit}_0(\mathsf{v\_{balance}})$
    /// 2. Recompute the binding sighash
    /// 3. Verify $\text{BindingSig.Validate}_{\mathsf{bvk}}(\text{sighash},
    ///    \text{bindingSig}) = 1$
    /// 4. Verify each action's spend auth signature:
    ///    $\text{SpendAuthSig.Validate}_{\mathsf{rk}}(\text{msg}, \sigma) = 1$
    ///
    /// Full bundle verification also requires Ragu PCD proof
    /// verification (currently stubbed) and consensus-layer anchor
    /// range checks.
    pub fn verify_signatures(&self) -> Result<(), reddsa::Error> {
        // 1. Derive bvk from public data (validator-side, §4.14)
        let bvk = BindingVerificationKey::derive(&self.actions, self.value_balance);

        // 2-3. Recompute sighash and verify binding signature
        bvk.verify(self.sighash(), &self.binding_sig)?;

        // 4. Verify each action's spend auth signature
        for action in &self.actions {
            action.rk.verify(action.sighash(), &action.sig)?;
        }

        Ok(())
    }
}

use reddsa::orchard::Binding;
/// A binding signature (RedPallas over the Binding group).
///
/// Proves the signer knew the opening $\mathsf{bsk}$ of the Pedersen
/// commitment $\mathsf{bvk}$ to value 0. By the **binding property**
/// of the commitment scheme, it is infeasible to find
/// $(v^*, \mathsf{bsk}')$ such that
/// $\mathsf{bvk} = \text{ValueCommit}_{\mathsf{bsk}'}(v^*)$ for
/// $v^* \neq 0$ — so value balance is enforced.
///
/// In Tachyon, the signed message is:
/// `BLAKE2b-512("Tachyon-BindHash", value_balance || action_sigs)`
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
        keys::private,
        note::{self, CommitmentTrapdoor, Note, NullifierTrapdoor},
        primitives::Epoch,
    };

    fn build_test_bundle(rng: &mut (impl RngCore + CryptoRng)) -> Stamped<i64> {
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let pak = sk.derive_proving_key();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(Fp::ONE);

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

        let theta_spend = private::ActionEntropy::random(&mut *rng);
        let theta_output = private::ActionEntropy::random(&mut *rng);

        let nk = sk.derive_nullifier_key();
        let nf = spend_note.nullifier(&nk, epoch);
        let spend = Action::spend(&ask, spend_note, nf, epoch, &theta_spend, rng);
        let output = Action::output(output_note, epoch, &theta_output, rng);

        // value_balance = 1000 - 700 = 300
        Stamped::build(vec![spend, output], 300, anchor, &pak, rng)
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
}
