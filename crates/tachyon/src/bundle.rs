//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by its stamp state:
//!
//! - [`StampedBundle`] (`Bundle<Stamp>`) — has a stamp
//! - [`StrippedBundle`] (`Bundle<Stripped>`) — stamp stripped, merged into another bundle
//!
//! Actions are constant through state transitions; only the stamp
//! is stripped or merged.

use crate::Proof;
use crate::action::Action;
use crate::circuit::ActionWitness;
use crate::constants::BINDING_SIGHASH_PERSONALIZATION;
use crate::keys::{Binding, Signature, SigningKey};
use crate::primitives::{Anchor, EpAffine, Fq};
use crate::stamp::{Stamp, Stampless};
use ff::{Field, PrimeField};
use pasta_curves::group::GroupEncoding;
use rand::{CryptoRng, RngCore};

/// A binding signature for value balance verification (RedPallas).
pub type BindingSignature = Signature<Binding>;

/// A Tachyon transaction bundle parameterized by stamp state `S` and value
/// balance type `V`.
///
/// - `Bundle<Stamp, V>` ([`StampedBundle`]) — self-contained with stamp
/// - `Bundle<Stripped, V>` ([`StrippedBundle`]) — stamp stripped, dependent
///
/// The value balance type `V` is a user-defined signed integer representing
/// the net pool effect (e.g. `i64` or a constrained amount type).
#[derive(Clone, Debug)]
pub struct Bundle<S, V> {
    /// Actions (cv, rk, sig).
    pub actions: Vec<Action>,

    /// Net value of spends minus outputs (plaintext integer).
    pub value_balance: V,

    /// Binding signature over actions and value balance.
    pub binding_sig: BindingSignature,

    /// Stamp state: `Stamp` when present, `Stripped` when stripped.
    pub stamp: S,
}

/// A bundle with a stamp — can stand alone or cover adjunct bundles.
pub type Stamped<V> = Bundle<Stamp, V>;

/// A bundle whose stamp has been stripped — depends on a stamped bundle.
pub type Stripped<V> = Bundle<Stampless, V>;

// =============================================================================
// StampedBundle methods
// =============================================================================

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
    /// Builds a stamped bundle from spend and output action pairs.
    ///
    /// 1. Collects actions and witnesses, computes value balance
    /// 2. Creates a stamp via the proof black box
    /// 3. Derives binding signing key from accumulated rcvs
    /// 4. Computes sighash over actions (including their sigs) and value balance
    /// 5. Signs the sighash
    ///
    /// Unlike Orchard, Tachyon action sigs sign `cv || rk` at construction
    /// time (not the transaction sighash), so the binding sig can cover the
    /// fully-signed actions with no circular dependency.
    ///
    /// The stamp is excluded from the sighash because it is stripped during
    /// aggregation while the binding signature remains.
    pub fn build<R: RngCore + CryptoRng>(
        tachyactions: Vec<(Action, ActionWitness)>,
        anchor: Anchor,
        rng: &mut R,
    ) -> Self {
        let mut actions = Vec::new();
        let mut witnesses = Vec::new();
        let mut rcvs = Vec::new();
        let mut value_balance: i64 = 0;

        for (action, witness) in tachyactions {
            rcvs.push(witness.rcv);
            value_balance += i64::try_from(witness.note.value).expect("value fits in i64");
            actions.push(action);
            witnesses.push(witness);
        }

        // Binding sighash: H(actions || value_balance)
        // Covers cv, rk, AND sig for each action.
        let sighash = Self::sighash(&actions, value_balance);

        // Binding signature: $bsk = \sum rcv_i$
        let rcv_sum: Fq = rcvs.into_iter().fold(Fq::ZERO, |a, b| a + b);
        #[allow(clippy::expect_used)]
        let bsk: SigningKey<Binding> = SigningKey::<Binding>::try_from(rcv_sum.to_repr())
            .expect("nonzero trapdoor sum yields valid signing key");
        let binding_sig = bsk.sign(rng, &sighash);

        let (proof, tachygrams) = Proof::create(&witnesses, &actions, &anchor);

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

    /// Computes the sighash for the binding signature.
    ///
    /// $\text{sighash} = \text{BLAKE2b-512}(\text{"Tachyon-BindHash"}, cv_0 \| rk_0 \| \sigma_0 \| \ldots \| \text{value\_balance})$
    ///
    /// Covers all action fields (cv, rk, sig) and the value balance.
    /// The stamp is NOT included — it is stripped during aggregation.
    fn sighash(actions: &[Action], value_balance: i64) -> [u8; 64] {
        let mut state = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(BINDING_SIGHASH_PERSONALIZATION)
            .to_state();

        for action in actions {
            state.update(&EpAffine::from(action.cv).to_bytes());
            state.update(&action.rk.to_bytes());
            state.update(&<[u8; 64]>::from(&action.sig));
        }
        state.update(&value_balance.to_le_bytes());

        *state.finalize().as_array()
    }
}
