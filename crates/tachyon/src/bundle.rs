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
use crate::keys::{BindingSignature, BindingSigningKey};
use crate::primitives::Anchor;
use crate::stamp::{Stamp, Stampless};
use ff::Field;
use ragu_pasta::Fq;
use rand::{CryptoRng, RngCore};

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
    /// Builds a stamped bundle from action pairs.
    ///
    /// Action sigs sign `cv || rk` at construction time (not the transaction
    /// sighash), so the binding sig can cover fully-signed actions with no
    /// circular dependency. The stamp is excluded from the sighash because
    /// it is stripped during aggregation.
    pub fn build<R: RngCore + CryptoRng>(
        tachyactions: Vec<(Action, ActionWitness)>,
        value_balance: i64,
        anchor: Anchor,
        rng: &mut R,
    ) -> Self {
        let mut actions = Vec::new();
        let mut witnesses = Vec::new();

        let mut rcv_sum: Fq = Fq::ZERO;

        let mut sig_hash = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(BINDING_SIGHASH_PERSONALIZATION)
            .to_state();
        sig_hash.update(&value_balance.to_le_bytes());

        for (action, witness) in tachyactions {
            rcv_sum += witness.rcv;

            sig_hash.update(&<[u8; 64]>::from(&action.sig));

            actions.push(action);
            witnesses.push(witness);
        }

        let binding_sig =
            BindingSigningKey::from(rcv_sum).sign(rng, sig_hash.finalize().as_bytes());

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
}
