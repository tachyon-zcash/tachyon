//! Custody abstraction for spend authorization.
//!
//! A custody device holds the spend authorizing key (`ask`) and authorizes
//! spend actions **after seeing all effecting data**. The [`Custody`] trait
//! enables hardware wallets, software wallets, and test implementations
//! behind a common interface.
//!
//! ## Protocol (two-phase)
//!
//! 1. The user device assembles all unsigned actions (phase 1):
//!    - Computes each `cv` and `rk` (using `ak`, not `ask`)
//!    - Collects [`UnsignedAction`](crate::action::UnsignedAction) pairs
//!
//! 2. The custody device authorizes spends (phase 2):
//!    - Receives all unsigned actions + `value_balance` + per-spend
//!      [`SpendRequest`]s
//!    - Computes the transaction-wide sighash
//!    - For each spend: derives $\alpha$ from $(\theta, \mathsf{cm})$, signs
//!      with $\mathsf{rsk} = \mathsf{ask} + \alpha$
//!    - Returns one signature per spend
//!
//! Outputs do not involve custody — they use
//! [`ActionRandomizer<Output>::sign`](crate::keys::private::ActionRandomizer<Output>::sign)
//! directly.

use core::convert::Infallible;

use rand::{CryptoRng, RngCore};

use crate::{action, bundle, keys::private, note};

/// Per-spend authorization material sent to custody.
///
/// Carries the per-action entropy and note commitment needed for the
/// custody device to independently derive $\alpha$ and sign the
/// transaction-wide sighash.
#[derive(Clone, Copy, Debug)]
pub struct SpendRequest {
    /// Index of this spend in the unsigned actions array.
    pub action_index: usize,

    /// Per-action entropy $\theta$ chosen by the signer.
    pub theta: private::ActionEntropy,

    /// Note commitment for this spend.
    pub cm: note::Commitment,
}

/// Custody device abstraction for spend authorization.
///
/// The custody device holds the spend authorizing key (`ask`) and
/// authorizes spend actions after seeing the full transaction context.
/// This ensures custody can verify the transaction's intent before
/// signing.
///
/// ## Composability
///
/// The [`Local`] implementation calls
/// [`SpendRandomizer::sign`](private::SpendRandomizer::sign) — the same
/// primitive available for direct use in composable construction flows.
pub trait Custody {
    /// Error type for authorization failures.
    type Error;

    /// Authorize all spend actions in a transaction.
    ///
    /// The custody device receives the complete set of unsigned actions,
    /// the value balance, and a list of spend requests. For each spend:
    ///
    /// 1. Compute the transaction-wide sighash from all unsigned actions and
    ///    `value_balance`
    /// 2. Derive $\alpha = \theta.\text{spend\_randomizer}(\mathsf{cm})$
    /// 3. Sign the sighash with $\mathsf{rsk} = \mathsf{ask} + \alpha$
    ///
    /// Returns one signature per spend request, in the same order as
    /// `spends`.
    fn authorize<R: RngCore + CryptoRng>(
        &self,
        unsigned_actions: &[action::UnsignedAction],
        value_balance: i64,
        spends: &[SpendRequest],
        rng: &mut R,
    ) -> Result<Vec<action::Signature>, Self::Error>;
}

/// Software custody — holds the spend authorizing key in memory.
///
/// Suitable for single-device wallets where the spending key is
/// available locally.
#[derive(Clone, Copy, Debug)]
pub struct Local {
    /// The spend authorizing key.
    ask: private::SpendAuthorizingKey,
}

impl Local {
    /// Create a new software custody from a spend authorizing key.
    #[must_use]
    pub const fn new(ask: private::SpendAuthorizingKey) -> Self {
        Self { ask }
    }
}

impl Custody for Local {
    type Error = Infallible;

    fn authorize<R: RngCore + CryptoRng>(
        &self,
        unsigned_actions: &[action::UnsignedAction],
        value_balance: i64,
        spends: &[SpendRequest],
        rng: &mut R,
    ) -> Result<Vec<action::Signature>, Self::Error> {
        // Compute the transaction-wide sighash from all effecting data.
        let sighash = bundle::sighash(unsigned_actions, value_balance);

        // Sign each spend using the same SpendRandomizer::sign primitive
        // that is available for direct composable use.
        let sigs = spends
            .iter()
            .map(|spend| {
                let alpha = spend.theta.spend_randomizer(&spend.cm);
                alpha.sign(&self.ask, sighash, rng)
            })
            .collect();

        Ok(sigs)
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
        keys::private,
        note::{CommitmentTrapdoor, Note, NullifierTrapdoor},
        value,
    };

    /// Software custody authorization must produce valid signatures
    /// that verify against the transaction-wide sighash.
    #[test]
    fn software_custody_sig_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let custody = Local::new(sk.derive_auth_private());

        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let cm = note.commitment();
        let note_value: i64 = note.value.into();
        let rcv = value::CommitmentTrapdoor::random(&mut rng);
        let cv = rcv.commit(note_value);
        let theta = private::ActionEntropy::random(&mut rng);

        // Derive rk from public key (user device)
        let alpha = theta.spend_randomizer(&cm);
        let rk = pak.ak().derive_action_public(&alpha);

        let unsigned = UnsignedAction { cv, rk };
        let sighash = bundle::sighash(&[unsigned], note_value);

        let sigs = custody
            .authorize(
                &[unsigned],
                note_value,
                &[SpendRequest {
                    action_index: 0,
                    theta,
                    cm,
                }],
                &mut rng,
            )
            .unwrap();

        rk.verify(sighash, &sigs[0]).unwrap();
    }
}
