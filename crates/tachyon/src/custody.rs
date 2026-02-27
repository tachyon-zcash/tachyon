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
//!    - Collects typed [`UnsignedAction<Spend>`] and
//!      [`UnsignedAction<Output>`](crate::action::UnsignedAction)
//!
//! 2. The custody device authorizes spends (phase 2):
//!    - Receives all `(cv, rk)` pairs (for sighash) plus
//!      [`UnsignedAction<Spend>`]s with full note and theta
//!    - Computes the bundle sighash
//!    - For each spend: derives $\alpha$, signs with $\mathsf{rsk} =
//!      \mathsf{ask} + \alpha$
//!    - Returns signed [`Action`]s
//!
//! Outputs do not involve custody — they use
//! [`ActionRandomizer<Output>::sign`](crate::keys::randomizer::ActionRandomizer)
//! directly.

use core::convert::Infallible;

use rand::{CryptoRng, RngCore};

use crate::{
    action::{self, UnsignedAction},
    bundle,
    keys::{private, public, randomizer::Spend},
    value,
};

/// Custody device abstraction for spend authorization.
///
/// The custody device holds the spend authorizing key (`ask`) and
/// authorizes spend actions after seeing the full bundle context.
/// This ensures custody can verify the bundle's intent before signing.
///
/// ## Composability
///
/// The [`Local`] implementation calls
/// [`ActionRandomizer<Spend>::sign`](crate::keys::randomizer::ActionRandomizer)
/// — the same primitive available for direct use in composable
/// construction flows.
pub trait Custody {
    /// Error type for authorization failures.
    type Error;

    /// Authorize all spend actions in a bundle.
    ///
    /// The custody device receives:
    /// - `effecting_data`: all `(cv, rk)` pairs from every action (spends and
    ///   outputs) for sighash computation
    /// - `value_balance`: the declared net pool effect
    /// - `spends`: the full [`UnsignedAction<Spend>`]s, each carrying the note,
    ///   theta, and rcv — custody can verify intent
    ///
    /// Returns one signed [`Action`](action::Action) per spend, in the
    /// same order as `spends`.
    fn authorize<R: RngCore + CryptoRng>(
        &self,
        effecting_data: &[(value::Commitment, public::ActionVerificationKey)],
        value_balance: i64,
        spends: &[UnsignedAction<Spend>],
        rng: &mut R,
    ) -> Result<Vec<action::Action>, Self::Error>;
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
        effecting_data: &[(value::Commitment, public::ActionVerificationKey)],
        value_balance: i64,
        spends: &[UnsignedAction<Spend>],
        rng: &mut R,
    ) -> Result<Vec<action::Action>, Self::Error> {
        // Compute the bundle sighash from all effecting data.
        let sighash = bundle::sighash(effecting_data, value_balance);

        // Sign each spend using the same ActionRandomizer<Spend>::sign
        // primitive that is available for direct composable use.
        let actions = spends
            .iter()
            .map(|spend| {
                let cm = spend.note.commitment();
                let alpha = spend.theta.spend_randomizer(&cm);
                alpha.sign(&self.ask, spend.cv, spend.rk, sighash, rng)
            })
            .collect();

        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::{Fp, Fq};
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        keys::randomizer::ActionEntropy,
        note::{self, CommitmentTrapdoor, Note, NullifierTrapdoor},
    };

    /// Software custody authorization must produce valid signatures
    /// that verify against the bundle sighash.
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
        let theta = ActionEntropy::random(&mut rng);
        let unsigned = UnsignedAction::<Spend>::new(note, theta, &pak, &mut rng);

        let pairs = [unsigned.effecting_data()];
        let sighash = bundle::sighash(&pairs, 1000);

        let actions = custody
            .authorize(&pairs, 1000, &[unsigned], &mut rng)
            .unwrap();

        actions[0].rk.verify(sighash, &actions[0].sig).unwrap();
    }
}
