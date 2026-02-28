//! Custody abstraction for bundle authorization.
//!
//! A custody device holds the spend authorizing key (`ask`) and authorizes
//! a [`bundle::Plan`] **after seeing all effecting data**. The [`Custody`]
//! trait enables hardware wallets, software wallets, and test
//! implementations behind a common interface.
//!
//! ## Protocol
//!
//! 1. The user device assembles all action plans into a [`bundle::Plan`].
//!
//! 2. The custody device authorizes the plan:
//!    - Generates value commitments via [`Plan::commit`]
//!    - Computes the bundle [`sighash`](crate::bundle::sighash)
//!    - For each spend: derives $\alpha$, signs with $\mathsf{rsk} =
//!      \mathsf{ask} + \alpha$
//!    - For each output: derives $\alpha$, signs with $\mathsf{rsk} = \alpha$
//!    - Returns [`AuthorizationData`] containing signatures and commitments
//!
//! 3. The user device builds the stamped bundle:
//!    [`bundle::Plan::build`](Plan::build)

use core::convert::Infallible;

use rand::{CryptoRng, RngCore};

use crate::{
    action,
    bundle::{AuthorizationData, Plan},
    keys::private,
};

/// Custody device abstraction for bundle authorization.
///
/// The custody device holds the spend authorizing key (`ask`) and
/// authorizes a bundle plan after seeing the full context. This
/// ensures custody can verify the bundle's intent before signing.
///
/// ## Composability
///
/// The [`Local`] implementation calls
/// [`SpendRandomizer::sign`](crate::keys::randomizer::SpendRandomizer::sign)
/// and [`OutputSigningKey::sign`](crate::keys::private::OutputSigningKey::sign)
/// — the same primitives available for direct use in composable
/// construction flows.
pub trait Custody {
    /// Error type for authorization failures.
    type Error;

    /// Authorize a bundle plan.
    ///
    /// The custody device sees the full plan (all actions and value
    /// balance), generates value commitments, computes the sighash,
    /// and signs every action. Returns [`AuthorizationData`] with
    /// signatures and `(cv, rcv)` commitment pairs.
    fn authorize<R: RngCore + CryptoRng>(
        &self,
        plan: &Plan,
        rng: &mut R,
    ) -> Result<AuthorizationData, Self::Error>;
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
        plan: &Plan,
        rng: &mut R,
    ) -> Result<AuthorizationData, Self::Error> {
        let commitments = plan.commit(rng);
        let sighash = plan.sighash(&commitments);

        let mut sigs: Vec<action::Signature> = Vec::new();
        for action_plan in &plan.actions {
            let cm = action_plan.note.commitment();
            let sig = match action_plan.effect {
                | action::Effect::Spend => {
                    let alpha = action_plan.theta.spend_randomizer(&cm);
                    alpha.sign(&self.ask, sighash, rng)
                },
                | action::Effect::Output => {
                    let alpha = action_plan.theta.output_randomizer(&cm);
                    private::OutputSigningKey::from(alpha).sign(rng, sighash)
                },
            };
            sigs.push(sig);
        }

        Ok(AuthorizationData { sigs, commitments })
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
        let unsigned = action::Plan::spend(note, theta, pak.ak());

        let plan = Plan::new(vec![unsigned], 1000);
        let auth = custody.authorize(&plan, &mut rng).unwrap();

        let sighash = plan.sighash(&auth.commitments);
        plan.actions[0].rk.verify(sighash, &auth.sigs[0]).unwrap();
    }
}
