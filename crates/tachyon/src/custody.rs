//! Custody abstraction for bundle authorization.
//!
//! A custody device holds the spend authorizing key (`ask`) and authorizes
//! a [`BundlePlan`] **after seeing all effecting data**. The [`Custody`]
//! trait enables hardware wallets, software wallets, and test
//! implementations behind a common interface.
//!
//! ## Protocol
//!
//! 1. The user device assembles all unsigned actions into a
//!    [`BundlePlan`].
//!
//! 2. The custody device authorizes the plan:
//!    - Computes the bundle [`effect_hash`](crate::bundle::effect_hash)
//!    - For each spend: derives $\alpha$, signs with $\mathsf{rsk} =
//!      \mathsf{ask} + \alpha$
//!    - For each output: derives $\alpha$, signs with $\mathsf{rsk} =
//!      \alpha$ (no spend authority)
//!    - Returns [`AuthorizationData`] containing all signatures
//!
//! 3. The user device builds the stamped bundle:
//!    [`BundlePlan::build`](BundlePlan::build)

use core::convert::Infallible;

use rand::{CryptoRng, RngCore};

use crate::{
    action,
    bundle::{AuthorizationData, BundlePlan},
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
/// [`ActionRandomizer::sign`](crate::keys::randomizer::ActionRandomizer)
/// — the same primitive available for direct use in composable
/// construction flows.
pub trait Custody {
    /// Error type for authorization failures.
    type Error;

    /// Authorize a bundle plan.
    ///
    /// The custody device sees the full plan (all spends, outputs, and
    /// value balance), computes the effect hash, and signs every action.
    /// Returns [`AuthorizationData`] with one signature per action
    /// (spends first, then outputs).
    fn authorize<R: RngCore + CryptoRng>(
        &self,
        plan: &BundlePlan,
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
        plan: &BundlePlan,
        rng: &mut R,
    ) -> Result<AuthorizationData, Self::Error> {
        let eh = plan.effect_hash();
        let mut sigs: Vec<action::Signature> = Vec::new();

        // Spends: rsk = ask + alpha
        for spend in &plan.spends {
            let cm = spend.note.commitment();
            let alpha = spend.theta.spend_randomizer(&cm);
            let rsk = self.ask.derive_action_private(&alpha);
            sigs.push(rsk.sign(rng, eh));
        }

        // Outputs: sign with rsk = alpha (no spend authority)
        for output in &plan.outputs {
            let cm = output.note.commitment();
            let alpha = output.theta.output_randomizer(&cm);
            let signed = alpha.sign(output.cv, output.rk, eh, rng);
            sigs.push(signed.sig);
        }

        Ok(AuthorizationData { sigs })
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
        keys::randomizer::{ActionEntropy, Spend},
        note::{self, CommitmentTrapdoor, Note, NullifierTrapdoor},
    };

    /// Software custody authorization must produce valid signatures
    /// that verify against the bundle effect hash.
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

        let plan = BundlePlan::new(vec![unsigned], vec![], 1000);
        let eh = plan.effect_hash();

        let auth = custody.authorize(&plan, &mut rng).unwrap();

        plan.spends[0]
            .rk
            .verify(eh, &auth.sigs[0])
            .unwrap();
    }
}
