//! Custody abstraction for spend authorization.
//!
//! A custody device holds the spend authorizing key (`ask`) and performs
//! per-action authorization without exposing the key. The [`Custody`] trait
//! enables hardware wallets, software wallets, and test implementations
//! behind a common interface.
//!
//! ## Protocol
//!
//! The user device picks $\theta$ and sends `(cv, theta, cm)` to custody.
//! The custody device returns `(rk, sig)`:
//!
//! 1. $\alpha = \text{BLAKE2b}(\text{"Tachyon-AlphaDrv"},\; \theta \|
//!    \mathsf{cm})$
//! 2. $\mathsf{rsk} = \mathsf{ask} + \alpha$
//! 3. $\mathsf{rk} = [\mathsf{rsk}]\,\mathcal{G}$
//! 4. $\text{sig} = \mathsf{rsk}.\text{sign}(H(\mathsf{cv} \|
//!    \mathsf{rk}))$
//!
//! The caller derives $\alpha$ independently via
//! [`ActionEntropy::spend_randomizer`](crate::keys::private::ActionEntropy::spend_randomizer)
//! from `theta` and `cm`.
//!
//! Outputs do not involve custody — they use
//! [`ActionEntropy::output_randomizer`](crate::keys::private::ActionEntropy::output_randomizer)
//! followed by
//! [`derive_action_private`](crate::keys::private::OutputRandomizer::derive_action_private).

use core::convert::Infallible;

use rand::{CryptoRng, RngCore};

use crate::{action, keys::private, keys::public, note, value};

/// Custody device abstraction for spend authorization.
///
/// A custody device holds the spend authorizing key (`ask`) and performs
/// per-action authorization: given a value commitment, per-action entropy,
/// and note commitment, it returns the verification key and signature.
pub trait Custody {
    /// Error type for authorization failures.
    type Error;

    /// Authorize a spend action.
    ///
    /// The custody device independently derives $\alpha$ from `theta` and
    /// `cm`, computes $\mathsf{rsk} = \mathsf{ask} + \alpha$, and signs
    /// the action. Returns $(\mathsf{rk}, \text{sig})$.
    ///
    /// `cv` is needed to compute the sighash
    /// $H(\text{"Tachyon-SpendSig"},\; \mathsf{cv} \| \mathsf{rk})$.
    fn authorize_spend<R: RngCore + CryptoRng>(
        &self,
        cv: value::Commitment,
        theta: &private::ActionEntropy,
        cm: &note::Commitment,
        rng: &mut R,
    ) -> Result<(public::ActionVerificationKey, action::Signature), Self::Error>;
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

    fn authorize_spend<R: RngCore + CryptoRng>(
        &self,
        cv: value::Commitment,
        theta: &private::ActionEntropy,
        cm: &note::Commitment,
        rng: &mut R,
    ) -> Result<(public::ActionVerificationKey, action::Signature), Self::Error> {
        let alpha = theta.spend_randomizer(cm);
        Ok(alpha.authorize(&self.ask, cv, rng))
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::{Fp, Fq};
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::note::{CommitmentTrapdoor, Note, NullifierTrapdoor};

    /// Software custody authorization must produce a valid signature.
    #[test]
    fn software_custody_sig_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
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

        let (rk, sig) = custody.authorize_spend(cv, &theta, &cm, &mut rng).unwrap();

        rk.verify(action::sighash(cv, rk), &sig).unwrap();
    }
}
