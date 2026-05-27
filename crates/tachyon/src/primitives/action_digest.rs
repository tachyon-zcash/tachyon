use core::{error::Error, fmt};

use ff::PrimeField as _;
use pasta_curves::{EpAffine, Fp, arithmetic::CurveAffine as _};

use crate::{digest::poseidon, keys::public, value};

/// Poseidon digest of a single action's $(\mathsf{cv}, \mathsf{rk})$ pair.
///
/// Each action produces one digest, which serves as a root in the
/// accumulator polynomial. Multiple actions are accumulated via
/// polynomial commitment, not on this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionDigest(Fp);

/// Errors from action digest computation.
#[derive(Clone, Copy, Debug)]
pub enum ActionDigestError {
    /// The cv is the identity point, so the digest cannot be computed.
    IdentityCv,
    /// The rk is the identity point, so the digest cannot be computed.
    IdentityRk,
}

impl fmt::Display for ActionDigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::IdentityCv => write!(f, "cv is the identity point"),
            | Self::IdentityRk => write!(f, "rk is the identity point"),
        }
    }
}

impl Error for ActionDigestError {}

impl ActionDigest {
    /// Digest a single action's $(\mathsf{cv}, \mathsf{rk})$ pair.
    pub fn new(
        cv: value::Commitment,
        rk: public::ActionVerificationKey,
    ) -> Result<Self, ActionDigestError> {
        let cv_coords = EpAffine::from(cv)
            .coordinates()
            .into_option()
            .ok_or(ActionDigestError::IdentityCv)?;
        let rk_coords = EpAffine::from(rk)
            .coordinates()
            .into_option()
            .ok_or(ActionDigestError::IdentityRk)?;
        Ok(Self(poseidon::action_digest(cv_coords, rk_coords)))
    }
}

/// Extract the inner field element (polynomial root).
impl From<ActionDigest> for Fp {
    fn from(digest: ActionDigest) -> Self {
        digest.0
    }
}

impl From<Fp> for ActionDigest {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

impl From<ActionDigest> for [u8; 32] {
    fn from(digest: ActionDigest) -> Self {
        digest.0.to_repr()
    }
}

impl TryFrom<&[u8; 32]> for ActionDigest {
    type Error = &'static str;

    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        let fp: Fp = Option::from(Fp::from_repr(*bytes)).ok_or("invalid field element")?;
        Ok(Self(fp))
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;
    use core::iter;

    use rand::{CryptoRng, RngCore, SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        entropy::ActionEntropy,
        keys::private,
        note::{self, Note, ProNf},
        primitives::{ProNfSeqPoly, effect},
        value,
    };

    fn make_action_parts<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        val: u64,
    ) -> (value::Commitment, public::ActionVerificationKey) {
        let sk = private::SpendingKey::random(rng);
        let pronfs: Vec<ProNf> = iter::repeat_with(|| ProNf::random(rng)).take(8).collect();
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(val),
            psi: ProNfSeqPoly::from(pronfs.as_slice()).commit(),
            rcm: note::CommitmentTrapdoor::random(rng),
        };
        let rcv = value::CommitmentTrapdoor::random(rng);
        let cv = rcv.commit(i64::from(note.value));
        let theta = ActionEntropy::random(rng);
        let alpha = theta.randomizer::<effect::Output>(note.commitment());
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        (cv, rk)
    }

    /// Different (cv, rk) pairs produce different digests.
    #[test]
    fn distinct_actions_distinct_digests() {
        let rng = &mut StdRng::seed_from_u64(0);
        let (cv_a, rk_a) = make_action_parts(rng, 1000);
        let (cv_b, rk_b) = make_action_parts(rng, 700);

        assert_ne!(
            ActionDigest::new(cv_a, rk_a).unwrap(),
            ActionDigest::new(cv_b, rk_b).unwrap()
        );
    }

    /// Identity cv is rejected.
    #[test]
    fn digest_rejects_identity_cv() {
        use pasta_curves::group::prime::PrimeCurveAffine as _;

        let rng = &mut StdRng::seed_from_u64(0);
        let (_, rk) = make_action_parts(rng, 500);
        let cv = value::Commitment::from(EpAffine::identity());
        assert!(matches!(
            ActionDigest::new(cv, rk),
            Err(ActionDigestError::IdentityCv)
        ));
    }

    /// Identity rk is rejected.
    #[test]
    fn digest_rejects_identity_rk() {
        let rng = &mut StdRng::seed_from_u64(0);
        let (cv, _) = make_action_parts(rng, 500);
        let rk =
            public::ActionVerificationKey(reddsa::VerificationKey::try_from([0u8; 32]).unwrap());
        assert!(matches!(
            ActionDigest::new(cv, rk),
            Err(ActionDigestError::IdentityRk)
        ));
    }
}
