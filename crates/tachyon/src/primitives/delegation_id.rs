use ff::Field as _;
use pasta_curves::Fp;
use rand_core::{CryptoRng, RngCore};

/// Per-delegation identifier binding a note's master key and commitment to a
/// caller-supplied trapdoor.
///
/// Derived via
/// [`NullifierKey::derive_delegation_id`](crate::keys::NullifierKey::derive_delegation_id)
/// as `H(domain, mk, cm, trapdoor)`. A fresh trapdoor per delegation makes
/// different delegations of the same note produce unrelated identifiers, and
/// hides the note's identity from anyone who could otherwise guess its fields.
///
/// The trapdoor is witness material; only this derived value flows through
/// proof headers. Two proofs asserting the same `DelegationId` must have been
/// constructed with the same trapdoor, which is how the wallet links its own
/// proofs without letting the delegate forge the linkage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegationId(pub(crate) Fp);

impl From<&Fp> for DelegationId {
    fn from(fp: &Fp) -> Self {
        Self(*fp)
    }
}

impl From<&DelegationId> for Fp {
    fn from(id: &DelegationId) -> Self {
        id.0
    }
}

/// Delegation trapdoor — per-delegation randomness blinding
/// [`DelegationId`](crate::primitives::DelegationId).
///
/// Used to bind delegated proofs from the syncing service to user-generated
/// proofs involving the same note. Select a fresh value for every delegation.
#[derive(Clone, Copy, Debug)]
pub struct DelegationTrapdoor(Fp);

impl DelegationTrapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(Fp::random(rng))
    }
}

impl From<&Fp> for DelegationTrapdoor {
    fn from(fp: &Fp) -> Self {
        Self(*fp)
    }
}

impl From<&DelegationTrapdoor> for Fp {
    fn from(trap: &DelegationTrapdoor) -> Self {
        trap.0
    }
}
