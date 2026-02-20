//! Signature types that bridge private (sign) and public (verify) keys.

use reddsa::orchard::{Binding, SpendAuth};

/// A spend authorization signature (RedPallas over SpendAuth).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpendAuthSignature(pub reddsa::Signature<SpendAuth>);

impl From<[u8; 64]> for SpendAuthSignature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(reddsa::Signature::<SpendAuth>::from(bytes))
    }
}

impl From<SpendAuthSignature> for [u8; 64] {
    fn from(sig: SpendAuthSignature) -> [u8; 64] {
        <[u8; 64]>::from(sig.0)
    }
}

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
pub struct BindingSignature(pub reddsa::Signature<Binding>);

impl From<[u8; 64]> for BindingSignature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes.into())
    }
}

impl From<BindingSignature> for [u8; 64] {
    fn from(sig: BindingSignature) -> Self {
        sig.0.into()
    }
}
