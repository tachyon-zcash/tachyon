//! Compile-time effect markers for spend vs output actions.
//!
//! [`Spend`] and [`Output`] are zero-sized marker types that parameterize
//! [`Plan`](crate::action::Plan),
//! [`ActionRandomizer`](crate::entropy::ActionRandomizer),
//! [`ActionSigningKey`](crate::keys::private::ActionSigningKey), and key types
//! to enforce the spend/output distinction at compile time.

use ff::{FromUniformBytes as _, PrimeField as _};
use pasta_curves::{Fp, Fq};

use crate::{digest::blake2b, entropy::ActionEntropy, note, value};

mod sealed {
    pub trait Sealed: Copy {}
    impl Sealed for super::Spend {}
    impl Sealed for super::Output {}
}

/// Sealed trait marking an action effect (spend or output).
pub trait Effect: sealed::Sealed + 'static {
    /// Derive this effect's $\alpha$ scalar from per-action entropy and a note
    /// commitment.
    ///
    /// TODO: finalize alpha derivation spec. poseidon, or other native Fq?
    fn derive_alpha(theta: ActionEntropy, cm: note::Commitment) -> Fq;

    /// Commit to this effect's signed value contribution using the given
    /// trapdoor.
    fn commit_value(rcv: value::CommitmentTrapdoor, value: note::Value) -> value::Commitment;
}

/// Spend effect marker.
#[derive(Clone, Copy, Debug)]
pub struct Spend;

/// Output effect marker.
#[derive(Clone, Copy, Debug)]
pub struct Output;

impl Effect for Spend {
    fn derive_alpha(theta: ActionEntropy, cm: note::Commitment) -> Fq {
        Fq::from_uniform_bytes(&blake2b::alpha_spend(&theta.0, &Fp::from(cm).to_repr()))
    }

    fn commit_value(rcv: value::CommitmentTrapdoor, value: note::Value) -> value::Commitment {
        rcv.commit(i64::from(value))
    }
}

impl Effect for Output {
    fn derive_alpha(theta: ActionEntropy, cm: note::Commitment) -> Fq {
        Fq::from_uniform_bytes(&blake2b::alpha_output(&theta.0, &Fp::from(cm).to_repr()))
    }

    fn commit_value(rcv: value::CommitmentTrapdoor, value: note::Value) -> value::Commitment {
        rcv.commit(-i64::from(value))
    }
}
