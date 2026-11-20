//! Compile-time effect markers for spend vs output actions.
//!
//! [`Spend`] and [`Output`] are zero-sized marker types that parameterize
//! [`Plan`](crate::action::Plan),
//! [`ActionRandomizer`](crate::entropy::ActionRandomizer),
//! [`ActionSigningKey`](crate::keys::private::ActionSigningKey), and key types
//! to enforce the spend/output distinction at compile time.

use ragu::udon::field::Field as _;

use crate::digest::poseidon;
use crate::entropy::ActionEntropy;
use crate::pasta::{Fp, Fq};
use crate::{note, value};

/// Embeds a base-field element in the scalar field, which is larger.
///
/// # Panics
///
/// Panics if the base-field representation is not canonical in the scalar
/// field. This is unreachable because `p < q`, so every `Fp` value is a valid
/// `Fq` representation.
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "p < q, so every Fp repr is canonical in Fq"
)]
fn embed(alpha: Fp) -> Fq {
    Fq::from_bytes(alpha.to_bytes()).expect("p < q")
}

mod sealed {
    pub trait Sealed: Copy {}
    impl Sealed for super::Spend {}
    impl Sealed for super::Output {}
}

/// Sealed trait marking an action effect (spend or output).
pub trait Effect: sealed::Sealed {
    /// Derive this effect's $\alpha$ scalar from per-action entropy and a note
    /// commitment.
    #[must_use]
    fn derive_alpha(theta: ActionEntropy, cm: note::Commitment) -> Fq;

    /// Commit to this effect's signed value contribution using the given
    /// trapdoor.
    #[must_use]
    fn commit_value(rcv: value::Trapdoor, value: value::Positive) -> value::Commitment;
}

/// Spend effect marker.
#[derive(Clone, Copy, Debug)]
pub struct Spend;

/// Output effect marker.
#[derive(Clone, Copy, Debug)]
pub struct Output;

impl Effect for Spend {
    fn derive_alpha(theta: ActionEntropy, cm: note::Commitment) -> Fq {
        embed(poseidon::alpha_spend(theta.0, cm.into()))
    }

    fn commit_value(rcv: value::Trapdoor, value: value::Positive) -> value::Commitment {
        rcv.commit(value)
    }
}

impl Effect for Output {
    fn derive_alpha(theta: ActionEntropy, cm: note::Commitment) -> Fq {
        embed(poseidon::alpha_output(theta.0, cm.into()))
    }

    fn commit_value(rcv: value::Trapdoor, value: value::Positive) -> value::Commitment {
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "a positive note amount has a representable negative counterpart"
        )]
        rcv.commit(-value)
    }
}
