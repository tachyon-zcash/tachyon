//! Value commitments and bounded value types.

use core::{cmp, ops};

use derive_more::{Add, Debug, Display, Eq as TotalEq, Error, From, Into, PartialEq, Sub, Sum};
use ff::Field as _;
use group::{Curve as _, GroupEncoding as _};
use lazy_static::lazy_static;
use pasta_curves::{Ep, EpAffine, Fq, arithmetic::CurveExt as _};
use rand_core::CryptoRng;

use crate::constants::MAX_MONEY;

/// Alias for [`ValueTrapdoor`].
pub type Trapdoor = ValueTrapdoor;

/// Alias for [`ValueCommitment`].
pub type Commitment = ValueCommitment;

/// An integer bounded to `-MAX_MONEY..=MAX_MONEY`.
pub type Balance = Value<{ -MAX_MONEY.cast_signed() }, { MAX_MONEY.cast_signed() }>;

/// A non-negative integer not greater than `MAX_MONEY`.
pub type Positive = Value<0, { MAX_MONEY.cast_signed() }>;

/// A non-positive integer not less than `-MAX_MONEY`.
pub type Negative = Value<{ -MAX_MONEY.cast_signed() }, 0>;

/// Shared with Orchard (§5.4.8.3).
const VALUE_COMMITMENT_DOMAIN: &str = "z.cash:Orchard-cv";

lazy_static! {
    /// Generator $\mathcal{V}$ for value commitments.
    static ref VALUE_COMMIT_V: Ep = Ep::hash_to_curve(VALUE_COMMITMENT_DOMAIN)(b"v");

    /// Generator $\mathcal{R}$ for value commitments and binding signatures.
    static ref VALUE_COMMIT_R: Ep = Ep::hash_to_curve(VALUE_COMMITMENT_DOMAIN)(b"r");
}

/// Entropy for a value commitment.
///
/// Each action gets a fresh trapdoor, to commit its value secretly.
/// $\mathsf{cv} = \[v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R}$.
///
/// The bundle's binding signing key is the scalar sum of trapdoors:
/// $\mathsf{bsk} = \boxplus_i \mathsf{rcv}_i$
/// ($\mathbb{F}_q$, Pallas scalar field).
#[derive(Clone, Copy, Debug, Default, Into)]
#[expect(clippy::module_name_repetitions, reason = "deliberate name")]
pub struct ValueTrapdoor(#[debug(skip)] Fq);

impl Trapdoor {
    /// The zero trapdoor.
    pub const ZERO: Self = Self(Fq::ZERO);

    /// Generate a random trapdoor.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fq::random(rng))
    }

    /// A trapdoor derived from other secret data, such as a max fee note's
    /// blind.
    pub(crate) const fn from_scalar(scalar: Fq) -> Self {
        Self(scalar)
    }

    /// Commit to a given value with this trapdoor.
    ///
    /// $$
    ///   \mathsf{cv} = \[v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R}
    /// $$
    ///
    /// where $\mathcal{V}$, $\mathcal{R}$ are generator points shared with
    /// Orchard (§5.4.8.3).
    #[must_use]
    pub fn commit<const MIN: i64, const MAX: i64>(self, value: Value<MIN, MAX>) -> Commitment {
        let commit_value = *VALUE_COMMIT_V * Fq::from(value);
        let commit_trapdoor = *VALUE_COMMIT_R * self.0;
        ValueCommitment(commit_value + commit_trapdoor)
    }
}

/// A value commitment for Tachyon.
///
/// $$
///   \mathsf{cv} = \[v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R}
/// $$
///
/// where $\mathcal{V}$, $\mathcal{R}$ are generator points
/// shared with Orchard (§5.4.8.3).
#[derive(Add, Clone, Copy, Debug, Default, From, Into, PartialEq, Sub, Sum, TotalEq)]
#[expect(clippy::module_name_repetitions, reason = "deliberate name")]
pub struct ValueCommitment(#[debug(skip)] Ep);

impl From<EpAffine> for Commitment {
    fn from(value: EpAffine) -> Self {
        Self(value.into())
    }
}

impl From<Commitment> for EpAffine {
    fn from(value: Commitment) -> Self {
        value.0.to_affine()
    }
}

impl From<Commitment> for [u8; 32] {
    fn from(value: Commitment) -> Self {
        EpAffine::from(value).to_bytes()
    }
}

/// A value bounded to `MIN..=MAX` (inclusive), backed by `i64`.
///
/// This could be replaced with `ranged_integers` if it was stable.
#[derive(Clone, Copy, Debug, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct Value<const MIN: i64, const MAX: i64>(i64);

impl From<Negative> for Balance {
    fn from(value: Negative) -> Self {
        Self(value.0)
    }
}

impl From<Positive> for Balance {
    fn from(value: Positive) -> Self {
        Self(value.0)
    }
}

/// Error returned when a value falls outside its type's bound.
#[derive(Clone, Copy, Debug, Display, Error, PartialEq, TotalEq)]
#[display("value not in range")]
pub struct OutOfRange;

impl<const MIN: i64, const MAX: i64> Default for Value<MIN, MAX> {
    // Do not derive. This manual impl will hit the const assert.
    fn default() -> Self {
        Self::ZERO
    }
}

impl<const MIN: i64, const MAX: i64> Value<MIN, MAX> {
    /// The largest representable value within range.
    pub const MAX: Self = Self(MAX);
    /// The smallest representable value within range.
    pub const MIN: Self = Self(MIN);
    /// The zero value, if it is valid. Checked at compile time.
    ///
    /// ```compile_fail
    /// # use zcash_tachyon::value::Value;
    /// let _ = Value::<1, 2>::ZERO; // does not compile
    /// ```
    pub const ZERO: Self = {
        assert!(
            MIN <= 0 && 0 <= MAX,
            "Value::<MIN, MAX>::ZERO requires MIN <= 0 <= MAX"
        );
        Self(0)
    };

    /// Negate the value into the negative range.
    ///
    /// This isn't a `Neg` impl because const generic expressions are unstable.
    #[must_use]
    pub const fn negate<const NEG_MAX: i64, const NEG_MIN: i64>(self) -> Value<NEG_MAX, NEG_MIN> {
        const {
            assert!(
                NEG_MAX == -MAX && NEG_MIN == -MIN,
                "NEG_MAX must be -MAX and NEG_MIN must be -MIN"
            );
        }
        Value(-self.0)
    }
}

impl<const MIN: i64, const MAX: i64> TryFrom<i64> for Value<MIN, MAX> {
    type Error = OutOfRange;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        if MIN <= value && value <= MAX {
            Ok(Self(value))
        } else {
            Err(OutOfRange)
        }
    }
}

impl<const MIN: i64, const MAX: i64> TryFrom<u64> for Value<MIN, MAX> {
    type Error = OutOfRange;

    fn try_from(u_value: u64) -> Result<Self, Self::Error> {
        Self::try_from(i64::try_from(u_value).map_err(|_err| OutOfRange)?)
    }
}

// Some literals are i32 unless explicitly named as i64, so this helps.
impl<const MIN: i64, const MAX: i64> TryFrom<i32> for Value<MIN, MAX> {
    type Error = OutOfRange;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::try_from(i64::from(value))
    }
}

impl<const MIN: i64, const MAX: i64> TryFrom<i128> for Value<MIN, MAX> {
    type Error = OutOfRange;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        Self::try_from(i64::try_from(value).map_err(|_err| OutOfRange)?)
    }
}

impl<const MIN: i64, const MAX: i64> From<Value<MIN, MAX>> for i128 {
    fn from(value: Value<MIN, MAX>) -> Self {
        Self::from(value.0)
    }
}

impl<const MAX: i64> From<Value<0, MAX>> for u64 {
    fn from(value: Value<0, MAX>) -> Self {
        value.0.unsigned_abs()
    }
}

impl<const MIN: i64, const MAX: i64> From<Value<MIN, MAX>> for Fq {
    /// Signed value as a Pallas scalar, for use as the `V`-component
    /// exponent in a value commitment.
    fn from(value: Value<MIN, MAX>) -> Self {
        match value.0.cmp(&0) {
            cmp::Ordering::Equal => Self::ZERO,
            cmp::Ordering::Greater => Self::from(value.0.unsigned_abs()),
            cmp::Ordering::Less => Self::from(value.0.unsigned_abs()).neg(),
        }
    }
}

impl ops::Neg for Balance {
    type Output = Self;

    fn neg(self) -> Self {
        self.negate()
    }
}

impl ops::Neg for Negative {
    type Output = Positive;

    fn neg(self) -> Self::Output {
        self.negate()
    }
}

impl ops::Neg for Positive {
    type Output = Negative;

    fn neg(self) -> Self::Output {
        self.negate()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{constants::MAX_MONEY, testing::check};

    /// A signed amount around and beyond `±MAX_MONEY`.
    fn amount() -> impl Strategy<Value = i64> {
        let max = MAX_MONEY.cast_signed();
        prop_oneof![
            -max..=max,
            Just(max),
            Just(-max),
            Just(max + 1),
            Just(-max - 1),
            Just(0),
            any::<i64>(),
        ]
    }

    /// Any in-range signed amount.
    fn balance() -> impl Strategy<Value = i64> {
        -MAX_MONEY.cast_signed()..=MAX_MONEY.cast_signed()
    }

    /// Each range type holds exactly its bounds, from any integer width.
    #[test]
    fn a_value_type_holds_exactly_its_range() {
        check(256, (amount(), any::<u64>()), |(value, wide)| {
            let max = MAX_MONEY.cast_signed();
            prop_assert_eq!(
                Balance::try_from(value).is_ok(),
                (-max..=max).contains(&value)
            );
            prop_assert_eq!(
                Positive::try_from(value).is_ok(),
                (0..=max).contains(&value)
            );
            prop_assert_eq!(
                Negative::try_from(value).is_ok(),
                (-max..=0).contains(&value)
            );
            prop_assert_eq!(
                Balance::try_from(i128::from(value)),
                Balance::try_from(value)
            );
            prop_assert_eq!(Positive::try_from(wide).is_ok(), wide <= MAX_MONEY);
            Ok(())
        });
    }

    /// Negation stays in range and the scalar of a value and of its negation
    /// cancel.
    #[test]
    fn negation_mirrors_the_scalar() {
        check(256, balance(), |value| {
            let amount = Balance::try_from(value).unwrap();
            prop_assert_eq!(i128::from(-amount), -i128::from(value));
            prop_assert_eq!(-(-amount), amount);
            prop_assert_eq!(Fq::from(amount) + Fq::from(-amount), Fq::ZERO);
            Ok(())
        });
    }

    /// The binding property: $\mathsf{cv}_a + \mathsf{cv}_b$ less a
    /// trapdoor-free commitment to $a + b$ leaves $[\mathsf{rcv}_a +
    /// \mathsf{rcv}_b]\mathcal{R}$, the value components cancelling.
    #[test]
    fn commitments_are_homomorphic() {
        check(
            256,
            (any::<u64>(), balance(), balance()),
            |(seed, left, right)| {
                let sum = Balance::try_from(i128::from(left) + i128::from(right));
                prop_assume!(sum.is_ok());
                let rng = &mut StdRng::seed_from_u64(seed);
                let (rcv_left, rcv_right) = (Trapdoor::random(rng), Trapdoor::random(rng));
                let remainder = rcv_left.commit(Balance::try_from(left).unwrap())
                    + rcv_right.commit(Balance::try_from(right).unwrap())
                    - Trapdoor::ZERO.commit(sum.unwrap());
                prop_assert_eq!(
                    remainder,
                    ValueCommitment(*VALUE_COMMIT_R * (Fq::from(rcv_left) + Fq::from(rcv_right)))
                );
                prop_assert_eq!(Trapdoor::ZERO.commit(Balance::ZERO), Commitment::default());
                Ok(())
            },
        );
    }

    #[test]
    fn debug_redacts_trapdoors_and_commitments() {
        check(256, (any::<u64>(), 0..=MAX_MONEY), |(seed, value)| {
            let rcv = Trapdoor::random(&mut StdRng::seed_from_u64(seed));
            let cv = rcv.commit(Positive::try_from(value).unwrap());
            prop_assert_eq!(alloc::format!("{rcv:?}"), "ValueTrapdoor(..)");
            prop_assert_eq!(alloc::format!("{cv:?}"), "ValueCommitment(..)");
            Ok(())
        });
    }
}
