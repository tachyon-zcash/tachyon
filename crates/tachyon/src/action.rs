#![allow(clippy::from_over_into)]

//! Tachyon Action descriptions.

use std::iter::Sum;
use std::ops;
use std::sync::LazyLock;

use ff::Field;
use pasta_curves::group::GroupEncoding;
use pasta_curves::group::prime::PrimeCurveAffine;
use pasta_curves::{arithmetic::CurveExt, pallas};
use rand::{CryptoRng, RngCore};

use crate::circuit::ActionWitness;
use crate::constants::VALUE_COMMITMENT_DOMAIN;
use crate::keys::{
    Binding, RandomizedSigningKey, RandomizedVerificationKey, SpendAuthRandomizer,
    SpendAuthSignature, SpendAuthorizingKey, VerificationKey,
};
use crate::note::{Note, Nullifier};
use crate::primitives::{EpAffine, Epoch, Fq};

/// A Tachyon Action description.
///
///
/// ## Fields
///
/// - `cv`: Value commitment to net value (input - output)
/// - `rk`: Randomized spend authorization key
/// - `sig`: RedPallas authorization by `rk`
///
/// ## Note
///
/// The tachygram (nullifier or note commitment) is NOT part of the action.
/// Tachygrams are collected separately in the
/// [`Stamp`](crate::stamp::Stamp).  However, `rk` is not a
/// direct input to the Ragu proof -- each `rk` is cryptographically bound to
/// its corresponding tachygram, which *is* a proof input, so the proof
/// validates `rk` transitively.
///
/// This separation allows the stamp to be stripped during aggregation
/// while the action (with its authorization) remains in the transaction.
#[derive(Clone, Debug)]
pub struct Action {
    /// Value commitment to net value (input - output).
    pub cv: ValueCommitment,

    /// Randomized spend authorization key.
    pub rk: RandomizedVerificationKey,

    /// RedPallas authorization by `rk`.
    pub sig: SpendAuthSignature,
}

impl Action {
    fn new<R: RngCore + CryptoRng>(
        rsk: &RandomizedSigningKey,
        cv: ValueCommitment,
        rng: &mut R,
    ) -> Self {
        let rk = RandomizedVerificationKey::from(rsk);

        let msg = {
            let cv_bytes: [u8; 32] = cv.0.to_bytes();
            let rk_bytes: [u8; 32] = rk.to_bytes();
            let mut msg = [0u8; 64];
            msg[..32].copy_from_slice(&cv_bytes);
            msg[32..].copy_from_slice(&rk_bytes);
            msg
        };

        Self {
            cv,
            rk,
            sig: rsk.sign(rng, &msg),
        }
    }

    /// Consume a note.
    #[allow(clippy::expect_used)]
    pub fn spend<R: RngCore + CryptoRng>(
        ask: &SpendAuthorizingKey,
        note: Note,
        nf: Nullifier,
        flavor: Epoch,
        rng: &mut R,
    ) -> (Self, ActionWitness) {
        let alpha = SpendAuthRandomizer::random(&mut *rng);
        let rsk = ask.randomize(&alpha);
        let value = i64::try_from(note.value).expect("value fits in i64");
        let (rcv, cv) = ValueCommitment::commit(value, rng);

        (
            Self::new(&rsk, cv, rng),
            ActionWitness {
                tachygram: nf.into(),
                alpha,
                flavor,
                note,
                rcv,
            },
        )
    }

    /// Create a note.
    #[allow(clippy::expect_used)]
    pub fn output<R: RngCore + CryptoRng>(
        note: Note,
        flavor: Epoch,
        rng: &mut R,
    ) -> (Self, ActionWitness) {
        let alpha = SpendAuthRandomizer::random(&mut *rng);
        let rsk = RandomizedSigningKey::for_output(&alpha);
        let value = -i64::try_from(note.value).expect("value fits in i64");
        let (rcv, cv) = ValueCommitment::commit(value, rng);

        (
            Self::new(&rsk, cv, rng),
            ActionWitness {
                tachygram: note.commitment().into(),
                alpha,
                flavor,
                rcv,
                note,
            },
        )
    }
}

/// Generator V for value commitments.
#[allow(non_snake_case)]
static VALUE_COMMIT_V: LazyLock<pallas::Point> =
    LazyLock::new(|| pallas::Point::hash_to_curve(VALUE_COMMITMENT_DOMAIN)(b"v"));

/// Generator R for value commitments and binding signatures.
#[allow(non_snake_case)]
static VALUE_COMMIT_R: LazyLock<pallas::Point> =
    LazyLock::new(|| pallas::Point::hash_to_curve(VALUE_COMMITMENT_DOMAIN)(b"r"));

/// A value commitment for a Tachyon action.
///
/// Commits to the value being transferred in an action without revealing it.
/// This is a Pedersen commitment (curve point) used in value balance verification.
///
/// The commitment has the form: `[v] V + [rcv] R` where:
/// - `v` is the value
/// - `rcv` is the randomness
/// - `V` and `R` are generator points derived from [`VALUE_COMMITMENT_DOMAIN`]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueCommitment(EpAffine);

impl ValueCommitment {
    /// Create a value commitment from a signed value and randomness.
    ///
    /// `cv = [v] V + [rcv] R`
    ///
    /// Positive for spends (balance contributed), negative for outputs (balance exhausted).
    #[allow(non_snake_case)]
    pub fn commit(v: i64, rng: &mut impl RngCore) -> (Fq, Self) {
        let rcv = Fq::random(&mut *rng);

        let scalar = if v >= 0 {
            Fq::from(v.cast_unsigned())
        } else {
            -Fq::from((-v).cast_unsigned())
        };

        (
            rcv,
            Self((*VALUE_COMMIT_V * scalar + *VALUE_COMMIT_R * rcv).into()),
        )
    }

    /// Create the value balance commitment `[value_balance] V`.
    ///
    /// This is `commit(value_balance, 0)` — a deterministic commitment with
    /// no randomness. Used by validators to derive the binding verification key:
    ///
    /// `bvk = sum(cv_i) - ValueCommitment::balance(value_balance)`
    #[must_use]
    pub fn balance(v: i64) -> Self {
        let rcv = Fq::ZERO;

        let scalar = if v >= 0 {
            Fq::from(v.cast_unsigned())
        } else {
            -Fq::from((-v).cast_unsigned())
        };

        Self((*VALUE_COMMIT_V * scalar + *VALUE_COMMIT_R * rcv).into())
    }
}

impl Into<VerificationKey<Binding>> for ValueCommitment {
    fn into(self) -> VerificationKey<Binding> {
        VerificationKey::<Binding>::try_from(self.0.to_bytes())
            .expect("valid curve point yields valid verification key")
    }
}

impl From<ValueCommitment> for EpAffine {
    fn from(cv: ValueCommitment) -> Self {
        cv.0
    }
}

impl ops::Add for ValueCommitment {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self((self.0 + rhs.0).into())
    }
}

impl ops::Sub for ValueCommitment {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self((self.0 - rhs.0).into())
    }
}

impl Sum for ValueCommitment {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self(EpAffine::identity()), ops::Add::add)
    }
}
