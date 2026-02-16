#![allow(clippy::from_over_into)]

//! Tachyon Action descriptions.

use crate::constants::{SPEND_AUTH_PERSONALIZATION, VALUE_COMMITMENT_DOMAIN};
use crate::keys::{
    BindingVerificationKey, RandomizedSigningKey, RandomizedVerificationKey, SpendAuthRandomizer,
    SpendAuthSignature, SpendAuthorizingKey,
};
use crate::note::{self, Note};
use crate::primitives::{CurveExt, EpAffine, Epoch, Field, Fq, GroupEncoding, pallas};
use crate::value;
use crate::witness::ActionPrivate;
use rand::{CryptoRng, RngCore};
use std::ops;
use std::sync::LazyLock;

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
        let rk = rsk.verification_key();

        // H("Tachyon-SpendSig", cv || rk) — domain-separated signing message
        let msg = {
            let mut state = blake2b_simd::Params::new()
                .hash_length(64)
                .personal(SPEND_AUTH_PERSONALIZATION)
                .to_state();
            state.update(&EpAffine::from(cv).to_bytes());
            state.update(&<[u8; 32]>::from(&rk));
            *state.finalize().as_array()
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
        nf: note::Nullifier,
        flavor: Epoch,
        rng: &mut R,
    ) -> (Self, ActionPrivate) {
        let alpha = SpendAuthRandomizer::random(&mut *rng);
        let rsk = ask.randomize(&alpha);
        let value = i64::try_from(note.value).expect("value fits in i64");
        let (rcv, cv) = ValueCommitment::commit(value, rng);

        (
            Self::new(&rsk, cv, rng),
            ActionPrivate {
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
    ) -> (Self, ActionPrivate) {
        let alpha = SpendAuthRandomizer::random(&mut *rng);
        let rsk = RandomizedSigningKey::for_output(&alpha);
        let value = -i64::try_from(note.value).expect("value fits in i64");
        let (rcv, cv) = ValueCommitment::commit(value, rng);

        (
            Self::new(&rsk, cv, rng),
            ActionPrivate {
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
    pub fn commit(
        v: i64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (value::CommitmentTrapdoor, Self) {
        let rcv = value::CommitmentTrapdoor::random(&mut *rng);

        let scalar = if v >= 0 {
            Fq::from(v.cast_unsigned())
        } else {
            -Fq::from((-v).cast_unsigned())
        };

        let rcv_scalar: Fq = rcv.into();
        (
            rcv,
            Self((*VALUE_COMMIT_V * scalar + *VALUE_COMMIT_R * rcv_scalar).into()),
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

impl Into<BindingVerificationKey> for ValueCommitment {
    fn into(self) -> BindingVerificationKey {
        BindingVerificationKey::try_from(self.0.to_bytes())
            .expect("valid curve point yields valid verification key")
    }
}

impl From<ValueCommitment> for EpAffine {
    fn from(cv: ValueCommitment) -> Self {
        cv.0
    }
}

impl From<EpAffine> for ValueCommitment {
    fn from(affine: EpAffine) -> Self {
        Self(affine)
    }
}

impl TryFrom<&[u8; 32]> for ValueCommitment {
    type Error = &'static str;
    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        EpAffine::from_bytes(bytes)
            .into_option()
            .ok_or("invalid curve point")
            .map(Self)
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
