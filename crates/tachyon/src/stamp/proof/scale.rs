//! Wallet-private radix-8 multiplication certificates.
//!
//! Each base has a unique producer at windows 24, 54 and 85. Limbs encode
//! the canonical integer separately across the 128-bit boundary. Headers
//! contain secret scalars and belong to the prover's private proof tree.

use alloc::{vec, vec::Vec};
use core::{array, marker::PhantomData};

use derive_more::{From, Into};
use lazy_static::lazy_static;
use ragu::{Header, Index, Step, Suffix};
use rand_core::CryptoRng;
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use super::{
    super::super::{
        constants::MAX_MONEY,
        keys::public::ActionVerificationKey,
        pasta::{Ep, EpAffine, Eq, Fp, Fq},
        ragu_constraint::enforce_zero,
        reddsa, value,
    },
    PROOF_SYSTEM,
};

/// Low 128 bits of a canonical scalar.
#[derive(Clone, Copy, Debug, From, Into)]
pub struct ScalarLo(Fp);

/// High 127 bits of a canonical scalar.
#[derive(Clone, Copy, Debug, From, Into)]
pub struct ScalarHi(Fp);

/// Finite carrier of a tagged logical point.
#[derive(Clone, Copy, Debug)]
pub struct Carrier(EpAffine);

/// Identity tag; a true tag requires the standard Pallas generator carrier.
#[derive(Clone, Copy, Debug)]
pub struct IdentityFlag(bool);

/// Value-commitment blinding base.
#[derive(Clone, Copy, Debug, Default)]
pub struct R;

/// Action-authorization base.
#[derive(Clone, Copy, Debug, Default)]
pub struct G;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::R {}
    impl Sealed for super::G {}
}

/// Fixed protocol base and its registry positions.
pub trait Base: sealed::Sealed + Copy + core::fmt::Debug + Send + Sync + 'static {
    /// Index of the Start registration.
    const INDEX: usize;
    /// Suffix of the state after 24 windows.
    const SUFFIX: usize;
    /// Fixed radix-8 table.
    fn table() -> &'static [[EpAffine; 8]; 85];
}

impl Base for R {
    const INDEX: usize = 39;
    const SUFFIX: usize = 17;

    fn table() -> &'static [[EpAffine; 8]; 85] {
        &R_TABLE
    }
}

impl Base for G {
    const INDEX: usize = 42;
    const SUFFIX: usize = 20;

    fn table() -> &'static [[EpAffine; 8]; 85] {
        &G_TABLE
    }
}

lazy_static! {
    static ref R_TABLE: [[EpAffine; 8]; 85] = table(Ep::from(
        value::Trapdoor::from_scalar(Fq::ONE).commit(value::Positive::ZERO)
    ));
    static ref G_TABLE: [[EpAffine; 8]; 85] = {
        #[expect(clippy::expect_used, reason = "one is a canonical signing scalar")]
        let signing = reddsa::SigningKey::<reddsa::ActionAuth>::try_from(Fq::ONE.to_bytes())
            .expect("canonical signing scalar");
        let key = ActionVerificationKey(reddsa::VerificationKey::from(&signing));
        table(Ep::from(EpAffine::from(key)))
    };
    static ref V_TABLE: [[EpAffine; 8]; 17] = {
        #[expect(clippy::expect_used, reason = "one is in the monetary range")]
        let one = value::Positive::try_from(1).expect("one is bounded");
        table(Ep::from(value::Trapdoor::ZERO.commit(one)))
    };
    static ref NEG_V_TABLE: [[EpAffine; 8]; 17] = {
        #[expect(clippy::expect_used, reason = "one is in the monetary range")]
        let one = value::Positive::try_from(1).expect("one is bounded");
        table(-Ep::from(value::Trapdoor::ZERO.commit(one)))
    };
}

pub(super) fn initialize() {
    lazy_static::initialize(&R_TABLE);
    lazy_static::initialize(&G_TABLE);
    lazy_static::initialize(&V_TABLE);
    lazy_static::initialize(&NEG_V_TABLE);
}

fn table<const N: usize>(mut power: Ep) -> [[EpAffine; 8]; N] {
    array::from_fn(|_| {
        let mut multiple = Ep::identity();
        let row = array::from_fn(|_| {
            let entry = multiple.to_affine();
            multiple += power;
            entry
        });
        power = power.double().double().double();
        row
    })
}

/// Private partial product after a fixed number of windows.
#[derive(Debug)]
pub struct ScaleState<B: Base, const WINDOWS: usize>(PhantomData<B>);

/// Private completed full-width product.
#[derive(Debug)]
pub struct ScaleResult<B: Base>(PhantomData<B>);

fn encode(
    (lo, hi, point, identity): &(ScalarLo, ScalarHi, Carrier, IdentityFlag),
) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
    (
        vec![lo.0, hi.0, Fp::from(u64::from(identity.0))],
        Vec::new(),
        vec![Ep::from(point.0)],
        Vec::new(),
    )
}

macro_rules! state_header {
    ($windows:literal, $offset:literal) => {
        impl<B: Base> Header for ScaleState<B, $windows> {
            /// `(lo, hi, point, is_identity)`
            type Data = (ScalarLo, ScalarHi, Carrier, IdentityFlag);

            const SUFFIX: Suffix = Suffix::new(B::SUFFIX + $offset);

            fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
                encode(data)
            }
        }
    };
}

state_header!(24, 0);
state_header!(54, 1);

impl<B: Base> Header for ScaleResult<B> {
    /// `(lo, hi, point, is_identity)`
    type Data = (ScalarLo, ScalarHi, Carrier, IdentityFlag);

    const SUFFIX: Suffix = Suffix::new(B::SUFFIX + 2);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        encode(data)
    }
}

/// Establishes canonical scalar limbs and the first 24 windows. No polynomials.
#[derive(Debug, Default)]
pub struct ScaleStart<B: Base>(PhantomData<B>);

/// Extends the authenticated product from window 24 to 54. No polynomials.
#[derive(Debug, Default)]
pub struct ScaleMiddle<B: Base>(PhantomData<B>);

/// Completes the authenticated product from window 54 to 85. No polynomials.
#[derive(Debug, Default)]
pub struct ScaleEnd<B: Base>(PhantomData<B>);

fn limbs(bits: &[bool; 255]) -> (ScalarLo, ScalarHi) {
    let mut lo = Fp::ZERO;
    let mut hi = Fp::ZERO;
    for i in (0..128).rev() {
        lo = lo.double() + Fp::from(u64::from(bits[i]));
    }
    for i in (128..255).rev() {
        hi = hi.double() + Fp::from(u64::from(bits[i]));
    }
    (ScalarLo(lo), ScalarHi(hi))
}

fn canonical(bits: &[bool; 255]) -> ragu_core::Result<()> {
    let maximum = (-Fq::ONE).to_le_bits();
    for i in (0..255).rev() {
        if bits[i] != maximum.as_ref()[i] {
            return if bits[i] {
                Err(ragu_core::Error::InvalidWitness(
                    "ScaleStart: noncanonical scalar".into(),
                ))
            } else {
                Ok(())
            };
        }
    }
    Ok(())
}

fn export(point: Ep) -> (Carrier, IdentityFlag) {
    let affine = point.to_affine();
    let identity = affine.coordinates().is_none();
    (
        Carrier(if identity {
            EpAffine::generator()
        } else {
            affine
        }),
        IdentityFlag(identity),
    )
}

pub(super) fn decode(point: Carrier, identity: IdentityFlag) -> ragu_core::Result<Ep> {
    if point.0.coordinates().is_none() || (identity.0 && point.0 != EpAffine::generator()) {
        return Err(ragu_core::Error::InvalidWitness(
            "Scale: invalid tagged point".into(),
        ));
    }
    Ok(if identity.0 {
        Ep::identity()
    } else {
        Ep::from(point.0)
    })
}

fn select_coordinate(values: [Fp; 8], bits: [bool; 3]) -> Fp {
    let select = |low, high, bit| if bit { high } else { low };
    let first = array::from_fn::<_, 4, _>(|i| select(values[2 * i], values[2 * i + 1], bits[0]));
    let second = array::from_fn::<_, 2, _>(|i| select(first[2 * i], first[2 * i + 1], bits[1]));
    select(second[0], second[1], bits[2])
}

fn select_digit(row: &[EpAffine; 8], bits: [bool; 3]) -> ragu_core::Result<Ep> {
    let coords = row.map(|point| point.coordinates().unwrap_or((Fp::ZERO, Fp::ZERO)));
    let x = select_coordinate(coords.map(|pair| pair.0), bits);
    let y = select_coordinate(coords.map(|pair| pair.1), bits);
    if !bits[0] && !bits[1] && !bits[2] {
        enforce_zero(x, "Scale: zero digit x")?;
        enforce_zero(y, "Scale: zero digit y")?;
        Ok(Ep::identity())
    } else {
        EpAffine::from_xy(x, y)
            .map(Ep::from)
            .ok_or_else(|| ragu_core::Error::InvalidWitness("Scale: invalid selected point".into()))
    }
}

fn windows<const N: usize, const BITS: usize, const FIRST: usize, const END: usize>(
    table: &[[EpAffine; 8]; N],
    bits: &[bool; BITS],
    mut acc: Ep,
) -> ragu_core::Result<Ep> {
    for j in FIRST..END {
        acc += select_digit(&table[j], [bits[3 * j], bits[3 * j + 1], bits[3 * j + 2]])?;
    }
    Ok(acc)
}

impl<B: Base> Step for ScaleStart<B> {
    type Aux<'source> = ();
    type Left = ();
    type Output = ScaleState<B, 24>;
    type Right = ();
    /// `(bits)`
    type Witness<'source> = ([bool; 255],);

    const INDEX: Index = Index::new(B::INDEX);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (bits,): Self::Witness<'source>,
        (): (),
        (): (),
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        canonical(&bits)?;
        let (lo, hi) = limbs(&bits);
        let (point, identity) = export(windows::<85, 255, 0, 24>(
            B::table(),
            &bits,
            Ep::identity(),
        )?);
        Ok(((lo, hi, point, identity), ()))
    }
}

macro_rules! continuation {
    ($step:ident, $left:ty, $output:ty, $offset:literal, $first:literal, $end:literal) => {
        impl<B: Base> Step for $step<B> {
            type Aux<'source> = ();
            type Left = $left;
            type Output = $output;
            type Right = ();
            /// `(bits)`
            type Witness<'source> = ([bool; 255],);

            const INDEX: Index = Index::new(B::INDEX + $offset);

            fn witness<'source>(
                &self,
                _ctx: &mut ragu::StepCtx<'_>,
                (bits,): Self::Witness<'source>,
                (lo, hi, point, identity): <Self::Left as Header>::Data,
                (): (),
            ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
                let (actual_lo, actual_hi) = limbs(&bits);
                enforce_zero(actual_lo.0 - lo.0, "Scale: low limb mismatch")?;
                enforce_zero(actual_hi.0 - hi.0, "Scale: high limb mismatch")?;
                let acc = decode(point, identity)?;
                let (output_point, output_identity) =
                    export(windows::<85, 255, $first, $end>(B::table(), &bits, acc)?);
                Ok(((lo, hi, output_point, output_identity), ()))
            }
        }
    };
}

continuation!(ScaleMiddle, ScaleState<B, 24>, ScaleState<B, 54>, 1, 24, 54);
continuation!(ScaleEnd, ScaleState<B, 54>, ScaleResult<B>, 2, 54, 85);

/// Prepare a full-width scalar's ordered bits.
#[must_use]
pub fn scalar_bits(scalar: Fq) -> [bool; 255] {
    let bits = scalar.to_le_bits();
    array::from_fn(|i| bits.as_ref()[i])
}

/// Prove the three private stages for a fixed base.
///
/// # Errors
///
/// Returns a proof-system error if a stage fails.
pub fn prove<B: Base + Default, RNG: CryptoRng>(
    rng: &mut RNG,
    scalar: Fq,
) -> ragu_core::Result<ragu::Pcd<ScaleResult<B>>> {
    let bits = scalar_bits(scalar);
    let (start, ()) = PROOF_SYSTEM.seed(rng, ScaleStart::<B>::default(), (bits,))?;
    let (middle, ()) = PROOF_SYSTEM.fuse(
        rng,
        ScaleMiddle::<B>::default(),
        (bits,),
        start,
        ragu::Proof::bootstrap().carry::<()>(()),
    )?;
    let (end, ()) = PROOF_SYSTEM.fuse(
        rng,
        ScaleEnd::<B>::default(),
        (bits,),
        middle,
        ragu::Proof::bootstrap().carry::<()>(()),
    )?;
    Ok(end)
}

pub(super) fn match_scalar(scalar: Fq, lo: ScalarLo, hi: ScalarHi) -> ragu_core::Result<()> {
    let (expected_lo, expected_hi) = limbs(&scalar_bits(scalar));
    enforce_zero(lo.0 - expected_lo.0, "Scale: scalar low limb mismatch")?;
    enforce_zero(hi.0 - expected_hi.0, "Scale: scalar high limb mismatch")
}

pub(super) fn amount_bits(amount: value::Positive) -> ragu_core::Result<[bool; 51]> {
    let integer = u64::from(amount);
    if integer > MAX_MONEY {
        return Err(ragu_core::Error::InvalidWitness(
            "Scale: amount exceeds MAX_MONEY".into(),
        ));
    }
    let complement = MAX_MONEY - integer;
    let bits = array::from_fn(|i| (integer >> i) & 1 == 1);
    let complement_bits = array::from_fn::<_, 51, _>(|i| (complement >> i) & 1 == 1);
    let recompose = |input: [bool; 51]| {
        input
            .into_iter()
            .rev()
            .fold(0_u64, |acc, bit| 2 * acc + u64::from(bit))
    };
    if recompose(bits) + recompose(complement_bits) != MAX_MONEY {
        return Err(ragu_core::Error::InvalidWitness(
            "Scale: invalid amount bound".into(),
        ));
    }
    Ok(bits)
}

pub(super) fn value_product<const NEGATIVE: bool>(
    amount: value::Positive,
) -> ragu_core::Result<Ep> {
    let bits = amount_bits(amount)?;
    let table = if NEGATIVE { &*NEG_V_TABLE } else { &*V_TABLE };
    windows::<17, 51, 0, 17>(table, &bits, Ep::identity())
}

pub(super) fn finite(point: Ep) -> ragu_core::Result<EpAffine> {
    let affine = point.to_affine();
    affine.coordinates().ok_or_else(|| {
        ragu_core::Error::InvalidWitness("Scale: final point is the identity".into())
    })?;
    Ok(affine)
}
