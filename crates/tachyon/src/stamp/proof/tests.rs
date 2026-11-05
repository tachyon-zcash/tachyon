//! Local step-wiring tests with raw predecessor headers, not authenticated
//! PCDs.
//!
//! Producer lineage correlates these epochs and anchors. Raw inputs let each
//! test break just one seam while preserving all other local relations.

use alloc::{string::ToString as _, vec::Vec};
use core::{iter, marker::PhantomData};

use ragu::{ApplicationBuilder, Encoded, Header, HeaderInput, Index, Oracles, Step, pasta::Pasta};
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe as _,
};
use rand::{SeedableRng as _, rngs::StdRng};

use super::{
    pool::{ArbitraryUnspent, NoteUnspent, UnspentFuse, UnspentLift},
    qr::QrBucket,
    spendable::{NoteSpendable, QrSpendableInit, SpendableLift},
};
use crate::{
    note,
    nullifier::Nullifier,
    pasta::{self, Fp},
    primitives::{
        Anchor, EpochIndex, NfSeqPoly, QrDiscriminant, QrProfile, Tachygram, TachygramSetPoly,
    },
    witness,
};

/// Deliberately uncertified inputs isolate the production step's local seams.
struct RawSeed<H, const I: usize>(PhantomData<H>);

impl<H: Header<Fp>, const I: usize> Step<Pasta> for RawSeed<H, I> {
    type Aux<'source> = ();
    type Left = ();
    type Output = H;
    type Right = ();
    type Witness<'source> = (H::Data, [Vec<Fp>; 3]);

    const INDEX: Index = Index::new(I);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, ()>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<[Vec<Fp>; 3]> {
        Ok(witness.1.clone())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const WIDTH: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), WIDTH>,
            Encoded<'dr, D, (), WIDTH>,
            Encoded<'dr, D, H, WIDTH>,
        ),
        DriverValue<D, H::Data>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let data = witness.map(|value| value.0);
        Ok((
            (
                Encoded::new(dr, &mut (), left)?,
                Encoded::new(dr, &mut (), right)?,
                Encoded::new(dr, &mut (), data.clone())?,
            ),
            data,
            D::unit(),
        ))
    }
}

struct RawInputs<'step, S>(&'step S);

impl<S: Step<Pasta>> Step<Pasta> for RawInputs<'_, S> {
    type Aux<'source> = S::Aux<'source>;
    type Left = S::Left;
    type Output = S::Output;
    type Right = S::Right;
    type Witness<'source> = S::Witness<'source>;

    const INDEX: Index = Index::new(2);
    const NUM_STAGED: usize = S::NUM_STAGED;

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> Result<[Vec<Fp>; 3]> {
        self.0.polynomials(witness, left, right)
    }

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> Result<Vec<Fp>> {
        self.0.staged(witness, left, right)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const WIDTH: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, WIDTH>,
            Encoded<'dr, D, Self::Right, WIDTH>,
            Encoded<'dr, D, Self::Output, WIDTH>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        self.0
            .witness::<D, WIDTH>(dr, oracles, witness, left, right)
    }
}

fn simulate_step<S>(
    step: &S,
    witness: S::Witness<'static>,
    left: <S::Left as Header<Fp>>::Data,
    right: <S::Right as Header<Fp>>::Data,
    children: [[Vec<Fp>; 3]; 2],
) -> Result<()>
where
    S: Step<Pasta>,
{
    let app = ApplicationBuilder::<Pasta, ProductionRank, { super::HEADER_SIZE }>::new()
        .register(RawSeed::<S::Left, 0>(PhantomData))?
        .register(RawSeed::<S::Right, 1>(PhantomData))?
        .register(RawInputs(step))?
        .finalize(pasta::baked())?;
    let [left_polys, right_polys] = children;
    let rng = &mut StdRng::seed_from_u64(0);
    let (left_pcd, ()) = app.seed(rng, RawSeed::<S::Left, 0>(PhantomData), (left, left_polys))?;
    let (right_pcd, ()) = app.seed(
        rng,
        RawSeed::<S::Right, 1>(PhantomData),
        (right, right_polys),
    )?;
    app.fuse(rng, RawInputs(step), witness, left_pcd, right_pcd)
        .map(|_| ())
}

#[test]
fn unspent_fuse_epoch_seam_rejects_raw_unequal_header_fields() {
    let first = NfSeqPoly::new(EpochIndex::new(0), &[Nullifier::from(Fp::from(23))]);
    let second = NfSeqPoly::new(EpochIndex::new(1), &[Nullifier::from(Fp::from(29))]);
    let left: <ArbitraryUnspent as Header<Fp>>::Data = (
        Anchor::from(Fp::from(11)),
        EpochIndex::new(0),
        first.commit(),
        EpochIndex::new(1),
        Anchor::from(Fp::from(13)),
    );
    let mut right: <ArbitraryUnspent as Header<Fp>>::Data = (
        left.4,
        left.3,
        second.commit(),
        EpochIndex::new(2),
        Anchor::from(Fp::from(17)),
    );
    let witness = (first.clone(), first * second.clone(), second);
    let mut children = [super::unit_polynomials(), super::unit_polynomials()];
    children[0][0] = super::coefficients(witness.0.as_ref());
    children[1][0] = super::coefficients(witness.2.as_ref());
    simulate_step(&UnspentFuse, witness.clone(), left, right, children.clone()).unwrap();
    right.1 = EpochIndex::new(0);
    assert!(matches!(
        simulate_step(&UnspentFuse, witness, left, right, children),
        Err(Error::InvalidWitness(message)) if message.to_string() == "UnspentFuse: halves do not meet at one epoch"
    ));
}

#[test]
fn unspent_lift_epoch_seam_rejects_raw_unequal_header_fields() {
    let elapsed = [Nullifier::from(Fp::from(23))];
    let sequence = NfSeqPoly::new(EpochIndex::new(0), &elapsed);
    let mut left: <ArbitraryUnspent as Header<Fp>>::Data = (
        Anchor::from(Fp::from(11)),
        EpochIndex::new(0),
        sequence.commit(),
        EpochIndex::new(1),
        Anchor::from(Fp::from(13)),
    );
    let members = [Tachygram::from(Fp::from(17))];
    let contents = members.into_iter().collect::<TachygramSetPoly>();
    let right: <QrBucket as Header<Fp>>::Data = (
        left.3,
        left.4,
        Anchor::from(Fp::from(19)),
        QrDiscriminant::from(Fp::from(5)),
        QrProfile::ROOT,
        contents.commit(),
    );
    let witness = witness::unspent_lift(
        (left, right),
        Tachygram::from(Fp::from(29)),
        &elapsed,
        &members,
    );
    let mut children = [super::unit_polynomials(), super::unit_polynomials()];
    children[0][0] = super::coefficients(witness.3.as_ref());
    children[1][0] = super::coefficients(witness.5.as_ref());
    simulate_step(&UnspentLift, witness.clone(), left, right, children.clone()).unwrap();
    left.3 = EpochIndex::new(2);
    assert!(matches!(
        simulate_step(&UnspentLift, witness, left, right, children),
        Err(Error::InvalidWitness(message)) if message.to_string() == "UnspentLift: the bucket is not the segment's next epoch"
    ));
}

fn check_qr_spendable_seam(
    change: impl FnOnce(&mut <NoteUnspent as Header<Fp>>::Data),
    expected: &str,
) {
    let cm = note::Commitment::from(Fp::from(23));
    let contents = iter::once(Tachygram::from(cm)).collect::<TachygramSetPoly>();
    let mut left: <NoteUnspent as Header<Fp>>::Data = (
        cm,
        Anchor::from(Fp::from(11)),
        EpochIndex::new(1),
        EpochIndex::new(2),
        Anchor::from(Fp::from(13)),
    );
    let right: <QrBucket as Header<Fp>>::Data = (
        left.2,
        left.1,
        left.4,
        QrDiscriminant::from(Fp::from(5)),
        QrProfile::ROOT,
        contents.commit(),
    );
    let mut children = [super::unit_polynomials(), super::unit_polynomials()];
    children[1][0] = super::coefficients(contents.as_ref());
    simulate_step(
        &QrSpendableInit,
        (contents.clone(),),
        left,
        right,
        children.clone(),
    )
    .unwrap();
    change(&mut left);
    assert!(matches!(
        simulate_step(&QrSpendableInit, (contents,), left, right, children),
        Err(Error::InvalidWitness(message)) if message.to_string() == expected
    ));
}

#[test]
fn qr_spendable_start_epoch_rejects_raw_unequal_header_fields() {
    check_qr_spendable_seam(
        |left| left.2 = EpochIndex::new(0),
        "QrSpendableInit: segment does not start in the bucket's epoch",
    );
}

#[test]
fn qr_spendable_opening_anchor_rejects_raw_unequal_header_fields() {
    check_qr_spendable_seam(
        |left| left.1 = Anchor::from(Fp::from(17)),
        "QrSpendableInit: segment does not open where the bucket does",
    );
}

#[test]
fn qr_spendable_closing_epoch_rejects_raw_unequal_header_fields() {
    check_qr_spendable_seam(
        |left| left.3 = EpochIndex::new(3),
        "QrSpendableInit: segment does not end in the epoch after the bucket's",
    );
}

#[test]
fn spendable_lift_epoch_seam_rejects_raw_unequal_header_fields() {
    let mut left: <NoteSpendable as Header<Fp>>::Data = (
        note::Commitment::from(Fp::from(23)),
        EpochIndex::new(1),
        Anchor::from(Fp::from(11)),
    );
    let right: <NoteUnspent as Header<Fp>>::Data = (
        left.0,
        left.2,
        left.1,
        EpochIndex::new(2),
        Anchor::from(Fp::from(13)),
    );
    let children = [super::unit_polynomials(), super::unit_polynomials()];
    simulate_step(&SpendableLift, (), left, right, children.clone()).unwrap();
    left.1 = EpochIndex::new(0);
    assert!(matches!(
        simulate_step(&SpendableLift, (), left, right, children),
        Err(Error::InvalidWitness(message)) if message.to_string() == "SpendableLift: segment does not start at the lineage epoch"
    ));
}
