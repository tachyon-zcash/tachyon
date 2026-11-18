use ragu::{
    drivers::{Driver, DriverValue},
    header::Header,
    pasta::Pasta,
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
};
use rand::{SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;

use super::{QrBucket, QrBucketSeal, QrContents, QrEmptyIntakeSeed, QrIntake, QrSummaryIntake};
use crate::{
    Anchor, EpochIndex, QrDiscriminant, Tachygram,
    pasta::Fp,
    stamp::proof::{new_application, summary::SummarySeed},
    witness,
};

/// [`QrBucketSeal`] with one added to the constant coefficient of its prepared
/// contents.
struct ShiftedBucketSeal;

impl Step<Pasta> for ShiftedBucketSeal {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrBucket;
    type Right = ();
    type Witness<'source> = (Anchor,);

    const INDEX: Index = QrBucketSeal::INDEX;

    fn prepare(
        &self,
        _: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let mut contents = left.polynomial(QrContents).to_vec();
        contents[0] += Fp::ONE;
        Ok(Prepared::new().poly(QrContents, contents))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let (encoded, data) = QrBucketSeal::synthesize(dr, oracles, &witness, left, right)?;
        Ok((encoded, data, D::unit()))
    }
}

#[test]
fn qr_bucket_seal_rejects_substituted_contents() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(0);
    let previous = Anchor::from(Fp::ZERO);
    let start = Anchor::default();
    let members = [Tachygram::from(Fp::from(5))];
    let (summary, ()) = app
        .seed(
            rng,
            SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .unwrap();
    let empty = app.bootstrap_proof().clone().carry::<()>(());
    let disc = QrDiscriminant::random(rng);
    let (intake, ()) = app
        .fuse(
            rng,
            QrSummaryIntake,
            witness::qr_summary_intake((*summary.data(), ()), disc),
            summary,
            empty.clone(),
        )
        .unwrap();
    let (forged, ()) = app
        .fuse(
            rng,
            ShiftedBucketSeal,
            witness::qr_bucket_seal((*intake.data(), ()), previous),
            intake,
            empty,
        )
        .unwrap();
    assert!(
        !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
        "a seal must carry the intake's contents"
    );
}

/// [`QrEmptyIntakeSeed`] preparing the nonconstant contents `1 + X`.
struct NonemptyIntakeSeed;

impl Step<Pasta> for NonemptyIntakeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrIntake;
    type Right = ();
    type Witness<'source> = (Anchor, EpochIndex, QrDiscriminant);

    const INDEX: Index = QrEmptyIntakeSeed::INDEX;

    fn prepare(
        &self,
        _: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new().poly(QrContents, [Fp::ONE, Fp::ONE]))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let (encoded, data) = QrEmptyIntakeSeed::synthesize(dr, oracles, witness, left, right)?;
        Ok((encoded, data, D::unit()))
    }
}

#[test]
fn qr_empty_intake_seed_rejects_nonempty_output_slot() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let witness = witness::qr_empty_intake_seed(
        ((), ()),
        Anchor::default(),
        EpochIndex::new(0),
        QrDiscriminant::random(rng),
    );
    let (forged, ()) = app.seed(rng, NonemptyIntakeSeed, witness).unwrap();
    assert!(
        !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
        "an empty intake must carry the constant one"
    );
}
