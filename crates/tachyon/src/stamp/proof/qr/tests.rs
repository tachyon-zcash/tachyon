use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    stamp::proof::{new_application, summary::SummarySeed},
    witness,
};

/// [`QrBucketSeal`]'s circuit over contents shifted by the witnessed constant.
/// A zero shift prepares the intake's contents.
struct ShiftedBucketSeal;

impl Step<Pasta> for ShiftedBucketSeal {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrBucket;
    type Right = ();
    /// `(anchor_final_prev, shift)`
    type Witness<'source> = (Anchor, Fp);

    const INDEX: Index = QrBucketSeal::INDEX;

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let mut contents = left.polynomial(TachygramSetPoly::SLOT).to_vec();
        contents[0] += witness.1;
        Ok(Prepared::new().poly(TachygramSetPoly::SLOT, contents))
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let intake = left_encoded.as_gadget();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let next = intake.epoch.next(dr)?;
        let previous = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|&(anchor_final_prev, _)| Fp::from(anchor_final_prev)),
        )?;
        let boundary = poseidon::circuit::anchor_next_epoch(dr, &previous, &intake.epoch)?;
        intake.anchor_prev.enforce_equal(dr, &boundary)?;
        let crossing = poseidon::circuit::anchor_next_epoch(dr, &intake.anchor_end, &next)?;
        let fields = QrBucketOutput {
            epoch: intake.epoch.clone(),
            anchor_start: intake.anchor_prev.clone(),
            anchor_next: crossing,
            discriminant: intake.discriminant.clone(),
            profile: intake.profile.clone(),
            contents_hash: [
                oracles.bridge_hash().x().clone(),
                oracles.bridge_hash().y().clone(),
            ],
        };
        let [hash_x, hash_y] = fields.contents_hash.each_ref().map(Element::value);
        let data = D::just(|| {
            let (epoch, anchor_prev, _, discriminant, profile) = left.take();
            let contents_hash = TachygramSetBridge::from(
                EpAffine::from_xy(*hash_x.take(), *hash_y.take()).unwrap(),
            );
            (
                epoch,
                anchor_prev,
                Anchor::from(*fields.anchor_next.value().take()),
                discriminant,
                profile,
                contents_hash,
            )
        });
        let zeta = oracles.zeta().clone();
        let contents = oracles.left(TachygramSetPoly::SLOT).open(dr, &zeta)?;
        oracles
            .output(TachygramSetPoly::SLOT)
            .open(dr, &zeta)?
            .enforce_equal(dr, &contents)?;
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

#[test]
fn qr_bucket_seal_rejects_substituted_contents() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(0);
    let previous = Anchor::from(Fp::ZERO);
    let members = [Tachygram::from(Fp::from(5))];
    let (summary, ()) = app
        .seed(
            rng,
            SummarySeed,
            witness::summary_seed(((), ()), Anchor::default(), epoch, &members),
        )
        .unwrap();
    let empty = app.bootstrap_proof().clone().carry::<()>(());
    let discriminant = QrDiscriminant::random(rng);
    let (intake, ()) = app
        .fuse(
            rng,
            QrSummaryIntake,
            witness::qr_summary_intake((*summary.data(), ()), discriminant),
            summary,
            empty.clone(),
        )
        .unwrap();

    let [honest, forged] = [Fp::ZERO, Fp::ONE].map(|shift| {
        app.fuse(
            &mut *rng,
            ShiftedBucketSeal,
            (previous, shift),
            intake.clone(),
            empty.clone(),
        )
        .unwrap()
        .0
    });
    assert!(app.verify_uncompressed(&honest, &mut *rng).unwrap());
    assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
}

/// [`QrEmptyIntakeSeed`]'s circuit over the contents `1 + linear·X`, with
/// `linear` witnessed. A zero `linear` prepares the constant one.
struct NonemptyIntakeSeed;

impl Step<Pasta> for NonemptyIntakeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrIntake;
    type Right = ();
    /// `(anchor, epoch, discriminant, linear)`
    type Witness<'source> = (Anchor, EpochIndex, QrDiscriminant, Fp);

    const INDEX: Index = QrEmptyIntakeSeed::INDEX;

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new().poly(TachygramSetPoly::SLOT, [Fp::ONE, witness.3]))
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let zeta = oracles.zeta().clone();
        let contents = oracles.output(TachygramSetPoly::SLOT).open(dr, &zeta)?;
        let one = Element::constant(dr, Fp::ONE);
        contents.enforce_equal(dr, &one)?;
        let anchor_element = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(anchor, ..)| Fp::from(anchor)),
        )?;
        let discriminant_element = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|&(_, _, discriminant, _)| Fp::from(discriminant)),
        )?;
        let epoch_element = gadgets::epoch::EpochIndex::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(_, epoch, ..)| epoch),
        )?;
        let data = D::just(|| {
            let (anchor, epoch, discriminant, _) = witness.take();
            let () = left.take();
            let () = right.take();
            (epoch, anchor, anchor, discriminant, QrProfile::ROOT)
        });
        let fields = QrIntakeOutput {
            epoch: epoch_element,
            anchor_prev: anchor_element.clone(),
            anchor_end: anchor_element,
            discriminant: discriminant_element,
            profile: gadgets::qr::QrProfile::root(dr),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

#[test]
fn qr_empty_intake_seed_rejects_nonempty_output_slot() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let discriminant = QrDiscriminant::random(rng);

    let [honest, forged] = [Fp::ZERO, Fp::ONE].map(|linear| {
        app.seed(
            &mut *rng,
            NonemptyIntakeSeed,
            (Anchor::default(), EpochIndex::new(0), discriminant, linear),
        )
        .unwrap()
        .0
    });
    assert!(app.verify_uncompressed(&honest, &mut *rng).unwrap());
    assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
}
