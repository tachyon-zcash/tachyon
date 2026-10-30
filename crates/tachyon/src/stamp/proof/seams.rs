//! Local step-wiring tests with raw predecessor headers, not authenticated
//! PCDs.
//!
//! Producer lineage correlates these epochs and anchors. Raw inputs let each
//! test break just one seam while preserving all other local relations.

use alloc::string::ToString as _;
use core::iter;

use ragu::{Encoded, Header, Index, Step, StepCtx, pasta::Fp};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use rand::{SeedableRng as _, rngs::StdRng};

use super::{
    PROOF_SYSTEM,
    pool::{ArbitraryUnspent, NoteUnspent, UnspentFuse, UnspentLift},
    qr::QrBucket,
    spendable::{NoteSpendable, QrSpendableInit, SpendableLift},
};
use crate::{
    note,
    nullifier::Nullifier,
    primitives::{
        Anchor, EpochIndex, NfSeqPoly, QrDiscriminant, QrProfile, Tachygram, TachygramSetPoly,
    },
    witness,
};

/// The mock keeps StepCtx's constructor and polynomial hooks private. Its
/// application supplies a Simulator-backed context to this test-only adapter,
/// which calls the production witness directly with the supplied raw headers.
/// Only the adapter's outer inputs are unit/bootstrap; the real step's output
/// gadget and carrier are retained. No predecessor proof authenticates the raw
/// headers, so a child-proof connection cannot mask a missing local equality.
struct RawInputs<S>(S);

impl<S: Step<Shared = ()>> Step for RawInputs<S> {
    type Aux<'source> = S::Aux<'source>;
    type Left = ();
    type Output = S::Output;
    type Right = ();
    type Shared = ();
    type Witness<'source> = (
        S::Witness<'source>,
        <S::Left as Header>::Data,
        <S::Right as Header>::Data,
    );

    const INDEX: Index = S::INDEX;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const WIDTH: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), WIDTH>,
            Encoded<'dr, D, (), WIDTH>,
            Encoded<'dr, D, Self::Output, WIDTH>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let (step_witness, left_data, right_data) = witness.cast();
        let ((_, _, output), shared, data, aux) =
            self.0
                .witness::<D, WIDTH>(ctx, step_witness, left_data, right_data)?;
        Ok((
            (
                Encoded::new(ctx.dr, &mut (), left)?,
                Encoded::new(ctx.dr, &mut (), right)?,
                output,
            ),
            shared,
            data,
            aux,
        ))
    }
}

fn simulate_step<S>(
    step: S,
    witness: S::Witness<'static>,
    left: <S::Left as Header>::Data,
    right: <S::Right as Header>::Data,
) -> Result<()>
where
    S: Step<Shared = ()>,
{
    PROOF_SYSTEM
        .seed(
            &mut StdRng::seed_from_u64(0),
            RawInputs(step),
            (witness, left, right),
        )
        .map(|_| ())
}

fn assert_invalid_witness(error: Error, expected: &str) {
    let Error::InvalidWitness(message) = error else {
        panic!("unexpected rejection: {error:?}");
    };
    assert_eq!(message.to_string(), expected);
}

#[test]
fn unspent_fuse_epoch_seam_rejects_raw_unequal_header_fields() {
    // B07: anchors and polynomial product agree; only the epoch seam differs.
    let first = NfSeqPoly::new(EpochIndex::new(0), &[Nullifier::from(Fp::from(23))]);
    let second = NfSeqPoly::new(EpochIndex::new(1), &[Nullifier::from(Fp::from(29))]);
    let left: <ArbitraryUnspent as Header>::Data = (
        Anchor::from(Fp::from(11)),
        EpochIndex::new(0),
        first.commit(),
        EpochIndex::new(1),
        Anchor::from(Fp::from(13)),
    );
    let mut right: <ArbitraryUnspent as Header>::Data = (
        left.4,
        left.3,
        second.commit(),
        EpochIndex::new(2),
        Anchor::from(Fp::from(17)),
    );
    let witness = (first.clone(), first * second.clone(), second);
    simulate_step(UnspentFuse, witness.clone(), left, right).expect("matching epoch seam");
    right.1 = EpochIndex::new(0);
    let error = simulate_step(UnspentFuse, witness, left, right)
        .expect_err("UnspentFuse must reject the mismatched epoch seam");
    assert_invalid_witness(error, "UnspentFuse: halves do not meet at one epoch");
}

#[test]
fn unspent_lift_epoch_seam_rejects_raw_unequal_header_fields() {
    // B09: keep the shared anchor, all commitments and the extension unchanged.
    let elapsed = [Nullifier::from(Fp::from(23))];
    let sequence = NfSeqPoly::new(EpochIndex::new(0), &elapsed);
    let mut left: <ArbitraryUnspent as Header>::Data = (
        Anchor::from(Fp::from(11)),
        EpochIndex::new(0),
        sequence.commit(),
        EpochIndex::new(1),
        Anchor::from(Fp::from(13)),
    );
    let members = [Tachygram::from(Fp::from(17))];
    let contents = members.into_iter().collect::<TachygramSetPoly>();
    let right: <QrBucket as Header>::Data = (
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
    simulate_step(UnspentLift, witness.clone(), left, right).expect("matching epoch seam");
    left.3 = EpochIndex::new(2);
    let error = simulate_step(UnspentLift, witness, left, right)
        .expect_err("UnspentLift must reject the mismatched epoch seam");
    assert_invalid_witness(
        error,
        "UnspentLift: the bucket is not the segment's next epoch",
    );
}

fn check_qr_spendable_seam(
    change: impl FnOnce(&mut <NoteUnspent as Header>::Data),
    expected: &str,
) {
    let cm = note::Commitment::from(Fp::from(23));
    let contents = iter::once(Tachygram::from(cm)).collect::<TachygramSetPoly>();
    let mut left: <NoteUnspent as Header>::Data = (
        cm,
        Anchor::from(Fp::from(11)),
        EpochIndex::new(1),
        EpochIndex::new(2),
        Anchor::from(Fp::from(13)),
    );
    let right: <QrBucket as Header>::Data = (
        left.2,
        left.1,
        left.4,
        QrDiscriminant::from(Fp::from(5)),
        QrProfile::ROOT,
        contents.commit(),
    );
    simulate_step(QrSpendableInit, (contents.clone(),), left, right)
        .expect("matching extent and valid membership opening");
    change(&mut left);
    let error = simulate_step(QrSpendableInit, (contents,), left, right)
        .expect_err("QrSpendableInit must reject the mismatched seam");
    assert_invalid_witness(error, expected);
}

#[test]
fn qr_spendable_start_epoch_rejects_raw_unequal_header_fields() {
    // B28: both anchors, successor and membership opening still match.
    check_qr_spendable_seam(
        |left| left.2 = EpochIndex::new(0),
        "QrSpendableInit: segment does not start in the bucket's epoch",
    );
}

#[test]
fn qr_spendable_opening_anchor_rejects_raw_unequal_header_fields() {
    // B29: epochs, closing anchor and membership opening still match.
    check_qr_spendable_seam(
        |left| left.1 = Anchor::from(Fp::from(17)),
        "QrSpendableInit: segment does not open where the bucket does",
    );
}

#[test]
fn qr_spendable_closing_epoch_rejects_raw_unequal_header_fields() {
    // B32: both anchors, starting epoch and membership opening still match.
    check_qr_spendable_seam(
        |left| left.3 = EpochIndex::new(3),
        "QrSpendableInit: segment does not end in the epoch after the bucket's",
    );
}

#[test]
fn spendable_lift_epoch_seam_rejects_raw_unequal_header_fields() {
    // B34: the note commitment and the shared anchor still agree.
    let mut left: <NoteSpendable as Header>::Data = (
        note::Commitment::from(Fp::from(23)),
        EpochIndex::new(1),
        Anchor::from(Fp::from(11)),
    );
    let right: <NoteUnspent as Header>::Data = (
        left.0,
        left.2,
        left.1,
        EpochIndex::new(2),
        Anchor::from(Fp::from(13)),
    );
    simulate_step(SpendableLift, (), left, right).expect("matching epoch seam");
    left.1 = EpochIndex::new(0);
    let error = simulate_step(SpendableLift, (), left, right)
        .expect_err("SpendableLift must reject the mismatched epoch seam");
    assert_invalid_witness(
        error,
        "SpendableLift: segment does not start at the lineage epoch",
    );
}
