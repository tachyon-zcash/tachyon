//! Tachyon proofs via Ragu PCD.
//!
//! Registers all PCD step types and provides accumulator helpers for
//! stamp construction and verification.
//!
//! `Step::INDEX` runs from zero without gaps, and [`make_app`] registers the
//! steps in that order; `ApplicationBuilder` rejects any other sequence.
//! `Header::SUFFIX` runs from zero without gaps too.
//!
//! A step is named "noun + verb", where the noun is the header it **emits**,
//! not the one it reads. Most fuse steps read and emit the same header, which
//! leaves the rule invisible until one does not: `EvidenceTreeFuse` emits an
//! `EvidenceTree` and reads two `EvidenceTreePair`s, and `EvidenceTreePairFuse`
//! emits the pair. Three steps whose output is a part of what they read are
//! named for the input instead: `QrIntakeSplit`, `QrSideDescend` and
//! `EvidenceTreeOpen`.

extern crate alloc;

pub mod delegation;
pub mod evidence;
pub mod output;
pub mod pool;
pub mod qr;
pub mod spend;
pub mod spendable;
pub mod stamp;
pub mod summary;

#[cfg(test)]
mod seams;

use lazy_static::lazy_static;
pub use ragu::Proof;
use ragu::{Application, ApplicationBuilder};
use ragu_pcd::pasta::baked;

/// Application-wide encoded header width, including one suffix element.
///
/// | Header | Scalars | Pallas points | Host commitments | Payload |
/// | --- | ---: | ---: | ---: | ---: |
/// | unit | 0 | 0 | 0 | 0 |
/// | NoteSecret | 6 | 0 | 0 | 6 |
/// | NoteNullifiers | 3 | 0 | 1 | 5 |
/// | ArbitraryUnspent | 4 | 0 | 1 | 6 |
/// | NoteUnspent | 5 | 0 | 0 | 5 |
/// | NoteSpendable | 3 | 0 | 0 | 3 |
/// | SpendHeader | 5 | 1 | 0 | 7 |
/// | OutputHeader | 2 | 1 | 0 | 4 |
/// | Actions / Stamp | 1 | 0 | 2 | 5 |
/// | Summary | 3 | 0 | 1 | 5 |
/// | QrIntake / QrBucket | 6 | 0 | 1 | 8 |
/// | QrIntakeSides | 6 | 0 | 2 | 10 |
/// | EvidenceTree | 5 | 0 | 0 | 5 |
/// | EvidenceTreePair | 6 | 0 | 0 | 6 |
/// | AnchorSpan | 2 | 0 | 1 | 4 |
///
/// Points write two coordinates; commitments write two compressed limbs.
/// QrIntakeSides requires ten payload elements, so eleven is minimal. Steps
/// have one application fragment and export no cross-fragment witness schema:
/// their `Shared` is `()`, independently of their encoded header gadgets.
pub const HEADER_SIZE: usize = 11;

fn make_app() -> Result<Application<'static, HEADER_SIZE>, ragu_core::Error> {
    ApplicationBuilder::<HEADER_SIZE>::new(baked())
        .register(delegation::NoteSeed)?
        .register(delegation::NullifierDerive)?
        .register(pool::UnspentFuse)?
        .register(pool::UnspentBind)?
        .register(spendable::SpendableInit)?
        .register(spendable::SpendableLift)?
        .register(output::OutputBind)?
        .register(stamp::OutputAction)?
        .register(spend::SpendBind)?
        .register(stamp::SpendAction)?
        .register(stamp::StampMerge)?
        .register(stamp::StampLift)?
        .register(delegation::NullifierFuse)?
        .register(summary::SummarySeed)?
        .register(summary::SummaryAdvance)?
        .register(qr::QrSummaryIntake)?
        .register(qr::QrIntakeMerge)?
        .register(qr::QrIntakeSplit)?
        .register(qr::QrSideDescend)?
        .register(qr::QrUnspentInit)?
        .register(qr::QrBucketSeal)?
        .register(qr::QrStampIntakeSeed)?
        .register(spendable::QrSpendableInit)?
        .register(qr::QrEmptyIntakeSeed)?
        .register(pool::UnspentLift)?
        .register(evidence::EvidenceTreePairFuse)?
        .register(evidence::EvidenceTreeFuse)?
        .register(evidence::EvidenceTreeCap)?
        .register(evidence::EvidenceTreeDescend)?
        .register(evidence::EvidenceTreeOpen)?
        .register(evidence::EvidenceTreeLeafPair)?
        .register(pool::AnchorSpanSeed)?
        .register(pool::AnchorSpanFuse)?
        .register(stamp::FeeFuse)?
        .register(stamp::ActionMerge)?
        .register(stamp::ActionLift)?
        .register(stamp::FeeSeed)?
        .finalize()
}

lazy_static! {
    /// A static ref to the mock ragu application.
    pub static ref PROOF_SYSTEM: Application<'static, HEADER_SIZE> = {
        #[expect(
            clippy::expect_used,
            reason = "hardcoded step ordering must register cleanly"
        )]
        make_app().expect("registration of fixed step list must succeed")
    };
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ragu::{
        Header,
        pasta::{Ep, Eq, Fp},
    };
    use ragu_core::{drivers::Driver as _, maybe::Maybe as _};
    use ragu_primitives::{GadgetExt as _, Simulator};
    use udon::{
        curve::{Affine as _, Projective as _},
        field::Field as _,
    };

    use super::*;
    use crate::{
        keys::{NoteMasterKey, PaymentKey},
        note::{self, Note},
        nullifier::{self, Nullifier},
        primitives::*,
        value,
    };

    fn payload_width<H: Header>(data: H::Data) -> usize {
        let mut driver = Simulator::<Fp>::new();
        let header = H::encode(&mut driver, &mut (), Simulator::<Fp>::just(|| data))
            .expect("valid header data");
        let mut fields = Vec::new();
        header
            .write(&mut driver, &mut fields)
            .expect("header serializes");
        fields.len()
    }

    fn payload_values<H: Header>(data: H::Data) -> Vec<Fp> {
        let mut driver = Simulator::<Fp>::new();
        let header = H::encode(&mut driver, &mut (), Simulator::<Fp>::just(|| data))
            .expect("valid semantic fields");
        let mut fields = Vec::new();
        header
            .write(&mut driver, &mut fields)
            .expect("header serializes");
        fields.iter().map(|field| *field.value().take()).collect()
    }

    #[test]
    fn named_header_fields_preserve_semantic_serialization_order() {
        let anchor = Anchor::from(Fp::from(11));
        let actions = Eq::generator() * Fp::from(2);
        let tachygrams = Eq::generator() * Fp::from(3);
        let limbs = |point: Eq| {
            let encoding = point.to_affine().to_bytes();
            let (low, high) = encoding.split_at(16);
            [
                Fp::from_u128(u128::from_le_bytes(low.try_into().expect("16-byte limb"))),
                Fp::from_u128(u128::from_le_bytes(high.try_into().expect("16-byte limb"))),
            ]
        };
        let [action_low, action_high] = limbs(actions);
        let [tachygram_low, tachygram_high] = limbs(tachygrams);
        assert_eq!(
            payload_values::<stamp::Stamp>((
                ActionSetCommit::from(actions),
                TachygramSetCommit::from(tachygrams),
                anchor
            )),
            [
                Fp::from(11),
                action_low,
                action_high,
                tachygram_low,
                tachygram_high
            ]
        );
        assert_eq!(
            payload_values::<spendable::NoteSpendable>((
                note::Commitment::from(Fp::from(5)),
                EpochIndex::new(7),
                anchor
            )),
            [Fp::from(5), Fp::from(7), Fp::from(11)]
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one ledger case for every header layout"
    )]
    fn header_width_ledger_matches_serialized_gadgets_and_is_minimal() {
        let epoch = EpochIndex::new(0);
        let anchor = Anchor::from(Fp::ONE);
        let cm = note::Commitment::from(Fp::ONE);
        let host = Eq::generator();
        let contents = TachygramSetCommit::from(host);
        let discriminant = QrDiscriminant::from(Fp::ONE);
        let profile = QrProfile::ROOT;
        let root = EvidenceTreeRoot(Fp::ONE);
        let cv = value::Commitment::from(Ep::generator());
        let note = Note {
            pk: PaymentKey::from(Fp::ONE),
            value: value::Positive::ZERO,
            psi: nullifier::Trapdoor::from(Fp::ONE),
            rcm: note::CommitmentTrapdoor::from(Fp::ONE),
        };
        let widths = [
            (payload_width::<()>(()), 0),
            (
                payload_width::<delegation::NoteSecret>((cm, note, NoteMasterKey(Fp::ONE))),
                6,
            ),
            (
                payload_width::<delegation::NoteNullifiers>((
                    cm,
                    epoch,
                    NfSeqCommit::from(host),
                    epoch,
                )),
                5,
            ),
            (
                payload_width::<pool::ArbitraryUnspent>((
                    anchor,
                    epoch,
                    NfSeqCommit::from(host),
                    epoch,
                    anchor,
                )),
                6,
            ),
            (
                payload_width::<pool::NoteUnspent>((cm, anchor, epoch, epoch, anchor)),
                5,
            ),
            (
                payload_width::<spendable::NoteSpendable>((cm, epoch, anchor)),
                3,
            ),
            (
                payload_width::<spend::SpendHeader>((
                    cm,
                    Nullifier::from(Fp::ONE),
                    Nullifier::from(Fp::ONE),
                    anchor,
                    note.pk,
                    cv,
                )),
                7,
            ),
            (
                payload_width::<output::OutputHeader>((
                    Tachygram::from(Fp::ONE),
                    Tachygram::from(Fp::ONE),
                    cv,
                )),
                4,
            ),
            (
                payload_width::<stamp::Actions>((ActionSetCommit::from(host), contents, anchor)),
                5,
            ),
            (
                payload_width::<stamp::Stamp>((ActionSetCommit::from(host), contents, anchor)),
                5,
            ),
            (
                payload_width::<summary::Summary>((epoch, anchor, anchor, contents)),
                5,
            ),
            (
                payload_width::<qr::QrIntake>((
                    epoch,
                    anchor,
                    anchor,
                    discriminant,
                    profile,
                    contents,
                )),
                8,
            ),
            (
                payload_width::<qr::QrBucket>((
                    epoch,
                    anchor,
                    anchor,
                    discriminant,
                    profile,
                    contents,
                )),
                8,
            ),
            (
                payload_width::<qr::QrIntakeSides>((
                    epoch,
                    anchor,
                    anchor,
                    discriminant,
                    profile,
                    contents,
                    contents,
                )),
                10,
            ),
            (
                payload_width::<evidence::EvidenceTree>((
                    epoch,
                    anchor,
                    anchor,
                    discriminant,
                    root,
                )),
                5,
            ),
            (
                payload_width::<evidence::EvidenceTreePair>((
                    epoch,
                    anchor,
                    anchor,
                    discriminant,
                    root,
                    root,
                )),
                6,
            ),
            (
                payload_width::<pool::AnchorSpan>((anchor, AnchorSetCommit::from(host), anchor)),
                4,
            ),
        ];
        for (actual, expected) in widths {
            assert_eq!(actual, expected);
        }
        assert_eq!(
            widths
                .into_iter()
                .map(|(actual, _)| actual)
                .max()
                .expect("headers")
                + 1,
            HEADER_SIZE
        );
    }
}
