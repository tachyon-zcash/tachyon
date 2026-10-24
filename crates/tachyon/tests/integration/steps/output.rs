//! `OutputBind` and `OutputAction`: an output proved over its own note.

use ff::Field as _;
use pasta_curves::Fp;
use proptest::prelude::*;
use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionSetPoly, Anchor, Tachygram, TachygramSetPoly, action,
    constants::MAX_MONEY,
    digest::poseidon,
    entropy::ActionEntropy,
    note::Note,
    stamp::proof::{PROOF_SYSTEM, output, stamp},
    value, witness,
};

use crate::{
    fixtures::WalletSim,
    strategies::{assert_rejections, check, tachygrams},
};

/// A note of `amount` owned by a fresh wallet.
fn note_of(rng: &mut StdRng, amount: u64) -> Note {
    Note {
        value: value::Positive::try_from(amount).expect("amount in range"),
        ..WalletSim::random(rng).random_note(0)
    }
}

/// `OutputBind` publishes the note's commitment and its pad, both derived
/// from the note's fields under distinct domains, with the negated value
/// committed under `rcv`. `OutputAction` publishes that pair at the
/// witnessed anchor and the action the plan signs, and only for the planned
/// note: another note of the same value under the same `theta` and `rcv`
/// proves another action.
#[test]
fn output_steps_publish_the_note_pair() {
    let amounts = prop_oneof![Just(0), 0..=MAX_MONEY, Just(MAX_MONEY)];
    check(16, (any::<u64>(), amounts), |(seed, amount)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let note = note_of(rng, amount);
        let diverted = note_of(rng, amount);
        let rcv = value::Trapdoor::random(rng);
        let theta = ActionEntropy::random(rng);
        let anchor = Anchor::from(Fp::random(&mut *rng));
        let planned = action::Plan::output(note, theta, rcv)
            .digest()
            .expect("action digest");
        let planned_set = ActionSetPoly::from_iter([planned]).commit();

        let prove = |prove_rng: &mut StdRng, proved: Note| {
            let (bind, ()) = PROOF_SYSTEM
                .seed(prove_rng, output::OutputBind, (proved, rcv))
                .expect("OutputBind");
            let bound = *bind.data();
            let (pcd, ()) = PROOF_SYSTEM
                .fuse(
                    prove_rng,
                    stamp::OutputAction,
                    witness::output_action((bound, ()), theta, anchor),
                    bind,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("OutputAction");
            (bound, *pcd.data())
        };

        let ((cm, pad, cv), (action_set, tachygram_set, stamp_anchor)) = prove(rng, note);
        let expected_pad = Tachygram::from(poseidon::pad_tachygram(
            Fp::from(note.rcm),
            Fp::from(note.pk),
            u64::from(note.value),
            Fp::from(note.psi),
        ));
        prop_assert_eq!(cm, Tachygram::from(note.commitment()));
        prop_assert_eq!(pad, expected_pad);
        prop_assert_eq!(cv, rcv.commit(-note.value));
        prop_assert_ne!(cm, pad);
        prop_assert_eq!(action_set, planned_set);
        prop_assert_eq!(
            tachygram_set,
            TachygramSetPoly::from_iter([cm, pad]).commit()
        );
        prop_assert_eq!(stamp_anchor, anchor);

        let (_, (diverted_set, ..)) = prove(rng, diverted);
        prop_assert_ne!(diverted_set, planned_set);
        Ok(())
    });
}

/// `OutputAction` refuses a tachygram set other than the bound pair and an
/// action set other than the action it derives.
#[test]
fn output_steps_reject_corruptions() {
    let strategy = (any::<u64>(), 0..=MAX_MONEY, 1usize..=3);
    check(16, strategy, |(seed, amount, foreign_count)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let note = note_of(rng, amount);
        let rcv = value::Trapdoor::random(rng);
        let theta = ActionEntropy::random(rng);
        let anchor = Anchor::from(Fp::random(&mut *rng));
        let (bind, ()) = PROOF_SYSTEM
            .seed(rng, output::OutputBind, (note, rcv))
            .expect("OutputBind");

        let (.., action_set, tachygram_set) =
            witness::output_action((*bind.data(), ()), theta, anchor);
        let (.., foreign_action_set, _) =
            witness::output_action((*bind.data(), ()), ActionEntropy::random(rng), anchor);
        let foreign_tachygrams = tachygrams(rng, foreign_count)
            .into_iter()
            .collect::<TachygramSetPoly>();
        let fuse = |fuse_rng: &mut StdRng, action_witness| {
            PROOF_SYSTEM
                .fuse(
                    fuse_rng,
                    stamp::OutputAction,
                    action_witness,
                    bind.clone(),
                    Proof::trivial().carry::<()>(()),
                )
                .map(drop)
        };

        assert_rejections([
            (
                "a tachygram set other than the bound pair",
                fuse(rng, (theta, anchor, action_set, foreign_tachygrams)),
                "OutputAction: tachygram set does not commit to the bound pair",
            ),
            (
                "an action set under another theta",
                fuse(rng, (theta, anchor, foreign_action_set, tachygram_set)),
                "OutputAction: action set does not commit to the action",
            ),
        ]);
        Ok(())
    });
}
