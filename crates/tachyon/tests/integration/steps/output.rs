use core::iter;

use ragu::Proof;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    ActionSetPoly, Anchor, Tachygram, TachygramSetPoly, action,
    constants::MAX_MONEY,
    digest::poseidon,
    entropy::ActionEntropy,
    note::Note,
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, output, stamp},
    value, witness,
};

use crate::fixtures::{WalletSim, assert_rejected};

#[test]
fn output_steps_publish_the_note_pair() {
    let rng = &mut StdRng::seed_from_u64(0);
    for amount in [0, MAX_MONEY / 2, MAX_MONEY] {
        let wallet = WalletSim::random(rng);
        let note = wallet.random_note(amount);
        let diverted = wallet.random_note(amount);
        let rcv = value::Trapdoor::random(rng);
        let theta = ActionEntropy::random(rng);
        let anchor = Anchor::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
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
                    Proof::bootstrap().carry::<()>(()),
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
        assert_eq!(
            cm,
            Tachygram::from(note.commitment()),
            "{amount}: commitment"
        );
        assert_eq!(pad, expected_pad, "{amount}: pad");
        assert_eq!(cv, rcv.commit(-note.value), "{amount}: value commitment");
        assert_ne!(cm, pad, "{amount}: commitment and pad");
        assert_eq!(action_set, planned_set, "{amount}: action set");
        assert_eq!(
            tachygram_set,
            TachygramSetPoly::from_iter([cm, pad]).commit(),
            "{amount}: tachygram set"
        );
        assert_eq!(stamp_anchor, anchor, "{amount}: anchor");

        let (_, (diverted_set, ..)) = prove(rng, diverted);
        assert_ne!(diverted_set, planned_set, "{amount}: diverted action set");
    }
}

#[test]
fn output_steps_reject_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let note = WalletSim::random(rng).random_note(500);
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let anchor = Anchor::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let (bind, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .expect("OutputBind");

    let (.., action_set, tachygram_set) = witness::output_action((*bind.data(), ()), theta, anchor);
    let (.., foreign_action_set, _) =
        witness::output_action((*bind.data(), ()), ActionEntropy::random(rng), anchor);
    let foreign_tachygrams = iter::repeat_with(|| Tachygram::random(rng))
        .take(2)
        .collect::<TachygramSetPoly>();
    let fuse = |fuse_rng: &mut StdRng, action_witness| {
        PROOF_SYSTEM
            .fuse(
                fuse_rng,
                stamp::OutputAction,
                action_witness,
                bind.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
    };

    assert_rejected(
        fuse(rng, (theta, anchor, action_set, foreign_tachygrams)),
        "OutputAction: tachygram set does not commit to the bound pair",
    );
    assert_rejected(
        fuse(rng, (theta, anchor, foreign_action_set, tachygram_set)),
        "OutputAction: action set does not commit to the action",
    );
}
