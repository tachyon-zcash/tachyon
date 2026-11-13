use alloc::string::ToString as _;
use core::assert_matches;

use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    entropy::ActionEntropy,
    keys::PaymentKey,
    note::{self, Note},
    nullifier,
    pasta::Fp,
    primitives::{ActionSetPoly, Anchor, TachygramSetPoly},
    stamp::proof::{
        PROOF_SYSTEM,
        output::OutputBind,
        stamp::{FeeFuse, OutputAction},
    },
    witness,
};

#[test]
fn debug_value_trapdoor_redacts_scalar() {
    let rcv = ValueTrapdoor(Fq::from(0xFACEu64));
    assert_eq!(alloc::format!("{rcv:?}"), "ValueTrapdoor(..)");
}

#[test]
fn positive_spans_zero_to_max_money() {
    for (input, accepted) in [
        (Positive::try_from(0u64), true),
        (Positive::try_from(MAX_MONEY), true),
        (Positive::try_from(MAX_MONEY + 1), false),
        (Positive::try_from(-1i64), false),
    ] {
        assert_eq!(input.is_ok(), accepted);
    }
}

#[test]
fn fee_fuse_rejects_maximum_above_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let note = Note {
        pk: PaymentKey::from(Fp::from(11)),
        value: Positive::try_from(1u64).unwrap(),
        psi: nullifier::Trapdoor::from(Fp::from(13)),
        rcm: note::CommitmentTrapdoor::from(Fp::from(17)),
    };
    let (output, ()) = PROOF_SYSTEM
        .seed(rng, OutputBind, (note, ValueTrapdoor(Fq::ONE)))
        .unwrap();
    let (actions, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            OutputAction,
            witness::output_action(
                (*output.data(), ()),
                ActionEntropy(Fp::from(7)),
                Anchor::default(),
            ),
            output,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();

    // This module can hand-build the raw Value, bypassing Positive's cap.
    // The output sets are unused: the maximum-bound constraint must fail first.
    let bad_witness = (
        Note {
            value: Value(i64::try_from(MAX_MONEY + 1).unwrap()),
            ..note
        },
        Positive::ZERO,
        (
            ActionSetPoly::from_iter([]),
            TachygramSetPoly::from_iter([]),
        ),
    );
    assert_matches!(
        PROOF_SYSTEM.fuse(
            rng,
            FeeFuse,
            bad_witness,
            actions,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        ).err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "FeeFuse: maximum fee exceeds MAX_MONEY"
    );
}
