use alloc::collections::BTreeSet;
use core::assert_matches;

use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;

use super::{
    super::{
        super::super::{
            ActionDigest, ActionSetPoly, Anchor, EpochIndex, Tachygram, TachygramSetPoly,
            constants::{EPOCH_MAX, MAX_MONEY},
            digest::poseidon,
            effect,
            entropy::ActionEntropy,
            fee,
            keys::{
                ProofAuthorizingKey, SpendValidatingKey,
                private::{ActionSigningKey, SpendingKey},
            },
            note::{CommitmentTrapdoor, Note},
            nullifier,
            pasta::{EpAffine, Fp, Fq},
            reddsa, value, witness,
        },
        PROOF_SYSTEM,
        delegation::NoteSeed,
        output::OutputBind,
        scale::{self, G, R},
        spend::{SpendBind, SpendPrepare, SpendPrepared},
        spendable::NoteSpendable,
    },
    FeeBind, FeeFuse, FeeReady, FeeSeed, FeeValueCommit, FeeValueOpening, OutputAction,
    SpendAction,
};

#[test]
fn output_relations_match_native_commitments_keys_and_sets() {
    let rng = &mut StdRng::seed_from_u64(11);
    let pak = SpendingKey::random(rng).derive_proof_private();
    for amount in [0, 1, 7, 8, 9, 63, 64, 65, MAX_MONEY] {
        let note = Note {
            pk: pak.derive_payment_key(),
            value: value::Positive::try_from(amount).unwrap(),
            psi: nullifier::Trapdoor::random(rng),
            rcm: CommitmentTrapdoor::random(rng),
        };
        for scalar in [
            Fq::ZERO,
            Fq::ONE,
            -Fq::ONE,
            Fq::random(|bytes| rand_core::Rng::fill_bytes(rng, bytes)),
        ] {
            let blind = scale::prove::<R, _>(rng, scalar).unwrap();
            let result = PROOF_SYSTEM.fuse(
                rng,
                OutputBind,
                (note,),
                blind,
                Proof::bootstrap().carry::<()>(()),
            );
            if amount == 0 && scalar == Fq::ZERO {
                assert_matches!(result.err(), Some(_));
                continue;
            }
            let (bound, ()) = result.unwrap();
            let value_commitment = value::Trapdoor::from_scalar(scalar).commit(-note.value);
            let expected_cm = Tachygram::from(note.commitment());
            let expected_pad = Tachygram::from(poseidon::pad_tachygram(
                Fp::from(note.rcm),
                Fp::from(note.pk),
                amount,
                Fp::from(note.psi),
            ));
            assert_eq!(*bound.data(), (expected_cm, expected_pad, value_commitment));
            let theta = ActionEntropy::random(rng);
            let alpha = theta.randomizer::<effect::Output>(note.commitment());
            let randomizer = scale::prove::<G, _>(rng, alpha.into()).unwrap();
            let rk = EpAffine::from(ActionSigningKey::new(&alpha).derive_action_public());
            assert_eq!(
                scale::finite(scale::decode(randomizer.data().2, randomizer.data().3).unwrap())
                    .unwrap(),
                rk
            );
            let anchor = Anchor::from(Fp::ONE);
            let valid = witness::output_action((*bound.data(), *randomizer.data()), theta, anchor);
            let expected_digest = ActionDigest::new(
                value_commitment,
                ActionSigningKey::new(&alpha).derive_action_public(),
            )
            .unwrap();
            let (actions, ()) = PROOF_SYSTEM
                .fuse(rng, OutputAction, valid.clone(), bound.clone(), randomizer)
                .unwrap();
            assert_eq!(
                *actions.data(),
                (
                    ActionSetPoly::from_iter([expected_digest]).commit(),
                    TachygramSetPoly::from_iter([expected_cm, expected_pad]).commit(),
                    anchor
                )
            );
            let swapped = scale::prove::<G, _>(rng, Fq::ONE).unwrap();
            assert_matches!(
                PROOF_SYSTEM
                    .fuse(rng, OutputAction, valid, bound, swapped)
                    .err(),
                Some(_)
            );
        }
    }
}

#[test]
fn spend_preparation_and_actions_match_native_lineage() {
    let rng = &mut StdRng::seed_from_u64(12);
    let pak = SpendingKey::random(rng).derive_proof_private();
    for (amount, epoch) in [(0, 0), (1, 3), (8, 4), (MAX_MONEY, EPOCH_MAX - 1)] {
        let note = Note {
            pk: pak.derive_payment_key(),
            value: value::Positive::try_from(amount).unwrap(),
            psi: nullifier::Trapdoor::random(rng),
            rcm: CommitmentTrapdoor::random(rng),
        };
        let epoch_current = EpochIndex::new(epoch);
        let anchor = Anchor::from(Fp::from(u64::from(epoch) + 1));
        let mk = pak.nk.derive_note_private(note.psi);
        let (secret, ()) = PROOF_SYSTEM
            .seed(rng, NoteSeed, witness::note_seed(((), ()), note, pak))
            .unwrap();
        let spendable =
            Proof::bootstrap().carry::<NoteSpendable>((note.commitment(), epoch_current, anchor));
        let (prepared, ()) = PROOF_SYSTEM
            .fuse(rng, SpendPrepare, (), spendable, secret.clone())
            .unwrap();
        let (cm, current, next, prepared_anchor, pk, value) = *prepared.data();
        assert_eq!(
            (cm, current, next, prepared_anchor),
            (
                note.commitment(),
                mk.derive_nullifier(epoch_current),
                mk.derive_nullifier(epoch_current.next().unwrap()),
                anchor
            )
        );
        assert_eq!(Fp::from(pk), Fp::from(note.pk));
        assert_eq!(value, note.value);
        for changed in [
            (
                cm,
                nullifier::Nullifier::from(Fp::ONE),
                next,
                anchor,
                pk,
                value,
            ),
            (cm, current, next, Anchor::from(Fp::ZERO), pk, value),
            (
                cm,
                current,
                next,
                anchor,
                SpendingKey::random(rng).derive_payment_key(),
                value,
            ),
        ] {
            let forged = prepared.proof().clone().carry::<SpendPrepared>(changed);
            assert!(!PROOF_SYSTEM.verify(&forged, &mut *rng).unwrap());
        }
        let scalar = if amount == 0 { Fq::ONE } else { Fq::ZERO };
        let blind = scale::prove::<R, _>(rng, scalar).unwrap();
        let (bound, ()) = PROOF_SYSTEM
            .fuse(rng, SpendBind, (), prepared, blind)
            .unwrap();
        let expected_cv = value::Trapdoor::from_scalar(scalar).commit(note.value);
        assert_eq!(bound.data().5, expected_cv);
        let theta = ActionEntropy::random(rng);
        let alpha = theta.randomizer::<effect::Spend>(note.commitment());
        let randomizer = scale::prove::<G, _>(rng, alpha.into()).unwrap();
        let valid = witness::spend_action((*bound.data(), *randomizer.data()), theta, pak);
        let (actions, ()) = PROOF_SYSTEM
            .fuse(rng, SpendAction, valid.clone(), bound.clone(), randomizer)
            .unwrap();
        let digest = ActionDigest::new(expected_cv, pak.ak.derive_action_public(&alpha)).unwrap();
        assert_eq!(
            *actions.data(),
            (
                ActionSetPoly::from_iter([digest]).commit(),
                TachygramSetPoly::from_iter([Tachygram::from(current), Tachygram::from(next)])
                    .commit(),
                anchor
            )
        );
        let swapped = scale::prove::<G, _>(rng, Fq::ONE).unwrap();
        assert_matches!(
            PROOF_SYSTEM
                .fuse(rng, SpendAction, valid, bound, swapped)
                .err(),
            Some(_)
        );
        let final_epoch =
            Proof::bootstrap().carry::<NoteSpendable>((cm, EpochIndex::new(EPOCH_MAX), anchor));
        assert_matches!(
            PROOF_SYSTEM
                .fuse(rng, SpendPrepare, (), final_epoch, secret)
                .err(),
            Some(_)
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "monetary boundary matrix checks each opening and its substitutions together"
)]
fn fee_openings_match_native_roots_and_reject_owner_and_amount_substitutions() {
    let rng = &mut StdRng::seed_from_u64(13);
    let pak = SpendingKey::random(rng).derive_proof_private();
    for (maximum, fee) in [
        (0, 0),
        (1, 0),
        (1, 1),
        (MAX_MONEY, 0),
        (MAX_MONEY, 1),
        (MAX_MONEY, MAX_MONEY),
    ] {
        let note = Note {
            pk: pak.derive_payment_key(),
            value: value::Positive::try_from(maximum).unwrap(),
            psi: nullifier::Trapdoor::random(rng),
            rcm: CommitmentTrapdoor::random(rng),
        };
        let fee_value = value::Positive::try_from(fee).unwrap();
        let blind = scale::prove::<R, _>(rng, note.fee_blind().into()).unwrap();
        let (opening, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                FeeValueCommit,
                (note.value,),
                blind,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        assert_eq!(opening.data().3, note.fee_blind().commit(-note.value));
        let (ready, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                FeeBind,
                (note, fee_value),
                opening.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        let change = Note {
            value: value::Positive::try_from(maximum - fee).unwrap(),
            ..note
        };
        let digest = fee::Descriptor {
            max_commitment: note.fee_blind().commit(-note.value),
            value: fee_value,
        }
        .digest()
        .unwrap();
        assert_eq!(
            *ready.data(),
            (note.value, fee_value, digest, change.commitment())
        );
        for changed in [
            Note {
                pk: SpendingKey::random(rng).derive_payment_key(),
                ..note
            },
            Note {
                psi: nullifier::Trapdoor::random(rng),
                ..note
            },
            Note {
                rcm: CommitmentTrapdoor::random(rng),
                ..note
            },
            Note {
                value: if maximum == 0 {
                    value::Positive::MAX
                } else {
                    value::Positive::ZERO
                },
                ..note
            },
        ] {
            assert_matches!(
                PROOF_SYSTEM
                    .fuse(
                        rng,
                        FeeBind,
                        (changed, fee_value),
                        opening.clone(),
                        Proof::bootstrap().carry::<()>(())
                    )
                    .err(),
                Some(_)
            );
        }
        if maximum < MAX_MONEY {
            assert_matches!(
                PROOF_SYSTEM
                    .fuse(
                        rng,
                        FeeBind,
                        (note, value::Positive::try_from(maximum + 1).unwrap()),
                        opening.clone(),
                        Proof::bootstrap().carry::<()>(())
                    )
                    .err(),
                Some(_)
            );
        }
        let swapped = scale::prove::<R, _>(rng, Fq::ONE).unwrap();
        let (wrong_opening, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                FeeValueCommit,
                (note.value,),
                swapped,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        assert_matches!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    FeeBind,
                    (note, fee_value),
                    wrong_opening,
                    Proof::bootstrap().carry::<()>(())
                )
                .err(),
            Some(_)
        );
        let (maximum_value, lo, hi, _cv) = *opening.data();
        let changed_opening = opening.proof().clone().carry::<FeeValueOpening>((
            maximum_value,
            lo,
            hi,
            value::Trapdoor::from_scalar(Fq::ONE).commit(value::Positive::ZERO),
        ));
        assert!(!PROOF_SYSTEM.verify(&changed_opening, &mut *rng).unwrap());
        let changed_ready = ready.proof().clone().carry::<FeeReady>((
            maximum_value,
            fee_value,
            ActionDigest::from(Fp::ONE),
            change.commitment(),
        ));
        assert!(!PROOF_SYSTEM.verify(&changed_ready, &mut *rng).unwrap());
    }
}

#[test]
fn fee_seed_rejects_owner_substitution() {
    let rng = &mut StdRng::seed_from_u64(14);
    let pak = SpendingKey::random(rng).derive_proof_private();
    let note = Note {
        pk: pak.derive_payment_key(),
        value: value::Positive::ZERO,
        psi: nullifier::Trapdoor::random(rng),
        rcm: CommitmentTrapdoor::random(rng),
    };
    let blind = scale::prove::<R, _>(rng, note.fee_blind().into()).unwrap();
    let anchor = Anchor::from(Fp::ONE);
    let valid = witness::fee_seed((*blind.data(), ()), note, anchor);
    for changed_note in [
        Note {
            pk: SpendingKey::random(rng).derive_payment_key(),
            ..note
        },
        Note {
            psi: nullifier::Trapdoor::random(rng),
            ..note
        },
        Note {
            rcm: CommitmentTrapdoor::random(rng),
            ..note
        },
    ] {
        let mut changed = valid.clone();
        changed.0 = changed_note;
        assert_matches!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    FeeSeed,
                    changed,
                    blind.clone(),
                    Proof::bootstrap().carry::<()>(())
                )
                .err(),
            Some(_)
        );
    }
    let (stamp, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            FeeSeed,
            valid,
            blind,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    assert!(PROOF_SYSTEM.verify(&stamp, &mut *rng).unwrap());
}

#[test]
fn fee_fuse_sets_match_native_fee_roots() {
    let rng = &mut StdRng::seed_from_u64(15);
    let pak = SpendingKey::random(rng).derive_proof_private();
    let note = Note {
        pk: pak.derive_payment_key(),
        value: value::Positive::ZERO,
        psi: nullifier::Trapdoor::random(rng),
        rcm: CommitmentTrapdoor::random(rng),
    };
    let anchor = Anchor::from(Fp::ONE);
    let left_digests = BTreeSet::from([ActionDigest::from(Fp::from(2))]);
    let left_tgs = BTreeSet::from([Tachygram::from(Fp::from(3)), Tachygram::from(Fp::from(4))]);
    let left_header = (
        left_digests
            .iter()
            .copied()
            .collect::<ActionSetPoly>()
            .commit(),
        left_tgs
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit(),
        anchor,
    );
    let blind_again = scale::prove::<R, _>(rng, note.fee_blind().into()).unwrap();
    let (opening, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            FeeValueCommit,
            (note.value,),
            blind_again,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (ready, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            FeeBind,
            (note, value::Positive::ZERO),
            opening,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let sets = witness::fee_fuse((left_header, *ready.data()), &left_digests, &left_tgs);
    let expected_digest = fee::Descriptor {
        max_commitment: note.fee_blind().commit(-note.value),
        value: value::Positive::ZERO,
    }
    .digest()
    .unwrap();
    assert_eq!(
        sets.1.0.commit(),
        left_digests
            .into_iter()
            .chain([expected_digest])
            .collect::<ActionSetPoly>()
            .commit()
    );
    assert_eq!(
        sets.1.1.commit(),
        left_tgs
            .into_iter()
            .chain([Tachygram::from(note.commitment())])
            .collect::<TachygramSetPoly>()
            .commit()
    );
    let left = Proof::bootstrap().carry::<super::Actions>(left_header);
    let (fused, ()) = PROOF_SYSTEM
        .fuse(rng, FeeFuse, sets.clone(), left, ready)
        .unwrap();
    assert_eq!(
        *fused.data(),
        (sets.1.0.commit(), sets.1.1.commit(), anchor)
    );
}

#[test]
fn spend_action_rejects_identity_authorizing_key() {
    let rng = &mut StdRng::seed_from_u64(16);
    let pak = ProofAuthorizingKey {
        ak: SpendValidatingKey(reddsa::VerificationKey::from(
            &reddsa::SigningKey::<reddsa::ActionAuth>::try_from(Fq::ZERO.to_bytes()).unwrap(),
        )),
        nk: SpendingKey::random(rng).derive_nullifier_private(),
    };
    let header = (
        super::note::Commitment::from(Fp::ONE),
        nullifier::Nullifier::from(Fp::from(2)),
        nullifier::Nullifier::from(Fp::from(3)),
        Anchor::from(Fp::from(4)),
        SpendingKey::random(rng).derive_payment_key(),
        value::Trapdoor::from_scalar(Fq::ONE).commit(value::Positive::ZERO),
    );
    let randomizer = scale::prove::<G, _>(rng, Fq::ZERO).unwrap();
    let theta = ActionEntropy::random(rng);
    assert_matches!(
        PROOF_SYSTEM
            .fuse(
                rng,
                SpendAction,
                (
                    theta,
                    pak,
                    ActionSetPoly::from_iter([ActionDigest::from(Fp::ONE)]),
                    TachygramSetPoly::from_iter([Tachygram::from(Fp::ONE)])
                ),
                Proof::bootstrap().carry::<super::SpendHeader>(header),
                randomizer,
            )
            .err(),
        Some(_)
    );
}
