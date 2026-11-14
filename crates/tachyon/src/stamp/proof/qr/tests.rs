//! Scaled-split characterization: see `book/src/proof-tree.md`,
//! “Scaled splits: observed behavior and limits”, for interpretation and scope.

#![allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    clippy::integer_division_remainder_used,
    clippy::integer_division,
    clippy::missing_assert_message,
    clippy::must_use_candidate,
    clippy::panic,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity,
    missing_debug_implementations,
    missing_docs,
    unreachable_pub,
    reason = "test code"
)]

extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};
use core::{assert_matches, iter};

use ragu::Pcd;
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::pasta::Pasta;
use rand::{SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;

use super::{
    QrBucket, QrBucketSeal, QrEmptyIntakeSeed, QrIntake, QrIntakeSides, QrIntakeSplit,
    QrSideDescend, QrSideSelect, QrStampIntakeSeed, QrUnspentInit, classify,
};
use crate::{
    collections::qr::{class_multiplier, decomposition},
    constants::EVIDENCE_TREE_ARITY,
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    nullifier,
    pasta::Fp,
    primitives::{Anchor, EpochIndex, QrDiscriminant, QrProfile, Tachygram, TachygramSetPoly},
    stamp::proof::{
        PROOF_SYSTEM as APP,
        delegation::{NoteSeed, NullifierDerive},
        evidence::{
            EvidenceTreeCap, EvidenceTreeDescend, EvidenceTreeFuse, EvidenceTreeLeafPair,
            EvidenceTreeOpen,
        },
        pool::{NoteUnspent, UnspentBind},
        spend::SpendBind,
        spendable::QrSpendableInit,
    },
    value, witness,
};

type Proof<H> = Pcd<Pasta, ProductionRank, H>;

fn scaled_factors(
    roots: [&[Tachygram]; 2],
    scales: [Fp; 2],
) -> (TachygramSetPoly, TachygramSetPoly) {
    let [non_residue, residue] = core::array::from_fn(|index| {
        let monic: TachygramSetPoly = roots[index].iter().copied().collect();
        let mut poly: Polynomial<Fp, ProductionRank> = monic.into();
        poly.scale(scales[index]);
        TachygramSetPoly::arbitrary(poly)
    });
    (non_residue, residue)
}

fn split_stamp(
    rng: &mut StdRng,
    discriminant: QrDiscriminant,
    members: &[Tachygram],
    factors: Option<(TachygramSetPoly, TachygramSetPoly)>,
) -> (Proof<QrIntake>, Proof<QrIntakeSides>) {
    let (intake, ()) = APP
        .seed(
            rng,
            QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(
                ((), ()),
                Anchor::default(),
                EpochIndex::new(0),
                discriminant,
                members,
            ),
        )
        .unwrap();
    assert!(APP.verify_differential(&intake, &mut *rng).unwrap());
    let split = factors.unwrap_or_else(|| witness::qr_intake_split((*intake.data(), ()), members));
    let (sides, ()) = APP
        .fuse(
            rng,
            QrIntakeSplit,
            split,
            intake.clone(),
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&sides, &mut *rng).unwrap());
    (intake, sides)
}

/// Scale the sibling's quotient inversely to preserve its class identity.
fn descend(
    rng: &mut StdRng,
    sides: &Proof<QrIntakeSides>,
    bit: bool,
    sibling_members: &[Tachygram],
    sibling_scale: Fp,
) -> ragu_core::Result<Proof<QrIntake>> {
    let (.., discriminant, profile, _) = *sides.data();
    let shift = discriminant.at(profile.depth);
    let points: Vec<(Fp, Fp)> = sibling_members
        .iter()
        .map(|&member| (Fp::from(member), classify(Fp::from(member), shift).1))
        .collect();
    let (interpolant, mut quotient) = decomposition(&points, class_multiplier(!bit), shift)
        .expect("sibling members are distinct and take the sibling's class");
    quotient.scale(sibling_scale.invert().unwrap());
    let (selected, ()) = APP.fuse(
        rng,
        QrSideSelect,
        (interpolant.into(), quotient.into()),
        sides.clone(),
        APP.bootstrap_proof().clone().carry::<()>(()),
    )?;
    if !APP.verify_differential(&selected, &mut *rng)? {
        return Err(ragu_core::Error::InvalidWitness(
            "selection proof failed verification".into(),
        ));
    }
    let (child, ()) = APP.fuse(rng, QrSideDescend, (bit,), sides.clone(), selected)?;
    if !APP.verify_differential(&child, &mut *rng)? {
        return Err(ragu_core::Error::InvalidWitness(
            "child proof failed verification".into(),
        ));
    }
    Ok(child)
}

fn bucket(
    rng: &mut StdRng,
    sides: &Proof<QrIntakeSides>,
    bit: bool,
    sibling_members: &[Tachygram],
    sibling_scale: Fp,
) -> Proof<QrBucket> {
    let child = descend(rng, sides, bit, sibling_members, sibling_scale).unwrap();
    let (sealed, ()) = APP
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*child.data(), ()), Anchor::from(Fp::ZERO)),
            child,
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&sealed, &mut *rng).unwrap());
    sealed
}

struct NoteCase {
    pak: ProofAuthorizingKey,
    note: Note,
    cm: Tachygram,
    nf: Tachygram,
    discriminant: QrDiscriminant,
    side: bool,
}

fn note_case(rng: &mut StdRng) -> NoteCase {
    let sk = private::SpendingKey::random(rng);
    let pak = sk.derive_proof_private();
    let note = Note {
        pk: sk.derive_payment_key(),
        value: value::Positive::try_from(400u64).unwrap(),
        psi: nullifier::Trapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    };
    let cm = Tachygram::from(note.commitment());
    let nf = Tachygram::from(
        pak.nk
            .derive_note_private(note.psi)
            .derive_nullifier(EpochIndex::new(0)),
    );
    let discriminant = iter::repeat_with(|| QrDiscriminant::random(rng))
        .find(|discriminant| {
            classify(Fp::from(nf), discriminant.at(0)).0
                == classify(Fp::from(cm), discriminant.at(0)).0
        })
        .unwrap();
    let side = classify(Fp::from(cm), discriminant.at(0)).0;
    NoteCase {
        pak,
        note,
        cm,
        nf,
        discriminant,
        side,
    }
}

fn exclude_and_bind(
    rng: &mut StdRng,
    bucket: &Proof<QrBucket>,
    note: Note,
    pak: ProofAuthorizingKey,
) -> Proof<NoteUnspent> {
    let epoch = EpochIndex::new(0);
    let mk = pak.nk.derive_note_private(note.psi);
    let (segment, ()) = APP
        .fuse(
            rng,
            QrUnspentInit,
            witness::qr_unspent_init(
                (*bucket.data(), ()),
                Tachygram::from(mk.derive_nullifier(epoch)),
            ),
            bucket.clone(),
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&segment, &mut *rng).unwrap());
    let (secret, ()) = APP
        .seed(rng, NoteSeed, witness::note_seed(((), ()), note, pak))
        .unwrap();
    assert!(APP.verify_differential(&secret, &mut *rng).unwrap());
    let (derived, ()) = APP
        .fuse(
            rng,
            NullifierDerive,
            witness::nullifier_derive((*secret.data(), ()), epoch),
            secret,
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&derived, &mut *rng).unwrap());
    let (unspent, ()) = APP
        .fuse(
            rng,
            UnspentBind,
            witness::unspent_bind(
                (*segment.data(), *derived.data()),
                &mk.derive_window(epoch),
                &[mk.derive_nullifier(epoch)],
            ),
            segment,
            derived,
        )
        .unwrap();
    assert!(APP.verify_differential(&unspent, &mut *rng).unwrap());
    unspent
}

/// Pins acceptance of reciprocally scaled equal-root sides and empty contents,
/// beside rejection of their canonical forms; acceptance is not a requirement.
#[test]
#[expect(
    clippy::cognitive_complexity,
    reason = "paired canonical and scaled cases"
)]
fn qr_split_rules_test_canonical_form_only() {
    let rng = &mut StdRng::seed_from_u64(0);
    let discriminant = QrDiscriminant::random(rng);
    let member = Tachygram::random(rng);
    let member_fp = Fp::from(member);
    let side = classify(member_fp, discriminant.at(0)).0;
    let bit = !side;
    let scale = Fp::from(7u64);
    let scale_inv = scale.invert().unwrap();
    let deep_scale = Fp::from(11u64);
    let deep_cofactor = (scale * deep_scale).invert().unwrap();
    for constant in [scale, deep_scale] {
        assert!(constant != Fp::ZERO && constant != Fp::ONE && constant != -Fp::ONE);
    }
    let monic: TachygramSetPoly = [member].into_iter().collect();
    let empty: TachygramSetPoly = iter::empty().collect();
    let doubled = [member, member];
    let (intake, honest_sides) =
        split_stamp(rng, discriminant, &doubled, Some((monic.clone(), monic)));
    assert_matches!(
        descend(rng, &honest_sides, bit, &[member], Fp::ONE).err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrSideDescend: the two sides agree at the challenge"
    );

    let (non_residue, residue) = scaled_factors([&[member], &[member]], [scale, scale_inv]);
    for (poly, factor) in [(&non_residue, scale), (&residue, scale_inv)] {
        assert_eq!(
            poly.as_ref()
                .iter_stored_coeffs()
                .filter(|&(_, coeff)| *coeff != Fp::ZERO)
                .map(|(degree, &coeff)| (degree, coeff))
                .collect::<Vec<_>>(),
            vec![(0, -(factor * member_fp)), (1, factor)]
        );
        assert_eq!(poly.eval(member_fp), Fp::ZERO);
    }
    let (sides, ()) = APP
        .fuse(
            rng,
            QrIntakeSplit,
            (non_residue, residue),
            intake.clone(),
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&sides, &mut *rng).unwrap());
    assert_ne!(sides.commitments()[0], sides.commitments()[1]);
    let sibling_scale = if bit { scale } else { scale_inv };
    let child = descend(rng, &sides, bit, &[member], sibling_scale).unwrap();
    assert_eq!(
        *child.data(),
        (
            EpochIndex::new(0),
            Anchor::default(),
            intake.data().2,
            discriminant,
            QrProfile::ROOT.descend(bit),
        )
    );

    let single = [member];
    let (held, constant) = scaled_factors([&single, &[]], [scale, scale_inv]);
    for (poly, coeffs) in [
        (&held, vec![(0, -(scale * member_fp)), (1, scale)]),
        (&constant, vec![(0, scale_inv)]),
    ] {
        assert_eq!(
            poly.as_ref()
                .iter_stored_coeffs()
                .filter(|&(_, coeff)| *coeff != Fp::ZERO)
                .map(|(degree, &coeff)| (degree, coeff))
                .collect::<Vec<_>>(),
            coeffs,
        );
    }
    assert_eq!(held.eval(member_fp), Fp::ZERO);
    let factors = if side {
        (constant, held)
    } else {
        (held, constant)
    };
    let (single_intake, single_sides) = split_stamp(rng, discriminant, &single, Some(factors));
    let empty_child = descend(rng, &single_sides, bit, &single, scale).unwrap();
    assert_eq!(
        empty_child.commitments()[0],
        APP.commit(&[scale_inv]).unwrap()
    );
    assert_ne!(
        empty_child.commitments()[0],
        APP.commit(&[Fp::ONE]).unwrap()
    );
    let (first, second) = scaled_factors([&[], &[]], [deep_scale, deep_cofactor]);
    for (poly, factor) in [(&first, deep_scale), (&second, deep_cofactor)] {
        assert_eq!(
            poly.as_ref()
                .iter_stored_coeffs()
                .filter(|&(_, coeff)| *coeff != Fp::ZERO)
                .map(|(degree, &coeff)| (degree, coeff))
                .collect::<Vec<_>>(),
            vec![(0, factor)],
        );
    }
    let (deep_sides, ()) = APP
        .fuse(
            rng,
            QrIntakeSplit,
            (first, second),
            empty_child,
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&deep_sides, &mut *rng).unwrap());

    let (honest, ()) = APP
        .fuse(
            rng,
            QrIntakeSplit,
            witness::qr_intake_split((*single_intake.data(), ()), &single),
            single_intake,
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&honest, &mut *rng).unwrap());
    let honest_empty_child = descend(rng, &honest, bit, &single, Fp::ONE).unwrap();
    let (seeded, ()) = APP
        .seed(
            rng,
            QrEmptyIntakeSeed,
            witness::qr_empty_intake_seed(
                ((), ()),
                Anchor::default(),
                EpochIndex::new(0),
                discriminant,
            ),
        )
        .unwrap();
    for canonical_empty in [honest_empty_child, seeded] {
        assert_matches!(
            APP.fuse(
                rng, QrIntakeSplit, (empty.clone(), empty.clone()), canonical_empty,
                APP.bootstrap_proof().clone().carry::<()>(()),
            ).err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == "QrIntakeSplit: contents are one"
        );
    }
}

/// Pins matching queried answers for 7-scaled buckets and an 11-scaled empty
/// re-split, while evidence replay rejects a different contents commitment.
#[test]
#[expect(
    clippy::cognitive_complexity,
    reason = "end-to-end characterization of both consumers"
)]
fn scaled_qr_buckets_answer_as_honest_buckets() {
    let rng = &mut StdRng::seed_from_u64(1);
    let epoch = EpochIndex::new(0);
    let NoteCase {
        pak,
        note,
        cm,
        nf,
        discriminant,
        side,
    } = note_case(rng);
    let other_note = iter::repeat_with(|| Note {
        pk: note.pk,
        value: value::Positive::try_from(400u64).unwrap(),
        psi: nullifier::Trapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    })
    .find(|candidate| {
        let candidate_nf = pak
            .nk
            .derive_note_private(candidate.psi)
            .derive_nullifier(epoch);
        classify(Fp::from(Tachygram::from(candidate_nf)), discriminant.at(0)).0 != side
    })
    .unwrap();
    let other_nf = Tachygram::from(
        pak.nk
            .derive_note_private(other_note.psi)
            .derive_nullifier(epoch),
    );
    let deep_bit = classify(Fp::from(other_nf), discriminant.at(1)).0;
    let scale = Fp::from(7u64);
    let scale_inv = scale.invert().unwrap();
    let deep_scale = Fp::from(11u64);
    let deep_cofactor = (scale * deep_scale).invert().unwrap();
    let single = [cm];
    let (intake, honest_sides) = split_stamp(rng, discriminant, &single, None);
    let honest_held = bucket(rng, &honest_sides, side, &[], Fp::ONE);
    let honest_empty = bucket(rng, &honest_sides, !side, &single, Fp::ONE);
    let (held, constant) = scaled_factors([&single, &[]], [scale, scale_inv]);
    let factors = if side {
        (constant, held)
    } else {
        (held, constant)
    };
    let (sides, ()) = APP
        .fuse(
            rng,
            QrIntakeSplit,
            factors,
            intake,
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&sides, &mut *rng).unwrap());
    let scaled_held = bucket(rng, &sides, side, &[], scale_inv);
    let scaled_empty_intake = descend(rng, &sides, !side, &single, scale).unwrap();
    let (scaled_empty, ()) = APP
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*scaled_empty_intake.data(), ()), Anchor::from(Fp::ZERO)),
            scaled_empty_intake.clone(),
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&scaled_empty, &mut *rng).unwrap());
    let (deep_sides, ()) = APP
        .fuse(
            rng,
            QrIntakeSplit,
            scaled_factors([&[], &[]], [deep_scale, deep_cofactor]),
            scaled_empty_intake,
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&deep_sides, &mut *rng).unwrap());
    let deep_sibling_scale = if deep_bit { deep_scale } else { deep_cofactor };
    let scaled_deep = bucket(rng, &deep_sides, deep_bit, &[], deep_sibling_scale);
    for (honest, scaled_bucket) in [(&honest_held, &scaled_held), (&honest_empty, &scaled_empty)] {
        let (.., honest_profile, honest_hash) = *honest.data();
        let (.., scaled_profile, scaled_hash) = *scaled_bucket.data();
        assert_eq!(honest_profile, scaled_profile);
        assert_ne!(honest_hash, scaled_hash);
        assert_eq!(honest.data().2, scaled_bucket.data().2);
    }
    assert_eq!(
        scaled_deep.data().4,
        QrProfile::ROOT.descend(!side).descend(deep_bit)
    );

    let [scaled_pair, honest_pair] = [(&scaled_held, &scaled_empty), (&honest_held, &honest_empty)]
        .map(|(held, empty)| {
            let (pair, ()) = APP
                .fuse(rng, EvidenceTreeLeafPair, (), held.clone(), empty.clone())
                .unwrap();
            assert!(APP.verify_differential(&pair, &mut *rng).unwrap());
            pair
        });
    let leaves = [
        scaled_pair.data().4,
        scaled_pair.data().5,
        honest_pair.data().4,
        honest_pair.data().5,
    ];
    let (mut tree, ()) = APP
        .fuse(rng, EvidenceTreeFuse, (), scaled_pair, honest_pair)
        .unwrap();
    assert!(APP.verify_differential(&tree, &mut *rng).unwrap());
    let mut caps = Vec::new();
    while caps.len() + 1 < EvidenceTreeDescend::LEVELS {
        caps.push(tree.data().4);
        let (raised, ()) = APP
            .fuse(
                rng,
                EvidenceTreeCap,
                (),
                tree,
                APP.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert!(APP.verify_differential(&raised, &mut *rng).unwrap());
        tree = raised;
    }
    let mut open = |index: usize, profile: QrProfile, contents: TachygramSetPoly| {
        let mut path = [([index & 2 != 0, index & 1 != 0], leaves); EvidenceTreeDescend::LEVELS];
        for (level, child) in path.iter_mut().zip(caps.iter().rev()) {
            *level = ([false, false], [*child; EVIDENCE_TREE_ARITY]);
        }
        let (leaf, ()) = APP
            .fuse(
                rng,
                EvidenceTreeDescend,
                witness::evidence_tree_descend((*tree.data(), ()), path),
                tree.clone(),
                APP.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert!(APP.verify_differential(&leaf, &mut *rng).unwrap());
        let (opened, ()) = APP.fuse(
            rng,
            EvidenceTreeOpen,
            witness::evidence_tree_open((*leaf.data(), ()), profile, contents),
            leaf,
            APP.bootstrap_proof().clone().carry::<()>(()),
        )?;
        assert!(APP.verify_differential(&opened, &mut *rng).unwrap());
        Ok(opened)
    };
    let held_profile = QrProfile::ROOT.descend(side);
    let monic: TachygramSetPoly = single.into_iter().collect();
    let (scaled_monic, _) = scaled_factors([&single, &[]], [scale, scale_inv]);
    let opened_scaled_held = open(0, held_profile, scaled_monic.clone()).unwrap();
    assert_eq!(*opened_scaled_held.data(), *scaled_held.data());
    let opened_honest_held = open(2, held_profile, monic.clone()).unwrap();
    assert_eq!(*opened_honest_held.data(), *honest_held.data());
    for (index, contents) in [(0, monic), (2, scaled_monic)] {
        assert_matches!(
            open(index, held_profile, contents).err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == "EvidenceTreeOpen: witnessed bucket is not the tree's leaf"
        );
    }
    let rcv = value::Trapdoor::random(rng);
    let mut spends = Vec::new();
    for held_bucket in [&opened_honest_held, &opened_scaled_held] {
        let unspent = exclude_and_bind(rng, held_bucket, note, pak);
        assert_matches!(
            APP.fuse(
                rng, QrUnspentInit, witness::qr_unspent_init((*held_bucket.data(), ()), cm),
                held_bucket.clone(), APP.bootstrap_proof().clone().carry::<()>(()),
            ).err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == "QrUnspentInit: found nullifier in the bucket"
        );
        let (spendable, ()) = APP
            .fuse(
                rng,
                QrSpendableInit,
                (),
                unspent.clone(),
                held_bucket.clone(),
            )
            .unwrap();
        assert!(APP.verify_differential(&spendable, &mut *rng).unwrap());
        assert_eq!(
            *spendable.data(),
            (
                note.commitment(),
                epoch.next().unwrap(),
                held_bucket.data().2
            )
        );
        let (secret, ()) = APP
            .seed(rng, NoteSeed, witness::note_seed(((), ()), note, pak))
            .unwrap();
        assert!(APP.verify_differential(&secret, &mut *rng).unwrap());
        let (spend, ()) = APP
            .fuse(
                rng,
                SpendBind,
                witness::spend_bind((*spendable.data(), *secret.data()), rcv),
                spendable,
                secret,
            )
            .unwrap();
        assert!(APP.verify_differential(&spend, &mut *rng).unwrap());
        let (spend_cm, nf_current, nf_next, anchor, pk, _) = *spend.data();
        spends.push((spend_cm, nf_current, nf_next, anchor, Fp::from(pk)));
        for empty_bucket in [&honest_empty, &scaled_empty, &scaled_deep] {
            assert_matches!(
                APP.fuse(rng, QrSpendableInit, (), unspent.clone(), empty_bucket.clone()).err(),
                Some(ragu_core::Error::InvalidWitness(err))
                    if err.to_string() == "QrSpendableInit: commitment not in bucket"
            );
        }
    }
    assert_eq!(spends[0], spends[1]);
    for empty_bucket in [&honest_empty, &scaled_empty, &scaled_deep] {
        let unspent = exclude_and_bind(rng, empty_bucket, other_note, pak);
        for held_bucket in [&honest_held, &scaled_held, empty_bucket] {
            assert_matches!(
                APP.fuse(rng, QrSpendableInit, (), unspent.clone(), held_bucket.clone()).err(),
                Some(ragu_core::Error::InvalidWitness(err))
                    if err.to_string() == "QrSpendableInit: commitment not in bucket"
            );
        }
        assert_matches!(
            APP.fuse(
                rng, QrUnspentInit, witness::qr_unspent_init((*empty_bucket.data(), ()), nf),
                empty_bucket.clone(), APP.bootstrap_proof().clone().carry::<()>(()),
            ).err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == "QR profile: value does not take the bucket's profile"
        );
    }
}

/// Pins acceptance of a 7-and-1/7 duplicate split into a wrong-class bucket;
/// the same queried answers occur with monic stray members, not just scaling.
#[test]
fn scaled_duplicate_split_answers_as_a_monic_stray_bucket() {
    let rng = &mut StdRng::seed_from_u64(2);
    let NoteCase {
        pak,
        note,
        cm,
        nf: _,
        discriminant,
        side,
    } = note_case(rng);
    let absent = iter::repeat_with(|| Tachygram::random(rng))
        .find(|value| classify(Fp::from(*value), discriminant.at(0)).0 != side)
        .unwrap();
    let companion = iter::repeat_with(|| Tachygram::random(rng))
        .find(|value| classify(Fp::from(*value), discriminant.at(0)).0 == side)
        .unwrap();
    let scale = Fp::from(7u64);
    let scale_inv = scale.invert().unwrap();
    let (duplicate_intake, duplicate_sides) = split_stamp(rng, discriminant, &[cm, cm], None);
    let duplicate_held = bucket(rng, &duplicate_sides, side, &[], Fp::ONE);
    let (scaled_sides, ()) = APP
        .fuse(
            rng,
            QrIntakeSplit,
            scaled_factors([&[cm], &[cm]], [scale, scale_inv]),
            duplicate_intake,
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&scaled_sides, &mut *rng).unwrap());
    let sibling_scale = if side { scale_inv } else { scale };
    let scaled_stray = bucket(rng, &scaled_sides, !side, &[cm], sibling_scale);
    let pair = [cm, companion];
    let (pair_intake, honest_pair_sides) = split_stamp(rng, discriminant, &pair, None);
    let pair_held = bucket(rng, &honest_pair_sides, side, &[], Fp::ONE);
    let pair_empty = bucket(rng, &honest_pair_sides, !side, &pair, Fp::ONE);
    let (cm_poly, companion_poly) = scaled_factors([&[cm], &[companion]], [Fp::ONE; 2]);
    let stray_factors = if side {
        (cm_poly, companion_poly)
    } else {
        (companion_poly, cm_poly)
    };
    let (stray_sides, ()) = APP
        .fuse(
            rng,
            QrIntakeSplit,
            stray_factors,
            pair_intake,
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&stray_sides, &mut *rng).unwrap());
    let monic_stray = bucket(rng, &stray_sides, !side, &[companion], Fp::ONE);
    assert_eq!(scaled_stray.data().4, monic_stray.data().4);
    let mut unspents = Vec::new();
    for (held, stray) in [(&duplicate_held, &scaled_stray), (&pair_held, &monic_stray)] {
        let unspent = exclude_and_bind(rng, held, note, pak);
        for included in [held, stray] {
            let (spendable, ()) = APP
                .fuse(rng, QrSpendableInit, (), unspent.clone(), included.clone())
                .unwrap();
            assert!(APP.verify_differential(&spendable, &mut *rng).unwrap());
        }
        let (segment, ()) = APP
            .fuse(
                rng,
                QrUnspentInit,
                witness::qr_unspent_init((*stray.data(), ()), absent),
                stray.clone(),
                APP.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert!(APP.verify_differential(&segment, &mut *rng).unwrap());
        for (checked, message) in [
            (held, "QrUnspentInit: found nullifier in the bucket"),
            (
                stray,
                "QR profile: value does not take the bucket's profile",
            ),
        ] {
            assert_matches!(
                APP.fuse(
                    rng, QrUnspentInit, witness::qr_unspent_init((*checked.data(), ()), cm),
                    checked.clone(), APP.bootstrap_proof().clone().carry::<()>(()),
                ).err(),
                Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == message
            );
        }
        unspents.push(unspent);
    }
    assert_matches!(
        APP.fuse(rng, QrSpendableInit, (), unspents[1].clone(), pair_empty.clone()).err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrSpendableInit: commitment not in bucket"
    );
    let (segment, ()) = APP
        .fuse(
            rng,
            QrUnspentInit,
            witness::qr_unspent_init((*pair_empty.data(), ()), absent),
            pair_empty,
            APP.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(APP.verify_differential(&segment, &mut *rng).unwrap());
}
