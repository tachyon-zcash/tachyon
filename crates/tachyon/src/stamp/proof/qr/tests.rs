//! Scaled QR splits. [`QrIntakeSplit`] is the only step that witnesses both
//! factors of a pinned polynomial, and its product fixes each side only up to
//! a nonzero constant, so a prover may scale one side by $k$ and the other by
//! $1/k$. Roots survive: the contents are nonzero, so the product keeps their
//! root multiset, and the class identity in [`QrSideDescend`] constrains the
//! sibling's roots and takes any constant into its quotient. [`QrUnspentInit`]
//! and [`UnspentLift`](super::super::pool::UnspentLift) open a bucket for
//! nonzero at the tested value, [`QrSpendableInit`] for zero at `cm`, and
//! [`EvidenceTreeOpen`] replays only the polynomial its leaf hashes, so no
//! consumer reads more than the roots.
//!
//! These tests pin current behaviour: the empty-intake and same-set rules
//! test opened values against the canonical form and admit scaled forms. A
//! change that binds the rules to every scaling flips
//! `qr_split_rules_test_canonical_form_only`, as intended.

#![allow(clippy::too_many_lines, reason = "test module")]

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
        PROOF_SYSTEM,
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

/// Select and descend into side `bit`. The sibling is `sibling_scale` times
/// the monic polynomial over `sibling_members`, so the honest hints carry the
/// quotient divided by `sibling_scale`.
fn descend(
    rng: &mut StdRng,
    sides: &Pcd<Pasta, ProductionRank, QrIntakeSides>,
    bit: bool,
    sibling_members: &[Tachygram],
    sibling_scale: Fp,
) -> ragu_core::Result<Pcd<Pasta, ProductionRank, QrIntake>> {
    let (.., discriminant, profile, _) = *sides.data();
    let shift = discriminant.at(profile.depth);
    let points: Vec<(Fp, Fp)> = sibling_members
        .iter()
        .map(|&member| (Fp::from(member), classify(Fp::from(member), shift).1))
        .collect();
    let (interpolant, mut quotient) = decomposition(&points, class_multiplier(!bit), shift)
        .expect("sibling members are distinct and take the sibling's class");
    quotient.scale(sibling_scale.invert().unwrap());
    let (selected, ()) = PROOF_SYSTEM.fuse(
        rng,
        QrSideSelect,
        (interpolant.into(), quotient.into()),
        sides.clone(),
        PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
    )?;
    assert!(
        PROOF_SYSTEM
            .verify_differential(&selected, &mut *rng)
            .unwrap()
    );
    let (child, ()) = PROOF_SYSTEM.fuse(rng, QrSideDescend, (bit,), sides.clone(), selected)?;
    assert!(PROOF_SYSTEM.verify_differential(&child, &mut *rng).unwrap());
    Ok(child)
}

/// Exclude `note`'s epoch-zero nullifier from `bucket` and bind the segment to
/// the note's genuine nullifier derivation.
fn exclude_and_bind(
    rng: &mut StdRng,
    bucket: &Pcd<Pasta, ProductionRank, QrBucket>,
    note: Note,
    pak: ProofAuthorizingKey,
) -> Pcd<Pasta, ProductionRank, NoteUnspent> {
    let epoch = EpochIndex::new(0);
    let mk = pak.nk.derive_note_private(note.psi);
    let (segment, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrUnspentInit,
            witness::qr_unspent_init(
                (*bucket.data(), ()),
                Tachygram::from(mk.derive_nullifier(epoch)),
            ),
            bucket.clone(),
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&segment, &mut *rng)
            .unwrap()
    );
    let (secret, ()) = PROOF_SYSTEM
        .seed(rng, NoteSeed, witness::note_seed(((), ()), note, pak))
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&secret, &mut *rng)
            .unwrap()
    );
    let (derived, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            NullifierDerive,
            witness::nullifier_derive((*secret.data(), ()), epoch),
            secret,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&derived, &mut *rng)
            .unwrap()
    );
    let (unspent, ()) = PROOF_SYSTEM
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
    assert!(
        PROOF_SYSTEM
            .verify_differential(&unspent, &mut *rng)
            .unwrap()
    );
    unspent
}

/// Characterizes the scope of the canonical-form rules. `QrIntakeSplit`
/// rejects contents that open to one at the challenge and `QrSideDescend`
/// rejects sides that open equal, which is exactly the canonical empty set and
/// the canonical equal split. A split scaled by `a` and `1/a` keeps the
/// product and every root but opens to other values, so the same degenerate
/// partitions pass all three steps.
#[test]
fn qr_split_rules_test_canonical_form_only() {
    let rng = &mut StdRng::seed_from_u64(0);
    let discriminant = QrDiscriminant::random(rng);
    let member = Tachygram::random(rng);
    let member_fp = Fp::from(member);
    let side = classify(member_fp, discriminant.at(0)).0;
    // The sibling must hold the member in its own class, so descend into the
    // other.
    let bit = !side;

    let scale = Fp::from(7u64);
    let scale_inv = scale.invert().unwrap();
    let deep_scale = Fp::from(11u64);
    let deep_cofactor = (scale * deep_scale).invert().unwrap();
    for constant in [scale, deep_scale] {
        assert!(constant != Fp::ZERO && constant != Fp::ONE && constant != -Fp::ONE);
    }
    let monic = TachygramSetPoly::from_iter([member]);
    let empty = TachygramSetPoly::from_iter(iter::empty());

    // Duplicated member: contents (X - m)^2.
    let doubled = [member, member];
    let (intake, ()) = PROOF_SYSTEM
        .seed(
            rng,
            QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(
                ((), ()),
                Anchor::default(),
                EpochIndex::new(0),
                discriminant,
                &doubled,
            ),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&intake, &mut *rng)
            .unwrap()
    );
    let (honest_sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrIntakeSplit,
            (monic.clone(), monic.clone()),
            intake.clone(),
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&honest_sides, &mut *rng)
            .unwrap()
    );
    assert_matches!(
        descend(rng, &honest_sides, bit, &[member], Fp::ONE).err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrSideDescend: the two sides agree at the challenge"
    );

    let mut scaled_non_residue: Polynomial<Fp, ProductionRank> = monic.clone().into();
    scaled_non_residue.scale(scale);
    let scaled_non_residue = TachygramSetPoly::from_noncanonical_for_test(scaled_non_residue);
    let mut scaled_residue: Polynomial<Fp, ProductionRank> = monic.clone().into();
    scaled_residue.scale(scale_inv);
    let scaled_residue = TachygramSetPoly::from_noncanonical_for_test(scaled_residue);
    for (poly, factor) in [(&scaled_non_residue, scale), (&scaled_residue, scale_inv)] {
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
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrIntakeSplit,
            (scaled_non_residue, scaled_residue),
            intake.clone(),
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(PROOF_SYSTEM.verify_differential(&sides, &mut *rng).unwrap());
    assert_ne!(sides.commitments()[0], sides.commitments()[1]);
    let sibling_scale = if bit { scale } else { scale_inv };
    let child = descend(rng, &sides, bit, &[member], sibling_scale).unwrap();
    let (_, _, anchor_end, ..) = *intake.data();
    assert_eq!(
        *child.data(),
        (
            EpochIndex::new(0),
            Anchor::default(),
            anchor_end,
            discriminant,
            QrProfile::ROOT.descend(bit),
        )
    );

    // Empty side: contents {m}, descending into the side that holds nothing.
    let single = [member];
    let mut held: Polynomial<Fp, ProductionRank> = monic.clone().into();
    held.scale(scale);
    let held = TachygramSetPoly::from_noncanonical_for_test(held);
    let mut constant: Polynomial<Fp, ProductionRank> = empty.clone().into();
    constant.scale(scale_inv);
    let constant = TachygramSetPoly::from_noncanonical_for_test(constant);
    assert_eq!(
        held.as_ref()
            .iter_stored_coeffs()
            .filter(|&(_, coeff)| *coeff != Fp::ZERO)
            .map(|(degree, &coeff)| (degree, coeff))
            .collect::<Vec<_>>(),
        vec![(0, -(scale * member_fp)), (1, scale)]
    );
    assert_eq!(held.eval(member_fp), Fp::ZERO);
    assert_eq!(
        constant
            .as_ref()
            .iter_stored_coeffs()
            .filter(|&(_, coeff)| *coeff != Fp::ZERO)
            .map(|(degree, &coeff)| (degree, coeff))
            .collect::<Vec<_>>(),
        vec![(0, scale_inv)]
    );
    let (non_residue, residue) = if side {
        (constant, held)
    } else {
        (held, constant)
    };
    let (single_intake, ()) = PROOF_SYSTEM
        .seed(
            rng,
            QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(
                ((), ()),
                Anchor::default(),
                EpochIndex::new(0),
                discriminant,
                &single,
            ),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&single_intake, &mut *rng)
            .unwrap()
    );
    let (single_sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrIntakeSplit,
            (non_residue, residue),
            single_intake.clone(),
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&single_sides, &mut *rng)
            .unwrap()
    );
    let empty_child = descend(rng, &single_sides, bit, &single, scale).unwrap();
    assert_eq!(
        empty_child.commitments()[0],
        PROOF_SYSTEM.commit(&[scale_inv]).unwrap()
    );
    assert_ne!(
        empty_child.commitments()[0],
        PROOF_SYSTEM.commit(&[Fp::ONE]).unwrap()
    );

    let mut first: Polynomial<Fp, ProductionRank> = empty.clone().into();
    first.scale(deep_scale);
    let first = TachygramSetPoly::from_noncanonical_for_test(first);
    let mut second: Polynomial<Fp, ProductionRank> = empty.clone().into();
    second.scale(deep_cofactor);
    let second = TachygramSetPoly::from_noncanonical_for_test(second);
    assert_eq!(
        first
            .as_ref()
            .iter_stored_coeffs()
            .filter(|&(_, coeff)| *coeff != Fp::ZERO)
            .map(|(degree, &coeff)| (degree, coeff))
            .collect::<Vec<_>>(),
        vec![(0, deep_scale)]
    );
    assert_eq!(
        second
            .as_ref()
            .iter_stored_coeffs()
            .filter(|&(_, coeff)| *coeff != Fp::ZERO)
            .map(|(degree, &coeff)| (degree, coeff))
            .collect::<Vec<_>>(),
        vec![(0, deep_cofactor)]
    );
    let (deep_sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrIntakeSplit,
            (first, second),
            empty_child,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&deep_sides, &mut *rng)
            .unwrap()
    );

    let (honest_non_residue, honest_residue) =
        witness::qr_intake_split((*single_intake.data(), ()), &single);
    let (honest, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrIntakeSplit,
            (honest_non_residue, honest_residue),
            single_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&honest, &mut *rng)
            .unwrap()
    );
    let honest_empty_child = descend(rng, &honest, bit, &single, Fp::ONE).unwrap();
    assert_matches!(
        PROOF_SYSTEM
            .fuse(
                rng,
                QrIntakeSplit,
                (empty.clone(), empty.clone()),
                honest_empty_child,
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrIntakeSplit: contents are one"
    );
    let (seeded, ()) = PROOF_SYSTEM
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
    assert_matches!(
        PROOF_SYSTEM
            .fuse(
                rng,
                QrIntakeSplit,
                (empty.clone(), empty),
                seeded,
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrIntakeSplit: contents are one"
    );
}

/// Buckets from a scaled split answer every inclusion and exclusion question
/// as the honest buckets of the same profile and roots, through the evidence
/// tree and down to [`UnspentBind`] and [`SpendBind`].
///
/// The epoch publishes one stamp `{cm}`. The scaled split puts `a·(X - cm)` on
/// `cm`'s side and the constant `1/a` on the other; the honest split puts
/// `X - cm` and one. The scaled empty side splits again into `b` and
/// `1/(a·b)`, a bucket the honest network cannot reach.
#[test]
fn scaled_qr_buckets_answer_as_honest_buckets() {
    let rng = &mut StdRng::seed_from_u64(1);
    let epoch = EpochIndex::new(0);
    let sk = private::SpendingKey::random(rng);
    let pak = sk.derive_proof_private();
    let note = Note {
        pk: sk.derive_payment_key(),
        value: value::Positive::try_from(400u64).unwrap(),
        psi: nullifier::Trapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    };
    let cm = Tachygram::from(note.commitment());
    let nf = Tachygram::from(pak.nk.derive_note_private(note.psi).derive_nullifier(epoch));
    let discriminant = iter::repeat_with(|| QrDiscriminant::random(rng))
        .find(|discriminant| {
            classify(Fp::from(nf), discriminant.at(0)).0
                == classify(Fp::from(cm), discriminant.at(0)).0
        })
        .unwrap();
    let side = classify(Fp::from(cm), discriminant.at(0)).0;
    let other_note = iter::repeat_with(|| Note {
        pk: sk.derive_payment_key(),
        value: value::Positive::try_from(400u64).unwrap(),
        psi: nullifier::Trapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    })
    .find(|candidate| {
        let nf = pak
            .nk
            .derive_note_private(candidate.psi)
            .derive_nullifier(epoch);
        classify(Fp::from(Tachygram::from(nf)), discriminant.at(0)).0 != side
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
    let monic = TachygramSetPoly::from_iter([cm]);
    let empty = TachygramSetPoly::from_iter(iter::empty());
    let single = [cm];

    let (intake, ()) = PROOF_SYSTEM
        .seed(
            rng,
            QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(
                ((), ()),
                Anchor::default(),
                epoch,
                discriminant,
                &single,
            ),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&intake, &mut *rng)
            .unwrap()
    );
    let (honest_non_residue, honest_residue) =
        witness::qr_intake_split((*intake.data(), ()), &single);
    let (honest_sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrIntakeSplit,
            (honest_non_residue, honest_residue),
            intake.clone(),
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&honest_sides, &mut *rng)
            .unwrap()
    );
    let honest_held_intake = descend(rng, &honest_sides, side, &[], Fp::ONE).unwrap();
    let (honest_held, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*honest_held_intake.data(), ()), Anchor::from(Fp::ZERO)),
            honest_held_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&honest_held, &mut *rng)
            .unwrap()
    );
    let honest_empty_intake = descend(rng, &honest_sides, !side, &single, Fp::ONE).unwrap();
    let (honest_empty, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*honest_empty_intake.data(), ()), Anchor::from(Fp::ZERO)),
            honest_empty_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&honest_empty, &mut *rng)
            .unwrap()
    );

    let mut held: Polynomial<Fp, ProductionRank> = monic.clone().into();
    held.scale(scale);
    let held = TachygramSetPoly::from_noncanonical_for_test(held);
    let mut constant: Polynomial<Fp, ProductionRank> = empty.clone().into();
    constant.scale(scale_inv);
    let constant = TachygramSetPoly::from_noncanonical_for_test(constant);
    let (non_residue, residue) = if side {
        (constant, held)
    } else {
        (held, constant)
    };
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrIntakeSplit,
            (non_residue, residue),
            intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(PROOF_SYSTEM.verify_differential(&sides, &mut *rng).unwrap());
    let scaled_held_intake = descend(rng, &sides, side, &[], scale_inv).unwrap();
    let (scaled_held, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*scaled_held_intake.data(), ()), Anchor::from(Fp::ZERO)),
            scaled_held_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&scaled_held, &mut *rng)
            .unwrap()
    );
    let scaled_empty_intake = descend(rng, &sides, !side, &single, scale).unwrap();
    let (scaled_empty, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*scaled_empty_intake.data(), ()), Anchor::from(Fp::ZERO)),
            scaled_empty_intake.clone(),
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&scaled_empty, &mut *rng)
            .unwrap()
    );
    let mut first: Polynomial<Fp, ProductionRank> = empty.clone().into();
    first.scale(deep_scale);
    let mut second: Polynomial<Fp, ProductionRank> = empty.clone().into();
    second.scale(deep_cofactor);
    let (deep_sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrIntakeSplit,
            (
                TachygramSetPoly::from_noncanonical_for_test(first),
                TachygramSetPoly::from_noncanonical_for_test(second),
            ),
            scaled_empty_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&deep_sides, &mut *rng)
            .unwrap()
    );
    let deep_sibling_scale = if deep_bit { deep_scale } else { deep_cofactor };
    let scaled_deep_intake = descend(rng, &deep_sides, deep_bit, &[], deep_sibling_scale).unwrap();
    let (scaled_deep, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*scaled_deep_intake.data(), ()), Anchor::from(Fp::ZERO)),
            scaled_deep_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&scaled_deep, &mut *rng)
            .unwrap()
    );

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

    // Admit the scaled buckets next to the honest ones and replay them.
    let (admitted_scaled, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            EvidenceTreeLeafPair,
            (),
            scaled_held.clone(),
            scaled_empty.clone(),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&admitted_scaled, &mut *rng)
            .unwrap()
    );
    let scaled_pair = admitted_scaled;
    let (admitted_honest, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            EvidenceTreeLeafPair,
            (),
            honest_held.clone(),
            honest_empty.clone(),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&admitted_honest, &mut *rng)
            .unwrap()
    );
    let honest_pair = admitted_honest;
    let leaves = [
        scaled_pair.data().4,
        scaled_pair.data().5,
        honest_pair.data().4,
        honest_pair.data().5,
    ];
    let (fused, ()) = PROOF_SYSTEM
        .fuse(rng, EvidenceTreeFuse, (), scaled_pair, honest_pair)
        .unwrap();
    assert!(PROOF_SYSTEM.verify_differential(&fused, &mut *rng).unwrap());
    let mut tree = fused;
    let mut caps = Vec::new();
    while caps.len() + 1 < EvidenceTreeDescend::LEVELS {
        caps.push(tree.data().4);
        let (raised, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                EvidenceTreeCap,
                (),
                tree,
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert!(
            PROOF_SYSTEM
                .verify_differential(&raised, &mut *rng)
                .unwrap()
        );
        tree = raised;
    }
    let mut open = |index: usize, profile: QrProfile, contents: TachygramSetPoly| {
        let mut path = [([index & 2 != 0, index & 1 != 0], leaves); EvidenceTreeDescend::LEVELS];
        for (level, child) in path.iter_mut().zip(caps.iter().rev()) {
            *level = ([false, false], [*child; EVIDENCE_TREE_ARITY]);
        }
        let (descended, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                EvidenceTreeDescend,
                witness::evidence_tree_descend((*tree.data(), ()), path),
                tree.clone(),
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert!(
            PROOF_SYSTEM
                .verify_differential(&descended, &mut *rng)
                .unwrap()
        );
        let leaf = descended;
        let (bucket, ()) = PROOF_SYSTEM.fuse(
            rng,
            EvidenceTreeOpen,
            witness::evidence_tree_open((*leaf.data(), ()), profile, contents),
            leaf,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )?;
        assert!(
            PROOF_SYSTEM
                .verify_differential(&bucket, &mut *rng)
                .unwrap()
        );
        Ok(bucket)
    };
    let held_profile = QrProfile::ROOT.descend(side);
    let mut scaled_monic: Polynomial<Fp, ProductionRank> = monic.clone().into();
    scaled_monic.scale(scale);
    let scaled_monic = TachygramSetPoly::from_noncanonical_for_test(scaled_monic);
    let opened_scaled_held = open(0, held_profile, scaled_monic.clone()).unwrap();
    assert_eq!(*opened_scaled_held.data(), *scaled_held.data());
    let opened_honest_held = open(2, held_profile, monic.clone()).unwrap();
    assert_eq!(*opened_honest_held.data(), *honest_held.data());
    assert_matches!(
        open(0, held_profile, monic.clone()).err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "EvidenceTreeOpen: witnessed bucket is not the tree's leaf"
    );
    assert_matches!(
        open(2, held_profile, scaled_monic).err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "EvidenceTreeOpen: witnessed bucket is not the tree's leaf"
    );

    // Exclusion of the note's absent nullifier, bound to its derivation, then
    // inclusion of its commitment and a spend.
    let rcv = value::Trapdoor::random(rng);
    let mut spends = Vec::new();
    for bucket in [&opened_honest_held, &opened_scaled_held] {
        let unspent = exclude_and_bind(rng, bucket, note, pak);
        assert_matches!(
            PROOF_SYSTEM.fuse(
                rng,
                QrUnspentInit,
                witness::qr_unspent_init((*bucket.data(), ()), cm),
                bucket.clone(),
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            ).err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == "QrUnspentInit: found nullifier in the bucket"
        );
        let (spendable, ()) = PROOF_SYSTEM
            .fuse(rng, QrSpendableInit, (), unspent.clone(), bucket.clone())
            .unwrap();
        assert!(
            PROOF_SYSTEM
                .verify_differential(&spendable, &mut *rng)
                .unwrap()
        );
        assert_eq!(
            *spendable.data(),
            (note.commitment(), epoch.next().unwrap(), bucket.data().2)
        );
        let (secret, ()) = PROOF_SYSTEM
            .seed(rng, NoteSeed, witness::note_seed(((), ()), note, pak))
            .unwrap();
        assert!(
            PROOF_SYSTEM
                .verify_differential(&secret, &mut *rng)
                .unwrap()
        );
        let (spend, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                SpendBind,
                witness::spend_bind((*spendable.data(), *secret.data()), rcv),
                spendable,
                secret,
            )
            .unwrap();
        assert!(PROOF_SYSTEM.verify_differential(&spend, &mut *rng).unwrap());
        let (spend_cm, nf_current, nf_next, anchor, pk, _) = *spend.data();
        spends.push((spend_cm, nf_current, nf_next, anchor, Fp::from(pk)));

        for empty_bucket in [&honest_empty, &scaled_empty, &scaled_deep] {
            assert_matches!(
                PROOF_SYSTEM.fuse(rng, QrSpendableInit, (), unspent.clone(), empty_bucket.clone()).err(),
                Some(ragu_core::Error::InvalidWitness(err))
                    if err.to_string() == "QrSpendableInit: commitment not in bucket"
            );
        }
    }
    assert_eq!(spends[0], spends[1]);

    // Exclusion of any value of the empty side's profile, bound to a second
    // note, which none of the buckets holds.
    for empty_bucket in [&honest_empty, &scaled_empty, &scaled_deep] {
        let unspent = exclude_and_bind(rng, empty_bucket, other_note, pak);
        for bucket in [&honest_held, &scaled_held, empty_bucket] {
            assert_matches!(
                PROOF_SYSTEM.fuse(rng, QrSpendableInit, (), unspent.clone(), bucket.clone()).err(),
                Some(ragu_core::Error::InvalidWitness(err))
                    if err.to_string() == "QrSpendableInit: commitment not in bucket"
            );
        }
        assert_matches!(
            PROOF_SYSTEM.fuse(
                rng,
                QrUnspentInit,
                witness::qr_unspent_init((*empty_bucket.data(), ()), nf),
                empty_bucket.clone(),
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            ).err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == "QR profile: value does not take the bucket's profile"
        );
    }
}

/// A scaled split of a duplicated member yields a stray bucket: `k·(X - cm)`
/// on the side opposite `cm`'s class. Monic polynomials reach the same bucket
/// whenever two members share a class, by filing one on the wrong side, and
/// the stray bucket answers every question as the scaled one does. A stray
/// member proves only its own publication, which is true.
#[test]
fn scaled_duplicate_split_answers_as_a_monic_stray_bucket() {
    let rng = &mut StdRng::seed_from_u64(2);
    let epoch = EpochIndex::new(0);
    let sk = private::SpendingKey::random(rng);
    let pak = sk.derive_proof_private();
    let note = Note {
        pk: sk.derive_payment_key(),
        value: value::Positive::try_from(400u64).unwrap(),
        psi: nullifier::Trapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    };
    let cm = Tachygram::from(note.commitment());
    let nf = Tachygram::from(pak.nk.derive_note_private(note.psi).derive_nullifier(epoch));
    let discriminant = iter::repeat_with(|| QrDiscriminant::random(rng))
        .find(|discriminant| {
            classify(Fp::from(nf), discriminant.at(0)).0
                == classify(Fp::from(cm), discriminant.at(0)).0
        })
        .unwrap();
    let side = classify(Fp::from(cm), discriminant.at(0)).0;
    let absent = iter::repeat_with(|| Tachygram::random(rng))
        .find(|value| classify(Fp::from(*value), discriminant.at(0)).0 != side)
        .unwrap();
    let companion = iter::repeat_with(|| Tachygram::random(rng))
        .find(|value| classify(Fp::from(*value), discriminant.at(0)).0 == side)
        .unwrap();

    let scale = Fp::from(7u64);
    let scale_inv = scale.invert().unwrap();
    let monic = TachygramSetPoly::from_iter([cm]);

    // The duplicated stamp {cm, cm}, scaled into a stray bucket.
    let doubled = [cm, cm];
    let (duplicate_intake, ()) = PROOF_SYSTEM
        .seed(
            rng,
            QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(
                ((), ()),
                Anchor::default(),
                epoch,
                discriminant,
                &doubled,
            ),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&duplicate_intake, &mut *rng)
            .unwrap()
    );
    let (honest_non_residue, honest_residue) =
        witness::qr_intake_split((*duplicate_intake.data(), ()), &doubled);
    let (duplicate_sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrIntakeSplit,
            (honest_non_residue, honest_residue),
            duplicate_intake.clone(),
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&duplicate_sides, &mut *rng)
            .unwrap()
    );
    let duplicate_held_intake = descend(rng, &duplicate_sides, side, &[], Fp::ONE).unwrap();
    let (duplicate_held, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*duplicate_held_intake.data(), ()), Anchor::from(Fp::ZERO)),
            duplicate_held_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&duplicate_held, &mut *rng)
            .unwrap()
    );
    let mut scaled_non_residue: Polynomial<Fp, ProductionRank> = monic.clone().into();
    scaled_non_residue.scale(scale);
    let mut scaled_residue: Polynomial<Fp, ProductionRank> = monic.clone().into();
    scaled_residue.scale(scale_inv);
    let (scaled_sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrIntakeSplit,
            (
                TachygramSetPoly::from_noncanonical_for_test(scaled_non_residue),
                TachygramSetPoly::from_noncanonical_for_test(scaled_residue),
            ),
            duplicate_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&scaled_sides, &mut *rng)
            .unwrap()
    );
    let sibling_scale = if side { scale_inv } else { scale };
    let scaled_stray_intake = descend(rng, &scaled_sides, !side, &[cm], sibling_scale).unwrap();
    let (scaled_stray, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*scaled_stray_intake.data(), ()), Anchor::from(Fp::ZERO)),
            scaled_stray_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&scaled_stray, &mut *rng)
            .unwrap()
    );

    // The stamp {cm, companion}, filing cm on the wrong side with monic sides.
    let pair = [cm, companion];
    let (pair_intake, ()) = PROOF_SYSTEM
        .seed(
            rng,
            QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), Anchor::default(), epoch, discriminant, &pair),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&pair_intake, &mut *rng)
            .unwrap()
    );
    let (pair_non_residue, pair_residue) =
        witness::qr_intake_split((*pair_intake.data(), ()), &pair);
    let (honest_pair_sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrIntakeSplit,
            (pair_non_residue, pair_residue),
            pair_intake.clone(),
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&honest_pair_sides, &mut *rng)
            .unwrap()
    );
    let pair_held_intake = descend(rng, &honest_pair_sides, side, &[], Fp::ONE).unwrap();
    let (pair_held, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*pair_held_intake.data(), ()), Anchor::from(Fp::ZERO)),
            pair_held_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&pair_held, &mut *rng)
            .unwrap()
    );
    let pair_empty_intake = descend(rng, &honest_pair_sides, !side, &pair, Fp::ONE).unwrap();
    let (pair_empty, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*pair_empty_intake.data(), ()), Anchor::from(Fp::ZERO)),
            pair_empty_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&pair_empty, &mut *rng)
            .unwrap()
    );
    let (stray_non_residue, stray_residue) = if side {
        (monic, TachygramSetPoly::from_iter([companion]))
    } else {
        (TachygramSetPoly::from_iter([companion]), monic)
    };
    let (stray_sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrIntakeSplit,
            (stray_non_residue, stray_residue),
            pair_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&stray_sides, &mut *rng)
            .unwrap()
    );
    let monic_stray_intake = descend(rng, &stray_sides, !side, &[companion], Fp::ONE).unwrap();
    let (monic_stray, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*monic_stray_intake.data(), ()), Anchor::from(Fp::ZERO)),
            monic_stray_intake,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&monic_stray, &mut *rng)
            .unwrap()
    );
    assert_eq!(scaled_stray.data().4, monic_stray.data().4);

    let mut unspents = Vec::new();
    for (held, stray) in [(&duplicate_held, &scaled_stray), (&pair_held, &monic_stray)] {
        let unspent = exclude_and_bind(rng, held, note, pak);
        let (spendable, ()) = PROOF_SYSTEM
            .fuse(rng, QrSpendableInit, (), unspent.clone(), held.clone())
            .unwrap();
        assert!(
            PROOF_SYSTEM
                .verify_differential(&spendable, &mut *rng)
                .unwrap()
        );
        let (spendable, ()) = PROOF_SYSTEM
            .fuse(rng, QrSpendableInit, (), unspent.clone(), stray.clone())
            .unwrap();
        assert!(
            PROOF_SYSTEM
                .verify_differential(&spendable, &mut *rng)
                .unwrap()
        );
        let (segment, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                QrUnspentInit,
                witness::qr_unspent_init((*stray.data(), ()), absent),
                stray.clone(),
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert!(
            PROOF_SYSTEM
                .verify_differential(&segment, &mut *rng)
                .unwrap()
        );
        assert_matches!(
            PROOF_SYSTEM.fuse(
                rng,
                QrUnspentInit,
                witness::qr_unspent_init((*held.data(), ()), cm),
                held.clone(),
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            ).err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == "QrUnspentInit: found nullifier in the bucket"
        );
        assert_matches!(
            PROOF_SYSTEM.fuse(
                rng,
                QrUnspentInit,
                witness::qr_unspent_init((*stray.data(), ()), cm),
                stray.clone(),
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            ).err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == "QR profile: value does not take the bucket's profile"
        );
        unspents.push(unspent);
    }

    // The canonical bucket of the stray's profile holds nothing.
    assert_matches!(
        PROOF_SYSTEM.fuse(rng, QrSpendableInit, (), unspents[1].clone(), pair_empty.clone()).err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrSpendableInit: commitment not in bucket"
    );
    let (segment, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrUnspentInit,
            witness::qr_unspent_init((*pair_empty.data(), ()), absent),
            pair_empty,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(
        PROOF_SYSTEM
            .verify_differential(&segment, &mut *rng)
            .unwrap()
    );
}
