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

use ragu::{Pcd, header::Header};
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
        delegation::{NoteSecret, NoteSeed, NullifierDerive},
        evidence::{
            EvidenceTreeCap, EvidenceTreeDescend, EvidenceTreeFuse, EvidenceTreeLeafPair,
            EvidenceTreeOpen,
        },
        pool::{ArbitraryUnspent, NoteUnspent, UnspentBind},
        spend::SpendBind,
        spendable::{NoteSpendable, QrSpendableInit},
    },
    value, witness,
};

fn verified<H: Header<Fp>>(
    rng: &mut StdRng,
    pcd: Pcd<Pasta, ProductionRank, H>,
) -> Pcd<Pasta, ProductionRank, H> {
    assert!(PROOF_SYSTEM.verify_differential(&pcd, &mut *rng).unwrap());
    pcd
}

fn rejects<T>(result: ragu_core::Result<T>, message: &str) {
    assert_matches!(
        result.err(),
        Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == message
    );
}

fn bootstrap() -> Pcd<Pasta, ProductionRank, ()> {
    PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(())
}

fn scaled(poly: &TachygramSetPoly, by: Fp) -> TachygramSetPoly {
    let mut inner: Polynomial<Fp, ProductionRank> = poly.clone().into();
    inner.scale(by);
    TachygramSetPoly::from(inner)
}

fn nonzero_coeffs(poly: &TachygramSetPoly) -> Vec<(usize, Fp)> {
    poly.as_ref()
        .iter_stored_coeffs()
        .filter(|&(_, coeff)| *coeff != Fp::ZERO)
        .map(|(degree, &coeff)| (degree, coeff))
        .collect()
}

/// A root intake over one stamp, opening epoch zero at its entry anchor.
fn seed_stamp(
    rng: &mut StdRng,
    discriminant: QrDiscriminant,
    members: &[Tachygram],
) -> Pcd<Pasta, ProductionRank, QrIntake> {
    let (intake, ()) = PROOF_SYSTEM
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
    verified(rng, intake)
}

fn split(
    rng: &mut StdRng,
    intake: &Pcd<Pasta, ProductionRank, QrIntake>,
    non_residue: TachygramSetPoly,
    residue: TachygramSetPoly,
) -> ragu_core::Result<Pcd<Pasta, ProductionRank, QrIntakeSides>> {
    let (sides, ()) = PROOF_SYSTEM.fuse(
        rng,
        QrIntakeSplit,
        (non_residue, residue),
        intake.clone(),
        bootstrap(),
    )?;
    Ok(verified(rng, sides))
}

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
        bootstrap(),
    )?;
    let selection = verified(rng, selected);
    let (child, ()) = PROOF_SYSTEM.fuse(rng, QrSideDescend, (bit,), sides.clone(), selection)?;
    Ok(verified(rng, child))
}

fn seal(
    rng: &mut StdRng,
    intake: &Pcd<Pasta, ProductionRank, QrIntake>,
) -> Pcd<Pasta, ProductionRank, QrBucket> {
    let (bucket, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            QrBucketSeal,
            witness::qr_bucket_seal((*intake.data(), ()), Anchor::from(Fp::ZERO)),
            intake.clone(),
            bootstrap(),
        )
        .unwrap();
    verified(rng, bucket)
}

/// Descend as [`descend`] and seal the child.
fn descend_to_bucket(
    rng: &mut StdRng,
    sides: &Pcd<Pasta, ProductionRank, QrIntakeSides>,
    bit: bool,
    sibling_members: &[Tachygram],
    sibling_scale: Fp,
) -> Pcd<Pasta, ProductionRank, QrBucket> {
    let child = descend(rng, sides, bit, sibling_members, sibling_scale).unwrap();
    seal(rng, &child)
}

fn exclude(
    rng: &mut StdRng,
    bucket: &Pcd<Pasta, ProductionRank, QrBucket>,
    value: Tachygram,
) -> ragu_core::Result<Pcd<Pasta, ProductionRank, ArbitraryUnspent>> {
    let (segment, ()) = PROOF_SYSTEM.fuse(
        rng,
        QrUnspentInit,
        witness::qr_unspent_init((*bucket.data(), ()), value),
        bucket.clone(),
        bootstrap(),
    )?;
    Ok(verified(rng, segment))
}

fn note_secret(
    rng: &mut StdRng,
    note: Note,
    pak: ProofAuthorizingKey,
) -> Pcd<Pasta, ProductionRank, NoteSecret> {
    let (secret, ()) = PROOF_SYSTEM
        .seed(rng, NoteSeed, witness::note_seed(((), ()), note, pak))
        .unwrap();
    verified(rng, secret)
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
    let segment = exclude(rng, bucket, Tachygram::from(mk.derive_nullifier(epoch))).unwrap();
    let secret = note_secret(rng, note, pak);
    let (derived, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            NullifierDerive,
            witness::nullifier_derive((*secret.data(), ()), epoch),
            secret,
            bootstrap(),
        )
        .unwrap();
    let range = verified(rng, derived);
    let (unspent, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            UnspentBind,
            witness::unspent_bind(
                (*segment.data(), *range.data()),
                &mk.derive_window(epoch),
                &[mk.derive_nullifier(epoch)],
            ),
            segment,
            range,
        )
        .unwrap();
    verified(rng, unspent)
}

fn include(
    rng: &mut StdRng,
    unspent: &Pcd<Pasta, ProductionRank, NoteUnspent>,
    bucket: &Pcd<Pasta, ProductionRank, QrBucket>,
) -> ragu_core::Result<Pcd<Pasta, ProductionRank, NoteSpendable>> {
    let (spendable, ()) =
        PROOF_SYSTEM.fuse(rng, QrSpendableInit, (), unspent.clone(), bucket.clone())?;
    Ok(verified(rng, spendable))
}

fn random_note(rng: &mut StdRng, sk: &private::SpendingKey) -> Note {
    Note {
        pk: sk.derive_payment_key(),
        value: value::Positive::try_from(400u64).unwrap(),
        psi: nullifier::Trapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    }
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
    let intake = seed_stamp(rng, discriminant, &doubled);
    let honest_sides = split(rng, &intake, monic.clone(), monic.clone()).unwrap();
    rejects(
        descend(rng, &honest_sides, bit, &[member], Fp::ONE),
        "QrSideDescend: the two sides agree at the challenge",
    );

    let scaled_non_residue = scaled(&monic, scale);
    let scaled_residue = scaled(&monic, scale_inv);
    for (poly, factor) in [(&scaled_non_residue, scale), (&scaled_residue, scale_inv)] {
        assert_eq!(
            nonzero_coeffs(poly),
            vec![(0, -(factor * member_fp)), (1, factor)]
        );
        assert_eq!(poly.eval(member_fp), Fp::ZERO);
    }
    let sides = split(rng, &intake, scaled_non_residue, scaled_residue).unwrap();
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
    let held = scaled(&monic, scale);
    let constant = scaled(&empty, scale_inv);
    assert_eq!(
        nonzero_coeffs(&held),
        vec![(0, -(scale * member_fp)), (1, scale)]
    );
    assert_eq!(held.eval(member_fp), Fp::ZERO);
    assert_eq!(nonzero_coeffs(&constant), vec![(0, scale_inv)]);
    let (non_residue, residue) = if side {
        (constant, held)
    } else {
        (held, constant)
    };
    let single_intake = seed_stamp(rng, discriminant, &single);
    let single_sides = split(rng, &single_intake, non_residue, residue).unwrap();
    let empty_child = descend(rng, &single_sides, bit, &single, scale).unwrap();
    assert_eq!(
        empty_child.commitments()[0],
        PROOF_SYSTEM.commit(&[scale_inv]).unwrap()
    );
    assert_ne!(
        empty_child.commitments()[0],
        PROOF_SYSTEM.commit(&[Fp::ONE]).unwrap()
    );

    let first = scaled(&empty, deep_scale);
    let second = scaled(&empty, deep_cofactor);
    assert_eq!(nonzero_coeffs(&first), vec![(0, deep_scale)]);
    assert_eq!(nonzero_coeffs(&second), vec![(0, deep_cofactor)]);
    split(rng, &empty_child, first, second).unwrap();

    let (honest_non_residue, honest_residue) =
        witness::qr_intake_split((*single_intake.data(), ()), &single);
    let honest = split(rng, &single_intake, honest_non_residue, honest_residue).unwrap();
    let honest_empty_child = descend(rng, &honest, bit, &single, Fp::ONE).unwrap();
    rejects(
        split(rng, &honest_empty_child, empty.clone(), empty.clone()),
        "QrIntakeSplit: contents are one",
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
    rejects(
        split(rng, &seeded, empty.clone(), empty),
        "QrIntakeSplit: contents are one",
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
    let nullifier_of =
        |note: &Note| Tachygram::from(pak.nk.derive_note_private(note.psi).derive_nullifier(epoch));
    let note = random_note(rng, &sk);
    let cm = Tachygram::from(note.commitment());
    let nf = nullifier_of(&note);
    let discriminant = iter::repeat_with(|| QrDiscriminant::random(rng))
        .find(|discriminant| {
            classify(Fp::from(nf), discriminant.at(0)).0
                == classify(Fp::from(cm), discriminant.at(0)).0
        })
        .unwrap();
    let side = classify(Fp::from(cm), discriminant.at(0)).0;
    let other_note = iter::repeat_with(|| random_note(rng, &sk))
        .find(|candidate| classify(Fp::from(nullifier_of(candidate)), discriminant.at(0)).0 != side)
        .unwrap();
    let other_nf = nullifier_of(&other_note);
    let deep_bit = classify(Fp::from(other_nf), discriminant.at(1)).0;

    let scale = Fp::from(7u64);
    let scale_inv = scale.invert().unwrap();
    let deep_scale = Fp::from(11u64);
    let deep_cofactor = (scale * deep_scale).invert().unwrap();
    let monic = TachygramSetPoly::from_iter([cm]);
    let empty = TachygramSetPoly::from_iter(iter::empty());
    let single = [cm];

    let intake = seed_stamp(rng, discriminant, &single);
    let (honest_non_residue, honest_residue) =
        witness::qr_intake_split((*intake.data(), ()), &single);
    let honest_sides = split(rng, &intake, honest_non_residue, honest_residue).unwrap();
    let honest_held = descend_to_bucket(rng, &honest_sides, side, &[], Fp::ONE);
    let honest_empty = descend_to_bucket(rng, &honest_sides, !side, &single, Fp::ONE);

    let held = scaled(&monic, scale);
    let constant = scaled(&empty, scale_inv);
    let (non_residue, residue) = if side {
        (constant, held)
    } else {
        (held, constant)
    };
    let sides = split(rng, &intake, non_residue, residue).unwrap();
    let scaled_held = descend_to_bucket(rng, &sides, side, &[], scale_inv);
    let scaled_empty_intake = descend(rng, &sides, !side, &single, scale).unwrap();
    let scaled_empty = seal(rng, &scaled_empty_intake);
    let deep_sides = split(
        rng,
        &scaled_empty_intake,
        scaled(&empty, deep_scale),
        scaled(&empty, deep_cofactor),
    )
    .unwrap();
    let deep_sibling_scale = if deep_bit { deep_scale } else { deep_cofactor };
    let scaled_deep = descend_to_bucket(rng, &deep_sides, deep_bit, &[], deep_sibling_scale);

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
    let scaled_pair = verified(rng, admitted_scaled);
    let (admitted_honest, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            EvidenceTreeLeafPair,
            (),
            honest_held.clone(),
            honest_empty.clone(),
        )
        .unwrap();
    let honest_pair = verified(rng, admitted_honest);
    let leaves = [
        scaled_pair.data().4,
        scaled_pair.data().5,
        honest_pair.data().4,
        honest_pair.data().5,
    ];
    let (fused, ()) = PROOF_SYSTEM
        .fuse(rng, EvidenceTreeFuse, (), scaled_pair, honest_pair)
        .unwrap();
    let mut tree = verified(rng, fused);
    let mut caps = Vec::new();
    while caps.len() + 1 < EvidenceTreeDescend::LEVELS {
        caps.push(tree.data().4);
        let (raised, ()) = PROOF_SYSTEM
            .fuse(rng, EvidenceTreeCap, (), tree, bootstrap())
            .unwrap();
        tree = verified(rng, raised);
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
                bootstrap(),
            )
            .unwrap();
        let leaf = verified(rng, descended);
        let (bucket, ()) = PROOF_SYSTEM.fuse(
            rng,
            EvidenceTreeOpen,
            witness::evidence_tree_open((*leaf.data(), ()), profile, contents),
            leaf,
            bootstrap(),
        )?;
        Ok(verified(rng, bucket))
    };
    let held_profile = QrProfile::ROOT.descend(side);
    let opened_scaled_held = open(0, held_profile, scaled(&monic, scale)).unwrap();
    assert_eq!(*opened_scaled_held.data(), *scaled_held.data());
    let opened_honest_held = open(2, held_profile, monic.clone()).unwrap();
    assert_eq!(*opened_honest_held.data(), *honest_held.data());
    rejects(
        open(0, held_profile, monic.clone()),
        "EvidenceTreeOpen: witnessed bucket is not the tree's leaf",
    );
    rejects(
        open(2, held_profile, scaled(&monic, scale)),
        "EvidenceTreeOpen: witnessed bucket is not the tree's leaf",
    );

    // Exclusion of the note's absent nullifier, bound to its derivation, then
    // inclusion of its commitment and a spend.
    let rcv = value::Trapdoor::random(rng);
    let mut spends = Vec::new();
    for bucket in [&opened_honest_held, &opened_scaled_held] {
        let unspent = exclude_and_bind(rng, bucket, note, pak);
        rejects(
            exclude(rng, bucket, cm),
            "QrUnspentInit: found nullifier in the bucket",
        );
        let spendable = include(rng, &unspent, bucket).unwrap();
        assert_eq!(
            *spendable.data(),
            (note.commitment(), epoch.next().unwrap(), bucket.data().2)
        );
        let secret = note_secret(rng, note, pak);
        let (spend, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                SpendBind,
                witness::spend_bind((*spendable.data(), *secret.data()), rcv),
                spendable,
                secret,
            )
            .unwrap();
        let (spend_cm, nf_current, nf_next, anchor, pk, _) = *verified(rng, spend).data();
        spends.push((spend_cm, nf_current, nf_next, anchor, Fp::from(pk)));

        for empty_bucket in [&honest_empty, &scaled_empty, &scaled_deep] {
            rejects(
                include(rng, &unspent, empty_bucket),
                "QrSpendableInit: commitment not in bucket",
            );
        }
    }
    assert_eq!(spends[0], spends[1]);

    // Exclusion of any value of the empty side's profile, bound to a second
    // note, which none of the buckets holds.
    for empty_bucket in [&honest_empty, &scaled_empty, &scaled_deep] {
        let unspent = exclude_and_bind(rng, empty_bucket, other_note, pak);
        for bucket in [&honest_held, &scaled_held, empty_bucket] {
            rejects(
                include(rng, &unspent, bucket),
                "QrSpendableInit: commitment not in bucket",
            );
        }
        rejects(
            exclude(rng, empty_bucket, nf),
            "QR profile: value does not take the bucket's profile",
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
    let nullifier_of =
        |note: &Note| Tachygram::from(pak.nk.derive_note_private(note.psi).derive_nullifier(epoch));
    let note = random_note(rng, &sk);
    let cm = Tachygram::from(note.commitment());
    let nf = nullifier_of(&note);
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
    let duplicate_intake = seed_stamp(rng, discriminant, &doubled);
    let (honest_non_residue, honest_residue) =
        witness::qr_intake_split((*duplicate_intake.data(), ()), &doubled);
    let duplicate_sides =
        split(rng, &duplicate_intake, honest_non_residue, honest_residue).unwrap();
    let duplicate_held = descend_to_bucket(rng, &duplicate_sides, side, &[], Fp::ONE);
    let scaled_sides = split(
        rng,
        &duplicate_intake,
        scaled(&monic, scale),
        scaled(&monic, scale_inv),
    )
    .unwrap();
    let sibling_scale = if side { scale_inv } else { scale };
    let scaled_stray = descend_to_bucket(rng, &scaled_sides, !side, &[cm], sibling_scale);

    // The stamp {cm, companion}, filing cm on the wrong side with monic sides.
    let pair = [cm, companion];
    let pair_intake = seed_stamp(rng, discriminant, &pair);
    let (pair_non_residue, pair_residue) =
        witness::qr_intake_split((*pair_intake.data(), ()), &pair);
    let honest_pair_sides = split(rng, &pair_intake, pair_non_residue, pair_residue).unwrap();
    let pair_held = descend_to_bucket(rng, &honest_pair_sides, side, &[], Fp::ONE);
    let pair_empty = descend_to_bucket(rng, &honest_pair_sides, !side, &pair, Fp::ONE);
    let (stray_non_residue, stray_residue) = if side {
        (monic, TachygramSetPoly::from_iter([companion]))
    } else {
        (TachygramSetPoly::from_iter([companion]), monic)
    };
    let stray_sides = split(rng, &pair_intake, stray_non_residue, stray_residue).unwrap();
    let monic_stray = descend_to_bucket(rng, &stray_sides, !side, &[companion], Fp::ONE);
    assert_eq!(scaled_stray.data().4, monic_stray.data().4);

    let mut unspents = Vec::new();
    for (held, stray) in [(&duplicate_held, &scaled_stray), (&pair_held, &monic_stray)] {
        let unspent = exclude_and_bind(rng, held, note, pak);
        include(rng, &unspent, held).unwrap();
        include(rng, &unspent, stray).unwrap();
        exclude(rng, stray, absent).unwrap();
        rejects(
            exclude(rng, held, cm),
            "QrUnspentInit: found nullifier in the bucket",
        );
        rejects(
            exclude(rng, stray, cm),
            "QR profile: value does not take the bucket's profile",
        );
        unspents.push(unspent);
    }

    // The canonical bucket of the stray's profile holds nothing.
    rejects(
        include(rng, &unspents[1], &pair_empty),
        "QrSpendableInit: commitment not in bucket",
    );
    exclude(rng, &pair_empty, absent).unwrap();
}
