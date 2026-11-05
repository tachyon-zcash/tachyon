extern crate alloc;

use alloc::{collections::BTreeSet, string::ToString as _, vec};
use core::iter;

use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, ActionSetPoly, Anchor, Bundle, Note, Tachygram, TachygramSetPoly,
    VerificationError, VerifyCoverageError, VerifyTachygramsError, action, bundle, fee,
    stamp::{
        ProofStamp, StampState,
        proof::{
            PROOF_SYSTEM, output,
            stamp::{Actions, FeeFuse, FeeSeed, OutputAction, Stamp},
        },
    },
    value, witness,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_lift_span, build_output_plan, mock_sighash, mock_wtxid, random_block,
    random_block_with, shared_sk, stamp_coverage,
};

fn merge_side(
    bundle: &Bundle<ProofStamp>,
    adjuncts: &[&Bundle<dyn StampState>],
) -> (
    ProofStamp,
    BTreeSet<action::Descriptor>,
    BTreeSet<fee::Descriptor>,
) {
    let members = || iter::once(bundle.as_dyn()).chain(adjuncts.iter().copied());
    (
        bundle.stamp.clone(),
        members().flat_map(Bundle::descriptors).collect(),
        members().map(Bundle::fee_descriptor).collect(),
    )
}

fn fee_less_output_bundle(
    rng: &mut StdRng,
    wallet: &WalletSim,
    anchor: Anchor,
    max_fee_note: Note,
) -> Bundle<ProofStamp> {
    let (rcv, theta, output_plan) = build_output_plan(rng, wallet.random_note(500));
    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (output_plan.note, rcv))
        .unwrap();
    let (cm, pad, _cv) = *bind_pcd.data();
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            OutputAction,
            witness::output_action((*bind_pcd.data(), ()), theta, anchor),
            bind_pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let stamp = ProofStamp {
        coverage: stamp_coverage([output_plan.descriptor()], &[]),
        anchor,
        tachygram_set: pcd.data().1,
        tachygrams: BTreeSet::from([cm, pad]),
        proof: Box::new(pcd.proof().clone()),
        fee: value::Positive::ZERO,
    };

    let plan = bundle::Plan::new(vec![], vec![output_plan], max_fee_note);
    plan.sign(
        rng,
        &mock_sighash(plan.commitment().unwrap()),
        &wallet.sk.derive_auth_private(),
    )
    .unwrap()
    .stamp(stamp)
}

#[test]
fn fee_fuse_binds_its_sets() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_fee_note = wallet.random_note(300);
    let anchor = Anchor::random(rng);
    let left = fee_less_output_bundle(rng, &wallet, anchor, max_fee_note);

    let action_digests: BTreeSet<ActionDigest> = left
        .descriptors()
        .map(|desc| desc.digest().unwrap())
        .collect();
    let stamp_header = (
        action_digests
            .iter()
            .copied()
            .collect::<ActionSetPoly>()
            .commit(),
        left.stamp.tachygram_set,
        anchor,
    );
    assert!(
        PROOF_SYSTEM
            .verify(
                &left.stamp.proof.clone().carry::<Actions>(stamp_header),
                &mut *rng
            )
            .unwrap()
    );
    assert!(
        !left
            .stamp
            .verify_proof(rng, action_digests.iter().copied())
            .unwrap()
    );
    let valid = witness::fee_fuse(
        (stamp_header, ()),
        max_fee_note,
        value::Positive::try_from(120).unwrap(),
        &action_digests,
        &left.stamp.tachygrams,
    );
    let other = witness::fee_fuse(
        (stamp_header, ()),
        max_fee_note,
        value::Positive::try_from(50).unwrap(),
        &action_digests,
        &left.stamp.tachygrams,
    );

    for (corrupt, expected) in [
        (
            {
                let mut corrupt = valid.clone();
                corrupt.1 = value::Positive::try_from(301).unwrap();
                corrupt
            },
            "FeeFuse: change is out of range",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.2.0 = valid.3.0.clone();
                corrupt
            },
            "FeeFuse: left action accumulator must commit to header commit",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.2.1 = valid.3.1.clone();
                corrupt
            },
            "FeeFuse: left tachygram accumulator must commit to header commit",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.3.0 = other.3.0.clone();
                corrupt
            },
            "FeeFuse: output action set must be the product of left and fee action sets",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.3.1 = other.3.1.clone();
                corrupt
            },
            "FeeFuse: output tachygram set must be the product of left and fee tachygram sets",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.4.0 = other.4.0.clone();
                corrupt
            },
            "FeeFuse: fee action set does not commit to the fee digest",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.4.1 = other.4.1.clone();
                corrupt
            },
            "FeeFuse: fee tachygram set does not commit to the fee change note",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            FeeFuse,
            corrupt,
            left.stamp.proof.clone().carry::<Actions>(stamp_header),
            Proof::bootstrap().carry::<()>(()),
        ) {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }

    let (fee_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            FeeFuse,
            valid.clone(),
            left.stamp.proof.clone().carry::<Actions>(stamp_header),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    for (action_commit, tachygram_commit, expected) in [
        (valid.3.0.commit(), valid.3.1.commit(), true),
        (other.3.0.commit(), valid.3.1.commit(), false),
    ] {
        let pcd = fee_pcd
            .proof()
            .clone()
            .carry::<Stamp>((action_commit, tachygram_commit, anchor));
        assert_eq!(PROOF_SYSTEM.verify(&pcd, &mut *rng).unwrap(), expected);
    }
}

#[test]
fn fee_is_chosen_after_signing_up_to_the_max_and_applies_once() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (bundle_plan, signed, spend_pcds, anchor, max_fee_note) =
        wallet.fee_bundle(rng, 1000, 700, 300);
    let sighash = mock_sighash(signed.commitment());

    let fees = [0u64, 120, 300];
    let bundles = fees.map(|fee| {
        signed.clone().stamp(
            bundle_plan
                .stamp_plan(anchor, value::Positive::try_from(fee).unwrap())
                .prove(rng, &wallet.pak, spend_pcds.clone())
                .unwrap(),
        )
    });
    for (bundle, fee) in bundles.iter().zip(fees) {
        assert_eq!(u64::from(bundle.stamp.fee), fee);
        assert_eq!(bundle.commitment(), signed.commitment());
        assert_eq!(bundle.binding_sig, signed.binding_sig);
        assert_eq!(bundle.stamp.tachygrams.len(), 2 * 2 + 1);
        bundle
            .verify(rng, &sighash, &mock_wtxid(bundle).into(), &[])
            .unwrap();
    }
    assert_eq!(
        bundles
            .iter()
            .map(Bundle::auth_digest)
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );

    let [_, once, _] = bundles;
    let digests: BTreeSet<_> = once
        .descriptors()
        .map(|desc| desc.digest().unwrap())
        .chain([once.fee_descriptor().digest().unwrap()])
        .collect();
    let header = (
        ActionSetPoly::from_iter(digests.iter().copied()).commit(),
        once.stamp.tachygram_set,
        anchor,
    );
    let (twice_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            FeeFuse,
            witness::fee_fuse(
                (header, ()),
                max_fee_note,
                value::Positive::try_from(0).unwrap(),
                &digests,
                &once.stamp.tachygrams,
            ),
            once.stamp.proof.clone().carry::<Actions>(header),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let mut twice_stamp = once.stamp.clone();
    twice_stamp.proof = Box::new(twice_pcd.proof().clone());
    twice_stamp.tachygram_set = twice_pcd.data().1;
    twice_stamp
        .tachygrams
        .insert(max_fee_note.commitment().into());
    twice_stamp.coverage = [0; 32];
    let mut twice = Bundle {
        stamp: twice_stamp,
        ..once
    };

    let Err(VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch)) =
        twice.verify(rng, &sighash, &mock_wtxid(&twice).into(), &[])
    else {
        panic!();
    };

    twice.stamp.coverage = stamp_coverage(twice.descriptors(), &[twice.fee_descriptor()]);
    let Err(VerificationError::Tachygrams(VerifyTachygramsError::WrongArity)) =
        twice.verify(rng, &sighash, &mock_wtxid(&twice).into(), &[])
    else {
        panic!();
    };

    let published_digests: Vec<ActionDigest> = twice
        .descriptors()
        .map(|desc| desc.digest().unwrap())
        .chain([twice.fee_descriptor().digest().unwrap()])
        .collect();
    assert!(!twice.verify_proof(rng, &published_digests).unwrap());
}

#[test]
fn verify_rejects_a_fee_descriptor_shared_by_two_covered_bundles() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (bundle_plan, signed, spend_pcds, anchor, _) = wallet.fee_bundle(rng, 1000, 700, 300);
    let sighash = mock_sighash(signed.commitment());

    let mut aggregate = signed.stamp(
        bundle_plan
            .stamp_plan(anchor, value::Positive::try_from(120).unwrap())
            .prove(rng, &wallet.pak, spend_pcds)
            .unwrap(),
    );
    let fee_bearing = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(500)]);
    let (aggregate_stamp, aggregate_desc, aggregate_fees) = merge_side(&aggregate, &[]);
    aggregate.stamp = aggregate_stamp
        .merge(
            rng,
            (aggregate_desc, aggregate_fees),
            merge_side(&fee_bearing, &[]),
        )
        .unwrap();

    let mut adjunct = fee_bearing.strip(mock_wtxid(&aggregate));
    adjunct.fee_max_commitment = aggregate.fee_max_commitment;
    adjunct.stamp.fee = aggregate.stamp.fee;
    let Err(VerificationError::Coverage(VerifyCoverageError::DuplicateFees)) =
        aggregate.verify(rng, &sighash, &mock_wtxid(&aggregate).into(), &[&adjunct])
    else {
        panic!();
    };
}

#[test]
fn verify_rejects_a_stamp_without_its_fee() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_fee_note = wallet.random_note(300);
    let anchor = Anchor::random(rng);
    let mut fee_less = fee_less_output_bundle(rng, &wallet, anchor, max_fee_note);
    let sighash = mock_sighash(fee_less.commitment());

    let Err(VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch)) =
        fee_less.verify(rng, &sighash, &mock_wtxid(&fee_less).into(), &[])
    else {
        panic!();
    };

    fee_less.stamp.coverage = stamp_coverage(fee_less.descriptors(), &[fee_less.fee_descriptor()]);
    let Err(VerificationError::Tachygrams(VerifyTachygramsError::WrongArity)) =
        fee_less.verify(rng, &sighash, &mock_wtxid(&fee_less).into(), &[])
    else {
        panic!();
    };

    fee_less
        .stamp
        .tachygrams
        .insert(Tachygram::from(max_fee_note.commitment()));
    fee_less.stamp.tachygram_set = fee_less
        .stamp
        .tachygrams
        .iter()
        .copied()
        .collect::<TachygramSetPoly>()
        .commit();
    let Err(VerificationError::Disproved) =
        fee_less.verify(rng, &sighash, &mock_wtxid(&fee_less).into(), &[])
    else {
        panic!();
    };
}

#[test]
fn fee_applies_over_a_fee_bearing_adjunct() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (bundle_plan, signed, spend_pcds, anchor, max_fee_note) =
        wallet.fee_bundle(rng, 1000, 700, 300);
    let sighash = mock_sighash(signed.commitment());

    let adjunct_max_fee_note = wallet.random_note(100);
    let (adjunct_plan, adjunct_signed, _) = wallet.signed(
        rng,
        vec![],
        vec![wallet.random_note(500)],
        adjunct_max_fee_note,
    );
    let adjunct = adjunct_signed.stamp(
        adjunct_plan
            .stamp_plan(anchor, value::Positive::try_from(40).unwrap())
            .prove(rng, &wallet.pak, vec![])
            .unwrap(),
    );

    let aggregate_stamp = bundle_plan
        .stamp_plan(anchor, value::Positive::try_from(120).unwrap())
        .prove(rng, &wallet.pak, spend_pcds)
        .unwrap();
    let aggregate_descriptors: BTreeSet<action::Descriptor> = signed.descriptors().collect();
    let aggregate_fee_descriptors = BTreeSet::from([fee::Descriptor {
        max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
        value: aggregate_stamp.fee,
    }]);

    let merged_stamp = aggregate_stamp
        .merge(
            rng,
            (aggregate_descriptors, aggregate_fee_descriptors),
            merge_side(&adjunct, &[]),
        )
        .unwrap();
    let aggregate = signed.stamp(merged_stamp);

    assert_eq!(aggregate.stamp.fee, value::Positive::try_from(120).unwrap());
    assert!(
        adjunct
            .stamp
            .tachygrams
            .is_subset(&aggregate.stamp.tachygrams)
    );
    assert_eq!(
        aggregate.stamp.tachygrams.len(),
        2 * (aggregate.actions.len() + adjunct.actions.len()) + 2
    );
    let final_id = mock_wtxid(&aggregate);
    let stripped = adjunct.strip(final_id);
    assert_eq!(stripped.stamp.fee, value::Positive::try_from(40).unwrap());
    aggregate
        .verify(rng, &sighash, &final_id.into(), &[&stripped])
        .unwrap();
}

#[test]
fn fee_bearing_aggregates_merge_and_lift() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let notes: Vec<Note> = [1000, 900, 800, 700]
        .map(|value| wallet.random_note(value))
        .into();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let commitments: Vec<_> = notes.iter().map(Note::commitment).collect();
    pool.mine(random_block_with(rng, &[commitments], 1));
    let [mut left, left_auto, mut right, right_auto] = [0, 1, 2, 3].map(|i| {
        let spendable = wallet.spendable_init(rng, &notes[i], &pool, pool.height());
        let anchor = spendable.data().2;
        let (plan, signed, pcds) = wallet.signed(
            rng,
            vec![(notes[i], spendable)],
            vec![wallet.random_note(500)],
            wallet.random_note(100),
        );
        let stamp = plan
            .stamp_plan(anchor, value::Positive::try_from(40).unwrap())
            .prove(rng, &wallet.pak, pcds)
            .unwrap();
        signed.stamp(stamp)
    });
    let sighash = mock_sighash(left.commitment());

    for (bundle, auto) in [(&mut left, &left_auto), (&mut right, &right_auto)] {
        let (stamp, desc, fees) = merge_side(bundle, &[]);
        bundle.stamp = stamp
            .merge(rng, (desc, fees), merge_side(auto, &[]))
            .unwrap();
    }
    let (left_stamp, left_desc, left_fees) = merge_side(&left, &[left_auto.as_dyn()]);
    left.stamp = left_stamp
        .merge(
            rng,
            (left_desc, left_fees),
            merge_side(&right, &[right_auto.as_dyn()]),
        )
        .unwrap();

    pool.mine(random_block(rng, 1, 2));
    let span = build_lift_span(rng, &pool, pool.height()..=pool.height());
    let lifted = left
        .lift(
            rng,
            &[left_auto.as_dyn(), right.as_dyn(), right_auto.as_dyn()],
            vec![span],
        )
        .unwrap();

    let id = mock_wtxid(&lifted);
    lifted
        .verify(
            rng,
            &sighash,
            &id.into(),
            &[
                &left_auto.strip(id),
                &right.strip(id),
                &right_auto.strip(id),
            ],
        )
        .unwrap();
}

#[test]
fn zero_action_fee_seed_round_trips_and_verifies() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let bundle = wallet.autonome(rng, anchor, vec![], vec![]);
    let sighash = mock_sighash(bundle.commitment());
    assert_eq!(bundle.actions.len(), 0);
    assert_eq!(bundle.stamp.tachygrams.len(), 1);
    assert_eq!(bundle.verify_coverage(&[], &[]).unwrap().1.len(), 1);
    bundle
        .verify(rng, &sighash, &mock_wtxid(&bundle).into(), &[])
        .unwrap();
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).unwrap();
    let decoded = Bundle::<ProofStamp>::read(&*bytes).unwrap();
    assert_eq!(decoded.auth_digest(), bundle.auth_digest());
    decoded
        .verify(rng, &sighash, &mock_wtxid(&decoded).into(), &[])
        .unwrap();
}

#[test]
fn innocent_seed_merges_and_strips() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let mut innocent = wallet.autonome(rng, anchor, vec![], vec![]);
    let adjunct = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(100)]);
    let (innocent_stamp, innocent_desc, innocent_fees) = merge_side(&innocent, &[]);
    innocent.stamp = innocent_stamp
        .merge(
            rng,
            (innocent_desc, innocent_fees),
            merge_side(&adjunct, &[]),
        )
        .unwrap();
    let id = mock_wtxid(&innocent);
    innocent
        .verify(
            rng,
            &mock_sighash(innocent.commitment()),
            &id.into(),
            &[&adjunct.clone().strip(id)],
        )
        .unwrap();

    let mut parent = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(200)]);
    let (parent_stamp, parent_desc, parent_fees) = merge_side(&parent, &[]);
    parent.stamp = parent_stamp
        .merge(
            rng,
            (parent_desc, parent_fees),
            merge_side(&innocent, &[adjunct.as_dyn()]),
        )
        .unwrap();
    let parent_id = mock_wtxid(&parent);
    let stripped_innocent = innocent.strip(parent_id);
    assert_eq!(stripped_innocent.actions.len(), 0);
    parent
        .verify(
            rng,
            &mock_sighash(parent.commitment()),
            &parent_id.into(),
            &[&adjunct.strip(parent_id), &stripped_innocent],
        )
        .unwrap();
}

#[test]
fn fee_seed_binds_its_singletons_and_header() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let other_anchor = Anchor::random(rng);
    let valid = witness::fee_seed(((), ()), wallet.random_note(0), anchor);
    let other = witness::fee_seed(((), ()), wallet.random_note(0), anchor);

    for (corrupt, expected) in [
        (
            {
                let mut corrupt = valid.clone();
                corrupt.0.value = value::Positive::try_from(1).unwrap();
                corrupt
            },
            "FeeSeed: maximum fee must be zero",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.2 = other.2.clone();
                corrupt
            },
            "FeeSeed: fee action set does not commit to the fee digest",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.3 = other.3.clone();
                corrupt
            },
            "FeeSeed: fee tachygram set does not commit to the fee change note",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.seed(rng, FeeSeed, corrupt)
        {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }

    let (seed_pcd, ()) = PROOF_SYSTEM.seed(rng, FeeSeed, valid.clone()).unwrap();
    for (header, expected) in [
        ((valid.2.commit(), valid.3.commit(), anchor), true),
        ((other.2.commit(), valid.3.commit(), anchor), false),
        ((valid.2.commit(), other.3.commit(), anchor), false),
        ((valid.2.commit(), valid.3.commit(), other_anchor), false),
    ] {
        let pcd = seed_pcd.proof().clone().carry::<Stamp>(header);
        assert_eq!(PROOF_SYSTEM.verify(&pcd, &mut *rng).unwrap(), expected);
    }
}
