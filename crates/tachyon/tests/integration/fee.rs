extern crate alloc;

use alloc::{collections::BTreeSet, string::ToString as _, vec};
use core::iter;

use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, ActionSetPoly, Anchor, Bundle, Note, Tachygram, TachygramSetPoly,
    VerificationError, VerifyCoverageError, VerifyTachygramsError, action, bundle,
    digest::blake2b,
    fee,
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
    PoolSim, WalletSim, build_autonome, build_lift_span, build_output_plan,
    forge_overlapping_merge, mock_sighash, mock_wtxid, random_block_with, shared_sk,
    stamp_coverage,
};

fn zat(amount: u64) -> value::Positive {
    value::Positive::try_from(amount).unwrap()
}

fn verify_alone(
    rng: &mut StdRng,
    bundle: &Bundle<ProofStamp>,
    sighash: &[u8; 32],
) -> Result<(), VerificationError> {
    bundle.verify(rng, sighash, &mock_wtxid(bundle).into(), &[])
}

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

/// A signed output-only bundle whose genuine `OutputAction` stamp has no fee
/// applied, carrying the coverage of its action alone.
fn fee_less_output_bundle(
    rng: &mut StdRng,
    wallet: &WalletSim,
    anchor: Anchor,
    max_fee_note: Note,
) -> Bundle<ProofStamp> {
    let (rcv, theta, output_plan) = build_output_plan(rng, wallet.random_note(500));
    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (output_plan.note, rcv))
        .expect("OutputBind");
    let (cm, pad, _cv) = *bind_pcd.data();
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            OutputAction,
            witness::output_action((*bind_pcd.data(), ()), theta, anchor),
            bind_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("OutputAction");
    let stamp = ProofStamp {
        coverage: stamp_coverage(&Vec::from_iter([output_plan.descriptor()]), &[]),
        anchor,
        tachygram_set: pcd.data().1,
        tachygrams: BTreeSet::from([cm, pad]),
        proof: Box::new(pcd.proof().clone()),
        fee: value::Positive::ZERO,
    };

    let plan = bundle::Plan::new(vec![], vec![output_plan], max_fee_note);
    plan.sign(
        rng,
        &mock_sighash(plan.commitment().expect("bundle commitment")),
        &wallet.sk.derive_auth_private(),
    )
    .expect("sign the fee-less bundle")
    .stamp(stamp)
}

fn coverage_of(bundles: &[&Bundle<dyn StampState>]) -> [u8; 32] {
    let mut descriptors: Vec<[u8; 64]> = bundles
        .iter()
        .flat_map(|bundle| bundle.descriptors())
        .collect();
    descriptors.sort_unstable();
    let mut fee_descriptors: Vec<[u8; 40]> = bundles
        .iter()
        .map(|bundle| bundle.fee_descriptor().into())
        .collect();
    fee_descriptors.sort_unstable();
    blake2b::stamp_coverage_digest(
        &blake2b::action_descriptor_digest(&descriptors),
        &blake2b::stamp_fees_digest(&fee_descriptors),
    )
}

/// `FeeFuse` binds the left, fee and output sets to its header, and rejects
/// each substituted set polynomial.
#[test]
fn fee_fuse_binds_its_sets() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_fee_note = wallet.random_note(300);
    let anchor = PoolSim::genesis(rng).anchor();
    let left = fee_less_output_bundle(rng, &wallet, anchor, max_fee_note);

    let action_digests: BTreeSet<ActionDigest> = left
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
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
    let stamp_pcd = || left.stamp.proof.clone().carry::<Actions>(stamp_header);
    assert!(
        PROOF_SYSTEM
            .verify(&stamp_pcd(), &mut *rng)
            .expect("proof system verification"),
        "the OutputAction proof verifies as Actions"
    );
    assert!(
        !left
            .stamp
            .verify_proof(rng, action_digests.iter().copied())
            .expect("proof system verification"),
        "an Actions proof does not verify as a Stamp"
    );
    let fee_witness = |fee: u64| {
        witness::fee_fuse(
            (stamp_header, ()),
            max_fee_note,
            zat(fee),
            &action_digests,
            &left.stamp.tachygrams,
        )
    };

    let valid = fee_witness(120);
    let (fee_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            FeeFuse,
            valid.clone(),
            stamp_pcd(),
            Proof::trivial().carry::<()>(()),
        )
        .expect("a FeeFuse stamp");
    let (.., other_output_sets, other_fee_sets) = fee_witness(50);

    let mut left_actions = valid.clone();
    left_actions.2.0 = valid.3.0.clone();
    let mut left_tachygrams = valid.clone();
    left_tachygrams.2.1 = valid.3.1.clone();
    let mut output_actions = valid.clone();
    output_actions.3.0 = other_output_sets.0.clone();
    let mut output_tachygrams = valid.clone();
    output_tachygrams.3.1 = other_output_sets.1.clone();
    let mut fee_actions = valid.clone();
    fee_actions.4.0 = other_fee_sets.0;
    let mut fee_tachygrams = valid.clone();
    fee_tachygrams.4.1 = other_fee_sets.1;
    for (corrupt, expected) in [
        (
            left_actions,
            "FeeFuse: left action accumulator must commit to header commit",
        ),
        (
            left_tachygrams,
            "FeeFuse: left tachygram accumulator must commit to header commit",
        ),
        (
            output_actions,
            "FeeFuse: output action set must be the product of left and fee action sets",
        ),
        (
            output_tachygrams,
            "FeeFuse: output tachygram set must be the product of left and fee tachygram sets",
        ),
        (
            fee_actions,
            "FeeFuse: fee action set does not commit to the fee digest",
        ),
        (
            fee_tachygrams,
            "FeeFuse: fee tachygram set does not commit to the fee change note",
        ),
    ] {
        let Err(ragu_core::Error::InvalidWitness(inner)) = PROOF_SYSTEM.fuse(
            rng,
            FeeFuse,
            corrupt,
            stamp_pcd(),
            Proof::trivial().carry::<()>(()),
        ) else {
            panic!("expected InvalidWitness: {expected}");
        };
        assert_eq!(inner.to_string(), expected);
    }

    for (action_commit, tachygram_commit, expected) in [
        (valid.3.0.commit(), valid.3.1.commit(), true),
        (other_output_sets.0.commit(), valid.3.1.commit(), false),
    ] {
        let pcd = fee_pcd
            .proof()
            .clone()
            .carry::<Stamp>((action_commit, tachygram_commit, anchor));
        assert_eq!(
            PROOF_SYSTEM
                .verify(&pcd, &mut *rng)
                .expect("proof system verification"),
            expected,
        );
    }
}

#[test]
fn fee_is_chosen_after_signing_up_to_the_max_and_applies_once() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (bundle_plan, signed, spend_pcds, anchor, max_fee_note) =
        wallet.fee_bundle(rng, 1000, 700, 300);
    let sighash = mock_sighash(signed.commitment());
    let prove = |prove_rng: &mut StdRng, fee| {
        bundle_plan
            .stamp_plan(anchor, zat(fee))
            .prove(prove_rng, &wallet.pak, spend_pcds.clone())
            .map(|proved| signed.clone().stamp(proved))
    };

    assert_eq!(signed.value_balance, value::Balance::ZERO);

    let zero = fee_less_output_bundle(rng, &wallet, anchor, max_fee_note);
    let action_digests: BTreeSet<ActionDigest> = zero
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .collect();
    let stamp_header = (
        action_digests
            .iter()
            .copied()
            .collect::<ActionSetPoly>()
            .commit(),
        zero.stamp.tachygram_set,
        anchor,
    );
    let mut excess_witness = witness::fee_fuse(
        (stamp_header, ()),
        max_fee_note,
        zat(300),
        &action_digests,
        &zero.stamp.tachygrams,
    );
    excess_witness.1 = zat(301);
    let excess = PROOF_SYSTEM
        .fuse(
            rng,
            FeeFuse,
            excess_witness,
            zero.stamp
                .proof
                .as_ref()
                .clone()
                .carry::<Actions>(stamp_header),
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .expect("a fee above the maximum must not apply");
    let ragu_core::Error::InvalidWitness(inner) = excess else {
        panic!("expected InvalidWitness, got {excess:?}");
    };
    assert_eq!(inner.to_string(), "FeeFuse: change is out of range");

    let mut auth_digests = BTreeSet::new();
    for fee in [0u64, 120, 300] {
        let bundle = prove(rng, fee).expect("prove with the fee");

        assert_eq!(u64::from(bundle.stamp.fee), fee);
        assert_eq!(bundle.commitment(), signed.commitment(), "fee {fee}");
        assert_eq!(bundle.binding_sig, signed.binding_sig, "fee {fee}");
        assert_eq!(bundle.stamp.tachygrams.len(), 2 * 2 + 1, "fee {fee}");

        verify_alone(rng, &bundle, &sighash).expect("a fee-bearing bundle verifies");
        auth_digests.insert(bundle.auth_digest());
    }
    assert_eq!(auth_digests.len(), 3, "each fee has its own auth_digest");

    let once = prove(rng, 120).expect("first fee application");
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
                zat(0),
                &digests,
                &once.stamp.tachygrams,
            ),
            once.stamp.proof.clone().carry::<Actions>(header),
            Proof::trivial().carry::<()>(()),
        )
        .expect("mock ragu permits a substituted child header");
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

    let mismatch =
        verify_alone(rng, &twice, &sighash).expect_err("a second fee descriptor must be rejected");
    let VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch) = mismatch else {
        panic!("expected Coverage(StampActionsMismatch), got {mismatch:?}");
    };

    twice.stamp.coverage = coverage_of(&[twice.as_dyn()]);
    let arity =
        verify_alone(rng, &twice, &sighash).expect_err("a second fee change note must be rejected");
    let VerificationError::Tachygrams(VerifyTachygramsError::WrongArity) = arity else {
        panic!("expected Tachygrams(WrongArity), got {arity:?}");
    };

    let published_digests: Vec<ActionDigest> = twice
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain([twice.fee_descriptor().digest().expect("fee digest")])
        .collect();
    assert!(
        !twice
            .verify_proof(rng, &published_digests)
            .expect("proof system verification"),
        "the proof covers two fee descriptors against one published"
    );
}

/// A fee descriptor shared by two covered bundles is rejected, even forged.
#[test]
fn verify_rejects_a_fee_descriptor_shared_by_two_covered_bundles() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (bundle_plan, signed, spend_pcds, anchor, max_fee_note) =
        wallet.fee_bundle(rng, 1000, 700, 300);
    let sighash = mock_sighash(signed.commitment());

    let mut aggregate = signed.stamp(
        bundle_plan
            .stamp_plan(anchor, zat(120))
            .prove(rng, &wallet.pak, spend_pcds)
            .expect("prove with the fee"),
    );
    let fee_bearing = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(500)]);
    let (aggregate_stamp, aggregate_desc, aggregate_fees) = merge_side(&aggregate, &[]);
    let over_fee_bearing = aggregate_stamp
        .merge(
            rng,
            (aggregate_desc, aggregate_fees),
            merge_side(&fee_bearing, &[]),
        )
        .expect("merge the aggregate");

    let unapplied = fee_less_output_bundle(rng, &wallet, anchor, max_fee_note);
    let unapplied_pcd = forge_overlapping_merge(
        rng,
        (
            &aggregate.stamp,
            &aggregate.descriptors().collect(),
            &[aggregate.fee_descriptor()],
        ),
        (&unapplied.stamp, &unapplied.descriptors().collect(), &[]),
    );
    let over_unapplied = ProofStamp {
        coverage: coverage_of(&[aggregate.as_dyn(), unapplied.as_dyn()]),
        anchor,
        tachygram_set: unapplied_pcd.data().1,
        tachygrams: aggregate
            .stamp
            .tachygrams
            .union(&unapplied.stamp.tachygrams)
            .copied()
            .collect(),
        proof: Box::new(unapplied_pcd.proof().clone()),
        fee: aggregate.stamp.fee,
    };

    for (stamp, other) in [(over_fee_bearing, fee_bearing), (over_unapplied, unapplied)] {
        aggregate.stamp = stamp;
        let mut adjunct = other.strip(mock_wtxid(&aggregate));
        adjunct.fee_max_commitment = aggregate.fee_max_commitment;
        adjunct.stamp.fee = aggregate.stamp.fee;

        let err = aggregate
            .verify(rng, &sighash, &mock_wtxid(&aggregate).into(), &[&adjunct])
            .expect_err("a shared fee descriptor must be rejected");
        let VerificationError::Coverage(VerifyCoverageError::DuplicateFees) = err else {
            panic!("expected Coverage(DuplicateFees), got {err:?}");
        };

        aggregate.stamp.coverage = coverage_of(&[aggregate.as_dyn(), adjunct.as_dyn()]);
        adjunct.stamp.wtxid = mock_wtxid(&aggregate);

        let forged = aggregate
            .verify(rng, &sighash, &mock_wtxid(&aggregate).into(), &[&adjunct])
            .expect_err("a coverage forged over both bodies must be rejected");
        let VerificationError::Coverage(VerifyCoverageError::DuplicateFees) = forged else {
            panic!("expected Coverage(DuplicateFees), got {forged:?}");
        };
    }
}

/// A bundle whose stamp omits its fee fails verification at coverage, at
/// tachygram arity once the coverage is forged, and at the proof once the fee
/// change note is forged into the tachygrams.
#[test]
fn verify_rejects_a_stamp_without_its_fee() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_fee_note = wallet.random_note(300);
    let anchor = PoolSim::genesis(rng).anchor();
    let mut fee_less = fee_less_output_bundle(rng, &wallet, anchor, max_fee_note);
    let sighash = mock_sighash(fee_less.commitment());

    let mismatch =
        verify_alone(rng, &fee_less, &sighash).expect_err("a stamp without its fee must fail");
    let VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch) = mismatch else {
        panic!("expected Coverage(StampActionsMismatch), got {mismatch:?}");
    };

    fee_less.stamp.coverage = coverage_of(&[fee_less.as_dyn()]);
    let arity = verify_alone(rng, &fee_less, &sighash)
        .expect_err("a stamp without a fee change note must fail");
    let VerificationError::Tachygrams(VerifyTachygramsError::WrongArity) = arity else {
        panic!("expected Tachygrams(WrongArity), got {arity:?}");
    };

    // At a zero fee the fee change note is the max fee note itself.
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
    let disproved = verify_alone(rng, &fee_less, &sighash)
        .expect_err("a proof without the fee must not verify");
    let VerificationError::Disproved = disproved else {
        panic!("expected Disproved, got {disproved:?}");
    };
}

/// A fee-bearing aggregate merges a fee-bearing adjunct and verifies.
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
            .stamp_plan(anchor, zat(40))
            .prove(rng, &wallet.pak, vec![])
            .expect("prove the adjunct with its fee"),
    );

    let aggregate_stamp = bundle_plan
        .stamp_plan(anchor, zat(120))
        .prove(rng, &wallet.pak, spend_pcds)
        .expect("prove the aggregate with its fee");
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
        .expect("merge the aggregate's stamp with the adjunct's");
    let aggregate = signed.stamp(merged_stamp);

    assert_eq!(aggregate.stamp.fee, zat(120), "the receiver keeps its fee");
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
    assert_eq!(stripped.stamp.fee, zat(40), "the adjunct keeps its fee");
    aggregate
        .verify(rng, &sighash, &final_id.into(), &[&stripped])
        .expect("the aggregate verifies against the stripped adjunct");
}

#[test]
fn fee_bearing_aggregates_merge_and_lift() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let notes: Vec<Note> = [1000, 900, 800, 700]
        .map(|value| wallet.random_note(value))
        .into();
    let mut pool = PoolSim::genesis(rng);
    let commitments: Vec<_> = notes.iter().map(Note::commitment).collect();
    pool.mine(random_block_with(rng, &[commitments], 1));
    let [mut left, left_auto, mut right, right_auto] = [0, 1, 2, 3].map(|i| {
        let spendable = wallet.fresh_spend(rng, &pool, pool.height(), &notes[i]);
        let anchor = spendable.data().2;
        let (plan, signed, pcds) = wallet.signed(
            rng,
            vec![(notes[i], spendable)],
            vec![wallet.random_note(500)],
            wallet.random_note(100),
        );
        let stamp = plan
            .stamp_plan(anchor, zat(40))
            .prove(rng, &wallet.pak, pcds)
            .expect("prove with the fee");
        signed.stamp(stamp)
    });
    let sighash = mock_sighash(left.commitment());

    for (bundle, auto) in [(&mut left, &left_auto), (&mut right, &right_auto)] {
        let (stamp, desc, fees) = merge_side(bundle, &[]);
        bundle.stamp = stamp
            .merge(rng, (desc, fees), merge_side(auto, &[]))
            .expect("aggregate");
    }
    let (left_stamp, left_desc, left_fees) = merge_side(&left, &[left_auto.as_dyn()]);
    left.stamp = left_stamp
        .merge(
            rng,
            (left_desc, left_fees),
            merge_side(&right, &[right_auto.as_dyn()]),
        )
        .expect("merge two aggregates");

    pool.mine_bundles(&[&build_autonome(rng, &wallet, 400, 300)]);
    let span = build_lift_span(rng, &pool, pool.height()..=pool.height());
    let lifted = left
        .lift(
            rng,
            &[left_auto.as_dyn(), right.as_dyn(), right_auto.as_dyn()],
            vec![span],
        )
        .expect("lift the merged aggregate");

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
        .expect("the final aggregate verifies against every covered bundle");
}

/// A zero-action bundle's `FeeSeed` stamp verifies and survives a round-trip.
#[test]
fn zero_action_fee_seed_round_trips_and_verifies() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let bundle = wallet.autonome(rng, anchor, vec![], vec![]);
    let sighash = mock_sighash(bundle.commitment());
    assert_eq!(bundle.actions.len(), 0);
    assert_eq!(bundle.stamp.tachygrams.len(), 1);
    assert_eq!(bundle.verify_coverage(&[], &[]).unwrap().1.len(), 1);
    verify_alone(rng, &bundle, &sighash).expect("zero-action bundle verifies");
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).expect("write");
    let decoded = Bundle::<ProofStamp>::read(&*bytes).expect("read");
    assert_eq!(decoded.auth_digest(), bundle.auth_digest());
    verify_alone(rng, &decoded, &sighash).expect("decoded seed verifies");
}

/// An innocent's seed stamp absorbs an adjunct, then strips under a parent.
#[test]
fn innocent_seed_merges_and_strips() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let mut innocent = wallet.autonome(rng, anchor, vec![], vec![]);
    let adjunct = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(100)]);
    let (innocent_stamp, innocent_desc, innocent_fees) = merge_side(&innocent, &[]);
    innocent.stamp = innocent_stamp
        .merge(
            rng,
            (innocent_desc, innocent_fees),
            merge_side(&adjunct, &[]),
        )
        .expect("merge seed and adjunct");
    let id = mock_wtxid(&innocent);
    innocent
        .verify(
            rng,
            &mock_sighash(innocent.commitment()),
            &id.into(),
            &[&adjunct.clone().strip(id)],
        )
        .expect("innocent verifies");

    let mut parent = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(200)]);
    let (parent_stamp, parent_desc, parent_fees) = merge_side(&parent, &[]);
    parent.stamp = parent_stamp
        .merge(
            rng,
            (parent_desc, parent_fees),
            merge_side(&innocent, &[adjunct.as_dyn()]),
        )
        .expect("merge innocent into parent");
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
        .expect("parent verifies with the stripped innocent");
}

/// `FeeSeed` rejects a nonzero max fee.
#[test]
fn fee_seed_rejects_a_nonzero_max_fee() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let max_fee_note = wallet.random_note(0);
    let valid = witness::fee_seed(((), ()), max_fee_note, anchor);

    let mut max_fee = valid;
    max_fee.0.value = zat(1);
    let Err(ragu_core::Error::InvalidWitness(inner)) = PROOF_SYSTEM.seed(rng, FeeSeed, max_fee)
    else {
        panic!("expected InvalidWitness");
    };
    assert_eq!(inner.to_string(), "FeeSeed: maximum fee must be zero");
}

/// `FeeSeed` binds each singleton set to the fee digest or the fee change
/// note, and its output header to those sets and the witnessed anchor.
#[test]
fn fee_seed_binds_its_singletons_and_header() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let other_anchor = PoolSim::genesis(rng).anchor();
    assert_ne!(anchor, other_anchor);
    let valid = witness::fee_seed(((), ()), wallet.random_note(0), anchor);
    let other = witness::fee_seed(((), ()), wallet.random_note(0), anchor);

    let mut fee_actions = valid.clone();
    fee_actions.2 = other.2.clone();
    let mut fee_tachygrams = valid.clone();
    fee_tachygrams.3 = other.3.clone();
    for (corrupt, expected) in [
        (
            fee_actions,
            "FeeSeed: fee action set does not commit to the fee digest",
        ),
        (
            fee_tachygrams,
            "FeeSeed: fee tachygram set does not commit to the fee change note",
        ),
    ] {
        let Err(ragu_core::Error::InvalidWitness(inner)) = PROOF_SYSTEM.seed(rng, FeeSeed, corrupt)
        else {
            panic!("expected InvalidWitness: {expected}");
        };
        assert_eq!(inner.to_string(), expected);
    }

    let (seed_pcd, ()) = PROOF_SYSTEM
        .seed(rng, FeeSeed, valid.clone())
        .expect("a FeeSeed stamp");
    for (header, expected) in [
        ((valid.2.commit(), valid.3.commit(), anchor), true),
        ((other.2.commit(), valid.3.commit(), anchor), false),
        ((valid.2.commit(), other.3.commit(), anchor), false),
        ((valid.2.commit(), valid.3.commit(), other_anchor), false),
    ] {
        let pcd = seed_pcd.proof().clone().carry::<Stamp>(header);
        assert_eq!(
            PROOF_SYSTEM
                .verify(&pcd, &mut *rng)
                .expect("proof system verification"),
            expected,
        );
    }
}
