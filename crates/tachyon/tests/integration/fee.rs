extern crate alloc;

use alloc::{collections::BTreeSet, string::ToString as _, vec};
use core::iter;

use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, ActionSetPoly, Bundle, Note, VerificationError, VerifyCoverageError,
    VerifyTachygramsError, action, bundle,
    digest::blake2b,
    fee,
    stamp::{
        self, ProofStamp, ProveError, StampState,
        proof::{
            PROOF_SYSTEM,
            stamp::{Stamp, StampFee},
        },
    },
    value, witness,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_autonome, build_lift_span, build_output_stamp, mock_sighash,
    mock_wtxid, random_block_with, shared_sk,
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

/// `StampFee` binds the left, fee and output sets to its header.
#[test]
fn stamp_fee_binds_its_sets() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (bundle_plan, signed, spend_pcds, anchor, max_fee_note, _pool) =
        wallet.fee_bundle(rng, 1000, 700, 300);
    let left = signed.stamp(
        bundle_plan
            .stamp_plan(anchor, zat(0))
            .prove(rng, &wallet.pak, spend_pcds)
            .expect("prove the left stamp"),
    );

    let action_digests: BTreeSet<ActionDigest> = left
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain([left.fee_descriptor().digest().expect("fee digest")])
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
    let stamp_pcd = || left.stamp.proof.clone().carry::<Stamp>(stamp_header);
    let fee_witness = |fee: u64| {
        witness::stamp_fee(
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
            StampFee,
            valid.clone(),
            stamp_pcd(),
            Proof::trivial().carry::<()>(()),
        )
        .expect("a StampFee stamp");
    let (.., other_output_sets, _) = fee_witness(50);

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

/// A signed bundle reprices up to the max fee, and a fee applies once.
#[test]
fn fee_reprices_and_applies_once() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (bundle_plan, signed, spend_pcds, anchor, max_fee_note, _pool) =
        wallet.fee_bundle(rng, 1000, 700, 300);
    let sighash = mock_sighash(signed.commitment());
    let prove = |prove_rng: &mut StdRng, fee| {
        bundle_plan
            .stamp_plan(anchor, zat(fee))
            .prove(prove_rng, &wallet.pak, spend_pcds.clone())
            .map(|proved| signed.clone().stamp(proved))
    };

    assert_eq!(signed.value_balance, value::Balance::ZERO);

    let excess = prove(rng, 301).expect_err("a fee above the maximum must not apply");
    let ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner)) = excess else {
        panic!("expected ProofFailed(InvalidWitness), got {excess:?}");
    };
    assert_eq!(inner.to_string(), "StampFee: change is out of range");

    let mut auth_digests = BTreeSet::new();
    for fee in [0u64, 120, 300] {
        let bundle = prove(rng, fee).expect("prove with the fee");

        assert_eq!(u64::from(bundle.fee_value), fee);
        assert_eq!(bundle.commitment(), signed.commitment(), "fee {fee}");
        assert_eq!(bundle.binding_sig, signed.binding_sig, "fee {fee}");
        assert_eq!(bundle.stamp.tachygrams.len(), 2 * 2 + 1, "fee {fee}");

        verify_alone(rng, &bundle, &sighash).expect("a fee-bearing bundle verifies");
        auth_digests.insert(bundle.auth_digest());
    }
    assert_eq!(auth_digests.len(), 3, "each fee has its own auth_digest");

    let zero = prove(rng, 0).expect("prove the feeless base stamp");
    let once = prove(rng, 120).expect("first fee application");

    let Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(repeated))) =
        stamp::Plan::innocent(max_fee_note, vec![merge_side(&zero, &[])]).prove(
            rng,
            &wallet.pak,
            vec![],
        )
    else {
        panic!("a repeated fee must not apply");
    };
    assert_eq!(
        repeated.to_string(),
        "StampFee: output action set must be the product of left and fee action sets"
    );

    let (twice_stamp, _twice_fee) =
        stamp::Plan::innocent(max_fee_note, vec![merge_side(&once, &[])])
            .prove(rng, &wallet.pak, vec![])
            .expect("a second StampFee applies to the fee-bearing stamp");
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

    let digests: Vec<ActionDigest> = twice
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain([twice.fee_descriptor().digest().expect("fee digest")])
        .collect();
    assert!(
        !twice
            .verify_proof(rng, &digests)
            .expect("proof system verification"),
        "the proof covers two fee descriptors against one published"
    );
}

/// A fee descriptor shared by two covered bundles is rejected, even forged.
#[test]
fn verify_rejects_a_fee_descriptor_shared_by_two_covered_bundles() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (bundle_plan, signed, spend_pcds, anchor, max_fee_note, _pool) =
        wallet.fee_bundle(rng, 1000, 700, 300);
    let sighash = mock_sighash(signed.commitment());

    let mut aggregate = signed.stamp(
        bundle_plan
            .stamp_plan(anchor, zat(120))
            .prove(rng, &wallet.pak, spend_pcds)
            .expect("prove with the fee"),
    );
    let fee_bearing = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(500)]);
    let over_fee_bearing = ProofStamp::merge(
        rng,
        merge_side(&aggregate, &[]),
        merge_side(&fee_bearing, &[]),
    )
    .expect("merge the aggregate");

    let (unapplied_stamp, output_plan, _) =
        build_output_stamp(rng, anchor, wallet.random_note(500));
    let unapplied_plan = bundle::Plan::new(vec![], vec![output_plan], fee::Plan::new(max_fee_note));
    let unapplied_signed = unapplied_plan
        .sign(
            rng,
            &mock_sighash(unapplied_plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .expect("sign the unapplied bundle");
    let over_unapplied = ProofStamp::merge(
        rng,
        merge_side(&aggregate, &[]),
        (
            unapplied_stamp.clone(),
            unapplied_signed.descriptors().collect(),
            BTreeSet::new(),
        ),
    )
    .expect("merge the aggregate over a stamp without a fee");
    let unapplied = unapplied_signed.stamp((unapplied_stamp, value::Positive::ZERO));

    for (stamp, other) in [(over_fee_bearing, fee_bearing), (over_unapplied, unapplied)] {
        aggregate.stamp = stamp;
        let mut adjunct = other.strip(mock_wtxid(&aggregate));
        adjunct.fee_max_commitment = aggregate.fee_max_commitment;
        adjunct.fee_value = aggregate.fee_value;

        let err = aggregate
            .verify(rng, &sighash, &mock_wtxid(&aggregate).into(), &[&adjunct])
            .expect_err("a shared fee descriptor must be rejected");
        let VerificationError::Coverage(VerifyCoverageError::DuplicateFees) = err else {
            panic!("expected Coverage(DuplicateFees), got {err:?}");
        };

        aggregate.stamp.coverage = coverage_of(&[aggregate.as_dyn(), adjunct.as_dyn()]);
        adjunct.stamp = mock_wtxid(&aggregate);

        let forged = aggregate
            .verify(rng, &sighash, &mock_wtxid(&aggregate).into(), &[&adjunct])
            .expect_err("a coverage forged over both bodies must be rejected");
        let VerificationError::Coverage(VerifyCoverageError::DuplicateFees) = forged else {
            panic!("expected Coverage(DuplicateFees), got {forged:?}");
        };
    }
}

/// A fee-bearing aggregate merges a fee-bearing adjunct and verifies.
#[test]
fn fee_applies_over_a_fee_bearing_adjunct() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (bundle_plan, signed, spend_pcds, anchor, max_fee_note, _pool) =
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

    let (aggregate_stamp, aggregate_fee) = bundle_plan
        .stamp_plan(anchor, zat(120))
        .prove(rng, &wallet.pak, spend_pcds)
        .expect("prove the aggregate with its fee");
    let aggregate_descriptors: BTreeSet<action::Descriptor> = signed.descriptors().collect();
    let aggregate_fee_descriptors = BTreeSet::from([fee::Descriptor {
        max_commitment: fee::Plan::new(max_fee_note).max_commitment(),
        value: aggregate_fee,
    }]);

    let merged_stamp = ProofStamp::merge(
        rng,
        (
            aggregate_stamp,
            aggregate_descriptors,
            aggregate_fee_descriptors,
        ),
        merge_side(&adjunct, &[]),
    )
    .expect("merge the aggregate's stamp with the adjunct's");
    let aggregate = signed.stamp((merged_stamp, aggregate_fee));

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
    aggregate
        .verify(rng, &sighash, &final_id.into(), &[&adjunct.strip(final_id)])
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
        bundle.stamp = ProofStamp::merge(rng, merge_side(bundle, &[]), merge_side(auto, &[]))
            .expect("aggregate");
    }
    left.stamp = ProofStamp::merge(
        rng,
        merge_side(&left, &[left_auto.as_dyn()]),
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
