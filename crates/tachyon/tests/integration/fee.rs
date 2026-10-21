extern crate alloc;

use alloc::{collections::BTreeSet, string::ToString as _, vec};
use core::{iter, slice};

use ff::PrimeField as _;
use group::GroupEncoding as _;
use pasta_curves::{EpAffine, Fp, arithmetic::CurveAffine as _};
use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, ActionSetPoly, Anchor, Bundle, Note, Tachygram, TachygramSetPoly,
    VerificationError, VerifyCoverageError, VerifyTachygramsError, action, bundle,
    constants::MAX_MONEY,
    digest::blake2b,
    fee,
    stamp::{
        self, PointerStamp, ProofStamp, StampState,
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

fn fee_value(amount: i64) -> value::Balance {
    value::Balance::try_from(amount).unwrap()
}

fn output_actions(
    rng: &mut StdRng,
    wallet: &WalletSim,
    anchor: Anchor,
) -> (ragu::Pcd<Actions>, action::Descriptor, BTreeSet<Tachygram>) {
    let note = wallet.random_note(0);
    let (rcv, theta, plan) = build_output_plan(rng, note);
    let (bound, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .unwrap();
    let (cm, pad, _) = *bound.data();
    let (actions, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            OutputAction,
            witness::output_action((*bound.data(), ()), theta, anchor),
            bound,
            Proof::trivial().carry::<()>(()),
        )
        .unwrap();
    (actions, plan.descriptor(), BTreeSet::from([cm, pad]))
}

fn round_trip<S: StampState>(bundle: &Bundle<S>) -> Bundle<S> {
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).unwrap();
    Bundle::read(&*bytes).unwrap()
}

fn seed_bundle(
    rng: &mut StdRng,
    wallet: &WalletSim,
    anchor: Anchor,
    fee: i64,
) -> (Bundle<ProofStamp>, Note) {
    let note = wallet.random_note(0);
    let (plan, signed, _) = wallet.signed(rng, vec![], vec![], note);
    let bundle = signed.stamp(
        plan.stamp_plan(anchor, fee_value(fee))
            .prove(rng, &wallet.pak, vec![])
            .unwrap(),
    );
    (
        bundle,
        Note {
            value: zat(fee.unsigned_abs()),
            ..note
        },
    )
}

fn payers(rng: &mut StdRng, amounts: &[u64]) -> (WalletSim, PoolSim, Vec<Bundle<ProofStamp>>) {
    let wallet = WalletSim::new(shared_sk());
    let notes: Vec<_> = amounts
        .iter()
        .map(|&amount| wallet.random_note(amount))
        .collect();
    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(
        rng,
        &[notes.iter().map(Note::commitment).collect()],
        1,
    ));
    let bundles = notes
        .into_iter()
        .map(|note| {
            let spendable = wallet.fresh_spend(rng, &pool, pool.height(), &note);
            let max_fee = wallet.random_note(u64::from(note.value));
            let (plan, signed, pcds) = wallet.signed(rng, vec![(note, spendable)], vec![], max_fee);
            signed.stamp(
                plan.stamp_plan(pool.anchor(), note.value.into())
                    .prove(rng, &wallet.pak, pcds)
                    .unwrap(),
            )
        })
        .collect();
    (wallet, pool, bundles)
}

fn aggregate(
    rng: &mut StdRng,
    mut top: Bundle<ProofStamp>,
    adjuncts: &[Bundle<ProofStamp>],
) -> Bundle<ProofStamp> {
    for (index, adjunct) in adjuncts.iter().enumerate() {
        top.stamp = ProofStamp::merge(
            rng,
            merge_side(
                &top,
                &adjuncts[..index]
                    .iter()
                    .map(Bundle::as_dyn)
                    .collect::<Vec<_>>(),
            ),
            merge_side(adjunct, &[]),
        )
        .unwrap();
    }
    top
}

/// A consumer-consensus fixture, using only wire data and explicit other-pool
/// balances. The top-level proof covers the entire final group.
fn verify_funding(
    rng: &mut StdRng,
    source_top: &Bundle<ProofStamp>,
    source_adjuncts: &[Bundle<ProofStamp>],
    other_balances: &[i128],
    coinbase: Option<usize>,
) -> Result<i128, &'static str> {
    let top = round_trip(source_top);
    let id = mock_wtxid(&top);
    let adjuncts: Vec<Bundle<PointerStamp>> = source_adjuncts
        .iter()
        .map(|bundle| round_trip(&bundle.clone().strip(id)))
        .collect();
    for adjunct in &adjuncts {
        adjunct
            .verify_signatures(&mock_sighash(adjunct.commitment()))
            .map_err(|_err| "adjunct signatures")?;
    }
    top.verify(
        rng,
        &mock_sighash(top.commitment()),
        &id.into(),
        &adjuncts.iter().collect::<Vec<_>>(),
    )
    .map_err(|_err| "aggregate")?;
    if other_balances.len() != 1 + adjuncts.len() {
        return Err("other-pool balance count");
    }
    let (mut deficits, mut allowances, mut total) = (0i128, 0i128, 0i128);
    for (index, bundle) in iter::once(top.as_dyn())
        .chain(adjuncts.iter().map(Bundle::as_dyn))
        .enumerate()
    {
        if coinbase == Some(index) {
            continue;
        }
        let fee = i128::from(bundle.fee_value);
        let transaction_fee = i128::from(bundle.value_balance)
            .checked_add(other_balances[index])
            .and_then(|balance| balance.checked_add(fee))
            .ok_or("overflow")?;
        if transaction_fee < fee.min(0) {
            return Err("transaction balance");
        }
        let deficit = if transaction_fee < 0 {
            transaction_fee.checked_neg().ok_or("overflow")?
        } else {
            0
        };
        let allowance = if fee >= 0 {
            fee.min(transaction_fee)
        } else {
            0
        };
        deficits = deficits.checked_add(deficit).ok_or("overflow")?;
        allowances = allowances.checked_add(allowance).ok_or("overflow")?;
        total = total.checked_add(transaction_fee).ok_or("overflow")?;
    }
    if deficits > allowances {
        return Err("group funding");
    }
    Ok(total)
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

/// A signed output-only bundle whose stamp is a genuine `OutputAction` proof
/// with no fee applied, carrying the coverage of its action alone.
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
    };

    let plan = bundle::Plan::new(vec![], vec![output_plan], max_fee_note);
    plan.sign(
        rng,
        &mock_sighash(plan.commitment().expect("bundle commitment")),
        &wallet.sk.derive_auth_private(),
    )
    .expect("sign the fee-less bundle")
    .stamp((stamp, value::Balance::ZERO))
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

/// `FeeFuse` over a genuine `OutputAction` proof binds the left, fee and output
/// sets to its header, and rejects each substituted set polynomial.
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
    let actions_header = (
        action_digests
            .iter()
            .copied()
            .collect::<ActionSetPoly>()
            .commit(),
        left.stamp.tachygram_set,
        anchor,
    );
    let actions_pcd = || left.stamp.proof.clone().carry::<Actions>(actions_header);
    assert!(
        PROOF_SYSTEM
            .verify(&actions_pcd(), &mut *rng)
            .expect("proof system verification"),
        "the OutputAction proof verifies as Actions"
    );
    let fee_witness = |fee: i64| {
        witness::fee_fuse(
            (actions_header, ()),
            max_fee_note,
            fee_value(fee),
            &action_digests,
            &left.stamp.tachygrams,
        )
        .unwrap()
    };

    let valid = fee_witness(-120);
    let (fee_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            FeeFuse,
            valid.clone(),
            actions_pcd(),
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
            actions_pcd(),
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
            .stamp_plan(anchor, fee_value(fee))
            .prove(prove_rng, &wallet.pak, spend_pcds.clone())
            .map(|proved| signed.clone().stamp(proved))
    };

    assert_eq!(signed.value_balance, value::Balance::ZERO);

    let actions = fee_less_output_bundle(rng, &wallet, anchor, max_fee_note);
    let action_digests: BTreeSet<ActionDigest> = actions
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .collect();
    let actions_header = (
        action_digests
            .iter()
            .copied()
            .collect::<ActionSetPoly>()
            .commit(),
        actions.stamp.tachygram_set,
        anchor,
    );
    let mut excess_witness = witness::fee_fuse(
        (actions_header, ()),
        max_fee_note,
        fee_value(300),
        &action_digests,
        &actions.stamp.tachygrams,
    )
    .expect("witness the maximum fee");
    excess_witness.1 = fee_value(301);
    let excess = PROOF_SYSTEM
        .fuse(
            rng,
            FeeFuse,
            excess_witness,
            actions
                .stamp
                .proof
                .as_ref()
                .clone()
                .carry::<Actions>(actions_header),
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .expect("a fee above the maximum must not apply");
    let ragu_core::Error::InvalidWitness(inner) = excess else {
        panic!("expected InvalidWitness, got {excess:?}");
    };
    assert_eq!(inner.to_string(), "FeeFuse: change is out of range");

    let mut auth_digests = BTreeSet::new();
    for fee in [0i64, 120, 300, -120] {
        let bundle = prove(rng, fee).expect("prove with the fee");

        assert_eq!(i64::from(bundle.fee_value), fee);
        assert_eq!(bundle.commitment(), signed.commitment(), "fee {fee}");
        assert_eq!(bundle.binding_sig, signed.binding_sig, "fee {fee}");
        assert_eq!(bundle.stamp.tachygrams.len(), 2 * 2 + 1, "fee {fee}");

        verify_alone(rng, &bundle, &sighash).expect("a fee-bearing bundle verifies");
        let payout = Note {
            value: zat(u64::try_from(300 - fee).unwrap()),
            ..max_fee_note
        };
        assert!(
            bundle
                .stamp
                .tachygrams
                .contains(&payout.commitment().into())
        );
        auth_digests.insert(bundle.auth_digest());
    }
    assert_eq!(auth_digests.len(), 4, "each fee has its own auth_digest");

    let once = prove(rng, 120).expect("first fee application");
    let (extra, _) = seed_bundle(rng, &wallet, anchor, -1);
    // Both children are genuine Stamps. Publish only the first bundle's body.
    let mut twice = aggregate(rng, once, &[extra]);

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
            .stamp_plan(anchor, fee_value(-120))
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
    };

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
            .stamp_plan(anchor, fee_value(40))
            .prove(rng, &wallet.pak, vec![])
            .expect("prove the adjunct with its fee"),
    );

    let (aggregate_stamp, aggregate_fee) = bundle_plan
        .stamp_plan(anchor, fee_value(120))
        .prove(rng, &wallet.pak, spend_pcds)
        .expect("prove the aggregate with its fee");
    let aggregate_descriptors: BTreeSet<action::Descriptor> = signed.descriptors().collect();
    let aggregate_fee_descriptors = BTreeSet::from([fee::Descriptor {
        max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
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
            .stamp_plan(anchor, fee_value(40))
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

#[test]
fn zero_action_fee_seed_round_trips_and_verifies() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let max_fee_note = wallet.random_note(0);
    let (_, signed, _) = wallet.signed(rng, vec![], vec![], max_fee_note);
    let proved = stamp::Plan::new(vec![], vec![], anchor, max_fee_note, fee_value(0))
        .prove(rng, &wallet.pak, vec![])
        .expect("seed");
    let bundle = signed.stamp(proved);
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

#[test]
fn innocent_seed_merges_and_strips() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let mut innocent = wallet.autonome(rng, anchor, vec![], vec![]);
    let adjunct = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(100)]);
    innocent.stamp = ProofStamp::merge(rng, merge_side(&innocent, &[]), merge_side(&adjunct, &[]))
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
    parent.stamp = ProofStamp::merge(
        rng,
        merge_side(&parent, &[]),
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

/// An `Actions` proof does not verify as a `Stamp`.
#[test]
fn actions_proof_cannot_substitute_for_a_stamp() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let note = wallet.random_note(500);
    let (rcv, theta, plan) = build_output_plan(rng, note);

    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .expect("bind the output");
    let (cm, pad, _cv) = *bind_pcd.data();
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            OutputAction,
            witness::output_action((*bind_pcd.data(), ()), theta, anchor),
            bind_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("prove the output action");
    assert!(
        PROOF_SYSTEM
            .verify(&pcd, &mut *rng)
            .expect("verify actions")
    );

    let stamp = ProofStamp {
        coverage: [0; 32],
        anchor,
        tachygram_set: pcd.data().1,
        tachygrams: BTreeSet::from_iter([cm, pad]),
        proof: Box::new(pcd.proof().clone()),
    };
    assert!(
        !stamp
            .verify_proof(rng, [plan.descriptor().digest().unwrap()])
            .expect("verify substituted header")
    );
}

#[test]
fn fee_seed_rejects_nonzero_value_and_positive_fee() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let max_fee_note = wallet.random_note(0);
    let valid = witness::fee_seed(((), ()), max_fee_note, fee_value(0), anchor).unwrap();
    for slot in 0..2 {
        let mut forged = valid.clone();
        let expected = if slot == 0 {
            forged.0.value = zat(1);
            "FeeSeed: maximum fee must be zero"
        } else {
            forged.1 = fee_value(1);
            "FeeFuse: change is out of range"
        };
        let err = PROOF_SYSTEM
            .seed(rng, FeeSeed, forged)
            .err()
            .expect("invalid seed");
        let ragu_core::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(inner.to_string(), expected);
    }

    let claim = value::Balance::try_from(-9).unwrap();
    let (pcd, ()) = PROOF_SYSTEM
        .seed(
            rng,
            FeeSeed,
            witness::fee_seed(((), ()), max_fee_note, claim, anchor).unwrap(),
        )
        .expect("negative fee seed");
    assert!(PROOF_SYSTEM.verify(&pcd, rng).unwrap());
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
    let valid = witness::fee_seed(((), ()), wallet.random_note(0), fee_value(0), anchor).unwrap();
    let other = witness::fee_seed(((), ()), wallet.random_note(0), fee_value(0), anchor).unwrap();

    let mut fee_actions = valid.clone();
    fee_actions.3 = other.3.clone();
    let mut fee_tachygrams = valid.clone();
    fee_tachygrams.4 = other.4.clone();
    for (corrupt, expected) in [
        (
            fee_actions,
            "FeeFuse: fee action set does not commit to the fee digest",
        ),
        (
            fee_tachygrams,
            "FeeFuse: fee tachygram set does not commit to the fee change note",
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
        ((valid.3.commit(), valid.4.commit(), anchor), true),
        ((other.3.commit(), valid.4.commit(), anchor), false),
        ((valid.3.commit(), other.4.commit(), anchor), false),
        ((valid.3.commit(), valid.4.commit(), other_anchor), false),
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

#[test]
fn stamp_proof_cannot_substitute_for_actions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let bundle = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(0)]);
    verify_alone(rng, &bundle, &mock_sighash(bundle.commitment())).unwrap();
    let digests = bundle
        .descriptors()
        .map(|descriptor| descriptor.digest().unwrap())
        .chain([bundle.fee_descriptor().digest().unwrap()]);
    let substituted = bundle.stamp.proof.clone().carry::<Actions>((
        ActionSetPoly::from_iter(digests).commit(),
        bundle.stamp.tachygram_set,
        anchor,
    ));
    assert!(!PROOF_SYSTEM.verify(&substituted, rng).unwrap());
}

#[test]
fn signed_fee_change_boundaries() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let money_max = MAX_MONEY.cast_signed();
    let (actions, descriptor, tachygrams) = output_actions(rng, &wallet, anchor);
    let digests = BTreeSet::from([descriptor.digest().unwrap()]);
    for (maximum, fee) in [
        (0, 0),
        (0, -money_max),
        (money_max, 0),
        (money_max, money_max),
        (money_max - 1, -1),
    ] {
        let note = wallet.random_note(maximum.cast_unsigned());
        let witness = witness::fee_fuse(
            (*actions.data(), ()),
            note,
            fee_value(fee),
            &digests,
            &tachygrams,
        )
        .unwrap();
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                FeeFuse,
                witness,
                actions.clone(),
                Proof::trivial().carry::<()>(()),
            )
            .unwrap();
        assert!(PROOF_SYSTEM.verify(&pcd, &mut *rng).unwrap());
        if maximum == 0 {
            let seed = witness::fee_seed(((), ()), note, fee_value(fee), anchor).unwrap();
            let (seed_pcd, ()) = PROOF_SYSTEM.seed(rng, FeeSeed, seed).unwrap();
            assert!(PROOF_SYSTEM.verify(&seed_pcd, &mut *rng).unwrap());
        }
    }
    for (maximum, fee) in [(money_max, -1), (0, 1)] {
        let note = wallet.random_note(maximum.cast_unsigned());
        let mut raw = witness::fee_fuse(
            (*actions.data(), ()),
            note,
            fee_value(0),
            &digests,
            &tachygrams,
        )
        .unwrap();
        raw.1 = fee_value(fee);
        let err = PROOF_SYSTEM
            .fuse(
                rng,
                FeeFuse,
                raw,
                actions.clone(),
                Proof::trivial().carry::<()>(()),
            )
            .err()
            .unwrap();
        let ragu_core::Error::InvalidWitness(reason) = err else {
            panic!("{err:?}");
        };
        assert_eq!(reason.to_string(), "FeeFuse: change is out of range");
        witness::fee_fuse(
            (*actions.data(), ()),
            note,
            fee_value(fee),
            &digests,
            &tachygrams,
        )
        .unwrap_err();
        witness::fee_seed(((), ()), note, fee_value(fee), anchor).unwrap_err();
    }
}

fn independent_fee_digest(commitment: value::Commitment, encoded_fee: Fp) -> ActionDigest {
    use ragu_arithmetic::Cycle as _;
    use ragu_core::{
        drivers::emulator::{Emulator, Wireless},
        maybe::{Always, Maybe as _},
    };
    use ragu_pasta::{Pasta, PoseidonFp};
    use ragu_primitives::{Element, poseidon::Sponge};
    let cv = EpAffine::from(commitment);
    let coords = cv.coordinates().into_option().unwrap();
    let mut emulator = Emulator::<Wireless<Always<()>, Fp>>::execute();
    let mut sponge =
        Sponge::<_, PoseidonFp>::new(&mut emulator, Pasta::circuit_poseidon(Pasta::baked()));
    for input in [
        Fp::from_u128(u128::from_le_bytes(*b"Tachyon-FeeDg\0\0\0")),
        *coords.x(),
        *coords.y(),
        encoded_fee,
    ] {
        let element = Element::constant(&mut emulator, input);
        sponge.absorb(&mut emulator, &element).unwrap();
    }
    ActionDigest::from(*sponge.squeeze(&mut emulator).unwrap().value().take())
}

#[test]
fn signed_fee_digest_uses_field_negation() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    for fee in [0, 120, MAX_MONEY.cast_signed(), -120] {
        let max_fee = wallet.random_note(if fee < 0 { 0 } else { MAX_MONEY });
        let (plan, signed, _) = wallet.signed(rng, vec![], vec![wallet.random_note(0)], max_fee);
        let bundle = round_trip(
            &signed.stamp(
                plan.stamp_plan(anchor, fee_value(fee))
                    .prove(rng, &wallet.pak, vec![])
                    .unwrap(),
            ),
        );
        verify_alone(rng, &bundle, &mock_sighash(bundle.commitment())).unwrap();
        let field = if fee < 0 {
            -Fp::from(fee.unsigned_abs())
        } else {
            Fp::from(fee.cast_unsigned())
        };
        assert_eq!(
            bundle.fee_descriptor().digest().unwrap(),
            independent_fee_digest(bundle.fee_max_commitment, field)
        );
        let mut entry = [0u8; 40];
        entry[..32].copy_from_slice(&EpAffine::from(bundle.fee_max_commitment).to_bytes());
        if fee >= 0 {
            // The pre-Phase-2 unsigned encoding, independently reconstructed.
            let old_fee_bytes = fee.cast_unsigned().to_le_bytes();
            entry[32..].copy_from_slice(&old_fee_bytes);
            assert_eq!(entry, <[u8; 40]>::from(bundle.fee_descriptor()));
            let mut auth = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"ZTxAuthTachyHash")
                .to_state();
            auth.update(&[1]);
            let mut signatures = Vec::new();
            for action in &bundle.actions {
                action.sig.write(&mut signatures).unwrap();
            }
            bundle.binding_sig.write(&mut signatures).unwrap();
            auth.update(&signatures);
            auth.update(&old_fee_bytes);
            auth.update(&bundle.stamp.stamp_digest());
            assert_eq!(auth.finalize().as_bytes(), bundle.auth_digest());
        } else {
            let wrong =
                independent_fee_digest(bundle.fee_max_commitment, Fp::from(fee.cast_unsigned()));
            let mut digests: Vec<_> = bundle
                .descriptors()
                .map(|descriptor| descriptor.digest().unwrap())
                .collect();
            digests.push(wrong);
            assert!(!bundle.verify_proof(rng, &digests).unwrap());
            let mut descriptors = [
                bundle.fee_descriptor(),
                fee::Descriptor {
                    max_commitment: max_fee.fee_blind().commit(-max_fee.value),
                    value: fee_value(0),
                },
            ];
            descriptors.sort();
            let bytes: Vec<[u8; 40]> = descriptors.into_iter().map(Into::into).collect();
            assert!(bytes.is_sorted());
            assert_eq!(
                bundle.verify_coverage(&[], &[]).unwrap().1,
                BTreeSet::from([bundle.fee_descriptor()])
            );
        }
    }
}

#[test]
fn signed_fee_wire_and_auth_binding() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (plan, signed, pcds, anchor, ..) = wallet.fee_bundle(rng, 1000, 700, 300);
    for fee in [0, 120, -120] {
        let bundle = signed.clone().stamp(
            plan.stamp_plan(anchor, fee_value(fee))
                .prove(rng, &wallet.pak, pcds.clone())
                .unwrap(),
        );
        let decoded = round_trip(&bundle);
        assert_eq!(bundle.auth_digest(), decoded.auth_digest());
        assert_eq!(decoded.fee_value, fee_value(fee));
        verify_alone(rng, &decoded, &mock_sighash(decoded.commitment())).unwrap();
        let stripped = round_trip(&bundle.clone().strip(mock_wtxid(&bundle)));
        assert_eq!(stripped.fee_value, fee_value(fee));
        stripped
            .verify_signatures(&mock_sighash(stripped.commitment()))
            .unwrap();
        assert_eq!(
            bundle
                .verify_pointers(&mock_wtxid(&bundle).into(), &[&stripped])
                .unwrap()
                .1,
            vec![bundle.fee_descriptor()]
        );
    }
    let original = signed.stamp(
        plan.stamp_plan(anchor, fee_value(-120))
            .prove(rng, &wallet.pak, pcds)
            .unwrap(),
    );
    let old_pointer = original.clone().strip(mock_wtxid(&original));
    for altered_fee in [120, -119] {
        let mut altered = original.clone();
        altered.fee_value = fee_value(altered_fee);
        altered.stamp.coverage = coverage_of(&[altered.as_dyn()]);
        assert_ne!(altered.auth_digest(), original.auth_digest());
        let err = verify_alone(rng, &altered, &mock_sighash(altered.commitment())).unwrap_err();
        let VerificationError::Disproved = err else {
            panic!("{err:?}");
        };
        altered
            .verify_pointers(&mock_wtxid(&altered).into(), &[&old_pointer])
            .unwrap_err();
    }
}

#[test]
fn signed_fee_wire_range() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let (bundle, _) = seed_bundle(rng, &wallet, anchor, -MAX_MONEY.cast_signed());
    verify_alone(rng, &bundle, &mock_sighash(bundle.commitment())).unwrap();
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).unwrap();
    // state, value balance, zero action count, cvFeeMax, binding signature.
    let offset = 1 + 8 + 1 + 32 + 64;
    for fee in [
        MAX_MONEY.cast_signed() + 1,
        -MAX_MONEY.cast_signed() - 1,
        i64::MIN,
        i64::MAX,
    ] {
        let mut malformed = bytes.clone();
        malformed[offset..offset + 8].copy_from_slice(&fee.to_le_bytes());
        Bundle::<ProofStamp>::read(&*malformed).unwrap_err();
    }
    let decoded = round_trip(&bundle);
    verify_alone(rng, &decoded, &mock_sighash(decoded.commitment())).unwrap();
}

#[test]
fn identity_fee_commitment_is_rejected() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let (mut bundle, _) = seed_bundle(rng, &wallet, anchor, -1);
    verify_alone(rng, &bundle, &mock_sighash(bundle.commitment())).unwrap();
    bundle.fee_max_commitment = value::Commitment::default();
    bundle.fee_descriptor().digest().unwrap_err();
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).unwrap();
    Bundle::<ProofStamp>::read(&*bytes).unwrap_err();
}

#[test]
fn claim_opening_and_payout_are_bound() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let note = wallet.random_note(0);
    let valid = witness::fee_seed(((), ()), note, fee_value(-9), anchor).unwrap();
    let (pcd, ()) = PROOF_SYSTEM.seed(rng, FeeSeed, valid.clone()).unwrap();
    assert!(PROOF_SYSTEM.verify(&pcd, &mut *rng).unwrap());
    let foreign = WalletSim::random(rng).random_note(0);
    for slot in 0..2 {
        let mut raw = valid.clone();
        if slot == 0 {
            raw.0.pk = foreign.pk;
        } else {
            raw.0.rcm = foreign.rcm;
        }
        assert!(PROOF_SYSTEM.seed(rng, FeeSeed, raw).is_err());
    }
    let (mut bundle, _) = seed_bundle(rng, &wallet, anchor, -9);
    verify_alone(rng, &bundle, &mock_sighash(bundle.commitment())).unwrap();
    let mut redirected = bundle.clone();
    redirected.fee_max_commitment = foreign.fee_blind().commit(-foreign.value);
    assert!(
        redirected
            .verify_signatures(&mock_sighash(redirected.commitment()))
            .is_err()
    );
    assert!(
        !redirected
            .verify_proof(rng, &[redirected.fee_descriptor().digest().unwrap()])
            .unwrap()
    );
    bundle.stamp.tachygrams = BTreeSet::from([foreign.commitment().into()]);
    let Err(VerifyTachygramsError::WrongSet) = bundle.verify_tachygrams(0, 1) else {
        panic!("payout replaced");
    };
}

#[test]
fn innocent_claim_is_funded() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, pool, payers) = payers(rng, &[7, 5]);
    let (claim, payout) = seed_bundle(rng, &wallet, pool.anchor(), -9);
    let top = aggregate(rng, claim, &payers);
    assert_eq!(verify_funding(rng, &top, &payers, &[0, 0, 0], None), Ok(3));
    assert_eq!(payout.value, zat(9));
    assert!(top.stamp.tachygrams.contains(&payout.commitment().into()));
    assert_eq!(top.stamp.tachygrams.len(), 2 * 2 + 3);
    let (zero, _) = seed_bundle(rng, &wallet, pool.anchor(), 0);
    assert_eq!(verify_funding(rng, &zero, &[], &[0], None), Ok(0));
    let mut adjuncts = payers.clone();
    adjuncts.push(zero);
    let (padded_claim, _) = seed_bundle(rng, &wallet, pool.anchor(), -9);
    let padded_top = aggregate(rng, padded_claim, &adjuncts);
    assert_eq!(
        verify_funding(rng, &padded_top, &adjuncts, &[0, 0, 0, 0], None),
        Ok(3)
    );
}

#[test]
fn based_claim_is_funded() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, pool, payers) = payers(rng, &[5]);
    let max_fee = wallet.random_note(4);
    let (plan, signed, _) = wallet.signed(rng, vec![], vec![wallet.random_note(0)], max_fee);
    let own = signed.stamp(
        plan.stamp_plan(pool.anchor(), fee_value(-3))
            .prove(rng, &wallet.pak, vec![])
            .unwrap(),
    );
    let payout = Note {
        value: zat(7),
        ..max_fee
    };
    let top = aggregate(rng, own, &payers);
    // The other pool deposits the aggregator's maxfee: b = -4 + 4 = 0.
    assert_eq!(verify_funding(rng, &top, &payers, &[4, 0], None), Ok(2));
    assert!(top.stamp.tachygrams.contains(&payout.commitment().into()));
}

#[test]
fn claim_payout_is_spendable() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, mut pool, payers) = payers(rng, &[7, 5]);
    let (claim, payout) = seed_bundle(rng, &wallet, pool.anchor(), -9);
    let top = aggregate(rng, claim, &payers);
    assert_eq!(verify_funding(rng, &top, &payers, &[0, 0, 0], None), Ok(3));
    pool.mine_bundles(&[&top]);
    let spendable = wallet.fresh_spend(rng, &pool, pool.height(), &payout);
    let (plan, signed, pcds) = wallet.signed(
        rng,
        vec![(payout, spendable)],
        vec![wallet.random_note(9)],
        wallet.random_note(0),
    );
    let proved = plan
        .stamp_plan(pool.anchor(), fee_value(0))
        .prove(rng, &wallet.pak, pcds)
        .unwrap();
    let spend = signed.stamp(proved.clone());
    assert_eq!(verify_funding(rng, &spend, &[], &[0], None), Ok(0));
    let other = WalletSim::random(rng);
    let wrong = plan
        .sign(
            rng,
            &mock_sighash(spend.commitment()),
            &other.sk.derive_auth_private(),
        )
        .unwrap()
        .stamp(proved);
    assert!(
        wrong
            .verify_signatures(&mock_sighash(wrong.commitment()))
            .is_err()
    );
}

#[test]
fn nested_claims_merge_lift_and_strip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, mut pool, payers) = payers(rng, &[7, 5]);
    let (seed, inner_payout) = seed_bundle(rng, &wallet, pool.anchor(), -4);
    let inner = aggregate(rng, seed, &payers[..1]);
    let max_fee = wallet.random_note(4);
    let (plan, signed, _) = wallet.signed(rng, vec![], vec![wallet.random_note(0)], max_fee);
    let outer = signed.stamp(
        plan.stamp_plan(pool.anchor(), fee_value(-5))
            .prove(rng, &wallet.pak, vec![])
            .unwrap(),
    );
    let outer_payout = Note {
        value: zat(9),
        ..max_fee
    };
    let mut top = aggregate(rng, outer, &payers[1..]);
    top.stamp = ProofStamp::merge(
        rng,
        merge_side(&top, &[payers[1].as_dyn()]),
        merge_side(&inner, &[payers[0].as_dyn()]),
    )
    .unwrap();
    let adjuncts = vec![payers[0].clone(), payers[1].clone(), inner];
    assert_eq!(
        verify_funding(rng, &top, &adjuncts, &[4, 0, 0, 0], None),
        Ok(3)
    );
    let advance = wallet.autonome(rng, pool.anchor(), vec![], vec![wallet.random_note(0)]);
    pool.mine_bundles(&[&advance]);
    let span = build_lift_span(rng, &pool, pool.height()..=pool.height());
    let lifted = top
        .lift(
            rng,
            &adjuncts.iter().map(Bundle::as_dyn).collect::<Vec<_>>(),
            vec![span],
        )
        .unwrap();
    assert_eq!(
        verify_funding(rng, &lifted, &adjuncts, &[4, 0, 0, 0], None),
        Ok(3)
    );
    for payout in [inner_payout, outer_payout] {
        assert!(
            lifted
                .stamp
                .tachygrams
                .contains(&payout.commitment().into())
        );
    }
    assert_eq!(
        verify_funding(rng, &lifted, &payers, &[4, 0, 0], None),
        Err("aggregate")
    );
}

#[test]
fn overdrawn_inner_aggregate_can_be_funded() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, pool, payers) = payers(rng, &[7, 5]);
    let (seed, _) = seed_bundle(rng, &wallet, pool.anchor(), -9);
    let inner = aggregate(rng, seed, &payers[..1]);
    assert_eq!(
        verify_funding(rng, &inner, &payers[..1], &[0, 0], None),
        Err("group funding")
    );
    for (fee, result) in [(-3, Ok(0)), (-4, Err("group funding"))] {
        let (outer_seed, _) = seed_bundle(rng, &wallet, pool.anchor(), fee);
        let mut top = aggregate(rng, outer_seed, &payers[1..]);
        top.stamp = ProofStamp::merge(
            rng,
            merge_side(&top, &[payers[1].as_dyn()]),
            merge_side(&inner, &[payers[0].as_dyn()]),
        )
        .unwrap();
        let adjuncts = [payers[0].clone(), payers[1].clone(), inner.clone()];
        assert_eq!(
            verify_funding(rng, &top, &adjuncts, &[0, 0, 0, 0], None),
            result
        );
    }
}

#[test]
fn claim_rebuild_and_replay() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, pool, payers) = payers(rng, &[7, 5, 6]);
    let (claim, payout) = seed_bundle(rng, &wallet, pool.anchor(), -4);
    let (seed, _) = seed_bundle(rng, &wallet, pool.anchor(), 0);
    let inner = aggregate(rng, claim.clone(), &payers[..1]);
    let mut top = aggregate(rng, seed.clone(), &payers[1..2]);
    top.stamp = ProofStamp::merge(
        rng,
        merge_side(&top, &[payers[1].as_dyn()]),
        merge_side(&inner, &[payers[0].as_dyn()]),
    )
    .unwrap();
    assert_eq!(
        verify_funding(
            rng,
            &top,
            &[payers[0].clone(), payers[1].clone(), inner],
            &[0, 0, 0, 0],
            None
        ),
        Ok(8)
    );
    let rebuilt = aggregate(rng, seed, &payers[..2]);
    assert_eq!(
        verify_funding(rng, &rebuilt, &payers[..2], &[0, 0, 0], None),
        Ok(12)
    );
    let cm = Tachygram::from(payout.commitment());
    assert!(top.stamp.tachygrams.contains(&cm));
    assert!(!rebuilt.stamp.tachygrams.contains(&cm));
    assert!(!rebuilt.is_covering(&[payers[0].as_dyn(), payers[1].as_dyn(), claim.as_dyn()]));

    // A distinct transaction body republishes the same opening and payout.
    let plan = bundle::Plan::new(
        vec![],
        vec![],
        Note {
            value: zat(0),
            ..payout
        },
    )
    .with_memo(vec![1]);
    let signed = plan
        .sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap();
    let replay_body = signed.stamp((claim.stamp.clone(), claim.fee_value));
    assert_ne!(replay_body.commitment(), claim.commitment());
    let replay = aggregate(rng, replay_body, &payers[2..]);
    assert_eq!(
        verify_funding(rng, &replay, &payers[2..], &[0, 0], None),
        Ok(2)
    );
    assert_eq!(
        top.stamp
            .tachygrams
            .intersection(&replay.stamp.tachygrams)
            .copied()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([cm])
    );
    // Block replay verification against the previous two epochs' published sets.
    let recent_epochs = [BTreeSet::new(), top.stamp.tachygrams.clone()];
    assert!(
        !recent_epochs
            .iter()
            .all(|recent| recent.is_disjoint(&replay.stamp.tachygrams))
    );
    assert!(
        recent_epochs
            .iter()
            .all(|recent| recent.is_disjoint(&payers[2].stamp.tachygrams))
    );
}

#[test]
fn claim_cannot_exceed_group_allowances() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, pool, payers) = payers(rng, &[7, 5]);
    for (claim, expected) in [(12, Ok(0)), (13, Err("group funding"))] {
        let (seed, _) = seed_bundle(rng, &wallet, pool.anchor(), -claim);
        let top = aggregate(rng, seed, &payers);
        assert_eq!(
            verify_funding(rng, &top, &payers, &[0, 0, 0], None),
            expected
        );
    }
}

#[test]
fn distinct_fees_at_one_commitment_need_separate_proofs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, pool, payers) = payers(rng, &[10]);
    let max_fee = wallet.random_note(0);
    let claims = [(1, -4), (2, -5)].map(|(memo, fee)| {
        let plan = bundle::Plan::new(vec![], vec![], max_fee).with_memo(vec![memo]);
        let signed = plan
            .sign(
                rng,
                &mock_sighash(plan.commitment().unwrap()),
                &wallet.sk.derive_auth_private(),
            )
            .unwrap();
        signed.stamp(
            plan.stamp_plan(pool.anchor(), fee_value(fee))
                .prove(rng, &wallet.pak, vec![])
                .unwrap(),
        )
    });
    assert_eq!(claims[0].fee_max_commitment, claims[1].fee_max_commitment);
    assert_ne!(claims[0].commitment(), claims[1].commitment());
    let adjuncts = [payers[0].clone(), claims[1].clone()];
    let top = aggregate(rng, claims[0].clone(), &adjuncts);
    assert_eq!(
        verify_funding(rng, &top, &adjuncts, &[0, 0, 0], None),
        Ok(1)
    );
    let incomplete = aggregate(rng, claims[0].clone(), &payers);
    let published: Vec<_> = iter::once(&top)
        .chain(&adjuncts)
        .flat_map(|bundle| {
            bundle
                .descriptors()
                .map(|descriptor| descriptor.digest().unwrap())
                .chain([bundle.fee_descriptor().digest().unwrap()])
        })
        .collect();
    assert!(top.verify_proof(rng, &published).unwrap());
    assert!(!incomplete.verify_proof(rng, &published).unwrap());
}

#[test]
fn funding_rejects_cross_pool_double_use() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, pool, payers) = payers(rng, &[10]);
    assert_eq!(payers[0].value_balance, fee_value(0));
    assert_eq!(verify_funding(rng, &payers[0], &[], &[-10], None), Ok(0));
    let (claim, _) = seed_bundle(rng, &wallet, pool.anchor(), -10);
    let top = aggregate(rng, claim, &payers);
    assert_eq!(
        verify_funding(rng, &top, &payers, &[0, -10], None),
        Err("group funding")
    );
    // Part of the fee can fund an other-pool output, reducing q accordingly.
    assert_eq!(verify_funding(rng, &top, &payers, &[4, -4], None), Ok(0));
}

#[test]
fn funding_requires_each_transaction_to_balance() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, pool, payers) = payers(rng, &[10]);
    let (plan, signed, _) = wallet.signed(
        rng,
        vec![],
        vec![wallet.random_note(0)],
        wallet.random_note(10),
    );
    let unfunded = signed.stamp(
        plan.stamp_plan(pool.anchor(), fee_value(10))
            .prove(rng, &wallet.pak, vec![])
            .unwrap(),
    );
    assert_eq!(verify_funding(rng, &unfunded, &[], &[0], None), Ok(0));
    let (claim, _) = seed_bundle(rng, &wallet, pool.anchor(), -1);
    let top = aggregate(rng, claim.clone(), slice::from_ref(&unfunded));
    assert_eq!(
        verify_funding(rng, &top, slice::from_ref(&unfunded), &[0, 0], None),
        Err("group funding")
    );
    assert_eq!(
        verify_funding(rng, &top, &[unfunded], &[0, 10], None),
        Ok(9)
    );
    let invalid_transaction = aggregate(rng, claim, &payers);
    assert_eq!(
        verify_funding(rng, &invalid_transaction, &payers, &[-1, 0], None),
        Err("transaction balance")
    );
    assert_eq!(
        verify_funding(rng, &payers[0], &[], &[-11], None),
        Err("transaction balance")
    );
    assert_eq!(
        verify_funding(rng, &payers[0], &[], &[i128::MAX], None),
        Err("overflow")
    );
}

#[test]
fn funding_is_group_local() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, pool, payers) = payers(rng, &[7, 5]);
    let (seed, _) = seed_bundle(rng, &wallet, pool.anchor(), -9);
    let top = aggregate(rng, seed, &payers[..1]);
    assert_eq!(
        verify_funding(rng, &top, &payers[..1], &[0, 0], None),
        Err("group funding")
    );
    assert_eq!(verify_funding(rng, &payers[1], &[], &[0], None), Ok(5));
    // Repointing a surplus transaction does not add it to the proof.
    assert_eq!(
        verify_funding(rng, &top, &payers, &[0, 0, 0], None),
        Err("aggregate")
    );
}

#[test]
fn self_funded_claims_reduce_deficits() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, pool, payers) = payers(rng, &[6]);
    let (claim, _) = seed_bundle(rng, &wallet, pool.anchor(), -10);
    assert_eq!(verify_funding(rng, &claim, &[], &[10], None), Ok(0));
    assert_eq!(verify_funding(rng, &claim, &[], &[11], None), Ok(1));
    assert_eq!(
        verify_funding(rng, &claim, &[], &[9], None),
        Err("group funding")
    );
    let top = aggregate(rng, claim.clone(), &payers);
    assert_eq!(verify_funding(rng, &top, &payers, &[4, 0], None), Ok(0));
    let (implicit, _) = seed_bundle(rng, &wallet, pool.anchor(), 0);
    let implicit_top = aggregate(rng, claim, slice::from_ref(&implicit));
    assert_eq!(
        verify_funding(rng, &implicit_top, &[implicit], &[0, 100], None),
        Err("group funding")
    );
}

#[test]
fn signed_fees_enter_pool_and_coinbase_accounting() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (wallet, pool, payers) = payers(rng, &[7, 5]);
    let (claim, payout) = seed_bundle(rng, &wallet, pool.anchor(), -9);
    let top = aggregate(rng, claim, &payers);
    let fees = verify_funding(rng, &top, &payers, &[0, 0, 0], None).unwrap();
    assert_eq!(fees, 3);
    let outflow: i128 = iter::once(&top)
        .chain(&payers)
        .map(|bundle| {
            let decoded = round_trip(bundle);
            i128::from(decoded.value_balance)
                .checked_add(i128::from(decoded.fee_value))
                .unwrap()
        })
        .sum();
    assert_eq!(outflow, 12 - i128::from(payout.value));
    let subsidy = 20i128;
    for (fee, maximum) in [(0i64, 4), (2, 4)] {
        for (output, accepted) in [(19 + fee, true), (20 + fee, false)] {
            let max_note = wallet.random_note(maximum);
            let (plan, signed, _) = wallet.signed(
                rng,
                vec![],
                vec![wallet.random_note(output.cast_unsigned())],
                max_note,
            );
            let coinbase_body = signed.stamp(
                plan.stamp_plan(pool.anchor(), fee_value(fee))
                    .prove(rng, &wallet.pak, vec![])
                    .unwrap(),
            );
            let coinbase = round_trip(&coinbase_body);
            assert_eq!(verify_funding(rng, &coinbase, &[], &[0], Some(0)), Ok(0));
            let emission = i128::from(coinbase.value_balance)
                .checked_add(i128::from(coinbase.fee_value))
                .unwrap()
                .checked_neg()
                .unwrap();
            assert_eq!(emission <= subsidy.checked_add(fees).unwrap(), accepted);
            assert_eq!(
                emission,
                i128::from(output) + i128::from(maximum) - i128::from(fee)
            );
        }
    }
    let (unfunded_claim, _) = seed_bundle(rng, &wallet, pool.anchor(), -8);
    let unfunded_top = aggregate(rng, unfunded_claim, &payers);
    // Payer 7 is designated coinbase and contributes no allowance; only 5 remains.
    assert_eq!(
        verify_funding(rng, &unfunded_top, &payers, &[0, 0, 0], Some(1)),
        Err("group funding")
    );
}
