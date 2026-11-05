extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString as _,
    vec,
    vec::Vec,
};
use core::cmp::Reverse;

use corez::io;
use ragu::PROOF_SIZE_COMPRESSED;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    BlockHeight, SignatureError, Tachygram, action,
    bundle::{Plan, PlanError, Signature},
    constants::{EPOCH_SIZE, MAX_MONEY},
    digest::blake2b,
    effect,
    entropy::ActionEntropy,
    keys::private,
    pasta::Fp,
    stamp::{AggregateId, PointerStamp, ProofStamp, ProveError},
    value, *,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_autonome, build_lift_span, build_output_plan,
    build_output_stamp_with_fee, mock_sighash, mock_wtxid, random_block, random_block_with,
    shared_sk, stamp_coverage,
};


#[test]
fn stripped_bundle_retains_signatures() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());

    let covering = build_autonome(rng, &wallet, 500, 300);
    let adjunct = bundle.strip(mock_wtxid(&covering));
    adjunct.verify_signatures(&sighash).unwrap();
}

#[test]
fn sign_signs_an_honest_plan() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let spend = spend_plan_at(rng, &wallet, &ask, 200);
    let (_rcv, _theta, output) = build_output_plan(rng, wallet.random_note(100));
    let plan = Plan::new(
        alloc::vec![spend],
        alloc::vec![output],
        WalletSim::new(shared_sk()).random_note(0),
    );

    let bundle = plan
        .sign(rng, &mock_sighash(plan.commitment().unwrap()), &ask)
        .unwrap();
    bundle
        .verify_signatures(&mock_sighash(bundle.commitment()))
        .unwrap();
}

#[test]
fn actions_signed_despite_wrong_rk_fail_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();

    let spend = spend_plan_at(rng, &wallet, &ask, 200);

    let mut output = action::Plan::output(
        wallet.random_note(100),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    let unrelated = action::Plan::output(
        wallet.random_note(50),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    output.rk = unrelated.rk;

    let plan = Plan::new(
        alloc::vec![spend],
        alloc::vec![output],
        WalletSim::new(shared_sk()).random_note(0),
    );

    let bundle = plan
        .sign(rng, &mock_sighash(plan.commitment().unwrap()), &ask)
        .unwrap();

    let err = bundle
        .verify_signatures(&mock_sighash(bundle.commitment()))
        .unwrap_err();
    let SignatureError::Action(_) = err else {
        panic!("expected SignatureError::Action, got {err:?}");
    };
}

#[test]
fn actions_signed_by_wrong_rsk_fail_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let wrong_ask = WalletSim::random(rng).sk.derive_auth_private();

    let spend = spend_plan_at(rng, &wallet, &ask, 200);
    let note = wallet.random_note(100);
    let (_rcv, _theta, output) = build_output_plan(rng, note);

    let plan = Plan::new(
        alloc::vec![spend],
        alloc::vec![output],
        WalletSim::new(shared_sk()).random_note(0),
    );

    let bundle = plan
        .sign(rng, &mock_sighash(plan.commitment().unwrap()), &wrong_ask)
        .unwrap();

    let err = bundle
        .verify_signatures(&mock_sighash(bundle.commitment()))
        .unwrap_err();
    let SignatureError::Action(_) = err else {
        panic!("expected SignatureError::Action, got {err:?}");
    };
}

#[test]
fn apply_signatures_rejects_wrong_sig_count() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let ask = wallet.sk.derive_auth_private();
    let spend_a = spend_plan_at(rng, &wallet, &ask, 200);
    let spend_b = spend_plan_at(rng, &wallet, &ask, 100);
    let spend_c = spend_plan_at(rng, &wallet, &ask, 300);
    let plan = Plan::new(
        alloc::vec![spend_a, spend_b],
        alloc::vec![],
        WalletSim::new(shared_sk()).random_note(0),
    );

    let sig_a = {
        let alpha = spend_a
            .theta
            .randomizer::<effect::Spend>(spend_a.note.commitment());
        ask.derive_action_private(&alpha)
            .sign(rng, &mock_sighash(plan.commitment().unwrap()))
    };

    let sig_b = {
        let alpha = spend_b
            .theta
            .randomizer::<effect::Spend>(spend_b.note.commitment());
        ask.derive_action_private(&alpha)
            .sign(rng, &mock_sighash(plan.commitment().unwrap()))
    };

    let sig_c = {
        let alpha = spend_c
            .theta
            .randomizer::<effect::Spend>(spend_c.note.commitment());
        ask.derive_action_private(&alpha)
            .sign(rng, &mock_sighash(plan.commitment().unwrap()))
    };

    let too_few = plan
        .apply_signatures(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            BTreeMap::from([(spend_a.descriptor(), sig_a)]),
        )
        .unwrap_err();
    assert_eq!(too_few, PlanError::ActionSigMismatch);

    let too_many = plan
        .apply_signatures(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            BTreeMap::from([
                (spend_a.descriptor(), sig_a),
                (spend_b.descriptor(), sig_b),
                (spend_c.descriptor(), sig_c),
            ]),
        )
        .unwrap_err();
    assert_eq!(too_many, PlanError::ActionSigMismatch);
}

#[test]
fn apply_signatures_with_shuffled_sigs_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();

    let spend_a = spend_plan_at(rng, &wallet, &ask, 200);
    let spend_b = spend_plan_at(rng, &wallet, &ask, 100);
    let plan = Plan::new(
        alloc::vec![spend_a, spend_b],
        alloc::vec![],
        WalletSim::new(shared_sk()).random_note(0),
    );

    let mut sigs: Vec<action::Signature> = plan
        .sign(rng, &mock_sighash(plan.commitment().unwrap()), &ask)
        .unwrap()
        .actions
        .into_iter()
        .map(|action| action.sig)
        .collect();

    sigs.reverse();
    let authorized = plan.descriptors().into_iter().zip(sigs).collect();

    let bundle = plan
        .apply_signatures(rng, &mock_sighash(plan.commitment().unwrap()), authorized)
        .unwrap();

    let err = bundle
        .verify_signatures(&mock_sighash(bundle.commitment()))
        .unwrap_err();
    let SignatureError::Action(_) = err else {
        panic!("expected SignatureError::Action, got {err:?}");
    };
}

#[test]
fn permuted_actions_change_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let original = build_autonome(rng, &wallet, 1000, 700);

    original
        .verify_signatures(&mock_sighash(original.commitment()))
        .unwrap();

    let mut permuted = original.clone();
    permuted.actions.swap(0, 1);

    assert_ne!(
        mock_sighash(original.commitment()),
        mock_sighash(permuted.commitment())
    );

    let sig_err = permuted
        .verify_signatures(&mock_sighash(permuted.commitment()))
        .unwrap_err();
    let SignatureError::Binding(_) = sig_err else {
        panic!("expected SignatureError::Binding, got {sig_err:?}");
    };
}

#[test]
fn tampered_value_balance_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let original = build_autonome(rng, &wallet, 1000, 700);

    original
        .verify_signatures(&mock_sighash(original.commitment()))
        .unwrap();

    let mut tampered = original.clone();
    tampered.value_balance = value::Balance::try_from(999).unwrap();

    let bind_err = tampered
        .verify_signatures(&mock_sighash(tampered.commitment()))
        .unwrap_err();
    let SignatureError::Binding(_) = bind_err else {
        panic!("expected SignatureError::Binding, got {bind_err:?}");
    };

    let also_err = tampered
        .verify_signatures(&mock_sighash(original.commitment()))
        .unwrap_err();
    let SignatureError::Binding(_) = also_err else {
        panic!("expected SignatureError::Binding, got {also_err:?}");
    };
}

#[test]
fn sign_and_apply_signatures_handle_one_sided_and_empty_plans() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let ask = wallet.sk.derive_auth_private();

    let spend_plan = Plan::new(
        alloc::vec![spend_plan_at(rng, &wallet, &ask, 200)],
        alloc::vec![],
        WalletSim::new(shared_sk()).random_note(0),
    );
    spend_plan
        .sign(rng, &mock_sighash(spend_plan.commitment().unwrap()), &ask)
        .unwrap()
        .verify_signatures(&mock_sighash(spend_plan.commitment().unwrap()))
        .unwrap();

    let note = wallet.random_note(200);
    let (_rcv, _theta, output) = build_output_plan(rng, note);
    let output_plan = Plan::new(
        alloc::vec![],
        alloc::vec![output],
        WalletSim::new(shared_sk()).random_note(0),
    );
    output_plan
        .sign(rng, &mock_sighash(output_plan.commitment().unwrap()), &ask)
        .unwrap()
        .verify_signatures(&mock_sighash(output_plan.commitment().unwrap()))
        .unwrap();

    let empty_plan = Plan::new(
        alloc::vec![],
        alloc::vec![],
        WalletSim::new(shared_sk()).random_note(0),
    );
    empty_plan
        .sign(rng, &mock_sighash(empty_plan.commitment().unwrap()), &ask)
        .unwrap()
        .verify_signatures(&mock_sighash(empty_plan.commitment().unwrap()))
        .unwrap();
    empty_plan
        .apply_signatures(
            rng,
            &mock_sighash(empty_plan.commitment().unwrap()),
            BTreeMap::new(),
        )
        .unwrap()
        .verify_signatures(&mock_sighash(empty_plan.commitment().unwrap()))
        .unwrap();
}

#[test]
fn no_bundle_commitment_differs_from_empty_bundle() {
    let empty_plan = Plan::new(
        alloc::vec![],
        alloc::vec![],
        WalletSim::new(shared_sk()).random_note(0),
    );
    assert_ne!(*blake2b::COMMIT_NO_BUNDLE, empty_plan.commitment().unwrap());
}

#[test]
fn zero_action_bundle_is_valid() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let covering = build_autonome(rng, &wallet, 1000, 700);

    let max_fee = wallet.random_note(0);
    let plan = Plan::new(alloc::vec![], alloc::vec![], max_fee);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let bundle = Bundle {
        actions: alloc::vec![],
        value_balance: value::Balance::ZERO,
        fee_max_commitment: max_fee.fee_blind().commit(-max_fee.value),
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        memo: Vec::new(),
        stamp: PointerStamp {
            wtxid: mock_wtxid(&covering),
            fee: value::Positive::ZERO,
        },
    };

    bundle.verify_signatures(&sighash).unwrap();
}

#[test]
fn duplicated_spend_cannot_inflate() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let note = wallet.random_note(200);

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 50));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let spendable = wallet.spendable_at(rng, &pool, &note, cm_height.epoch().next().unwrap());
    let anchor = spendable.data().2;

    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let plan = action::Plan::spend(note, theta, rcv, |alpha| {
        wallet.pak.ak.derive_action_public(&alpha)
    });
    let descriptor = plan.descriptor();
    let secret = wallet.secret_pcd(rng, note);
    let max_fee = wallet.random_note(0);
    let fee_max_commitment = max_fee.fee_blind().commit(-max_fee.value);
    let honest_stamp = Plan::new(alloc::vec![plan], alloc::vec![], max_fee)
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(rng, &wallet.pak, alloc::vec![(secret, spendable, vec![])])
        .unwrap();

    let doubled = 2 * i64::try_from(u64::from(note.value)).unwrap();
    let value_balance = value::Balance::try_from(doubled).unwrap();
    let action_bytes: Vec<[u8; 64]> = vec![descriptor, descriptor].into_iter().collect();
    let sighash = mock_sighash(blake2b::bundle_commitment(
        &blake2b::action_descriptor_digest(&action_bytes),
        doubled,
        &fee_max_commitment.into(),
        &blake2b::memo_digest(&[]),
    ));
    let alpha = theta.randomizer::<effect::Spend>(note.commitment());
    let sig = wallet
        .sk
        .derive_auth_private()
        .derive_action_private(&alpha)
        .sign(rng, &sighash);
    let action = Action::from((descriptor, sig));
    let binding_sig = Plan::new(alloc::vec![plan, plan], alloc::vec![], max_fee)
        .derive_bsk_private()
        .sign(rng, &sighash);
    let coverage = {
        let mut desc_bytes = Vec::<[u8; 64]>::from_iter([descriptor, descriptor]);
        desc_bytes.sort_unstable();
        stamp_coverage(
            &desc_bytes,
            &[fee::Descriptor {
                max_commitment: fee_max_commitment,
                value: value::Positive::ZERO,
            }],
        )
    };
    let bundle = Bundle {
        actions: vec![action, action],
        value_balance,
        fee_max_commitment,
        binding_sig,
        memo: Vec::new(),
        stamp: ProofStamp {
            coverage,
            anchor: honest_stamp.anchor,
            tachygram_set: honest_stamp.tachygram_set,
            tachygrams: honest_stamp.tachygrams,
            proof: honest_stamp.proof,
            fee: honest_stamp.fee,
        },
    };

    let mut buf = Vec::new();
    bundle.write(&mut buf).unwrap();
    let decoded = Bundle::<ProofStamp>::read(&*buf).unwrap();

    decoded
        .verify_signatures(&mock_sighash(decoded.commitment()))
        .unwrap();
    let dup_err = decoded.verify_coverage(&[], &[]).unwrap_err();
    let VerifyCoverageError::DuplicateActions = dup_err else {
        panic!("expected DuplicateActions, got {dup_err:?}");
    };

    let digests: Vec<ActionDigest> = decoded
        .descriptors()
        .map(|desc| desc.digest().unwrap())
        .chain([decoded.fee_descriptor().digest().unwrap()])
        .collect();
    assert!(!decoded.verify_proof(rng, &digests).unwrap());

    let err = decoded
        .verify(
            rng,
            &mock_sighash(decoded.commitment()),
            &mock_wtxid(&decoded).into(),
            &[],
        )
        .unwrap_err();
    let VerificationError::Coverage(VerifyCoverageError::DuplicateActions) = err else {
        panic!("expected Coverage(DuplicateActions), got {err:?}");
    };
}

#[test]
fn verify_proof_rejects_action_shared_with_adjunct() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);

    let adjunct = bundle.clone().strip(mock_wtxid(&bundle));

    let adjunct_descs: Vec<action::Descriptor> = adjunct.descriptors().collect();
    let err = bundle
        .verify_coverage(&adjunct_descs, &[adjunct.fee_descriptor()])
        .unwrap_err();
    let VerifyCoverageError::DuplicateActions = err else {
        panic!("expected DuplicateActions, got {err:?}");
    };

    let digests: Vec<ActionDigest> = bundle
        .descriptors()
        .chain(adjunct.descriptors())
        .map(|desc| desc.digest().unwrap())
        .chain([bundle.fee_descriptor().digest().unwrap()])
        .collect();
    assert!(!bundle.verify_proof(rng, &digests).unwrap());
}

#[test]
fn verify_proof_disproves_uncovered_adjunct() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);

    let foreign = build_autonome(rng, &wallet, 500, 300);
    let adjunct = foreign.strip(mock_wtxid(&bundle));

    let digests: Vec<ActionDigest> = bundle
        .descriptors()
        .chain(adjunct.descriptors())
        .map(|desc| desc.digest().unwrap())
        .chain([bundle.fee_descriptor().digest().unwrap()])
        .collect();
    assert!(!bundle.verify_proof(rng, &digests).unwrap());
}

#[test]
fn innocent_aggregate_from_two_autonomes() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let spend_a = wallet.random_note(1000);
    let output_a = wallet.random_note(700);
    let spend_b = wallet.random_note(500);
    let output_b = wallet.random_note(200);

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(
        rng,
        &[vec![spend_a.commitment()], vec![spend_b.commitment()]],
        50,
    ));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let sp_a = wallet.spendable_at(rng, &pool, &spend_a, cm_height.epoch().next().unwrap());
    let sp_b = wallet.spendable_at(rng, &pool, &spend_b, cm_height.epoch().next().unwrap());
    let anchor_a = sp_a.data().2;
    let anchor_b = sp_b.data().2;

    let autonome_a = wallet.autonome(
        rng,
        anchor_a,
        alloc::vec![(spend_a, sp_a)],
        alloc::vec![output_a],
    );
    let autonome_b = wallet.autonome(
        rng,
        anchor_b,
        alloc::vec![(spend_b, sp_b)],
        alloc::vec![output_b],
    );

    let descriptors_a: BTreeSet<action::Descriptor> =
        autonome_a.actions.iter().map(Action::descriptor).collect();
    let descriptors_b: BTreeSet<action::Descriptor> =
        autonome_b.actions.iter().map(Action::descriptor).collect();
    let stamp_a = autonome_a.stamp.clone();
    let stamp_b = autonome_b.stamp.clone();

    let innocent = {
        let max_fee = wallet.random_note(0);
        let innocent_plan = Plan::new(alloc::vec![], alloc::vec![], max_fee);
        let innocent_sighash = mock_sighash(innocent_plan.commitment().unwrap());

        let fees_a = BTreeSet::from([autonome_a.fee_descriptor()]);
        let fees_b = BTreeSet::from([autonome_b.fee_descriptor()]);
        let seed = stamp::Plan::new(vec![], vec![], anchor_a, max_fee, value::Positive::ZERO)
            .prove(rng, &wallet.pak, vec![])
            .unwrap();
        let descs = descriptors_a.union(&descriptors_b).copied().collect();
        let fees = fees_a.union(&fees_b).copied().collect();
        let adjuncts = stamp_a
            .merge(
                rng,
                (descriptors_a, fees_a),
                (stamp_b, descriptors_b, fees_b),
            )
            .unwrap();
        let stamp = seed
            .merge(
                rng,
                (
                    BTreeSet::new(),
                    [fee::Descriptor {
                        max_commitment: max_fee.fee_blind().commit(-max_fee.value),
                        value: value::Positive::ZERO,
                    }]
                    .into(),
                ),
                (adjuncts, descs, fees),
            )
            .unwrap();

        Bundle {
            actions: alloc::vec![],
            value_balance: value::Balance::ZERO,
            fee_max_commitment: max_fee.fee_blind().commit(-max_fee.value),
            binding_sig: innocent_plan
                .derive_bsk_private()
                .sign(rng, &innocent_sighash),
            memo: Vec::new(),
            stamp,
        }
    };

    let adjuncts = [
        autonome_a.strip(mock_wtxid(&innocent)),
        autonome_b.strip(mock_wtxid(&innocent)),
    ];

    innocent
        .verify(
            rng,
            &mock_sighash(innocent.commitment()),
            &mock_wtxid(&innocent).into(),
            &adjuncts.iter().collect::<Vec<_>>(),
        )
        .unwrap();
}

#[test]
fn based_aggregate_with_two_adjuncts() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let based_spend = wallet.random_note(800);
    let based_output = wallet.random_note(400);
    let a_spend = wallet.random_note(1000);
    let a_output = wallet.random_note(700);
    let b_spend = wallet.random_note(500);
    let b_output = wallet.random_note(200);

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(
        rng,
        &[
            vec![based_spend.commitment()],
            vec![a_spend.commitment()],
            vec![b_spend.commitment()],
        ],
        50,
    ));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let spend_epoch = cm_height.epoch().next().unwrap();
    let based_sp = wallet.spendable_at(rng, &pool, &based_spend, spend_epoch);
    let a_sp = wallet.spendable_at(rng, &pool, &a_spend, spend_epoch);
    let b_sp = wallet.spendable_at(rng, &pool, &b_spend, spend_epoch);
    let anchor = based_sp.data().2;

    let mut becomes_based = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(based_spend, based_sp)],
        alloc::vec![based_output],
    );
    let autonome_a = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(a_spend, a_sp)],
        alloc::vec![a_output],
    );
    let autonome_b = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(b_spend, b_sp)],
        alloc::vec![b_output],
    );

    let sighash = mock_sighash(becomes_based.commitment());

    let based_descriptors: BTreeSet<action::Descriptor> = becomes_based
        .actions
        .iter()
        .map(Action::descriptor)
        .collect();
    let descriptors_a: BTreeSet<action::Descriptor> =
        autonome_a.actions.iter().map(Action::descriptor).collect();
    let descriptors_b: BTreeSet<action::Descriptor> =
        autonome_b.actions.iter().map(Action::descriptor).collect();

    let stamp_a = autonome_a.stamp.clone();
    let stamp_b = autonome_b.stamp.clone();

    let innocent_descriptors: BTreeSet<action::Descriptor> =
        descriptors_a.union(&descriptors_b).copied().collect();
    let fees_a = BTreeSet::from([autonome_a.fee_descriptor()]);
    let fees_b = BTreeSet::from([autonome_b.fee_descriptor()]);
    let innocent_fees = fees_a.union(&fees_b).copied().collect();
    let innocent_stamp = stamp_a
        .merge(
            rng,
            (descriptors_a, fees_a),
            (stamp_b, descriptors_b, fees_b),
        )
        .unwrap();

    let based_fees = BTreeSet::from([becomes_based.fee_descriptor()]);
    let based_stamp = becomes_based
        .stamp
        .merge(
            rng,
            (based_descriptors, based_fees),
            (innocent_stamp, innocent_descriptors, innocent_fees),
        )
        .unwrap();

    becomes_based.stamp = based_stamp;

    let wtxid = mock_wtxid(&becomes_based);
    let wtxid_bytes: [u8; 64] = wtxid.into();
    let adjunct_a = autonome_a.strip(wtxid);
    let adjunct_b = autonome_b.strip(wtxid);
    let adjuncts = [&adjunct_a, &adjunct_b];

    assert!(becomes_based.is_aggregate());
    becomes_based
        .verify(rng, &sighash, &wtxid_bytes, &adjuncts)
        .unwrap();

    {
        let foreign = [0x5au8; 64];
        let err = becomes_based
            .verify(rng, &sighash, &foreign, &adjuncts)
            .unwrap_err();
        let VerificationError::Pointers(VerifyPointersError::AdjunctPointerMismatch) = err else {
            panic!("expected AdjunctPointerMismatch, got {err:?}");
        };
    }

    {
        let err = becomes_based
            .verify(rng, &sighash, &wtxid_bytes, &adjuncts[..1])
            .unwrap_err();
        let VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch) = err else {
            panic!("expected Coverage(StampActionsMismatch), got {err:?}");
        };
    }
}

#[test]
fn autonome_verify_composes_all_checks() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());
    let wtxid: [u8; 64] = mock_wtxid(&bundle).into();

    bundle.verify(rng, &sighash, &wtxid, &[]).unwrap();

    let mut tampered = bundle.clone();
    let mut sig_bytes: Vec<u8> = Vec::new();
    tampered.binding_sig.write(&mut sig_bytes).unwrap();
    sig_bytes[0] ^= 0xFF;
    tampered.binding_sig = Signature::read(&mut sig_bytes.as_slice()).unwrap();

    let err = tampered.verify_signatures(&sighash).unwrap_err();
    let SignatureError::Binding(_) = err else {
        panic!("expected SignatureError::Binding, got {err:?}");
    };
}

#[test]
fn invalid_action_sig_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());

    let mut sig_bytes: Vec<u8> = Vec::new();
    bundle.actions[0].sig.write(&mut sig_bytes).unwrap();
    sig_bytes[0] ^= 0xFF;
    let bad_sig = action::Signature::read(&mut sig_bytes.as_slice()).unwrap();
    bundle.actions[0].sig = bad_sig;

    let err = bundle.verify_signatures(&sighash).unwrap_err();
    let SignatureError::Action(sig) = err else {
        panic!("expected SignatureError::Action, got {err:?}");
    };
    assert_eq!(sig, bad_sig);
}

#[test]
fn stamped_read_write_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let original = build_autonome(rng, &wallet, 1000, 700);
    let mut buf = Vec::new();
    original.write(&mut buf).unwrap();
    let deserialized = Bundle::<ProofStamp>::read(&*buf).unwrap();

    assert_eq!(original.actions, deserialized.actions);
    assert_eq!(original.value_balance, deserialized.value_balance);
    assert_eq!(original.stamp.tachygrams, deserialized.stamp.tachygrams);
    assert_eq!(original.stamp.anchor, deserialized.stamp.anchor);

    let sighash = mock_sighash(deserialized.commitment());
    deserialized.verify_signatures(&sighash).unwrap();
}

#[test]
fn read_preserves_action_order() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);

    let note_a = wallet.random_note(200);
    let note_b = wallet.random_note(300);
    let (rcv_a, theta_a, plan_a) = build_output_plan(rng, note_a);
    let (rcv_b, theta_b, plan_b) = build_output_plan(rng, note_b);
    let alpha_a = theta_a.randomizer::<effect::Output>(note_a.commitment());
    let alpha_b = theta_b.randomizer::<effect::Output>(note_b.commitment());
    let mut items = [
        (plan_a.descriptor(), alpha_a, rcv_a),
        (plan_b.descriptor(), alpha_b, rcv_b),
    ];
    items.sort_by_key(|item| Reverse(item.0));

    let value_balance = value::Balance::try_from(-500i64).unwrap();
    let descriptors: Vec<[u8; 64]> = items.iter().map(|item| item.0).collect();
    let max_fee = wallet.random_note(0);
    let fee_max_commitment = max_fee.fee_blind().commit(-max_fee.value);
    let sighash = mock_sighash(blake2b::bundle_commitment(
        &blake2b::action_descriptor_digest(&descriptors),
        value_balance.into(),
        &fee_max_commitment.into(),
        &blake2b::memo_digest(&[]),
    ));
    let actions: Vec<Action> = items
        .iter()
        .map(|item| {
            Action::from((
                item.0,
                private::ActionSigningKey::new(&item.1).sign(rng, &sighash),
            ))
        })
        .collect();
    let binding_sig = Plan::new(alloc::vec![], alloc::vec![plan_a, plan_b], max_fee)
        .derive_bsk_private()
        .sign(rng, &sighash);

    let bundle = Bundle {
        actions,
        value_balance,
        fee_max_commitment,
        binding_sig,
        memo: Vec::new(),
        stamp: PointerStamp {
            wtxid: AggregateId::try_from([0x11u8; 64]).unwrap(),
            fee: value::Positive::ZERO,
        },
    };

    let mut buf = Vec::new();
    bundle.write(&mut buf).unwrap();
    let decoded = Bundle::<PointerStamp>::read(&*buf).unwrap();

    assert_eq!(bundle.actions, decoded.actions);
    decoded.verify_signatures(&sighash).unwrap();
}

#[test]
fn stripped_read_write_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let covering = build_autonome(rng, &wallet, 500, 300);
    let wtxid = mock_wtxid(&covering);
    let stripped = build_autonome(rng, &wallet, 1000, 700).strip(wtxid);

    let mut buf = Vec::new();
    stripped.write(&mut buf).unwrap();
    let deserialized = Bundle::<PointerStamp>::read(&*buf).unwrap();

    assert_eq!(stripped.commitment(), deserialized.commitment());
    assert_eq!(stripped.auth_digest(), deserialized.auth_digest());
    assert_eq!(deserialized.stamp.wtxid, wtxid);
}

#[test]
fn tachyon_bundle_conversions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let stamped = build_autonome(rng, &wallet, 1000, 700);
    let adjunct = build_autonome(rng, &wallet, 1000, 700).strip(mock_wtxid(&stamped));

    let stamped_erased: TachyonBundle = stamped.into();
    Bundle::<PointerStamp>::try_from(stamped_erased).unwrap_err();

    let adjunct_erased: TachyonBundle = adjunct.into();
    Bundle::<ProofStamp>::try_from(adjunct_erased).unwrap_err();
}

#[test]
fn tachyon_bundle_wire_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    {
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let erased: TachyonBundle = stamped.clone().into();
        let mut buf = Vec::new();
        erased.write(&mut buf).unwrap();
        let decoded = TachyonBundle::read(&*buf).unwrap();
        let back = Bundle::<ProofStamp>::try_from(decoded).unwrap();

        assert_eq!(stamped.actions, back.actions);
        assert_eq!(stamped.value_balance, back.value_balance);
        assert_eq!(stamped.stamp.tachygrams, back.stamp.tachygrams);
        assert_eq!(stamped.stamp.anchor, back.stamp.anchor);
    }

    {
        let covering = build_autonome(rng, &wallet, 500, 300);
        let stripped = build_autonome(rng, &wallet, 1000, 700).strip(mock_wtxid(&covering));
        let erased: TachyonBundle = stripped.clone().into();
        let mut buf = Vec::new();
        erased.write(&mut buf).unwrap();
        let decoded = TachyonBundle::read(&*buf).unwrap();
        let back = Bundle::<PointerStamp>::try_from(decoded).unwrap();

        assert_eq!(stripped.commitment(), back.commitment());
        assert_eq!(stripped.auth_digest(), back.auth_digest());
    }
}

#[test]
fn aggregate_id_try_from_rejects_zero() {
    AggregateId::try_from([0u8; 64]).unwrap_err();
}

#[test]
fn wire_state_byte_dispatch() {
    {
        let buf: &[u8] = &[0x03];
        for err in [
            Bundle::<ProofStamp>::read(buf).unwrap_err(),
            Bundle::<PointerStamp>::read(buf).unwrap_err(),
            TachyonBundle::read(buf).unwrap_err(),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "invalid bundle state");
        }
    }

    {
        let buf: &[u8] = &[0x00];
        let decoded = TachyonBundle::read(buf).unwrap();
        assert!(decoded.is_no_bundle());
    }

    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());

        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let mut stamped_buf = Vec::new();
        stamped.write(&mut stamped_buf).unwrap();

        let adjunct = build_autonome(rng, &wallet, 1000, 700).strip(mock_wtxid(&stamped));
        let mut adjunct_buf = Vec::new();
        adjunct.write(&mut adjunct_buf).unwrap();

        let adjunct_on_stamped = Bundle::<PointerStamp>::read(&*stamped_buf).unwrap_err();
        assert_eq!(
            adjunct_on_stamped.to_string(),
            "unexpected tachyonBundleState"
        );
        let stamped_on_adjunct = Bundle::<ProofStamp>::read(&*adjunct_buf).unwrap_err();
        assert_eq!(
            stamped_on_adjunct.to_string(),
            "unexpected tachyonBundleState"
        );
    }
}

#[test]
fn read_rejects_zero_wtxid() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let covering = build_autonome(rng, &wallet, 500, 300);
    let wtxid = mock_wtxid(&covering);

    let adjunct = build_autonome(rng, &wallet, 1000, 700).strip(wtxid);

    let innocent = {
        let max_fee = wallet.random_note(0);
        let plan = Plan::new(alloc::vec![], alloc::vec![], max_fee);
        let sighash = mock_sighash(plan.commitment().unwrap());
        let bundle = Bundle {
            actions: alloc::vec![],
            value_balance: value::Balance::ZERO,
            fee_max_commitment: max_fee.fee_blind().commit(-max_fee.value),
            binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
            memo: Vec::new(),
            stamp: PointerStamp {
                wtxid,
                fee: value::Positive::ZERO,
            },
        };
        bundle
    };

    for stripped in [adjunct, innocent] {
        let mut buf = Vec::new();
        stripped.write(&mut buf).unwrap();

        for byte in buf.iter_mut().rev().take(64) {
            *byte = 0;
        }

        let adjunct_err = Bundle::<PointerStamp>::read(&*buf).unwrap_err();
        assert_eq!(adjunct_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            adjunct_err.to_string(),
            "aggregate id is zero and refers to no aggregate"
        );

        let enum_err = TachyonBundle::read(&*buf).unwrap_err();
        assert_eq!(enum_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            enum_err.to_string(),
            "aggregate id is zero and refers to no aggregate"
        );
    }
}

#[test]
fn innocent_round_trips_with_nonzero_wtxid() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let covering = build_autonome(rng, &wallet, 1000, 700);

    let max_fee = wallet.random_note(0);
    let plan = Plan::new(alloc::vec![], alloc::vec![], max_fee);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let innocent = Bundle {
        actions: alloc::vec![],
        value_balance: value::Balance::ZERO,
        fee_max_commitment: max_fee.fee_blind().commit(-max_fee.value),
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        memo: Vec::new(),
        stamp: PointerStamp {
            wtxid: mock_wtxid(&covering),
            fee: value::Positive::ZERO,
        },
    };

    let mut buf = Vec::new();
    innocent.write(&mut buf).unwrap();

    let via_adjunct = Bundle::<PointerStamp>::read(&*buf).unwrap();
    assert_eq!(innocent.commitment(), via_adjunct.commitment());
    assert_eq!(innocent.auth_digest(), via_adjunct.auth_digest());

    let decoded = TachyonBundle::read(&*buf).unwrap();
    let via_enum = Bundle::<PointerStamp>::try_from(decoded).unwrap();
    assert_eq!(innocent.commitment(), via_enum.commitment());
    assert_eq!(innocent.auth_digest(), via_enum.auth_digest());
}

#[test]
fn auth_digest_invariants() {
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let stamped = build_autonome(rng, &wallet, 1000, 700);

        let covering = build_autonome(rng, &wallet, 500, 300);
        let stripped = stamped.clone().strip(mock_wtxid(&covering));

        assert_eq!(stamped.commitment(), stripped.commitment());
        assert_ne!(stamped.auth_digest(), stripped.auth_digest());
    }

    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let autonome = build_autonome(rng, &wallet, 1000, 700);

        let covering_a = build_autonome(rng, &wallet, 500, 300);
        let covering_b = build_autonome(rng, &wallet, 800, 600);

        let stripped_aa = autonome.clone().strip(mock_wtxid(&covering_a));
        let digest_aa = stripped_aa.auth_digest();
        let stripped_bb = autonome.strip(mock_wtxid(&covering_b));
        let digest_bb = stripped_bb.auth_digest();
        assert_ne!(digest_aa, digest_bb);

        let mut stripped_fee = stripped_aa;
        stripped_fee.stamp.fee =
            value::Positive::try_from(u64::from(stripped_fee.stamp.fee) + 1).unwrap();
        assert_ne!(digest_aa, stripped_fee.auth_digest());
    }

    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let stamped_direct = stamped.auth_digest();
        let covering_wtxid = mock_wtxid(&stamped);
        let erased: TachyonBundle = stamped.into();
        assert_eq!(erased.auth_digest(), stamped_direct);

        let wallet2 = WalletSim::new(shared_sk());
        let stripped = build_autonome(rng, &wallet2, 1000, 700).strip(covering_wtxid);
        let stripped_direct = stripped.auth_digest();
        let erased_stripped: TachyonBundle = stripped.into();
        assert_eq!(erased_stripped.auth_digest(), stripped_direct);
    }

    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let baseline = stamped.auth_digest();
        let baseline_commitment = stamped.commitment();

        let mut altered_actions = stamped.clone();
        altered_actions.stamp.coverage[0] ^= 0x01;
        assert_eq!(baseline_commitment, altered_actions.commitment());
        assert_ne!(baseline, altered_actions.auth_digest());

        let mut altered_fee = stamped.clone();
        altered_fee.stamp.fee =
            value::Positive::try_from(u64::from(stamped.stamp.fee) + 1).unwrap();
        assert_eq!(baseline_commitment, altered_fee.commitment());
        assert_ne!(baseline, altered_fee.auth_digest());

        let mut extra_tachygram = stamped;
        extra_tachygram
            .stamp
            .tachygrams
            .insert(Tachygram::from(Fp::from(7u64)));
        assert_eq!(baseline_commitment, extra_tachygram.commitment());
        assert_ne!(baseline, extra_tachygram.auth_digest());
    }
}

#[test]
fn coverage_check_matches_stamp_actions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);

    let based_spend = wallet.random_note(800);
    let based_output = wallet.random_note(400);
    let a_spend = wallet.random_note(1000);
    let a_output = wallet.random_note(700);
    let b_spend = wallet.random_note(500);
    let b_output = wallet.random_note(200);

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(
        rng,
        &[
            vec![based_spend.commitment()],
            vec![a_spend.commitment()],
            vec![b_spend.commitment()],
        ],
        50,
    ));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let spend_epoch = cm_height.epoch().next().unwrap();
    let based_sp = wallet.spendable_at(rng, &pool, &based_spend, spend_epoch);
    let a_sp = wallet.spendable_at(rng, &pool, &a_spend, spend_epoch);
    let b_sp = wallet.spendable_at(rng, &pool, &b_spend, spend_epoch);
    let anchor = based_sp.data().2;

    let mut becomes_based = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(based_spend, based_sp)],
        alloc::vec![based_output],
    );
    let autonome_a = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(a_spend, a_sp)],
        alloc::vec![a_output],
    );
    let autonome_b = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(b_spend, b_sp)],
        alloc::vec![b_output],
    );

    let based_descriptors: BTreeSet<action::Descriptor> = becomes_based
        .actions
        .iter()
        .map(Action::descriptor)
        .collect();
    let descriptors_a: BTreeSet<action::Descriptor> =
        autonome_a.actions.iter().map(Action::descriptor).collect();
    let descriptors_b: BTreeSet<action::Descriptor> =
        autonome_b.actions.iter().map(Action::descriptor).collect();

    let stamp_a = autonome_a.stamp.clone();
    let stamp_b = autonome_b.stamp.clone();
    let fees_a = BTreeSet::from([autonome_a.fee_descriptor()]);
    let fees_b = BTreeSet::from([autonome_b.fee_descriptor()]);
    let innocent_fees = fees_a.union(&fees_b).copied().collect();
    let based_fees = BTreeSet::from([becomes_based.fee_descriptor()]);

    let innocent_descriptors: BTreeSet<action::Descriptor> =
        descriptors_a.union(&descriptors_b).copied().collect();
    let innocent_stamp = stamp_a
        .merge(
            rng,
            (descriptors_a, fees_a),
            (stamp_b, descriptors_b, fees_b),
        )
        .unwrap();

    let based_stamp = becomes_based
        .stamp
        .merge(
            rng,
            (based_descriptors, based_fees),
            (innocent_stamp, innocent_descriptors, innocent_fees),
        )
        .unwrap();
    becomes_based.stamp = based_stamp;

    let adjunct_a = autonome_a.strip(mock_wtxid(&becomes_based));
    let adjunct_b = autonome_b.strip(mock_wtxid(&becomes_based));

    assert!(becomes_based.is_covering(&[&adjunct_a, &adjunct_b]));

    assert!(!becomes_based.is_covering(&[&adjunct_a]));

    assert!(!becomes_based.is_covering(&[&adjunct_a, &adjunct_b, &adjunct_a]));
}

#[test]
fn read_rejects_noncanonical_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);
    let n = bundle.stamp.tachygrams.len();
    assert!(n >= 2);

    let mut buf = Vec::new();
    bundle.write(&mut buf).unwrap();

    let end = buf.len() - PROOF_SIZE_COMPRESSED;
    let first = end - n * 32;
    let last = end - 32;
    let (head, tail) = buf.split_at_mut(last);
    head[first..first + 32].swap_with_slice(&mut tail[..32]);

    let err = Bundle::<ProofStamp>::read(&*buf).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(err.to_string(), "tachygrams are not canonically sorted");
}

fn spend_plan_at(
    rng: &mut StdRng,
    wallet: &WalletSim,
    ask: &private::SpendAuthorizingKey,
    value: u64,
) -> action::Plan<effect::Spend> {
    let note = wallet.random_note(value);
    let (rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    action::Plan::spend(note, theta, rcv, |alpha| {
        ask.derive_action_private(&alpha).derive_action_public()
    })
}









#[test]
fn plan_value_balance_is_bounded_by_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let max_money = i64::try_from(MAX_MONEY).unwrap();
    for (spends, outputs, balance) in [
        (&[300][..], &[200][..], Some(100)),
        (&[MAX_MONEY][..], &[][..], Some(max_money)),
        (&[][..], &[MAX_MONEY][..], Some(-max_money)),
        (&[MAX_MONEY, MAX_MONEY][..], &[][..], None),
        (&[][..], &[MAX_MONEY, MAX_MONEY][..], None),
    ] {
        let plan = Plan::new(
            spends
                .iter()
                .map(|&amount| spend_plan_at(rng, &wallet, &ask, amount))
                .collect(),
            outputs
                .iter()
                .map(|&amount| build_output_plan(rng, wallet.random_note(amount)).2)
                .collect(),
            WalletSim::new(shared_sk()).random_note(0),
        );
        if let Some(balance) = balance {
            assert_eq!(
                plan.value_balance(),
                Ok(value::Balance::try_from(balance).unwrap())
            );
        } else {
            assert_eq!(plan.value_balance(), Err(value::OutOfRange));
            assert_eq!(plan.commitment().unwrap_err(), value::OutOfRange);
            assert_eq!(
                plan.sign(rng, &[0u8; 32], &ask).unwrap_err(),
                PlanError::BalanceOverflow
            );
        }
    }
}

#[test]
fn read_bounds_the_value_balance() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut buf = Vec::new();
    build_autonome(rng, &wallet, 1000, 700)
        .write(&mut buf)
        .unwrap();
    let max_money = i64::try_from(MAX_MONEY).unwrap();

    for value_balance in [max_money, -max_money] {
        buf[1..9].copy_from_slice(&value_balance.to_le_bytes());
        let decoded: i64 = Bundle::<ProofStamp>::read(&*buf)
            .unwrap()
            .value_balance
            .into();
        assert_eq!(decoded, value_balance);
    }
    for value_balance in [max_money + 1, -max_money - 1, i64::MAX, i64::MIN] {
        buf[1..9].copy_from_slice(&value_balance.to_le_bytes());
        for err in [
            Bundle::<ProofStamp>::read(&*buf).unwrap_err(),
            TachyonBundle::read(&*buf).unwrap_err(),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "value balance out of range");
        }
    }
}

#[test]
fn zero_action_bundle_rejects_nonzero_balance() {
    let rng = &mut StdRng::seed_from_u64(0);
    let max_fee = WalletSim::new(shared_sk()).random_note(0);
    let plan = Plan::new(alloc::vec![], alloc::vec![], max_fee);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let bundle = Bundle {
        actions: alloc::vec![],
        value_balance: value::Balance::try_from(1).unwrap(),
        fee_max_commitment: max_fee.fee_blind().commit(-max_fee.value),
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        memo: Vec::new(),
        stamp: PointerStamp {
            wtxid: AggregateId::try_from([0x42u8; 64]).unwrap(),
            fee: value::Positive::ZERO,
        },
    };
    let Err(SignatureError::Binding(_)) = bundle.verify_signatures(&sighash) else {
        panic!();
    };

    let mut buf = Vec::new();
    bundle.write(&mut buf).unwrap();
    for err in [
        Bundle::<PointerStamp>::read(&*buf).unwrap_err(),
        TachyonBundle::read(&*buf).unwrap_err(),
    ] {
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            err.to_string(),
            "bundle with no actions must have zero value balance"
        );
    }
}

#[test]
fn verify_tachygrams_rejects_wrong_arity() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(200);
    let pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let (stamp, output_plan, max_fee) = build_output_stamp_with_fee(rng, pool.anchor(), note);

    assert_eq!(stamp.tachygrams.len(), 2 + 1);

    let mut short = stamp;
    let dropped = *short.tachygrams.iter().next().unwrap();
    short.tachygrams.remove(&dropped);

    let bundle_plan = Plan::new(alloc::vec![], alloc::vec![output_plan], max_fee);
    let sighash = mock_sighash(bundle_plan.commitment().unwrap());
    let bundle = bundle_plan.sign(rng, &sighash, &ask).unwrap().stamp(short);

    let (covered, covered_fees) = bundle.verify_coverage(&[], &[]).unwrap();

    let err = bundle
        .verify_tachygrams(covered.len(), covered_fees.len())
        .unwrap_err();
    let VerifyTachygramsError::WrongArity = err else {
        panic!("expected WrongArity, got {err:?}");
    };
}

#[test]
fn verify_tachygrams_rejects_a_tampered_list() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(200);
    let pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let (stamp, output_plan, max_fee) = build_output_stamp_with_fee(rng, pool.anchor(), note);

    let mut tampered = stamp;
    let dropped = *tampered.tachygrams.iter().next().unwrap();
    tampered.tachygrams.remove(&dropped);
    tampered.tachygrams.insert(Tachygram::random(rng));

    let bundle_plan = Plan::new(alloc::vec![], alloc::vec![output_plan], max_fee);
    let sighash = mock_sighash(bundle_plan.commitment().unwrap());
    let bundle = bundle_plan
        .sign(rng, &sighash, &ask)
        .unwrap()
        .stamp(tampered);

    let (covered, covered_fees) = bundle.verify_coverage(&[], &[]).unwrap();

    let err = bundle
        .verify_tachygrams(covered.len(), covered_fees.len())
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "tachygrams do not reproduce the set commitment"
    );
}




#[test]
fn memo_binds_the_commitment_but_not_the_auth_digest() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);
    let (commitment, auth_digest) = (bundle.commitment(), bundle.auth_digest());

    bundle.memo = vec![0x5Au8; 128];
    assert_ne!(bundle.commitment(), commitment);
    assert_eq!(bundle.auth_digest(), auth_digest);

    let adjunct = bundle.clone().strip(mock_wtxid(&bundle));
    assert_eq!(adjunct.memo, bundle.memo);
    assert_eq!(adjunct.commitment(), bundle.commitment());
}

#[test]
fn memo_round_trips_and_rejects_truncation() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);

    for memo in [Vec::new(), vec![0xABu8; 1500]] {
        bundle.memo = memo.clone();
        let mut buf = Vec::new();
        bundle.write(&mut buf).unwrap();
        assert_eq!(Bundle::<ProofStamp>::read(&*buf).unwrap().memo, memo);
    }

    bundle.memo = vec![0x33u8; 8192];
    let mut buf = Vec::new();
    bundle.write(&mut buf).unwrap();
    buf.truncate(1024);
    let err = Bundle::<ProofStamp>::read(&*buf).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn plan_memo_reaches_the_signed_bundle() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(200);
    let pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let (stamp, output_plan, max_fee) = build_output_stamp_with_fee(rng, pool.anchor(), note);

    let memo = vec![0x7Fu8; 900];
    let bundle_plan =
        Plan::new(alloc::vec![], alloc::vec![output_plan], max_fee).with_memo(memo.clone());
    let sighash = mock_sighash(bundle_plan.commitment().unwrap());

    let bundle = bundle_plan.sign(rng, &sighash, &ask).unwrap().stamp(stamp);

    assert_eq!(bundle.memo, memo);
    assert_eq!(bundle_plan.commitment().unwrap(), bundle.commitment());
    bundle.verify_signatures(&sighash).unwrap();
}



#[test]
fn bundle_lift_preserves_coverage() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let spend_note = wallet.random_note(1000);
    let output_note = wallet.random_note(700);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(rng, &[vec![spend_note.commitment()]], 1));
    let cm_height = pool.height();
    let spendable_pcd = wallet.fresh_spend(rng, &pool, cm_height, &spend_note);
    let bundle = wallet.autonome(
        rng,
        spendable_pcd.data().2,
        vec![(spend_note, spendable_pcd)],
        vec![output_note],
    );

    let descriptors = bundle.verify_coverage(&[], &[]).unwrap();

    let next_a = build_autonome(rng, &wallet, 400, 300);
    let next_b = build_autonome(rng, &wallet, 500, 200);
    pool.mine_bundles(&[&next_a, &next_b]);
    let span = build_lift_span(rng, &pool, pool.height()..=pool.height());

    let lifted = bundle.lift(rng, &[], vec![span]).unwrap();

    assert_eq!(lifted.stamp.anchor, pool.anchor());
    assert!(lifted.is_autonome());
    assert_eq!(lifted.verify_coverage(&[], &[]).unwrap(), descriptors);
}

#[test]
fn bundle_lift_rejects_no_spans() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let spend_note = wallet.random_note(1000);
    let output_note = wallet.random_note(700);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(rng, &[vec![spend_note.commitment()]], 1));
    let cm_height = pool.height();
    let spendable_pcd = wallet.fresh_spend(rng, &pool, cm_height, &spend_note);
    let bundle = wallet.autonome(
        rng,
        spendable_pcd.data().2,
        vec![(spend_note, spendable_pcd)],
        vec![output_note],
    );

    let err = bundle.lift(rng, &[], vec![]).unwrap_err();
    let ProveError::MissingPcd(reason) = err else {
        panic!("expected a missing anchor span, got {err:?}");
    };
    assert_eq!(
        reason.to_string(),
        "no anchor span proof for no anchor advance"
    );
}

#[test]
fn bundle_lift_over_an_aggregate() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let spend_a = wallet.random_note(1000);
    let output_a = wallet.random_note(700);
    let spend_b = wallet.random_note(500);
    let output_b = wallet.random_note(200);

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(
        rng,
        &[vec![spend_a.commitment()], vec![spend_b.commitment()]],
        50,
    ));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE - 1) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let sp_a = wallet.spendable_at(rng, &pool, &spend_a, cm_height.epoch().next().unwrap());
    let sp_b = wallet.spendable_at(rng, &pool, &spend_b, cm_height.epoch().next().unwrap());
    let anchor = sp_a.data().2;

    let autonome_a = wallet.autonome(rng, anchor, vec![(spend_a, sp_a)], vec![output_a]);
    let autonome_b = wallet.autonome(rng, anchor, vec![(spend_b, sp_b)], vec![output_b]);

    let descriptors_a: BTreeSet<action::Descriptor> =
        autonome_a.actions.iter().map(Action::descriptor).collect();
    let descriptors_b: BTreeSet<action::Descriptor> =
        autonome_b.actions.iter().map(Action::descriptor).collect();

    let max_fee = wallet.random_note(0);
    let fees_a = BTreeSet::from([autonome_a.fee_descriptor()]);
    let fees_b = BTreeSet::from([autonome_b.fee_descriptor()]);
    let innocent_plan = Plan::new(vec![], vec![], max_fee);
    let seed = innocent_plan
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(rng, &wallet.pak, vec![])
        .unwrap();
    let descs = descriptors_a.union(&descriptors_b).copied().collect();
    let fees = fees_a.union(&fees_b).copied().collect();
    let adjunct_stamp = autonome_a
        .stamp
        .clone()
        .merge(
            rng,
            (descriptors_a, fees_a),
            (autonome_b.stamp.clone(), descriptors_b, fees_b),
        )
        .unwrap();
    let innocent = Bundle {
        actions: vec![],
        value_balance: value::Balance::ZERO,
        fee_max_commitment: max_fee.fee_blind().commit(-max_fee.value),
        binding_sig: innocent_plan
            .derive_bsk_private()
            .sign(rng, &mock_sighash(innocent_plan.commitment().unwrap())),
        memo: Vec::new(),
        stamp: seed
            .merge(
                rng,
                (
                    BTreeSet::new(),
                    [fee::Descriptor {
                        max_commitment: max_fee.fee_blind().commit(-max_fee.value),
                        value: value::Positive::ZERO,
                    }]
                    .into(),
                ),
                (adjunct_stamp, descs, fees),
            )
            .unwrap(),
    };

    let adjunct_a = autonome_a.strip(mock_wtxid(&innocent));
    let adjunct_b = autonome_b.strip(mock_wtxid(&innocent));
    let adjuncts = [adjunct_a.as_dyn(), adjunct_b.as_dyn()];

    pool.advance(1, |_| alloc::vec![]);
    let next = build_autonome(rng, &wallet, 400, 300);
    pool.mine_bundles(&[&next]);
    let span = build_lift_span(rng, &pool, pool.height()..=pool.height());

    let lifted = innocent.lift(rng, &adjuncts, vec![span]).unwrap();

    assert_eq!(lifted.stamp.anchor, pool.anchor());

    let adjunct_descs: Vec<action::Descriptor> =
        adjuncts.iter().flat_map(|adj| adj.descriptors()).collect();
    let adjunct_fee_descriptors: Vec<fee::Descriptor> =
        adjuncts.iter().map(|adj| adj.fee_descriptor()).collect();
    let (covered_descs, covered_fee_descriptors) = lifted
        .verify_coverage(&adjunct_descs, &adjunct_fee_descriptors)
        .unwrap();
    let digests: Vec<ActionDigest> = covered_descs
        .iter()
        .map(|desc| desc.digest().unwrap())
        .chain(
            covered_fee_descriptors
                .into_iter()
                .map(|descriptor| descriptor.digest().unwrap()),
        )
        .collect();
    assert!(lifted.verify_proof(rng, &digests).unwrap());
}
