extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString as _,
    vec,
    vec::Vec,
};
use core::{assert_matches, cmp::Reverse};

use corez::io;
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
    stamp::{self, AggregateId, PointerStamp, ProofStamp, ProveError},
    value, *,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_autonome, build_lift_span, build_output_plan,
    build_output_stamp_with_fee, mock_sighash, mock_wtxid, random_block, random_block_with,
    shared_sk, stamp_coverage,
};

#[test]
fn sign_and_apply_signatures_verify_every_plan_shape() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    for (spends, outputs) in [
        (&[200][..], &[100][..]),
        (&[200][..], &[][..]),
        (&[][..], &[200][..]),
        (&[][..], &[][..]),
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
            wallet.random_note(0),
        );
        let sighash = mock_sighash(plan.commitment().unwrap());
        let signed = plan.sign(rng, &sighash, &ask).unwrap();
        signed.verify_signatures(&sighash).unwrap();
        let authorized = plan
            .descriptors()
            .into_iter()
            .zip(signed.actions.into_iter().map(|action| action.sig))
            .collect();
        plan.apply_signatures(rng, &sighash, authorized)
            .unwrap()
            .verify_signatures(&sighash)
            .unwrap();
    }
}

#[test]
fn apply_signatures_rejects_wrong_sig_count() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let ask = wallet.sk.derive_auth_private();
    let spend_a = spend_plan_at(rng, &wallet, &ask, 200);
    let spend_b = spend_plan_at(rng, &wallet, &ask, 100);
    let spend_c = spend_plan_at(rng, &wallet, &ask, 300);
    let plan = Plan::new(vec![spend_a, spend_b], vec![], wallet.random_note(0));
    let sighash = mock_sighash(plan.commitment().unwrap());
    let sig = ask
        .derive_action_private(
            &spend_a
                .theta
                .randomizer::<effect::Spend>(spend_a.note.commitment()),
        )
        .sign(rng, &sighash);

    for authorized in [
        BTreeMap::from([(spend_a.descriptor(), sig)]),
        BTreeMap::from([
            (spend_a.descriptor(), sig),
            (spend_b.descriptor(), sig),
            (spend_c.descriptor(), sig),
        ]),
    ] {
        assert_eq!(
            plan.apply_signatures(rng, &sighash, authorized)
                .unwrap_err(),
            PlanError::ActionSigMismatch
        );
    }
}

#[test]
fn apply_signatures_with_shuffled_sigs_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();

    let spend_a = spend_plan_at(rng, &wallet, &ask, 200);
    let spend_b = spend_plan_at(rng, &wallet, &ask, 100);
    let plan = Plan::new(vec![spend_a, spend_b], vec![], wallet.random_note(0));

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

    assert_matches!(
        bundle.verify_signatures(&mock_sighash(bundle.commitment())),
        Err(SignatureError::Action(_))
    );
}

#[test]
fn edited_bundles_fail_binding_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let original = build_autonome(rng, &wallet, 1000, 700);
    for edited in [
        {
            let mut permuted = original.clone();
            permuted.actions.swap(0, 1);
            permuted
        },
        {
            let mut tampered = original.clone();
            tampered.value_balance = value::Balance::try_from(999).unwrap();
            tampered
        },
    ] {
        assert_ne!(edited.commitment(), original.commitment());
        assert_matches!(
            edited.verify_signatures(&mock_sighash(edited.commitment())),
            Err(SignatureError::Binding(_))
        );
    }
}

#[test]
fn no_bundle_commitment_differs_from_empty_bundle() {
    let empty_plan = Plan::new(vec![], vec![], WalletSim::new(shared_sk()).random_note(0));
    assert_ne!(*blake2b::COMMIT_NO_BUNDLE, empty_plan.commitment().unwrap());
}

#[test]
fn zero_action_bundle_requires_a_zero_balance() {
    let rng = &mut StdRng::seed_from_u64(0);
    let max_fee_note = WalletSim::new(shared_sk()).random_note(0);
    let plan = Plan::new(vec![], vec![], max_fee_note);
    let sighash = mock_sighash(plan.commitment().unwrap());
    for value_balance in [0i64, 1] {
        let bundle = Bundle {
            actions: vec![],
            value_balance: value::Balance::try_from(value_balance).unwrap(),
            cv_feemax: max_fee_note.cv_feemax(),
            binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
            memo: Vec::new(),
            stamp: PointerStamp {
                wtxid: AggregateId::try_from([0x11u8; 64]).unwrap(),
                fee: value::Positive::ZERO,
            },
        };
        let mut buf = Vec::new();
        bundle.write(&mut buf).unwrap();
        if value_balance == 0 {
            bundle.verify_signatures(&sighash).unwrap();
            for decoded in [
                Bundle::<PointerStamp>::read(&*buf).unwrap(),
                Bundle::<PointerStamp>::try_from(TachyonBundle::read(&*buf).unwrap()).unwrap(),
            ] {
                assert_eq!(decoded.commitment(), bundle.commitment());
                assert_eq!(decoded.auth_digest(), bundle.auth_digest());
            }
        } else {
            assert_matches!(
                bundle.verify_signatures(&sighash),
                Err(SignatureError::Binding(_))
            );
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
    }
}

#[test]
fn duplicated_spend_cannot_inflate() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let note = wallet.random_note(200);

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 50));
    let spendable = wallet.spendable_init(rng, &note, &pool, pool.height());
    let anchor = spendable.data().2;

    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let plan = action::Plan::spend(note, theta, rcv, |alpha| {
        wallet.pak.ak.derive_action_public(&alpha)
    });
    let descriptor = plan.descriptor();
    let secret = wallet.secret_pcd(rng, note);
    let max_fee_note = wallet.random_note(0);
    let cv_feemax = max_fee_note.cv_feemax();
    let honest_stamp = Plan::new(vec![plan], vec![], max_fee_note)
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(rng, &wallet.pak, vec![(secret, spendable, vec![])])
        .unwrap();

    let doubled = 2 * i64::try_from(u64::from(note.value)).unwrap();
    let value_balance = value::Balance::try_from(doubled).unwrap();
    let action_bytes: Vec<[u8; 64]> = [descriptor, descriptor].into_iter().collect();
    let sighash = mock_sighash(blake2b::bundle_commitment(
        &blake2b::action_descriptor_digest(&action_bytes),
        doubled,
        &cv_feemax.into(),
        &blake2b::memo_digest(&[]),
    ));
    let alpha = theta.randomizer::<effect::Spend>(note.commitment());
    let sig = wallet
        .sk
        .derive_auth_private()
        .derive_action_private(&alpha)
        .sign(rng, &sighash);
    let action = Action::from((descriptor, sig));
    let binding_sig = Plan::new(vec![plan, plan], vec![], max_fee_note)
        .derive_bsk_private()
        .sign(rng, &sighash);
    let bundle = Bundle {
        actions: vec![action, action],
        value_balance,
        cv_feemax,
        binding_sig,
        memo: Vec::new(),
        stamp: ProofStamp {
            coverage: stamp_coverage(
                [descriptor, descriptor],
                &[fee::Descriptor {
                    cv_feemax,
                    v_fee: value::Positive::ZERO,
                }],
            ),
            ..honest_stamp
        },
    };

    let mut buf = Vec::new();
    bundle.write(&mut buf).unwrap();
    let decoded = Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*buf).unwrap();

    decoded
        .verify_signatures(&mock_sighash(decoded.commitment()))
        .unwrap();
    let digests: Vec<ActionDigest> = decoded
        .descriptors()
        .map(|desc| desc.digest().unwrap())
        .chain([decoded.fee_descriptor().digest().unwrap()])
        .collect();
    assert!(!decoded.verify_proof(rng, &digests).unwrap());

    assert_matches!(
        decoded.verify(
            rng,
            &mock_sighash(decoded.commitment()),
            &mock_wtxid(&decoded).into(),
            &[],
        ),
        Err(VerificationError::Coverage(
            VerifyCoverageError::DuplicateActions
        ))
    );
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
        vec![(based_spend, based_sp)],
        vec![based_output],
    );
    let autonome_a = wallet.autonome(rng, anchor, vec![(a_spend, a_sp)], vec![a_output]);
    let autonome_b = wallet.autonome(rng, anchor, vec![(b_spend, b_sp)], vec![b_output]);

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
    assert!(becomes_based.is_covering(&[&adjunct_a, &adjunct_b]));
    assert!(!becomes_based.is_covering(&[&adjunct_a]));
    assert!(!becomes_based.is_covering(&[&adjunct_a, &adjunct_b, &adjunct_a]));
    becomes_based
        .verify(rng, &sighash, &wtxid_bytes, &adjuncts)
        .unwrap();

    assert_matches!(
        becomes_based.verify(rng, &sighash, &[0x5au8; 64], &adjuncts),
        Err(VerificationError::Pointers(
            VerifyPointersError::AdjunctPointerMismatch
        ))
    );
    assert_matches!(
        becomes_based.verify(rng, &sighash, &wtxid_bytes, &adjuncts[..1]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::StampActionsMismatch
        ))
    );
    assert_matches!(
        becomes_based.verify(
            rng,
            &sighash,
            &wtxid_bytes,
            &[&adjunct_a, &adjunct_b, &adjunct_a],
        ),
        Err(VerificationError::Coverage(
            VerifyCoverageError::DuplicateActions
        ))
    );
}

#[test]
fn autonome_verify_rejects_flipped_signatures() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());
    let wtxid: [u8; 64] = mock_wtxid(&bundle).into();
    bundle.verify(rng, &sighash, &wtxid, &[]).unwrap();

    let mut binding_bytes = Vec::new();
    bundle.binding_sig.write(&mut binding_bytes).unwrap();
    binding_bytes[0] ^= 0xFF;
    let mut bad_binding = bundle.clone();
    bad_binding.binding_sig = Signature::read(&mut binding_bytes.as_slice()).unwrap();
    assert_matches!(
        bad_binding.verify(rng, &sighash, &wtxid, &[]),
        Err(VerificationError::Signatures(SignatureError::Binding(_)))
    );

    let mut action_bytes = Vec::new();
    bundle.actions[0].sig.write(&mut action_bytes).unwrap();
    action_bytes[0] ^= 0xFF;
    let bad_sig = action::Signature::read(&mut action_bytes.as_slice()).unwrap();
    let mut bad_action = bundle;
    bad_action.actions[0].sig = bad_sig;
    assert_matches!(
        bad_action.verify(rng, &sighash, &wtxid, &[]),
        Err(VerificationError::Signatures(SignatureError::Action(sig))) if sig == bad_sig
    );
}

#[test]
fn stamped_bundle_round_trips() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let stamped = build_autonome(rng, &wallet, 1000, 700);
    let mut buf = Vec::new();
    stamped.write(&mut buf).unwrap();
    let decoded = Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*buf).unwrap();
    assert_eq!(
        TachyonBundle::read(&*buf).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(decoded.actions, stamped.actions);
    assert_eq!(decoded.value_balance, stamped.value_balance);
    assert_eq!(decoded.stamp.tachygrams, stamped.stamp.tachygrams);
    assert_eq!(decoded.stamp.anchor, stamped.stamp.anchor);
    decoded
        .verify(
            rng,
            &mock_sighash(decoded.commitment()),
            &mock_wtxid(&decoded).into(),
            &[],
        )
        .unwrap();
    let compressed = Bundle {
        stamp: stamped.stamp.compress(rng).unwrap(),
        actions: stamped.actions,
        value_balance: stamped.value_balance,
        cv_feemax: stamped.cv_feemax,
        binding_sig: stamped.binding_sig,
        memo: stamped.memo,
    };
    let mut bytes = Vec::new();
    compressed.write(&mut bytes).unwrap();
    let mut erased_buf = Vec::new();
    let erased = TachyonBundle::from(compressed);
    erased.write(&mut erased_buf).unwrap();
    assert_eq!(erased_buf, bytes);
    let mut block = Bundle::<ProofStamp<stamp::Compressed>>::read(&*bytes).unwrap();
    assert_eq!(TachyonBundle::read(&*bytes).unwrap(), erased);
    Bundle::<PointerStamp>::try_from(erased).unwrap_err();
    let sighash = mock_sighash(block.commitment());
    let wtxid = mock_wtxid(&block).into();
    block.verify(rng, &sighash, &wtxid, &[]).unwrap();
    block.stamp.anchor = Anchor::random(rng);
    assert_matches!(
        block.verify(rng, &sighash, &wtxid, &[]),
        Err(VerificationError::Disproved)
    );
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
    let max_fee_note = wallet.random_note(0);
    let cv_feemax = max_fee_note.cv_feemax();
    let sighash = mock_sighash(blake2b::bundle_commitment(
        &blake2b::action_descriptor_digest(&descriptors),
        value_balance.into(),
        &cv_feemax.into(),
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
    let binding_sig = Plan::new(vec![], vec![plan_a, plan_b], max_fee_note)
        .derive_bsk_private()
        .sign(rng, &sighash);

    let bundle = Bundle {
        actions,
        value_balance,
        cv_feemax,
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
fn stripped_bundle_round_trips() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let wtxid = AggregateId::try_from([0x11u8; 64]).unwrap();
    let stripped = build_autonome(rng, &wallet, 1000, 700).strip(wtxid);
    let mut buf = Vec::new();
    stripped.write(&mut buf).unwrap();
    let mut erased_buf = Vec::new();
    TachyonBundle::from(stripped.clone())
        .write(&mut erased_buf)
        .unwrap();
    assert_eq!(erased_buf, buf);

    for decoded in [
        Bundle::<PointerStamp>::read(&*buf).unwrap(),
        Bundle::<PointerStamp>::try_from(TachyonBundle::read(&*buf).unwrap()).unwrap(),
    ] {
        assert_eq!(decoded.commitment(), stripped.commitment());
        assert_eq!(decoded.auth_digest(), stripped.auth_digest());
        assert_eq!(decoded.stamp.wtxid, wtxid);
        decoded
            .verify_signatures(&mock_sighash(decoded.commitment()))
            .unwrap();
    }

    for byte in buf.iter_mut().rev().take(64) {
        *byte = 0;
    }
    for err in [
        Bundle::<PointerStamp>::read(&*buf).unwrap_err(),
        TachyonBundle::read(&*buf).unwrap_err(),
    ] {
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            err.to_string(),
            "aggregate id is zero and refers to no aggregate"
        );
    }
}

#[test]
fn bundle_state_mismatches_are_rejected() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let buf: &[u8] = &[0x03];
    for err in [
        Bundle::<ProofStamp<stamp::Uncompressed>>::read(buf).unwrap_err(),
        Bundle::<PointerStamp>::read(buf).unwrap_err(),
        TachyonBundle::read(buf).unwrap_err(),
    ] {
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "invalid bundle state");
    }

    assert!(TachyonBundle::read(&[0x00][..]).unwrap().is_no_bundle());

    let stamped = build_autonome(rng, &wallet, 1000, 700);
    let adjunct = stamped
        .clone()
        .strip(AggregateId::try_from([0x11u8; 64]).unwrap());
    let mut stamped_buf = Vec::new();
    stamped.write(&mut stamped_buf).unwrap();
    let mut adjunct_buf = Vec::new();
    adjunct.write(&mut adjunct_buf).unwrap();
    assert_eq!(
        Bundle::<PointerStamp>::read(&*stamped_buf)
            .unwrap_err()
            .to_string(),
        "unexpected tachyonBundleState"
    );
    assert_eq!(
        Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*adjunct_buf)
            .unwrap_err()
            .to_string(),
        "unexpected tachyonBundleState"
    );
    Bundle::<ProofStamp<stamp::Compressed>>::try_from(TachyonBundle::from(adjunct)).unwrap_err();
}

#[test]
fn auth_digest_invariants() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let stamped = build_autonome(rng, &wallet, 1000, 700);
    let (commitment, auth_digest) = (stamped.commitment(), stamped.auth_digest());
    let pointer = stamped.clone().strip(mock_wtxid(&stamped));
    let repointed = stamped
        .clone()
        .strip(AggregateId::try_from([0x11u8; 64]).unwrap());
    assert_eq!(pointer.commitment(), commitment);
    assert_ne!(pointer.auth_digest(), auth_digest);
    assert_ne!(pointer.auth_digest(), repointed.auth_digest());
    let erased_pointer: TachyonBundle = pointer.clone().into();
    assert_eq!(erased_pointer.auth_digest(), pointer.auth_digest());
    let mut refeed = pointer.clone();
    refeed.stamp.fee = value::Positive::try_from(u64::from(pointer.stamp.fee) + 1).unwrap();
    assert_ne!(refeed.auth_digest(), pointer.auth_digest());

    let mut coverage = stamped.clone();
    coverage.stamp.coverage[0] ^= 0x01;
    let mut fee = stamped.clone();
    fee.stamp.fee = value::Positive::try_from(u64::from(stamped.stamp.fee) + 1).unwrap();
    let mut extra = stamped;
    extra
        .stamp
        .tachygrams
        .insert(Tachygram::from(Fp::from(7u64)));
    for edited in [coverage, fee, extra] {
        assert_eq!(edited.commitment(), commitment);
        assert_ne!(edited.auth_digest(), auth_digest);
    }
}

#[test]
fn read_rejects_noncanonical_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);
    let n = bundle.stamp.tachygrams.len();

    let mut buf = Vec::new();
    bundle.write(&mut buf).unwrap();

    let proof_len = bundle.stamp.proof.to_bytes().unwrap().len();
    let mut proof_size_prefix = Vec::new();
    CompactSize::try_from(proof_len)
        .unwrap()
        .write(&mut proof_size_prefix)
        .unwrap();
    let end = buf.len() - proof_len - proof_size_prefix.len();
    let first = end - n * 32;
    let last = end - 32;
    let (head, tail) = buf.split_at_mut(last);
    head[first..first + 32].swap_with_slice(&mut tail[..32]);

    let err = Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*buf).unwrap_err();
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
    for (spends, outputs, expected) in [
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
            wallet.random_note(0),
        );
        if let Some(balance) = expected {
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
        let decoded: i64 = Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*buf)
            .unwrap()
            .value_balance
            .into();
        assert_eq!(decoded, value_balance);
    }
    for value_balance in [max_money + 1, -max_money - 1, i64::MAX, i64::MIN] {
        buf[1..9].copy_from_slice(&value_balance.to_le_bytes());
        for err in [
            Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*buf).unwrap_err(),
            TachyonBundle::read(&*buf).unwrap_err(),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "value balance out of range");
        }
    }
}

#[test]
fn verify_tachygrams_rejects_an_edited_list() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let (stamp, output_plan, max_fee_note) =
        build_output_stamp_with_fee(rng, anchor, wallet.random_note(200));
    let bundle_plan = Plan::new(vec![], vec![output_plan], max_fee_note);
    let signed = bundle_plan
        .sign(
            rng,
            &mock_sighash(bundle_plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap();
    let dropped = *stamp.tachygrams.iter().next().unwrap();

    for (tachygrams, expected) in [
        (
            stamp
                .tachygrams
                .iter()
                .copied()
                .filter(|&tachygram| tachygram != dropped)
                .collect(),
            "stamp does not publish two tachygrams per action and one per fee",
        ),
        (
            stamp
                .tachygrams
                .iter()
                .copied()
                .filter(|&tachygram| tachygram != dropped)
                .chain([Tachygram::random(rng)])
                .collect(),
            "tachygrams do not reproduce the set commitment",
        ),
    ] {
        let bundle = signed.clone().stamp(ProofStamp {
            tachygrams,
            ..stamp.clone()
        });
        let (covered, covered_fees) = bundle.verify_coverage(&[], &[]).unwrap();
        assert_eq!(
            bundle
                .verify_tachygrams(covered.len(), covered_fees.len())
                .unwrap_err()
                .to_string(),
            expected
        );
    }
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
        assert_eq!(
            Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*buf)
                .unwrap()
                .memo,
            memo
        );
    }

    bundle.memo = vec![0x33u8; 8192];
    let mut buf = Vec::new();
    bundle.write(&mut buf).unwrap();
    buf.truncate(1024);
    let err = Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*buf).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn plan_memo_reaches_the_signed_bundle() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let memo = vec![0x7Fu8; 900];
    let bundle_plan = Plan::new(
        vec![],
        vec![build_output_plan(rng, wallet.random_note(200)).2],
        wallet.random_note(0),
    )
    .with_memo(memo.clone());
    let sighash = mock_sighash(bundle_plan.commitment().unwrap());

    let bundle = bundle_plan
        .sign(rng, &sighash, &wallet.sk.derive_auth_private())
        .unwrap();

    assert_eq!(bundle.memo, memo);
    assert_eq!(bundle.commitment(), bundle_plan.commitment().unwrap());
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
    let spendable_pcd = wallet.spendable_init(rng, &spend_note, &pool, cm_height);
    let bundle = wallet.autonome(
        rng,
        spendable_pcd.data().2,
        vec![(spend_note, spendable_pcd)],
        vec![output_note],
    );

    let descriptors = bundle.verify_coverage(&[], &[]).unwrap();

    assert_matches!(
        bundle.clone().lift(rng, &[], vec![]),
        Err(ProveError::MissingPcd(reason))
            if reason.to_string() == "no anchor span proof for no anchor advance"
    );

    pool.mine(random_block(rng, 1, 2));
    let span = build_lift_span(rng, &pool, pool.height()..=pool.height());

    let lifted = bundle.lift(rng, &[], vec![span]).unwrap();

    assert_eq!(lifted.stamp.anchor, pool.anchor());
    assert!(lifted.is_autonome());
    assert_eq!(lifted.verify_coverage(&[], &[]).unwrap(), descriptors);
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

    let max_fee_note = wallet.random_note(0);
    let fees_a = BTreeSet::from([autonome_a.fee_descriptor()]);
    let fees_b = BTreeSet::from([autonome_b.fee_descriptor()]);
    let innocent_plan = Plan::new(vec![], vec![], max_fee_note);
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
        cv_feemax: max_fee_note.cv_feemax(),
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
                        cv_feemax: max_fee_note.cv_feemax(),
                        v_fee: value::Positive::ZERO,
                    }]
                    .into(),
                ),
                (adjunct_stamp, descs, fees),
            )
            .unwrap(),
    };

    let adjunct_a = autonome_a.strip(mock_wtxid(&innocent));
    let adjunct_b = autonome_b.strip(mock_wtxid(&innocent));
    innocent
        .verify(
            rng,
            &mock_sighash(innocent.commitment()),
            &mock_wtxid(&innocent).into(),
            &[&adjunct_a, &adjunct_b],
        )
        .unwrap();
    let adjuncts = [adjunct_a.as_dyn(), adjunct_b.as_dyn()];

    pool.advance(1, |_| vec![]);
    pool.mine(random_block(rng, 1, 2));
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
                .iter()
                .map(|descriptor| descriptor.digest().unwrap()),
        )
        .collect();
    assert!(lifted.verify_proof(rng, &digests).unwrap());

    let mut bytes = Vec::new();
    lifted.write(&mut bytes).unwrap();
    let decoded = Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*bytes).unwrap();
    assert!(decoded.verify_proof(rng, &digests).unwrap());
    let compressed = decoded.stamp.compress(rng).unwrap();
    bytes.clear();
    compressed.write(&mut bytes).unwrap();
    let decoded_stamp = ProofStamp::<stamp::Compressed>::read(&*bytes).unwrap();
    assert!(decoded_stamp.verify_proof(rng, digests).unwrap());
}
