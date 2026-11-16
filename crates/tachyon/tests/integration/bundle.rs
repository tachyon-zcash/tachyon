extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString as _,
    vec,
    vec::Vec,
};
use core::{assert_matches, cmp::Reverse, mem};

use corez::io;
use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use rand::{SeedableRng as _, rngs::StdRng};
use udon::curve::Projective as _;
use zcash_tachyon::{
    BlockHeight, SignatureError, Tachygram, action,
    bundle::{Plan, PlanError, Signature},
    constants::MAX_MONEY,
    digest::blake2b,
    effect,
    entropy::ActionEntropy,
    keys::private,
    pasta::Eq,
    stamp::{self, AggregateId, PointerStamp, ProofStamp, ProveError},
    value, *,
};

use super::fixtures::application;
use crate::fixtures::{
    mock_sighash, mock_wtxid,
    pool::PoolSim,
    stamp_coverage,
    wallet::{WalletSim, alice, entry_spends, merged, output_plan, shared_sk, spend, zero_action},
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
                .map(|&amount| output_plan(rng, wallet.random_note(amount)).2)
                .collect(),
            wallet.random_note(0),
        );
        let sighash = mock_sighash(plan.commitment().unwrap());
        let signed = plan.sign(rng, &sighash, &ask).unwrap();
        signed.verify_signatures(&sighash).unwrap();
        plan.apply_signatures(rng, &sighash, signed.action_sigs.into_iter().collect())
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
        .action_sigs
        .into_iter()
        .map(|(_, sig)| sig)
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
    let app = &application();
    let (_, original) = spend(app);
    for edited in [
        {
            let mut permuted = original.clone();
            permuted.action_sigs.swap(0, 1);
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
            action_sigs: vec![],
            value_balance: value::Balance::try_from(value_balance).unwrap(),
            cv_feemax: max_fee_note.cv_feemax(),
            binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
            memo: Vec::new(),
            stamp: PointerStamp {
                wtxid: AggregateId::try_from([0x11u8; 64]).unwrap(),
                fee: value::Positive::ZERO,
                tachygrams: stamp::Tachygrams {
                    pairs: vec![],
                    fee_change: max_fee_note.commitment().into(),
                },
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
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(1000);
    let pool = PoolSim::shared();
    let spendable = wallet.spendable_init(app, pool, &note, BlockHeight(1));
    let anchor = spendable.data().2;
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let plan = action::Plan::spend(note, theta, rcv, |alpha| {
        wallet.pak.ak.derive_action_public(&alpha)
    });
    let descriptor = plan.descriptor();
    let secret = wallet.note_secret(app, note);
    let max_fee_note = wallet.random_note(0);
    let cv_feemax = max_fee_note.cv_feemax();
    let honest_stamp = Plan::new(vec![plan], vec![], max_fee_note)
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(rng, app, &wallet.pak, vec![(secret, spendable, vec![])])
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
    let binding_sig = Plan::new(vec![plan, plan], vec![], max_fee_note)
        .derive_bsk_private()
        .sign(rng, &sighash);
    let bundle = Bundle {
        action_sigs: vec![(descriptor, sig), (descriptor, sig)],
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
                    fee_change: honest_stamp.tachygrams.fee_change,
                }],
            ),
            tachygrams: stamp::Tachygrams {
                pairs: vec![honest_stamp.tachygrams.pairs[0]; 2],
                fee_change: honest_stamp.tachygrams.fee_change,
            },
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
        .actions()
        .map(|decoded_action| decoded_action.digest().unwrap())
        .chain([decoded.fee_descriptor().digest().unwrap()])
        .collect();
    assert!(!decoded.verify_proof(rng, app, &digests).unwrap());

    assert_matches!(
        decoded.verify(
            rng,
            app,
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
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let [(_, autonome_a), (_, autonome_b), (_, mut becomes_based)] = entry_spends(app);

    let sighash = mock_sighash(becomes_based.commitment());

    let based_descriptors = becomes_based.action_tachygrams().collect();
    let descriptors_a: BTreeMap<_, _> = autonome_a.action_tachygrams().collect();
    let descriptors_b: BTreeMap<_, _> = autonome_b.action_tachygrams().collect();

    let innocent_descriptors: BTreeMap<_, _> = descriptors_a
        .iter()
        .chain(&descriptors_b)
        .map(|(&desc, &pair)| (desc, pair))
        .collect();
    let fees_a = BTreeSet::from([autonome_a.fee_descriptor()]);
    let fees_b = BTreeSet::from([autonome_b.fee_descriptor()]);
    let innocent_fees = fees_a.union(&fees_b).copied().collect();
    let innocent_stamp = merged(app, &autonome_a, &autonome_b).stamp;

    let based_fees = BTreeSet::from([becomes_based.fee_descriptor()]);
    let based_stamp = becomes_based
        .stamp
        .merge(
            rng,
            app,
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
        .verify(rng, app, &sighash, &wtxid_bytes, &adjuncts)
        .unwrap();

    {
        let mut edited = becomes_based.clone();
        let mut adjunct = adjunct_a.clone();
        mem::swap(
            &mut edited.stamp.tachygrams.pairs[0].1,
            &mut adjunct.stamp.tachygrams.pairs[0].1,
        );
        assert_matches!(
            edited.verify(rng, app, &sighash, &wtxid_bytes, &[&adjunct, &adjunct_b]),
            Err(VerificationError::Disproved)
        );
    }
    {
        let mut edited = becomes_based.clone();
        let mut adjunct = adjunct_a.clone();
        mem::swap(
            &mut edited.stamp.tachygrams.fee_change,
            &mut adjunct.stamp.tachygrams.fee_change,
        );
        assert_matches!(
            edited.verify(rng, app, &sighash, &wtxid_bytes, &[&adjunct, &adjunct_b]),
            Err(VerificationError::Disproved)
        );
    }

    assert_matches!(
        becomes_based.verify(rng, app, &sighash, &[0x5au8; 64], &adjuncts),
        Err(VerificationError::Pointers(
            VerifyPointersError::AdjunctPointerMismatch
        ))
    );
    assert_matches!(
        becomes_based.verify(rng, app, &sighash, &wtxid_bytes, &adjuncts[..1]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::StampActionsMismatch
        ))
    );
    assert_matches!(
        becomes_based.verify(
            rng,
            app,
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
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, bundle) = spend(app);
    let sighash = mock_sighash(bundle.commitment());
    let wtxid: [u8; 64] = mock_wtxid(&bundle).into();
    bundle.verify(rng, app, &sighash, &wtxid, &[]).unwrap();

    let mut binding_bytes = Vec::new();
    bundle.binding_sig.write(&mut binding_bytes).unwrap();
    binding_bytes[0] ^= 0xFF;
    let mut bad_binding = bundle.clone();
    bad_binding.binding_sig = Signature::read(&mut binding_bytes.as_slice()).unwrap();
    assert_matches!(
        bad_binding.verify(rng, app, &sighash, &wtxid, &[]),
        Err(VerificationError::Signatures(SignatureError::Binding(_)))
    );

    let mut action_bytes = Vec::new();
    bundle.action_sigs[0].1.write(&mut action_bytes).unwrap();
    action_bytes[0] ^= 0xFF;
    let bad_sig = action::Signature::read(&mut action_bytes.as_slice()).unwrap();
    let mut bad_action = bundle;
    bad_action.action_sigs[0].1 = bad_sig;
    assert_matches!(
        bad_action.verify(rng, app, &sighash, &wtxid, &[]),
        Err(VerificationError::Signatures(SignatureError::Action(sig))) if sig == bad_sig
    );
}

#[test]
fn autonome_verify_rejects_exchanged_tachygrams() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, mut bundle) = spend(app);
    let (first, second) = (
        bundle.stamp.tachygrams.pairs[0],
        bundle.stamp.tachygrams.pairs[1],
    );
    bundle.stamp.tachygrams.pairs[0] = (first.0, second.1);
    bundle.stamp.tachygrams.pairs[1] = (second.0, first.1);
    assert_matches!(
        bundle.verify(
            rng,
            app,
            &mock_sighash(bundle.commitment()),
            &mock_wtxid(&bundle).into(),
            &[],
        ),
        Err(VerificationError::Disproved)
    );
}

#[test]
fn prove_rejects_a_note_output_twice_under_different_thetas() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let note = wallet.random_note(200);
    let anchor = Anchor::random(rng);
    let outputs = [(), ()].map(|()| output_plan(rng, note).2).to_vec();
    let bundle_plan = Plan::new(vec![], outputs, wallet.random_note(0));
    assert_matches!(
        bundle_plan
            .stamp_plan(anchor, value::Positive::ZERO)
            .prove(rng, app, &wallet.pak, vec![]),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err))) if err.to_string()
            == "ActionMerge: merged tachygram set must be the product of left and right tachygram sets"
    );
}

#[test]
fn verify_rejects_a_repeated_tachygram_pair() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, mut bundle) = spend(app);
    bundle.stamp.tachygrams.pairs[1] = bundle.stamp.tachygrams.pairs[0];
    assert_matches!(
        bundle.verify(
            rng,
            app,
            &mock_sighash(bundle.commitment()),
            &mock_wtxid(&bundle).into(),
            &[],
        ),
        Err(VerificationError::Coverage(
            VerifyCoverageError::DuplicateTachygrams
        ))
    );
}

#[test]
fn stamped_bundle_round_trips() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, stamped) = spend(app);
    let mut buf = Vec::new();
    stamped.write(&mut buf).unwrap();
    let decoded = Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*buf).unwrap();
    assert_eq!(
        TachyonBundle::read(&*buf).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(decoded.actions().eq(stamped.actions()));
    assert_eq!(decoded.value_balance, stamped.value_balance);
    assert_eq!(decoded.stamp.anchor, stamped.stamp.anchor);
    assert_eq!(
        decoded.stamp.tachygrams.fee_change,
        stamped.stamp.tachygrams.fee_change
    );
    decoded
        .verify(
            rng,
            app,
            &mock_sighash(decoded.commitment()),
            &mock_wtxid(&decoded).into(),
            &[],
        )
        .unwrap();
    let compressed = Bundle {
        stamp: stamped.stamp.compress(rng, app).unwrap(),
        action_sigs: stamped.action_sigs,
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
    assert!(block.actions().eq(decoded.actions()));
    assert_eq!(
        block.stamp.tachygrams.fee_change,
        decoded.stamp.tachygrams.fee_change
    );
    assert_eq!(TachyonBundle::read(&*bytes).unwrap(), erased);
    Bundle::<PointerStamp>::try_from(erased).unwrap_err();
    let sighash = mock_sighash(block.commitment());
    let wtxid = mock_wtxid(&block).into();
    block.verify(rng, app, &sighash, &wtxid, &[]).unwrap();
    block.stamp.anchor = Anchor::random(rng);
    assert_matches!(
        block.verify(rng, app, &sighash, &wtxid, &[]),
        Err(VerificationError::Disproved)
    );
}

#[test]
fn read_preserves_action_order() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);

    let note_a = wallet.random_note(200);
    let note_b = wallet.random_note(300);
    let (rcv_a, theta_a, plan_a) = output_plan(rng, note_a);
    let (rcv_b, theta_b, plan_b) = output_plan(rng, note_b);
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
    let action_sigs = items
        .iter()
        .map(|item| {
            let sig = private::ActionSigningKey::new(&item.1).sign(rng, &sighash);
            (item.0, sig)
        })
        .collect();
    let pairs = items
        .iter()
        .map(|_| (Tachygram::random(rng), Tachygram::random(rng)))
        .collect();
    let binding_sig = Plan::new(vec![], vec![plan_a, plan_b], max_fee_note)
        .derive_bsk_private()
        .sign(rng, &sighash);

    let bundle = Bundle {
        action_sigs,
        value_balance,
        cv_feemax,
        binding_sig,
        memo: Vec::new(),
        stamp: PointerStamp {
            wtxid: AggregateId::try_from([0x11u8; 64]).unwrap(),
            fee: value::Positive::ZERO,
            tachygrams: stamp::Tachygrams {
                pairs,
                fee_change: max_fee_note.commitment().into(),
            },
        },
    };

    let mut buf = Vec::new();
    bundle.write(&mut buf).unwrap();
    let decoded = Bundle::<PointerStamp>::read(&*buf).unwrap();

    assert!(bundle.actions().eq(decoded.actions()));
    decoded.verify_signatures(&sighash).unwrap();
}

#[test]
fn stripped_bundle_round_trips() {
    let app = &application();
    let wtxid = AggregateId::try_from([0x11u8; 64]).unwrap();
    let (_, stamped) = spend(app);
    let stripped = stamped.strip(wtxid);
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
        assert!(decoded.actions().eq(stripped.actions()));
        assert_eq!(
            decoded.stamp.tachygrams.fee_change,
            stripped.stamp.tachygrams.fee_change
        );
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
    let app = &application();

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

    let (_, stamped) = spend(app);
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
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, stamped) = spend(app);
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
    let mut pointer_pair = pointer.clone();
    pointer_pair.stamp.tachygrams.pairs[0] = (Tachygram::random(rng), Tachygram::random(rng));
    let mut pointer_change = pointer.clone();
    pointer_change.stamp.tachygrams.fee_change = Tachygram::random(rng);
    for edited in [pointer_pair, pointer_change] {
        assert_eq!(edited.commitment(), commitment);
        assert_ne!(edited.auth_digest(), pointer.auth_digest());
    }

    let mut coverage = stamped.clone();
    coverage.stamp.coverage[0] ^= 0x01;
    let mut fee = stamped.clone();
    fee.stamp.fee = value::Positive::try_from(u64::from(stamped.stamp.fee) + 1).unwrap();
    let mut pair = stamped.clone();
    pair.stamp.tachygrams.pairs[0] = (Tachygram::random(rng), Tachygram::random(rng));
    let mut flipped = stamped.clone();
    let (first, second) = flipped.stamp.tachygrams.pairs[0];
    flipped.stamp.tachygrams.pairs[0] = (second, first);
    let mut anchor = stamped.clone();
    anchor.stamp.anchor = Anchor::random(rng);
    let mut tachygram_set = stamped.clone();
    tachygram_set.stamp.tachygram_set =
        TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit();
    let mut proof = stamped.clone();
    proof.stamp.proof = alice(app).1.stamp.proof;
    let mut fee_change = stamped;
    fee_change.stamp.tachygrams.fee_change = Tachygram::random(rng);
    for edited in [
        coverage,
        fee,
        pair,
        flipped,
        anchor,
        tachygram_set,
        proof,
        fee_change,
    ] {
        assert_eq!(edited.commitment(), commitment);
        assert_ne!(edited.auth_digest(), auth_digest);
    }
}

#[test]
fn a_pair_verifies_in_either_order_but_not_repeated() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, mut bundle) = spend(app);
    let (first, second) = bundle.stamp.tachygrams.pairs[0];
    for (pair, repeated) in [((second, first), false), ((first, first), true)] {
        bundle.stamp.tachygrams.pairs[0] = pair;
        let mut bytes = Vec::new();
        bundle.write(&mut bytes).unwrap();
        let decoded = Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*bytes).unwrap();
        assert_eq!(decoded.stamp.tachygrams, bundle.stamp.tachygrams);
        let verified = decoded.verify(
            rng,
            app,
            &mock_sighash(decoded.commitment()),
            &mock_wtxid(&decoded).into(),
            &[],
        );
        if repeated {
            assert_matches!(
                verified,
                Err(VerificationError::Coverage(
                    VerifyCoverageError::DuplicateTachygrams
                ))
            );
        } else {
            assert_eq!(verified.unwrap(), decoded.stamp.tachygram_set);
        }
    }
}

#[test]
fn read_bounds_the_action_count() {
    let most = (ProductionRank::num_coeffs() - 2) / 2;
    for (n_actions, kind) in [
        (most, io::ErrorKind::UnexpectedEof),
        (most + 1, io::ErrorKind::InvalidData),
    ] {
        let mut bytes = vec![0x01];
        bytes.extend_from_slice(&1i64.to_le_bytes());
        CompactSize::try_from(n_actions)
            .unwrap()
            .write(&mut bytes)
            .unwrap();
        for err in [
            Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*bytes).unwrap_err(),
            TachyonBundle::read(&*bytes).unwrap_err(),
        ] {
            assert_eq!(err.kind(), kind);
            if kind == io::ErrorKind::InvalidData {
                assert_eq!(err.to_string(), "too many actions");
            }
        }
    }
}

#[test]
fn read_rejects_an_identity_tachygram_set() {
    let app = &application();
    let (_, mut bundle) = spend(app);
    bundle.stamp.tachygram_set = TachygramSetCommit::from(Eq::identity());
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).unwrap();
    for err in [
        Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*bytes).unwrap_err(),
        TachyonBundle::read(&*bytes).unwrap_err(),
    ] {
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "tachygram set commitment is the identity");
    }
}

#[test]
fn verify_covered_bounds_the_covered_tachygrams() {
    let app = &application();
    let (_, bundle) = alice(app);
    let adjunct = bundle.clone().strip(mock_wtxid(&bundle));
    // Two bundles' fee changes leave room for this many actions' pairs.
    let most = (ProductionRank::num_coeffs() - 3) / 2;
    for (n_actions, expected) in [
        (most, VerifyCoverageError::DuplicateActions),
        (most + 1, VerifyCoverageError::TooLarge),
    ] {
        let n_adjunct = n_actions - bundle.action_sigs.len();
        let mut oversized = adjunct.clone();
        oversized.action_sigs = vec![adjunct.action_sigs[0]; n_adjunct];
        oversized.stamp.tachygrams.pairs = vec![adjunct.stamp.tachygrams.pairs[0]; n_adjunct];
        assert_eq!(
            bundle
                .verify_covered(&[&oversized])
                .unwrap_err()
                .to_string(),
            expected.to_string()
        );
    }
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
                .map(|&amount| output_plan(rng, wallet.random_note(amount)).2)
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
    let app = &application();
    let mut buf = Vec::new();
    let (_, bundle) = spend(app);
    bundle.write(&mut buf).unwrap();
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
fn verify_covered_rejects_an_edited_tachygram() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (plan, stamped) = alice(app);

    let mut change = stamped.clone();
    change.stamp.tachygrams.fee_change = Tachygram::random(rng);
    assert_matches!(
        change.verify_covered(&[]),
        Err(VerifyCoverageError::WrongSet)
    );

    let wallet = WalletSim::new(shared_sk());
    let signed = plan
        .sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap();
    let mut edited = stamped.stamp.clone();
    edited.tachygrams.pairs[0].1 = Tachygram::random(rng);
    let bundle = signed.clone().stamp(edited).unwrap();
    assert_matches!(
        bundle.verify_covered(&[]),
        Err(VerifyCoverageError::WrongSet)
    );

    let mut short = stamped.stamp;
    short.tachygrams.pairs.pop();
    assert_matches!(signed.stamp(short), Err(StampError::ActionCountMismatch));
}

#[test]
fn memo_binds_the_commitment_but_not_the_auth_digest() {
    let app = &application();
    let (_, mut bundle) = spend(app);
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
    let app = &application();
    let (_, mut bundle) = spend(app);

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
        vec![output_plan(rng, wallet.random_note(200)).2],
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
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let (_, bundle) = spend(app);

    let covered = bundle.verify_covered(&[]).unwrap();

    assert_matches!(
        bundle.clone().lift(rng, app, &[], vec![]),
        Err(ProveError::MissingPcd(reason))
            if reason.to_string() == "no anchor span proof for no anchor advance"
    );

    let span = pool.anchor_span(app, BlockHeight(1)..=BlockHeight(2));

    let lifted = bundle.lift(rng, app, &[], vec![span]).unwrap();

    assert_eq!(lifted.stamp.anchor, pool.block(BlockHeight(2)).anchor());
    assert!(lifted.is_autonome());
    assert_eq!(lifted.verify_covered(&[]).unwrap(), covered);
}

#[test]
fn bundle_lift_over_an_aggregate() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch1 = EpochIndex::new(1);
    let [(_, autonome_a), (_, autonome_b), _] = entry_spends(app);
    let (_, zero) = zero_action(app, pool.entry_anchor(epoch1));

    let descriptors_a: BTreeMap<_, _> = autonome_a.action_tachygrams().collect();
    let descriptors_b: BTreeMap<_, _> = autonome_b.action_tachygrams().collect();

    let fees_a = BTreeSet::from([autonome_a.fee_descriptor()]);
    let fees_b = BTreeSet::from([autonome_b.fee_descriptor()]);
    let seed = zero.stamp.clone();
    let zero_fee = zero.fee_descriptor();
    let descs = descriptors_a
        .iter()
        .chain(&descriptors_b)
        .map(|(&desc, &pair)| (desc, pair))
        .collect();
    let fees = fees_a.union(&fees_b).copied().collect();
    let adjunct_stamp = merged(app, &autonome_a, &autonome_b).stamp;
    let innocent = Bundle {
        stamp: seed
            .merge(
                rng,
                app,
                (BTreeMap::new(), [zero_fee].into()),
                (adjunct_stamp, descs, fees),
            )
            .unwrap(),
        ..zero
    };

    let adjunct_a = autonome_a.strip(mock_wtxid(&innocent));
    let adjunct_b = autonome_b.strip(mock_wtxid(&innocent));
    innocent
        .verify(
            rng,
            app,
            &mock_sighash(innocent.commitment()),
            &mock_wtxid(&innocent).into(),
            &[&adjunct_a, &adjunct_b],
        )
        .unwrap();
    let adjuncts = [adjunct_a.as_dyn(), adjunct_b.as_dyn()];

    let first = epoch1.first_block();
    let span = pool.anchor_span(app, first..=first);

    let lifted = innocent.lift(rng, app, &adjuncts, vec![span]).unwrap();

    assert_eq!(lifted.stamp.anchor, pool.block(first).anchor());

    let (digests, tachygram_set) = lifted.verify_covered(&[&adjunct_a, &adjunct_b]).unwrap();
    assert_eq!(tachygram_set, lifted.stamp.tachygram_set);
    assert!(lifted.verify_proof(rng, app, &digests).unwrap());

    let mut bytes = Vec::new();
    lifted.write(&mut bytes).unwrap();
    let decoded = Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*bytes).unwrap();
    assert!(decoded.verify_proof(rng, app, &digests).unwrap());
    let n_actions = decoded.action_sigs.len();
    let compressed = decoded.stamp.compress(rng, app).unwrap();
    bytes.clear();
    compressed.write(&mut bytes).unwrap();
    let decoded_stamp = ProofStamp::<stamp::Compressed>::read(&*bytes, n_actions).unwrap();
    assert!(decoded_stamp.verify_proof(rng, app, digests).unwrap());
}
