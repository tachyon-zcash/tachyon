extern crate alloc;

use alloc::{collections::BTreeSet, vec, vec::Vec};
use core::assert_matches;

use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionSetPoly, Anchor, BlockHeight, Bundle, Tachygram, TachygramSetPoly, VerificationError,
    VerifyCoverageError, bundle,
    stamp::{
        UnmergeError,
        proof::transaction::{TransactionMerge, TransactionUnmerge},
    },
    value, witness,
};

use super::fixtures::application;
use crate::fixtures::{
    aggregator::{aggregated, aggregator, imported, proves, publication, raw_import, verify_on},
    mock_sighash, mock_txid,
    pool::PoolSim,
    wallet::{
        WalletSim, alice, alice_max_fee_note, bob, later_output, lifted, output_plan,
        outputs_with_fees, shared_sk,
    },
};

#[test]
fn unmerge_removes_a_divisor_across_merge_boundaries() {
    let wallet = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(wallet);
    let (_, bob) = bob(wallet);
    let [(_, carol), _, _] = outputs_with_fees(wallet);
    let (bob_txid, carol_txid) = (mock_txid(&bob), mock_txid(&carol));
    let all_three = aggregated(app, &alice, &bob)
        .merge(rng, app, imported(app, &carol), carol_txid)
        .unwrap();
    assert_eq!(
        all_three.adjuncts(),
        &BTreeSet::from([bob_txid, carol_txid])
    );

    for (divisor, adjuncts) in [
        (imported(app, &bob), vec![carol.clone()]),
        (aggregated(app, &bob, &carol), vec![]),
    ] {
        let unmerged = all_three
            .clone()
            .unmerge(rng, app, divisor, bob_txid)
            .unwrap();
        let stripped: Vec<_> = adjuncts.into_iter().map(Bundle::strip).collect();
        assert_eq!(
            unmerged.adjuncts(),
            &stripped.iter().map(mock_txid).collect()
        );
        verify_on(
            app,
            rng,
            &alice,
            unmerged,
            &stripped.iter().collect::<Vec<_>>(),
        )
        .unwrap();
    }
}

#[test]
fn unmerge_hostless_quotient_fails_coverage_on_its_host() {
    let wallet = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    let [(_, alice), (_, bob), (_, carol)] = outputs_with_fees(wallet);
    let (alice_txid, bob_txid) = (mock_txid(&alice), mock_txid(&bob));

    let on_alice = aggregated(app, &alice, &bob);
    assert_eq!(on_alice.adjuncts(), &BTreeSet::from([bob_txid]));

    let kept = on_alice
        .clone()
        .unmerge(rng, app, imported(app, &bob), bob_txid)
        .unwrap();
    assert!(kept.adjuncts().is_empty());
    verify_on(app, rng, &alice, kept, &[]).unwrap();

    let hostless = on_alice
        .clone()
        .unmerge(rng, app, imported(app, &alice), alice_txid)
        .unwrap();
    assert_eq!(hostless.adjuncts(), &BTreeSet::from([bob_txid]));
    assert_matches!(
        verify_on(app, rng, &alice, hostless, &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::WrongTachygramSet
        ))
    );

    let rehosted = imported(app, &carol)
        .merge(rng, app, on_alice, alice_txid)
        .unwrap();
    assert_eq!(rehosted.adjuncts(), &BTreeSet::from([alice_txid, bob_txid]));
    let quotient = rehosted
        .unmerge(rng, app, imported(app, &alice), alice_txid)
        .unwrap();
    assert_eq!(quotient.adjuncts(), &BTreeSet::from([bob_txid]));
    verify_on(app, rng, &carol, quotient, &[&bob.strip()]).unwrap();
}

#[test]
fn unmerge_by_a_lifted_divisor() {
    let wallet = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let (_, earlier) = alice(wallet);
    let (_, later) = later_output(wallet);
    // The wallet lifts its own transaction before publishing it.
    let lifted_bundle = lifted(wallet, &earlier, pool, BlockHeight(1)..=BlockHeight(2));
    let earlier_txid = mock_txid(&earlier);
    let dividend = aggregated(app, &later, &lifted_bundle);

    let unaligned = dividend
        .clone()
        .unmerge(rng, app, imported(app, &earlier), earlier_txid)
        .unwrap();
    assert!(!proves(
        app,
        rng,
        unaligned,
        &later.verify_covered(&[]).unwrap().0
    ));

    let quotient = dividend
        .unmerge(rng, app, imported(app, &lifted_bundle), earlier_txid)
        .unwrap();
    verify_on(app, rng, &later, quotient, &[]).unwrap();
}

#[test]
fn unmerge_by_itself_leaves_no_leaves() {
    let wallet = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(wallet);

    let quotient = imported(app, &alice)
        .unmerge(rng, app, imported(app, &alice), mock_txid(&alice))
        .unwrap();
    assert!(quotient.adjuncts().is_empty());
    let stamp = quotient.compress(rng, app).unwrap();
    assert!(stamp.verify_proof(app, &[]).unwrap());
    assert_matches!(
        publication(&alice, stamp).verify(app, &mock_sighash(alice.commitment()), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::WrongTachygramSet
        ))
    );
}

#[test]
fn unmerge_splitting_a_bundle() {
    let wallet_app = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::shared().mint_anchor();
    let (alice_plan, alice) = alice(wallet_app);
    let kept_plan = output_plan(rng, wallet.random_note(300));
    let removed_plan = alice_plan
        .iter_actions(|_| None, |plan| Some(*plan))
        .flatten()
        .next()
        .unwrap();
    let kept_descriptor = kept_plan.descriptor();

    let max_fee_note = alice_max_fee_note();
    let plan = bundle::Plan::new(vec![], vec![kept_plan, removed_plan], max_fee_note);
    let (wallet_stamp, pairs) = plan
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(rng, wallet_app, &wallet.pak, vec![])
        .unwrap();
    let signatures = plan
        .sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap();
    let whole = plan.assemble(signatures, wallet_stamp, pairs, value::Positive::ZERO);
    let kept_index = whole
        .actions
        .iter()
        .position(|action| action.descriptor == kept_descriptor)
        .unwrap();
    let kept_digest = whole.verify_covered(&[]).unwrap().0[kept_index];

    // Alice's bundle holds the removed action and the same fee leaf.
    let quotient = imported(app, &whole)
        .unmerge(rng, app, imported(app, &alice), mock_txid(&alice))
        .unwrap();
    assert!(quotient.adjuncts().is_empty());
    let stamp = quotient.compress(rng, app).unwrap();
    assert!(stamp.verify_proof(app, &[kept_digest]).unwrap());
    assert_matches!(
        publication(&whole, stamp).verify(app, &mock_sighash(whole.commitment()), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::WrongTachygramSet
        ))
    );
}

#[test]
fn unmerge_rejects_a_reproven_note_as_divisor() {
    let wallet_app = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let note = wallet.random_note(300);
    let max_fee_note = wallet.random_note(100);
    let fee = value::Positive::try_from(40u64).unwrap();
    let [original, reproven] = [(), ()].map(|()| {
        let output = output_plan(rng, note);
        let plan = bundle::Plan::new(vec![], vec![output], max_fee_note);
        let signatures = plan
            .sign(
                rng,
                &mock_sighash(plan.commitment().unwrap()),
                &wallet.sk.derive_auth_private(),
            )
            .unwrap();
        let (stamp, pairs) = plan
            .stamp_plan(anchor, fee)
            .prove(rng, wallet_app, &wallet.pak, vec![])
            .unwrap();
        plan.assemble(signatures, stamp, pairs, fee)
    });
    let (_, other) = wallet.bundle(
        wallet_app,
        anchor,
        &[],
        &[wallet.random_note(200)],
        wallet.random_note(0),
        value::Positive::ZERO,
    );
    let dividend = imported(app, &original)
        .merge(rng, app, imported(app, &other), mock_txid(&other))
        .unwrap();

    // The reproven action commits to the same note under a fresh action
    // digest, which the dividend does not hold.
    assert_matches!(
        dividend.unmerge(rng, app, imported(app, &reproven), mock_txid(&reproven)),
        Err(UnmergeError::NotADivisor)
    );
}

#[test]
fn unmerge_binds_its_sets() {
    let wallet = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(wallet);
    let (_, bob) = bob(wallet);

    let alice_members = alice
        .actions
        .iter()
        .flat_map(|action| <[Tachygram; 2]>::from(action.tachygrams))
        .chain([alice.fee_auth]);
    let bob_members = bob
        .actions
        .iter()
        .flat_map(|action| <[Tachygram; 2]>::from(action.tachygrams))
        .chain([bob.fee_auth]);
    let alice_digests = alice.verify_covered(&[]).unwrap().0;
    let bob_digests = bob.verify_covered(&[]).unwrap().0;
    let alice_actions = ActionSetPoly::try_from_roots(alice_digests.iter().copied()).unwrap();
    let bob_actions = ActionSetPoly::try_from_roots(bob_digests.iter().copied()).unwrap();
    let alice_tachygrams = TachygramSetPoly::try_from_roots(alice_members.clone()).unwrap();

    // Merge by hand under the aggregator profile.
    let (alice_pcd, bob_pcd) = (raw_import(rng, app, &alice), raw_import(rng, app, &bob));
    let (alice_bob, ()) = app
        .fuse(
            rng,
            TransactionMerge,
            witness::transaction_merge(
                (*alice_pcd.data(), *bob_pcd.data()),
                ActionSetPoly::try_from_roots(alice_digests.iter().chain(&bob_digests).copied())
                    .unwrap(),
                TachygramSetPoly::try_from_roots(alice_members.clone().chain(bob_members.clone()))
                    .unwrap(),
            ),
            alice_pcd,
            bob_pcd.clone(),
        )
        .unwrap();
    assert!(app.verify_uncompressed(&alice_bob, &mut *rng).unwrap());

    let valid = witness::transaction_unmerge(
        (*alice_bob.data(), *bob_pcd.data()),
        alice_actions,
        alice_tachygrams,
    );
    for (corrupt, expected) in [
        (
            {
                let mut corrupt = valid.clone();
                corrupt.0 = bob_actions;
                corrupt
            },
            "a substituted quotient action set",
        ),
        (
            {
                let mut corrupt = valid;
                let dropped = alice_members.clone().next().unwrap();
                corrupt.1 = TachygramSetPoly::try_from_roots(
                    alice_members
                        .filter(|&tachygram| tachygram != dropped)
                        .chain(bob_members.take(1)),
                )
                .unwrap();
                corrupt
            },
            "a quotient tachygram set with a swapped member",
        ),
    ] {
        let (forged, ()) = app
            .fuse(
                rng,
                TransactionUnmerge,
                corrupt,
                alice_bob.clone(),
                bob_pcd.clone(),
            )
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
            "{expected}"
        );
    }
}
