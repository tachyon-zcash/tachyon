extern crate alloc;

use alloc::collections::BTreeSet;
use core::assert_matches;

use ragu::{Rank as _, WalletRank};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, Bundle, DecompressError, Tachygram, TachygramSetBridge, TachygramSetPoly,
    stamp::{UnmergeError, proof::transaction::TransactionConvert},
    value,
};

use super::fixtures::{
    aggregator::{aggregator, raw_import},
    application, mock_sighash, mock_txid,
    wallet::{WalletSim, compressed, zero_action},
};

#[test]
fn decompress_checks_the_host_its_coverage_and_its_frame() {
    let rng = &mut StdRng::seed_from_u64(57);
    let app = aggregator();
    let wallet = &application();
    let anchor = Anchor::random(rng);
    let host = compressed(wallet, &zero_action(wallet, anchor).1);
    let owner = WalletSim::random(rng);
    let (_, signed) = owner.bundle(
        wallet,
        anchor,
        &[],
        &[],
        owner.random_note(0),
        value::Positive::ZERO,
    );
    let other = compressed(wallet, &signed);
    let sighash = mock_sighash(host.commitment());

    assert_matches!(
        host.decompress(rng, &app, &[0; 32]),
        Err(DecompressError::Signatures(_))
    );
    assert_matches!(
        {
            let mut wrong = host.clone();
            wrong.stamp.tachygram_set = other.stamp.tachygram_set;
            wrong.decompress(rng, &app, &sighash)
        },
        Err(DecompressError::Coverage(_))
    );
    let mut moved = host.clone();
    moved.stamp.anchor = Anchor::random(rng);
    assert_matches!(
        moved.decompress(rng, &app, &sighash),
        Err(DecompressError::Proof(_))
    );

    let imported = host.decompress(rng, &app, &sighash).unwrap();
    assert_eq!(imported.anchor(), anchor);
    assert!(imported.adjuncts().is_empty());
}

#[test]
fn wallet_publications_merge_and_unmerge() {
    let rng = &mut StdRng::seed_from_u64(58);
    let app = aggregator();
    let wallet = &application();
    let owner = WalletSim::random(rng);
    let anchor = Anchor::random(rng);
    let (_, signed) = owner.bundle(
        wallet,
        anchor,
        &[],
        &[owner.random_note(10)],
        owner.random_note(0),
        value::Positive::ZERO,
    );
    let left = compressed(wallet, &signed);
    let right = compressed(wallet, &zero_action(wallet, anchor).1);
    let left_work = left
        .decompress(rng, &app, &mock_sighash(left.commitment()))
        .unwrap();
    let right_work = right
        .decompress(rng, &app, &mock_sighash(right.commitment()))
        .unwrap();
    let (digests, commitment) = left.verify_covered().unwrap();
    let mut union = digests.clone();
    union.push(right.fee.digest(right.fee_auth));
    let id = mock_txid(&right);

    // The merge step equates the two anchors, so transactions at different
    // anchors merge into a proof that does not verify.
    let other_anchor = Anchor::random(rng);
    let elsewhere = compressed(wallet, &zero_action(wallet, other_anchor).1);
    let elsewhere_work = elsewhere
        .decompress(rng, &app, &mock_sighash(elsewhere.commitment()))
        .unwrap();
    let mut across = digests.clone();
    across.push(elsewhere.fee.digest(elsewhere.fee_auth));
    let mismatched = left_work
        .clone()
        .merge(rng, &app, elsewhere_work, mock_txid(&elsewhere))
        .unwrap()
        .compress(rng, &app)
        .unwrap();
    assert!(!mismatched.verify_proof(&app, &across).unwrap());

    let merged = left_work.merge(rng, &app, right_work.clone(), id).unwrap();
    assert_eq!(merged.anchor(), anchor);
    assert_eq!(merged.adjuncts(), &BTreeSet::from([id]));
    let mut published = merged.clone().compress(rng, &app).unwrap();
    assert_eq!(published.adjuncts, BTreeSet::from([id]));
    assert!(published.verify_proof(&app, &union).unwrap());
    assert!(!published.verify_proof(&app, &digests).unwrap());
    let oversized = vec![digests[0]; WalletRank::num_coeffs()];
    assert!(!published.verify_proof(&app, &oversized).unwrap());
    published.tachygram_set = commitment;
    assert!(!published.verify_proof(&app, &union).unwrap());

    let quotient = merged.unmerge(rng, &app, right_work, id).unwrap();
    assert!(quotient.adjuncts().is_empty());
    let remainder = quotient.compress(rng, &app).unwrap();
    assert_eq!(remainder.tachygram_set, commitment);
    assert!(remainder.verify_proof(&app, &digests).unwrap());
}

#[test]
fn merge_and_unmerge_keep_a_repeated_root_with_multiplicity() {
    let rng = &mut StdRng::seed_from_u64(61);
    let app = aggregator();
    let wallet = &application();
    let owner = WalletSim::random(rng);
    let anchor = Anchor::random(rng);
    let output = owner.random_note(10);
    // Two bundles output the same note, so both cover its commitment.
    let [first, second] = [(), ()].map(|()| {
        let (_, signed) = owner.bundle(
            wallet,
            anchor,
            &[],
            &[output],
            owner.random_note(0),
            value::Positive::ZERO,
        );
        compressed(wallet, &signed)
    });
    let [first_work, second_work] = [&first, &second].map(|bundle| {
        bundle
            .decompress(rng, &app, &mock_sighash(bundle.commitment()))
            .unwrap()
    });
    let roots = |bundle: &Bundle<zcash_tachyon::Autonome>| {
        let [first_member, second_member] = <[Tachygram; 2]>::from(bundle.actions[0].tachygrams);
        [first_member, second_member, bundle.fee_auth]
    };
    let shared = roots(&first)
        .into_iter()
        .filter(|root| roots(&second).contains(root))
        .count();
    assert_ne!(shared, 0);

    let id = mock_txid(&second);
    let product = first_work
        .merge(rng, &app, second_work.clone(), id)
        .unwrap();
    assert_eq!(
        product.clone().compress(rng, &app).unwrap().tachygram_set,
        TachygramSetPoly::from_iter(roots(&first).into_iter().chain(roots(&second))).commit()
    );
    let published = product
        .unmerge(rng, &app, second_work, id)
        .unwrap()
        .compress(rng, &app)
        .unwrap();
    let (digests, commitment) = first.verify_covered().unwrap();
    assert_eq!(published.tachygram_set, commitment);
    assert!(published.verify_proof(&app, &digests).unwrap());
}

#[test]
fn unmerge_refuses_a_divisor_holding_a_root_the_dividend_lacks() {
    let rng = &mut StdRng::seed_from_u64(62);
    let app = aggregator();
    let wallet = &application();
    let anchor = Anchor::random(rng);
    let owner = WalletSim::random(rng);
    let [dividend, divisor] = [(), ()].map(|()| {
        let (_, signed) = owner.bundle(
            wallet,
            anchor,
            &[],
            &[],
            owner.random_note(0),
            value::Positive::ZERO,
        );
        let bundle = compressed(wallet, &signed);
        let work = bundle
            .decompress(rng, &app, &mock_sighash(bundle.commitment()))
            .unwrap();
        (bundle, work)
    });
    assert_matches!(
        dividend
            .1
            .unmerge(rng, &app, divisor.1, mock_txid(&divisor.0)),
        Err(UnmergeError::NotADivisor)
    );
}

#[test]
fn convert_relabels_an_import_and_keeps_an_aggregator_transaction() {
    let rng = &mut StdRng::seed_from_u64(61);
    let app = aggregator();
    let anchor = Anchor::random(rng);
    let imported = raw_import(rng, &app, &zero_action(&application(), anchor).1);
    let [_, tachygrams] = imported.commitments();
    let own = TachygramSetBridge::from(app.bridge_hash(tachygrams).unwrap());
    assert_ne!(imported.data().0, own);
    let mut pcd = imported;
    // An imported wallet transaction takes the aggregator's bridge hash; an
    // aggregator transaction keeps its own.
    for _ in 0..2 {
        let commitments = pcd.commitments();
        (pcd, ()) = app
            .fuse(
                rng,
                TransactionConvert,
                (),
                pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert_eq!(*pcd.data(), (own, anchor));
        assert_eq!(pcd.commitments(), commitments);
        assert!(app.verify_uncompressed(&pcd, &mut *rng).unwrap());
    }
}

#[test]
fn untouched_wallet_import_verifies_after_aggregator_compression() {
    let rng = &mut StdRng::seed_from_u64(59);
    let app = aggregator();
    let wallet = app.context().wallet();
    let anchor = Anchor::random(rng);
    let body = compressed(wallet, &zero_action(wallet, anchor).1);
    let stamp = body
        .decompress(rng, &app, &mock_sighash(body.commitment()))
        .unwrap()
        .compress(rng, &app)
        .unwrap();
    assert!(
        stamp
            .verify_proof(&app, &body.verify_covered().unwrap().0)
            .unwrap()
    );
}
