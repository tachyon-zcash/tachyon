extern crate alloc;

use alloc::collections::BTreeSet;
use core::assert_matches;

use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, Bundle, Tachygram, TachygramSetPoly,
    stamp::{
        Compressed, Stamp, Uncompressed, UnmergeError,
        proof::{self, App},
    },
    value,
};

use super::fixtures::{
    application, mock_sighash, mock_txid,
    wallet::{WalletSim, zero_action},
};

fn publish(
    rng: &mut StdRng,
    app: &App<'_>,
    signed: Bundle<Stamp<Uncompressed>>,
) -> Bundle<Stamp<Compressed>> {
    let stamp = signed.stamp.compress(rng, app).unwrap();
    Bundle {
        stamp,
        actions: signed.actions,
        fee: signed.fee,
        fee_auth: signed.fee_auth,
        value_balance: signed.value_balance,
        binding_sig: signed.binding_sig,
        memo: signed.memo,
    }
}

#[test]
fn decompress_imports_the_frame_independently_of_host_signatures() {
    let rng = &mut StdRng::seed_from_u64(57);
    let app = proof::new_aggregator_application(rng).unwrap();
    let wallet = &application();
    let anchor = Anchor::random(rng);
    let host = publish(rng, wallet, zero_action(wallet, anchor).1);
    let owner = WalletSim::random(rng);
    let (_, signed) = owner.bundle(
        wallet,
        anchor,
        &[],
        &[],
        owner.random_note(0),
        value::Positive::ZERO,
    );
    let other = publish(rng, wallet, signed);
    let sighash = mock_sighash(host.commitment());

    let mut unsigned = host.clone();
    unsigned.binding_sig = other.binding_sig;
    unsigned.verify_signatures(&sighash).unwrap_err();
    assert_eq!(
        unsigned.decompress(rng, &app, &[]).unwrap().anchor(),
        anchor
    );
    let mut wrong = host.clone();
    wrong.fee_auth = other.fee_auth;
    wrong.decompress(rng, &app, &[]).unwrap_err();
    let mut moved = host.clone();
    moved.stamp.anchor = Anchor::random(rng);
    moved.decompress(rng, &app, &[]).unwrap_err();

    let imported = host.decompress(rng, &app, &[]).unwrap();
    assert_eq!(imported.anchor(), anchor);
    assert!(imported.adjuncts().is_empty());
}

#[test]
fn wallet_publications_merge_and_unmerge() {
    let rng = &mut StdRng::seed_from_u64(58);
    let app = proof::new_aggregator_application(rng).unwrap();
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
    let left = publish(rng, wallet, signed);
    let right = publish(rng, wallet, zero_action(wallet, anchor).1);
    let left_work = left.decompress(rng, &app, &[]).unwrap();
    let right_work = right.decompress(rng, &app, &[]).unwrap();
    let (digests, commitment) = left.verify_covered(&[]).unwrap();
    let mut union = digests.clone();
    union.push(right.fee.digest(right.fee_auth));
    let id = mock_txid(&right);

    // The merge step equates the two anchors, so transactions at different
    // anchors merge into a proof that does not verify.
    let other_anchor = Anchor::random(rng);
    let elsewhere = publish(rng, wallet, zero_action(wallet, other_anchor).1);
    let elsewhere_work = elsewhere.decompress(rng, &app, &[]).unwrap();
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
    let app = proof::new_aggregator_application(rng).unwrap();
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
        publish(rng, wallet, signed)
    });
    let [first_work, second_work] =
        [&first, &second].map(|bundle| bundle.decompress(rng, &app, &[]).unwrap());
    let roots = |bundle: &Bundle<Stamp<Compressed>>| {
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
        TachygramSetPoly::try_from_roots(roots(&first).into_iter().chain(roots(&second)))
            .unwrap()
            .commit()
    );
    let published = product
        .unmerge(rng, &app, second_work, id)
        .unwrap()
        .compress(rng, &app)
        .unwrap();
    let (digests, commitment) = first.verify_covered(&[]).unwrap();
    assert_eq!(published.tachygram_set, commitment);
    assert!(published.verify_proof(&app, &digests).unwrap());
}

#[test]
fn unmerge_refuses_a_divisor_holding_a_root_the_dividend_lacks() {
    let rng = &mut StdRng::seed_from_u64(62);
    let app = proof::new_aggregator_application(rng).unwrap();
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
        let bundle = publish(rng, wallet, signed);
        let work = bundle.decompress(rng, &app, &[]).unwrap();
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
fn untouched_wallet_import_verifies_after_aggregator_compression() {
    let rng = &mut StdRng::seed_from_u64(59);
    let app = proof::new_aggregator_application(rng).unwrap();
    let wallet = app.context().wallet();
    let anchor = Anchor::random(rng);
    let body = publish(rng, wallet, zero_action(wallet, anchor).1);
    let stamp = body
        .decompress(rng, &app, &[])
        .unwrap()
        .compress(rng, &app)
        .unwrap();
    assert!(
        stamp
            .verify_proof(&app, &body.verify_covered(&[]).unwrap().0)
            .unwrap()
    );
}
