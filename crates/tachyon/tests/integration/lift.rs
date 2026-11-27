extern crate alloc;

use alloc::vec;

use ragu::{
    AcceleratedProver, Application, Pcd,
    circuits::polynomials,
    pasta::Pasta,
    pcd::profile::{Aggregator, Profiled},
};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, BlockHeight, Bundle,
    stamp::proof::{HEADER_SIZE, new_aggregator_application, pool},
    value, witness,
};

use super::fixtures::{
    pool::{PoolSim, random_block},
    wallet::WalletSim,
};

/// The wallet compresses a span of `chain`, and the aggregator imports it with
/// the endpoints, members and absorbed tachygrams it reads from history.
fn import_span(
    rng: &mut StdRng,
    app: &Application<
        '_,
        Profiled<Pasta, Aggregator<HEADER_SIZE>>,
        polynomials::AggregatorRank,
        HEADER_SIZE,
        AcceleratedProver,
    >,
    chain: &PoolSim,
    first: BlockHeight,
    last: BlockHeight,
) -> Pcd<Profiled<Pasta, Aggregator<HEADER_SIZE>>, polynomials::AggregatorRank, pool::AnchorSpan> {
    let wallet = app.context().wallet();
    let span = chain.anchor_span(wallet, first..=last);
    let refreshed = wallet.rerandomize(span, &mut *rng).unwrap();
    let (frame, _) = wallet.compress(&refreshed, &mut *rng).unwrap().into_parts();

    let members = chain.anchors_in(first..=last);
    let absorbed = if members.len() == 1 {
        chain.block(first).stamps[0].1.as_slice()
    } else {
        &[]
    };
    pool::AnchorSpan::decompress(
        rng,
        app,
        &frame,
        (chain.block(first).prev, chain.block(last).anchor()),
        &members,
        absorbed,
    )
    .unwrap()
}

fn check_lift(
    rng: &mut StdRng,
    app: &Application<
        '_,
        Profiled<Pasta, Aggregator<HEADER_SIZE>>,
        polynomials::AggregatorRank,
        HEADER_SIZE,
        AcceleratedProver,
    >,
    start: Anchor,
    end: Anchor,
    spans: Vec<
        Pcd<
            Profiled<Pasta, Aggregator<HEADER_SIZE>>,
            polynomials::AggregatorRank,
            pool::AnchorSpan,
        >,
    >,
    valid: bool,
) {
    let wallet = app.context().wallet();
    let owner = WalletSim::random(rng);
    let (_, signed) = owner.bundle(
        wallet,
        start,
        &[],
        &[owner.random_note(10)],
        owner.random_note(0),
        value::Positive::ZERO,
    );
    let body = Bundle {
        stamp: signed.stamp.compress(rng, wallet).unwrap(),
        actions: signed.actions,
        fee: signed.fee,
        fee_auth: signed.fee_auth,
        value_balance: signed.value_balance,
        binding_sig: signed.binding_sig,
        memo: signed.memo,
    };
    let imported = body.decompress(rng, app, &[]).unwrap();
    let (digests, tachygrams) = body.verify_covered(&[]).unwrap();

    let unchanged = imported.lift(rng, app, vec![]).unwrap();
    assert_eq!(unchanged.anchor(), start);

    let lifted = unchanged.lift(rng, app, spans).unwrap();
    assert_eq!(lifted.anchor(), end);
    assert_eq!(lifted.adjuncts(), &body.stamp.adjuncts);
    let publication = lifted.compress(rng, app).unwrap();
    assert_eq!(publication.anchor, end);
    assert_eq!(publication.tachygram_set, tachygrams);
    assert_eq!(publication.verify_proof(app, &digests).unwrap(), valid);
}

#[test]
fn aggregator_lifts_over_imported_wallet_spans() {
    let rng = &mut StdRng::seed_from_u64(641);
    let app = new_aggregator_application(rng).unwrap();
    let mut chain = PoolSim::genesis_with(random_block(rng, 2, 1));
    chain.advance(3, |_| random_block(rng, 2, 1));
    let [start, middle, end, next] = [0, 1, 2, 3].map(|i| chain.block(BlockHeight(i)).anchor());
    let fused = import_span(rng, &app, &chain, BlockHeight(1), BlockHeight(2));
    let seed = import_span(rng, &app, &chain, BlockHeight(3), BlockHeight(3));

    check_lift(rng, &app, end, next, vec![seed.clone()], true);
    for (anchor, valid) in [(start, true), (middle, true), (next, false)] {
        check_lift(rng, &app, anchor, end, vec![fused.clone()], valid);
    }
    check_lift(
        rng,
        &app,
        start,
        next,
        vec![fused.clone(), seed.clone()],
        true,
    );
    let witness =
        witness::anchor_span_fuse((*fused.data(), *seed.data()), &[middle, end], &[next]).unwrap();
    let (joined, ()) = app
        .fuse(rng, pool::AnchorSpanFuse, witness, fused, seed)
        .unwrap();
    check_lift(rng, &app, start, next, vec![joined], true);
}

#[test]
fn aggregator_seed_reaches_wallet_endpoint_and_lifts() {
    let rng = &mut StdRng::seed_from_u64(642);
    let app = new_aggregator_application(rng).unwrap();
    let chain = PoolSim::genesis_with(random_block(rng, 2, 1));
    let height = BlockHeight(0);
    let wallet_span = chain.anchor_span(app.context().wallet(), height..=height);
    let (start, end) = *wallet_span.data();
    let witness = witness::anchor_span_seed(
        ((), ()),
        start,
        height.epoch(),
        &chain.block(height).stamps[0].1,
    )
    .unwrap();
    let (span, ()) = app.seed(rng, pool::AnchorSpanSeed, witness).unwrap();
    assert_eq!(*span.data(), (start, end));
    assert!(
        app.verify_compressed(&app.compress(&span, &mut *rng).unwrap())
            .unwrap()
    );
    check_lift(rng, &app, start, end, vec![span], true);
}
