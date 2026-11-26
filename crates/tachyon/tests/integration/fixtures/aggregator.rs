//! The aggregator's side of the workflow: each wallet bundle is compressed for
//! publication, decompressed at aggregator rank, and merged, unmerged and
//! lifted there.

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};

use polynomials::AggregatorRank;
use ragu::{
    AcceleratedProver, Application, Pcd,
    circuits::polynomials,
    pasta::Pasta,
    pcd::profile::{Aggregator, Profiled},
    udon::field::Field as _,
};
use rand::rngs::StdRng;
use zcash_tachyon::{
    ActionDigest, ActionSetPoly, BlockHeight, Bundle, Tachygram, TachygramSetCommit,
    TachygramSetPoly, VerificationError,
    pasta::Fp,
    stamp::{
        AggregatorProof, Stamp, Uncompressed,
        proof::{HEADER_SIZE, new_aggregator_application, pool, transaction::Transaction},
    },
};

use super::{
    Proved, application, keyed_rng, mock_sighash, mock_txid,
    pool::PoolSim,
    wallet::{compressed, stamp_key},
};

pub fn aggregator() -> Box<
    Application<
        'static,
        Profiled<Pasta, Aggregator<HEADER_SIZE>>,
        AggregatorRank,
        HEADER_SIZE,
        AcceleratedProver,
    >,
> {
    new_aggregator_application(&mut keyed_rng("aggregator", &[])).unwrap()
}

/// The bundle as the aggregator holds it after decompressing its publication.
pub(crate) fn imported(
    app: &Application<
        'static,
        Profiled<Pasta, Aggregator<HEADER_SIZE>>,
        AggregatorRank,
        HEADER_SIZE,
        AcceleratedProver,
    >,
    bundle: &Bundle<Stamp<Uncompressed>>,
) -> AggregatorProof {
    static IMPORTED: Proved<AggregatorProof> = Proved::new("imported_stamp");
    IMPORTED.get(&stamp_key(bundle), |rng| {
        let body = compressed(&application(), bundle);
        body.decompress(rng, app, &mock_sighash(body.commitment()))
            .unwrap()
    })
}

/// `left` with `right` merged into it under the aggregator profile, listing
/// `right`'s txid.
pub(crate) fn aggregated(
    app: &Application<
        'static,
        Profiled<Pasta, Aggregator<HEADER_SIZE>>,
        AggregatorRank,
        HEADER_SIZE,
        AcceleratedProver,
    >,
    left: &Bundle<Stamp<Uncompressed>>,
    right: &Bundle<Stamp<Uncompressed>>,
) -> AggregatorProof {
    static AGGREGATED: Proved<AggregatorProof> = Proved::new("aggregated_stamp");
    let mut key = stamp_key(left);
    key.extend_from_slice(&stamp_key(right));
    AGGREGATED.get(&key, |rng| {
        imported(app, left)
            .merge(rng, app, imported(app, right), mock_txid(right))
            .unwrap()
    })
}

/// Compress `stamp` and verify it as `host`'s publication covering `adjuncts`.
pub(crate) fn verify_on(
    app: &Application<
        'static,
        Profiled<Pasta, Aggregator<HEADER_SIZE>>,
        AggregatorRank,
        HEADER_SIZE,
        AcceleratedProver,
    >,
    rng: &mut StdRng,
    host: &Bundle<Stamp<Uncompressed>>,
    stamp: AggregatorProof,
    adjuncts: &[&Bundle<()>],
) -> Result<TachygramSetCommit, VerificationError> {
    let published = stamp.compress(rng, app).map_err(VerificationError::Proof)?;
    publication(host, published).verify(app, &mock_sighash(host.commitment()), adjuncts)
}

/// Whether `stamp` compresses to a proof of exactly `digests`.
pub(crate) fn proves(
    app: &Application<
        'static,
        Profiled<Pasta, Aggregator<HEADER_SIZE>>,
        AggregatorRank,
        HEADER_SIZE,
        AcceleratedProver,
    >,
    rng: &mut StdRng,
    stamp: AggregatorProof,
    digests: &[ActionDigest],
) -> bool {
    stamp
        .compress(rng, app)
        .unwrap()
        .verify_proof(app, digests)
        .unwrap()
}

/// `host`'s body carrying `stamp`, as a block or mempool carries it.
pub(crate) fn publication(
    host: &Bundle<Stamp<Uncompressed>>,
    stamp: zcash_tachyon::Aggregate,
) -> Bundle<zcash_tachyon::Aggregate> {
    compressed(&application(), host).restamp(stamp)
}

/// The wallet compresses a span of `chain`, and the aggregator imports it with
/// the endpoints, members and absorbed tachygrams it reads from history.
pub(crate) fn import_span(
    rng: &mut StdRng,
    app: &Application<
        '_,
        Profiled<Pasta, Aggregator<HEADER_SIZE>>,
        AggregatorRank,
        HEADER_SIZE,
        AcceleratedProver,
    >,
    chain: &PoolSim,
    first: BlockHeight,
    last: BlockHeight,
) -> Pcd<Profiled<Pasta, Aggregator<HEADER_SIZE>>, AggregatorRank, pool::AnchorSpan> {
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

/// The bundle's wallet proof imported with Ragu directly, for tests that fuse
/// transaction steps by hand under the aggregator profile.
pub(crate) fn raw_import(
    rng: &mut StdRng,
    app: &Application<
        'static,
        Profiled<Pasta, Aggregator<HEADER_SIZE>>,
        AggregatorRank,
        HEADER_SIZE,
        AcceleratedProver,
    >,
    bundle: &Bundle<Stamp<Uncompressed>>,
) -> Pcd<Profiled<Pasta, Aggregator<HEADER_SIZE>>, AggregatorRank, Transaction> {
    let body = compressed(&application(), bundle);
    let (digests, tachygram_set) = body.verify_covered().unwrap();
    let tachygrams = bundle
        .actions
        .iter()
        .flat_map(|action| <[Tachygram; 2]>::from(action.tachygrams))
        .chain([bundle.fee_auth]);
    let header = (
        app.context()
            .wallet()
            .bridge_hash(tachygram_set.into())
            .unwrap()
            .into(),
        body.stamp.anchor,
    );
    let frame = (*body.stamp.proof).carry::<Transaction>(header);
    app.decompress_with_polynomials(
        rng,
        &frame,
        [
            monic(ActionSetPoly::from_iter(digests).as_ref().iter_coeffs()),
            monic(
                TachygramSetPoly::from_iter(tachygrams)
                    .as_ref()
                    .iter_coeffs(),
            ),
        ],
    )
    .unwrap()
}

/// A set polynomial's coefficients through its leading one.
fn monic(padded: impl Iterator<Item = Fp>) -> Vec<Fp> {
    let mut coefficients: Vec<Fp> = padded.collect();
    while coefficients.last() == Some(&Fp::ZERO) {
        coefficients.pop();
    }
    coefficients
}
