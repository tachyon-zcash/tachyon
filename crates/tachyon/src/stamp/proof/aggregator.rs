//! Aggregator-rank application and wallet imports.

use alloc::boxed::Box;

use ragu::{
    AcceleratedProver, Application, Pcd, WalletRank,
    circuits::polynomials,
    pasta::Pasta,
    pcd::profile::{Aggregator, Decompression, Profiled},
    udon::curve::Affine as _,
};
use ragu_pcd::pasta::baked_aggregator;
use rand_core::CryptoRng;

use super::{HEADER_SIZE, registry, transaction};
use crate::{ActionSetCommit, ActionSetPoly, Anchor, pasta::EqAffine};

pub(crate) type Cycle = Profiled<Pasta, Aggregator<HEADER_SIZE>>;
pub(crate) type App<'app> =
    Application<'app, Cycle, polynomials::AggregatorRank, HEADER_SIZE, AcceleratedProver>;
pub(crate) type Transaction = Pcd<Cycle, polynomials::AggregatorRank, transaction::Transaction>;

pub(crate) fn new_application(rng: &mut impl CryptoRng) -> ragu::Result<Box<App<'static>>> {
    let params = baked_aggregator();
    let step = transaction::TransactionRehydrate::new()?;
    let wallet = registry::shared_builder::<Pasta, WalletRank>(step.clone())?.finalize(params)?;
    let context = Decompression::new(wallet, rng)?;
    registry::shared_builder::<Cycle, polynomials::AggregatorRank>(step)?
        .finalize_with(params, context)
        .map(Box::new)
}

pub(crate) fn import_transaction(
    rng: &mut impl CryptoRng,
    app: &App<'_>,
    public: &ragu::CompressedPcd<Pasta, transaction::PublicTransaction>,
    actions: ActionSetPoly,
    commitment: ActionSetCommit,
) -> ragu::Result<Transaction> {
    let input = app.decompress(rng, public)?;
    let unit = app.bootstrap_proof().clone().carry::<()>(());
    Ok(app
        .fuse(
            rng,
            transaction::TransactionRehydrate::new()?,
            (actions, commitment),
            input,
            unit,
        )?
        .0)
}

pub(crate) fn finalize(
    rng: &mut impl CryptoRng,
    app: &App<'_>,
    pcd: Transaction,
) -> ragu::Result<ragu::CompressedProof<Cycle>> {
    let refreshed = app.rerandomize(pcd, &mut *rng)?;
    Ok(app.compress(&refreshed, rng)?.into_parts().0)
}

pub(crate) fn verify(
    app: &App<'_>,
    proof: &ragu::CompressedProof<Cycle>,
    (actions, anchor): (ActionSetCommit, Anchor),
) -> ragu::Result<bool> {
    if proof.online_commitments()[1] != actions.into() || EqAffine::from(actions).is_identity() {
        return Ok(false);
    }
    let bridge = app.bridge_hash(actions.into())?.into();
    app.verify_compressed(
        &proof
            .clone()
            .carry::<transaction::Transaction>((bridge, anchor)),
    )
}
