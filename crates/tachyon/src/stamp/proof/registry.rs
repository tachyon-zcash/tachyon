//! The ordered step list shared by the wallet and the aggregator application.

use ragu::{
    AcceleratedProver, ApplicationBuilder, Rank,
    pasta::{Fp, Pasta},
    pcd::profile,
};

use super::{
    HEADER_SIZE, delegation, evidence, output, pool, qr, spend, spendable, summary, transaction,
};

pub(super) fn shared_builder<
    C: profile::ProfiledCycle<Base = Pasta, CircuitField = Fp>,
    R: Rank,
>(
    step: transaction::TransactionRehydrate,
) -> ragu::Result<ApplicationBuilder<'static, C, R, HEADER_SIZE, AcceleratedProver>> {
    dehydration_registry::<C, R>()?
        .register(step)?
        .register(pool::AnchorSpanDehydrate)?
        .register(pool::AnchorSpanRehydrate::new()?)
}

pub(super) fn dehydration_registry<
    C: profile::ProfiledCycle<Base = Pasta, CircuitField = Fp>,
    R: Rank,
>() -> ragu::Result<ApplicationBuilder<'static, C, R, HEADER_SIZE, AcceleratedProver>> {
    ApplicationBuilder::<'static, C, R, HEADER_SIZE, AcceleratedProver>::new()
        .register(delegation::NoteSeed)?
        .register(delegation::NullifierDerive)?
        .register(pool::UnspentFuse)?
        .register(pool::UnspentBind)?
        .register(spendable::SpendableInit)?
        .register(spendable::SpendableLift)?
        .register(output::OutputBind)?
        .register(transaction::OutputAction)?
        .register(spend::SpendBind)?
        .register(transaction::SpendAction)?
        .register(transaction::TransactionMerge)?
        .register(transaction::TransactionLift)?
        .register(delegation::NullifierFuse)?
        .register(summary::SummarySeed)?
        .register(summary::SummaryAdvance)?
        .register(qr::QrSummaryIntake)?
        .register(qr::QrIntakeMerge)?
        .register(qr::QrIntakeSplit)?
        .register(qr::QrSideDescend)?
        .register(qr::QrUnspentInit)?
        .register(qr::QrBucketSeal)?
        .register(qr::QrStampIntakeSeed)?
        .register(spendable::QrSpendableInit)?
        .register(qr::QrEmptyIntakeSeed)?
        .register(pool::UnspentLift)?
        .register(evidence::EvidenceTreePairFuse)?
        .register(evidence::EvidenceTreeFuse)?
        .register(evidence::EvidenceTreeCap)?
        .register(evidence::EvidenceTreeDescend)?
        .register(evidence::EvidenceTreeOpen)?
        .register(evidence::EvidenceTreeLeafPair)?
        // Both registries include this step; its canonical seed is wallet-rank only.
        .register(pool::AnchorSpanSeed)?
        .register(pool::AnchorSpanFuse)?
        .register(transaction::FeeFuse)?
        .register(transaction::ActionMerge)?
        .register(transaction::ActionLift)?
        .register(transaction::FeeSeed)?
        .register(transaction::TransactionUnmerge)?
        .register(qr::QrSideSelect)?
        .register(transaction::TransactionDehydrate)
}
