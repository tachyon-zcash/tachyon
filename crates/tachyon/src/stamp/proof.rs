//! Tachyon proofs via Ragu PCD.
//!
//! Registers all PCD step types.
//!
//! `Step::INDEX` runs from zero without gaps, and [`new_application`] registers
//! the steps in that order; `ApplicationBuilder` rejects any other sequence.
//! `Header::SUFFIX` runs from zero without gaps too.
//!
//! A step is named "noun + verb", where the noun is the header it **emits**,
//! not the one it reads. Most fuse steps read and emit the same header, which
//! leaves the rule invisible until one does not: `EvidenceTreeFuse` emits an
//! `EvidenceTree` and reads two `EvidenceTreePair`s, and `EvidenceTreePairFuse`
//! emits the pair. Three steps whose output is a part of what they read are
//! named for the input instead: `QrIntakeSplit`, `QrSideDescend` and
//! `EvidenceTreeOpen`.
//!
//! Steps relate polynomials through their openings at the challenge
//! $\zeta$, which the framework derives after committing every polynomial a
//! step opens. A product or root identity that holds at $\zeta$ therefore holds
//! as a polynomial identity, except with probability about
//! $\mathrm{deg}/|\mathbb{F}_p|$ (Schwartz-Zippel). The identity says which
//! polynomials it relates only through their commitments, so each step grounds
//! its operands in an input or output header, and each root it checks is fixed
//! before $\zeta$. A commitment that is only witnessed, or threaded onward
//! unchanged, binds nothing until a public input, a header or a consensus check
//! fixes it.

#![allow(missing_debug_implementations, missing_docs, reason = "todo")]

pub mod delegation;
pub mod evidence;
pub mod output;
pub mod pool;
pub mod publication;
pub mod qr;
pub mod spend;
pub mod spendable;
pub mod stamp;
pub mod summary;

use alloc::boxed::Box;

use ragu::{AcceleratedProver, Application, ApplicationBuilder, WalletRank, pasta::Pasta};

use crate::pasta;

/// Eight payload elements for QR split/selection and bucket headers and one
/// suffix element.
pub const HEADER_SIZE: usize = 9;

/// The Tachyon Ragu application, with accelerated proving and reference
/// verification kernels.
pub type App<'app> = Application<'app, Pasta, WalletRank, HEADER_SIZE, AcceleratedProver>;

/// Builds the Tachyon application with the baked setup.
///
/// Building runs the full setup, so a caller builds one application per
/// worker, keeps it on that worker and lends `&app` to each proof
/// operation.
///
/// # Errors
///
/// Returns an error if step registration or application finalization fails.
pub fn new_application() -> Result<Box<App<'static>>, ragu::Error> {
    working_steps()?.finalize(pasta::baked()).map(Box::new)
}

/// Builds the wallet publication registry. Use this builder to provision a
/// common bootstrap for this exact configuration. A wallet installs the
/// shared proof with [`WalletPublicationApp::new`].
///
/// # Errors
///
/// Returns an error if any step cannot be registered.
pub fn publication_builder() -> Result<
    ApplicationBuilder<'static, Pasta, WalletRank, HEADER_SIZE, AcceleratedProver>,
    ragu::Error,
> {
    working_steps()?
        .register(publication::StampBindActionSet)?
        .register(publication::StampPublish)?
        .register(publication::StampRestoreActionSet)?
        .register(publication::StampRestoreTachygramSet)
}

/// The wallet publication application, with its shared bootstrap verified.
pub struct WalletPublicationApp(Box<App<'static>>);

impl WalletPublicationApp {
    /// Installs and verifies the network's shared bootstrap before it is used
    /// as the public right child in rerandomization. The caller must obtain
    /// this proof from shared configuration (or check its pinned digest);
    /// validity alone does not establish that wallets use the same proof.
    ///
    /// # Errors
    ///
    /// Returns an error if setup or bootstrap verification fails.
    pub fn new<R: rand_core::CryptoRng>(
        rng: &mut R,
        shared_bootstrap: super::Uncompressed,
    ) -> Result<Self, ragu::Error> {
        let app = Box::new(
            publication_builder()?
                .with_bootstrap(shared_bootstrap)?
                .finalize(pasta::baked())?,
        );
        let bootstrap = app.bootstrap_proof().clone().carry::<()>(());
        if !app.verify_compressed(&app.compress(&bootstrap, rng)?)? {
            return Err(ragu::Error::Initialization(
                "invalid wallet publication bootstrap".into(),
            ));
        }
        Ok(Self(app))
    }

    /// The registered wallet application for building compatible stamps and
    /// history.
    #[must_use]
    pub const fn application(&self) -> &App<'static> {
        &self.0
    }
}

fn working_steps() -> Result<
    ApplicationBuilder<'static, Pasta, WalletRank, HEADER_SIZE, AcceleratedProver>,
    ragu::Error,
> {
    ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE, AcceleratedProver>::new()
        .register(delegation::NoteSeed)?
        .register(delegation::NullifierDerive)?
        .register(pool::UnspentFuse)?
        .register(pool::UnspentBind)?
        .register(spendable::SpendableInit)?
        .register(spendable::SpendableLift)?
        .register(output::OutputBind)?
        .register(stamp::OutputAction)?
        .register(spend::SpendBind)?
        .register(stamp::SpendAction)?
        .register(stamp::StampMerge)?
        .register(stamp::StampLift)?
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
        .register(pool::AnchorSpanSeed)?
        .register(pool::AnchorSpanFuse)?
        .register(stamp::FeeFuse)?
        .register(stamp::ActionMerge)?
        .register(stamp::ActionLift)?
        .register(stamp::FeeSeed)?
        .register(stamp::StampUnmerge)?
        .register(qr::QrSideSelect)
}
