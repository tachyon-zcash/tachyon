use polynomials::AggregatorRank;
use ragu::{
    AcceleratedProver, Application, CompressedProof, Rank,
    circuits::polynomials,
    pasta::Pasta,
    pcd::{
        ipa::IpaCycle,
        profile::{Aggregator, Profiled, ProfiledCycle},
    },
};

use super::proof::{HEADER_SIZE, transaction::Transaction};
use crate::{
    ActionDigest, ActionSetCommit, Anchor, TachygramSetCommit,
    pasta::{EpAffine, EqAffine, Fp},
};

/// Whether `proof` commits to both transaction sets and verifies under its
/// application for the header the trailer determines.
pub(super) fn verified_transaction<C, R: Rank>(
    app: &Application<'_, C, R, HEADER_SIZE, AcceleratedProver>,
    proof: &CompressedProof<C>,
    (actions, tachygrams, anchor): (ActionSetCommit, TachygramSetCommit, Anchor),
) -> ragu::Result<bool>
where
    C: IpaCycle
        + ProfiledCycle<Base = Pasta, CircuitField = Fp, HostCurve = EqAffine, NestedCurve = EpAffine>,
{
    if proof.online_commitments() != [actions.into(), tachygrams.into()] {
        return Ok(false);
    }
    let bridge = app.bridge_hash(tachygrams.into())?.into();
    app.verify_compressed(&proof.clone().carry::<Transaction>((bridge, anchor)))
}

impl super::Aggregate {
    /// Checks both transaction commitments and verifies the aggregator frame.
    ///
    /// # Errors
    /// Returns a Ragu error if verification fails internally. A disproved frame
    /// gives `Ok(false)`.
    pub fn verify_proof(
        &self,
        app: &Application<
            '_,
            Profiled<Pasta, Aggregator<HEADER_SIZE>>,
            AggregatorRank,
            HEADER_SIZE,
            AcceleratedProver,
        >,
        digests: &[ActionDigest],
    ) -> ragu::Result<bool> {
        let actions = super::action_commit(digests.iter().copied())?;
        verified_transaction(app, &self.proof, (actions, self.tachygram_set, self.anchor))
    }
}
