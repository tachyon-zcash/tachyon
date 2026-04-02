//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use mock_ragu::{Header, Index, Multiset, Polynomial, Step, Suffix};
use pasta_curves::Fp;

use super::{spend::SpendHeader, spendable::SpendableHeader};
use crate::{
    entropy::ActionRandomizer,
    keys::private,
    note::Note,
    primitives::{
        ActionAcc, ActionCommit, ActionDigest, ActionSet, Anchor, PoolDelta, PoolSet, Tachygram,
        TachygramAcc, TachygramCommit, TachygramSet, effect,
    },
    value,
};

/// Marker type for PCD headers carrying stamp data.
#[derive(Debug)]
pub struct StampHeader;

impl Header for StampHeader {
    /// `(action_commit, tachygram_commit, anchor)` — all 32-byte commitment
    /// handles. Polynomials travel prover-side via `Witness`/`Aux` as
    /// `ActionAcc` / `TachygramAcc` / `PoolAcc`.
    type Data<'source> = (ActionCommit, TachygramCommit, Anchor);

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 4 + 32);
        let action_bytes: [u8; 32] = data.0.0.into();
        let tachygram_bytes: [u8; 32] = data.1.0.into();
        out.extend_from_slice(&action_bytes);
        out.extend_from_slice(&tachygram_bytes);

        out.extend_from_slice(&u32::from(data.2.0).to_le_bytes());
        let pool_bytes: [u8; 32] = data.2.1.0.into();
        out.extend_from_slice(&pool_bytes);
        out
    }
}

/// Derives commitment, proves action, stamps an output.
#[derive(Debug)]
pub struct OutputStamp;

impl Step for OutputStamp {
    type Aux<'source> = (ActionAcc, TachygramAcc, Tachygram);
    type Left = ();
    type Output = StampHeader;
    type Right = ();
    type Witness<'source> = (
        value::CommitmentTrapdoor,
        ActionRandomizer<effect::Output>,
        Note,
        Anchor,
    );

    const INDEX: Index = Index::new(4);

    fn witness<'source>(
        &self,
        (rcv, alpha, note, anchor): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let cv = rcv.commit(-i64::from(note.value));
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        let action_digest = ActionDigest::new(cv, rk).map_err(|_err| mock_ragu::Error)?;

        let tachygram = Tachygram::from(Fp::from(note.commitment()));
        let action_acc = ActionAcc::from(&[action_digest][..]);
        let tachygram_acc = TachygramAcc::from(&[tachygram][..]);

        let data = (
            ActionCommit(action_acc.0.commit(Fp::ZERO)),
            TachygramCommit(tachygram_acc.0.commit(Fp::ZERO)),
            anchor,
        );
        Ok((data, (action_acc, tachygram_acc, tachygram)))
    }
}

/// Fuses spend with spendable chain into a stamp.
#[derive(Debug)]
pub struct SpendStamp;

impl Step for SpendStamp {
    type Aux<'source> = (ActionAcc, TachygramAcc);
    type Left = SpendHeader;
    type Output = StampHeader;
    type Right = SpendableHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(21);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (action_digest, nullifiers, epoch, note_id): <Self::Left as Header>::Data<'source>,
        (right_note_id, right_nf, right_anchor): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if note_id != right_note_id {
            return Err(mock_ragu::Error);
        }
        if nullifiers[0] != right_nf {
            return Err(mock_ragu::Error);
        }
        if epoch != right_anchor.0.epoch() {
            return Err(mock_ragu::Error);
        }

        let action_acc = ActionSet(Polynomial::from_roots(&[action_digest]));
        let tachygram_acc = TachygramSet(Polynomial::from_roots(&[
            Fp::from(nullifiers[0]),
            Fp::from(nullifiers[1]),
        ]));

        let data = (
            ActionCommit(action_acc.0.commit(Fp::ZERO)),
            TachygramCommit(tachygram_acc.0.commit(Fp::ZERO)),
            right_anchor,
        );
        Ok((data, (action_acc, tachygram_acc)))
    }
}

/// Universal merge — transaction assembly and aggregation.
#[derive(Debug)]
pub struct MergeStamp;

impl Step for MergeStamp {
    type Aux<'source> = ();
    type Left = StampHeader;
    type Output = StampHeader;
    type Right = StampHeader;
    type Witness<'source> = (
        ActionSet<Multiset>,
        ActionSet<Multiset>,
        TachygramSet<Multiset>,
        TachygramSet<Multiset>,
    );

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        (left_action, right_action, left_tachygram, right_tachygram): Self::Witness<'source>,
        (left_action_commit, left_tachygram_commit, left_anchor): <Self::Left as Header>::Data<
            'source,
        >,
        (right_action_commit, right_tachygram_commit, right_anchor): <Self::Right as Header>::Data<
            'source,
        >,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_anchor != right_anchor {
            return Err(mock_ragu::Error);
        }

        // Bind witness accumulators to the public commitments on Data.
        if left_action.0.commit() != left_action_commit.0
            || right_action.0.commit() != right_action_commit.0
            || left_tachygram.0.commit() != left_tachygram_commit.0
            || right_tachygram.0.commit() != right_tachygram_commit.0
        {
            return Err(mock_ragu::Error);
        }

        let merged_action = left_action.0.merge(&right_action.0);
        let merged_tachygram = left_tachygram.0.merge(&right_tachygram.0);

        let data = (
            ActionCommit(merged_action.commit()),
            TachygramCommit(merged_tachygram.commit()),
            left_anchor,
        );
        Ok((data, ()))
    }
}

/// Advances a stamp's anchor to a later block within the same epoch.
#[derive(Debug)]
pub struct StampLift;

impl Step for StampLift {
    type Aux<'source> = ();
    type Left = StampHeader;
    type Output = StampHeader;
    type Right = ();
    type Witness<'source> = (
        ActionSet<Multiset>,
        TachygramSet<Multiset>,
        PoolSet<Multiset>,
        PoolDelta<Multiset>,
        Anchor,
    );

    const INDEX: Index = Index::new(20);

    fn witness<'source>(
        &self,
        (left_action, left_tachygram, left_pool, delta, right_anchor): Self::Witness<'source>,
        (left_action_commit, left_tachygram_commit, left_anchor): <Self::Left as Header>::Data<
            'source,
        >,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_anchor.0.epoch() != right_anchor.0.epoch() {
            return Err(mock_ragu::Error);
        }
        if right_anchor.0 <= left_anchor.0 {
            return Err(mock_ragu::Error);
        }

        if left_action.0.commit() != left_action_commit.0
            || left_tachygram.0.commit() != left_tachygram_commit.0
            || left_pool.0.commit() != left_anchor.1.0
        {
            return Err(mock_ragu::Error);
        }

        let right_pool = left_pool.0.merge(&delta.0);
        if right_pool.commit() != right_anchor.1.0 {
            return Err(mock_ragu::Error);
        }

        let data = (left_action_commit, left_tachygram_commit, right_anchor);
        Ok((data, ()))
    }
}
