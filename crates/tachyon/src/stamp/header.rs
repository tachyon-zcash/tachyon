//! Stamp header and stamp-producing/transforming steps.
#![expect(
    clippy::module_name_repetitions,
    reason = "header/step names are intentional"
)]

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use super::{pool::PoolHeader, spend::SpendHeader, spendable::SpendableHeader};
use crate::{
    entropy::ActionRandomizer,
    keys::private,
    note::Note,
    primitives::{ActionDigest, Anchor, Tachygram, effect},
    value,
};

/// Marker type for PCD headers carrying stamp data.
#[derive(Debug)]
pub struct StampHeader;

impl Header for StampHeader {
    // (action_acc, tachygram_acc, anchor)
    type Data<'source> = (Fp, Fp, Anchor);

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(&(action_acc, tachygram_acc, anchor): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 2 + 4 + 32 * 4);
        out.extend_from_slice(&action_acc.to_repr());
        out.extend_from_slice(&tachygram_acc.to_repr());
        out.extend_from_slice(&anchor.encode_for_header());
        out
    }
}

/// Derives commitment, proves action, stamps an output.
#[derive(Debug)]
pub struct OutputStamp;

impl Step for OutputStamp {
    type Aux<'source> = Tachygram;
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
        let action_acc = Fp::from(action_digest);
        let tachygram_acc = Fp::from(tachygram);

        Ok(((action_acc, tachygram_acc, anchor), tachygram))
    }
}

/// Fuses spend with spendable chain into a stamp.
#[derive(Debug)]
pub struct SpendStamp;

impl Step for SpendStamp {
    type Aux<'source> = ();
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
        if epoch != right_anchor.block_height.epoch() {
            return Err(mock_ragu::Error);
        }

        let tachygram_acc =
            Fp::from(Tachygram::from(nullifiers[0])) * Fp::from(Tachygram::from(nullifiers[1]));

        Ok(((action_digest, tachygram_acc, right_anchor), ()))
    }
}

/// Universal merge -- transaction assembly and aggregation.
/// Requires exact anchor equality (use StampLift to align anchors first).
#[derive(Debug)]
pub struct MergeStamp;

impl Step for MergeStamp {
    type Aux<'source> = ();
    type Left = StampHeader;
    type Output = StampHeader;
    type Right = StampHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left.2 != right.2 {
            return Err(mock_ragu::Error);
        }

        Ok(((left.0 * right.0, left.1 * right.1, left.2), ()))
    }
}

/// Advances a stamp's anchor to a later block within the same epoch.
///
/// Only checks that the new anchor is later, same epoch, same epoch_chain.
/// Pool state continuity (block_chain) is verified by consensus outside
/// the proof — the stamp just needs to adopt a superset state.
#[derive(Debug)]
pub struct StampLift;

impl Step for StampLift {
    type Aux<'source> = ();
    type Left = StampHeader;
    type Output = StampHeader;
    type Right = PoolHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(20);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (action_acc, tachygram_acc, left_anchor): <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if right.block_height <= left_anchor.block_height {
            return Err(mock_ragu::Error);
        }
        if right.block_height.epoch() != left_anchor.block_height.epoch() {
            return Err(mock_ragu::Error);
        }
        if left_anchor.epoch_chain != right.epoch_chain {
            return Err(mock_ragu::Error);
        }

        Ok(((action_acc, tachygram_acc, right), ()))
    }
}
