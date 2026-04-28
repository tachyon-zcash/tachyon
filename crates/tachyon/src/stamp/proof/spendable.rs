//! Spendable status headers and steps.

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use mock_ragu::{Header, Index, Multiset, Polynomial, Step, Suffix};
use pasta_curves::Fp;

use super::delegation::NullifierHeader;
use crate::{
    keys::ProofAuthorizingKey,
    note::{Note, Nullifier},
    primitives::{Anchor, BlockHeight, BlockSet, DelegationId, DelegationTrapdoor},
};

fn encode_anchor(anchor: &Anchor) -> [u8; 32] {
    anchor.0.into()
}

fn encode_spendable(delegation_id: DelegationId, nf: Nullifier, anchor: &Anchor) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32 + 32);
    out.extend_from_slice(&Fp::from(&delegation_id).to_repr());
    out.extend_from_slice(&Fp::from(&nf).to_repr());
    out.extend_from_slice(&encode_anchor(anchor));
    out
}

/// Verify that `anchor` is the Pedersen commitment of `(X - prev_anchor_fp) *
/// block_polynomial` blinded by `height`. The commitment scheme is binding in
/// both the polynomial (block contents + prior anchor as a root) and the
/// blinding factor (height), so this single equality binds all three.
fn check_anchor(
    prev_anchor: Anchor,
    height: BlockHeight,
    block: &BlockSet<Multiset>,
    anchor: &Anchor,
) -> bool {
    let height_fp = Fp::from(u64::from(height.0));
    let prev_fp = Fp::from(&prev_anchor);
    let extended = block
        .0
        .merge(&Multiset::new(Polynomial::from_roots(&[prev_fp])));
    *anchor == Anchor(extended.commit_with(height_fp))
}

/// Header attesting a note is spendable at a specific anchor.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    type Data<'source> = (DelegationId, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        encode_spendable(data.0, data.1, &data.2)
    }
}

/// Header collecting information necessary for epoch transition.
#[derive(Debug)]
pub struct SpendableRolloverHeader;

impl Header for SpendableRolloverHeader {
    // (delegation_id, old_nf, new_nf, new_anchor)
    type Data<'source> = (DelegationId, Nullifier, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(4);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 64);
        out.extend_from_slice(&Fp::from(&data.0).to_repr());
        out.extend_from_slice(&Fp::from(&data.1).to_repr());
        out.extend_from_slice(&Fp::from(&data.2).to_repr());
        out.extend_from_slice(&encode_anchor(&data.3));
        out
    }
}

/// Proves cm inclusion in a specific block to bootstrap spendable status.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableHeader;
    type Right = ();
    type Witness<'source> = (
        Note,
        ProofAuthorizingKey,
        DelegationTrapdoor,
        Anchor,
        BlockSet<Multiset>,
        BlockHeight,
        Anchor,
    );

    const INDEX: Index = Index::new(6);

    fn witness<'source>(
        &self,
        (note, pak, trap, prev_anchor, block, height, anchor): Self::Witness<'source>,
        (nf, epoch, delegation_id): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if u64::from(note.value) == 0 {
            return Err(mock_ragu::Error);
        }
        if note.pk.0 != pak.derive_payment_key().0 {
            return Err(mock_ragu::Error);
        }
        if delegation_id != pak.nk.derive_delegation_id(&note, trap) {
            return Err(mock_ragu::Error);
        }

        if !check_anchor(prev_anchor, height, &block, &anchor) {
            return Err(mock_ragu::Error);
        }
        if epoch != height.epoch() {
            return Err(mock_ragu::Error);
        }

        let cm: Fp = Fp::from(&note.commitment());
        if block.0.query(cm) != Fp::ZERO {
            return Err(mock_ragu::Error);
        }
        if block.0.query(Fp::from(&nf)) == Fp::ZERO {
            return Err(mock_ragu::Error);
        }

        Ok(((delegation_id, nf, anchor), ()))
    }
}

/// Collects some prerequisites for epoch transition.
#[derive(Debug)]
pub struct SpendableRollover;

impl Step for SpendableRollover {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableRolloverHeader;
    type Right = NullifierHeader;
    type Witness<'source> = (Anchor, BlockSet<Multiset>, BlockHeight, Anchor);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        (prev_anchor, block, height, anchor): Self::Witness<'source>,
        (old_nf, old_epoch, old_delegation_id): <Self::Left as Header>::Data<'source>,
        (new_nf, new_epoch, new_delegation_id): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if old_delegation_id != new_delegation_id {
            return Err(mock_ragu::Error);
        }
        if new_epoch.0 != old_epoch.0 + 1 {
            return Err(mock_ragu::Error);
        }

        if !check_anchor(prev_anchor, height, &block, &anchor) {
            return Err(mock_ragu::Error);
        }
        if new_epoch != height.epoch() {
            return Err(mock_ragu::Error);
        }

        if block.0.query(Fp::from(&new_nf)) == Fp::ZERO {
            return Err(mock_ragu::Error);
        }

        Ok(((new_delegation_id, old_nf, new_nf, anchor), ()))
    }
}

/// Advances spendable status to the next block within the same epoch via a
/// single chain step. Multi-block lifts chain through PCD recursion.
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = ();
    type Witness<'source> = (
        Anchor,
        BlockSet<Multiset>,
        BlockHeight,
        BlockSet<Multiset>,
        BlockHeight,
        Anchor,
    );

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        (prev_anchor, old_block, old_height, new_block, new_height, new_anchor): Self::Witness<
            'source,
        >,
        (delegation_id, nf, old_anchor): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // Bind prev_anchor + old_block to old_anchor.
        if !check_anchor(prev_anchor, old_height, &old_block, &old_anchor) {
            return Err(mock_ragu::Error);
        }

        // Single chain step from the old anchor to the new anchor.
        if !check_anchor(old_anchor, new_height, &new_block, &new_anchor) {
            return Err(mock_ragu::Error);
        }

        // Both heights live in the same epoch and step by one.
        if new_height.0 != old_height.0 + 1 {
            return Err(mock_ragu::Error);
        }
        if new_height.epoch() != old_height.epoch() {
            return Err(mock_ragu::Error);
        }

        // Nullifier still has not been spent in the advanced block.
        if new_block.0.query(Fp::from(&nf)) == Fp::ZERO {
            return Err(mock_ragu::Error);
        }

        Ok(((delegation_id, nf, new_anchor), ()))
    }
}

/// Single-block chain step across an epoch boundary.
#[derive(Debug)]
pub struct SpendableEpochLift;

impl Step for SpendableEpochLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = SpendableRolloverHeader;
    type Witness<'source> = (
        Anchor,
        BlockSet<Multiset>,
        BlockHeight,
        BlockSet<Multiset>,
        BlockHeight,
        Anchor,
    );

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        (prev_anchor, old_block, old_height, new_block, new_height, new_anchor): Self::Witness<
            'source,
        >,
        (old_delegation_id, old_nf, old_anchor): <Self::Left as Header>::Data<'source>,
        (rollover_delegation_id, rollover_old_nf, new_nf, rollover_anchor): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if old_delegation_id != rollover_delegation_id {
            return Err(mock_ragu::Error);
        }
        if old_nf != rollover_old_nf {
            return Err(mock_ragu::Error);
        }
        if rollover_anchor != new_anchor {
            return Err(mock_ragu::Error);
        }

        // Bind prev_anchor + old_block to old_anchor.
        if !check_anchor(prev_anchor, old_height, &old_block, &old_anchor) {
            return Err(mock_ragu::Error);
        }

        // Single chain step from old anchor to new anchor.
        if !check_anchor(old_anchor, new_height, &new_block, &new_anchor) {
            return Err(mock_ragu::Error);
        }

        // Epoch boundary: old must be epoch-final, new starts the next epoch.
        if !old_height.is_epoch_final() {
            return Err(mock_ragu::Error);
        }
        if new_height.0 != old_height.0 + 1 {
            return Err(mock_ragu::Error);
        }
        if new_height.epoch().0 != old_height.epoch().0 + 1 {
            return Err(mock_ragu::Error);
        }

        // Nullifier still not spent in the new block.
        if new_block.0.query(Fp::from(&new_nf)) == Fp::ZERO {
            return Err(mock_ragu::Error);
        }

        Ok(((old_delegation_id, new_nf, new_anchor), ()))
    }
}
