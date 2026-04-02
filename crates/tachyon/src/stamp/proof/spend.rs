//! Spend action-binding header and step.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use super::delegation::NullifierHeader;
use crate::{
    entropy::ActionRandomizer,
    keys::ProofAuthorizingKey,
    note::{Note, Nullifier},
    primitives::{ActionDigest, DelegationId, DelegationTrapdoor, EpochIndex, effect},
    value,
};

/// Header binding an action to a nullifier pair.
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    // (action_digest, nullifiers, epoch, delegation_id)
    type Data<'source> = (ActionDigest, [Nullifier; 2], EpochIndex, DelegationId);

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 * 2 + 4 + 32);
        out.extend_from_slice(&Fp::from(&data.0).to_repr());
        out.extend_from_slice(&Fp::from(&data.1[0]).to_repr());
        out.extend_from_slice(&Fp::from(&data.1[1]).to_repr());

        out.extend_from_slice(&data.2.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(&data.3).to_repr());
        out
    }
}

/// Fuses two epoch-adjacent nullifiers and binds them to an action.
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendHeader;
    type Right = NullifierHeader;
    type Witness<'source> = (
        value::CommitmentTrapdoor,
        ActionRandomizer<effect::Spend>,
        ProofAuthorizingKey,
        Note,
        DelegationTrapdoor,
    );

    const INDEX: Index = Index::new(5);

    fn witness<'source>(
        &self,
        (rcv, alpha, pak, note, trap): Self::Witness<'source>,
        (nf0, left_epoch, left_delegation_id): <Self::Left as Header>::Data<'source>,
        (nf1, right_epoch, right_delegation_id): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_delegation_id != right_delegation_id {
            return Err(mock_ragu::Error);
        }
        if right_epoch.0 != left_epoch.0 + 1 {
            return Err(mock_ragu::Error);
        }
        if u64::from(note.value) == 0 {
            return Err(mock_ragu::Error);
        }
        if note.pk.0 != pak.derive_payment_key().0 {
            return Err(mock_ragu::Error);
        }

        let delegation_id = pak.nk.derive_delegation_id(&note, trap);
        if delegation_id != left_delegation_id {
            return Err(mock_ragu::Error);
        }

        let cv = rcv.commit(i64::from(note.value));
        let rk = pak.ak.derive_action_public(&alpha);
        let action_digest = ActionDigest::new(cv, rk).map_err(|_err| mock_ragu::Error)?;

        Ok((
            (action_digest, [nf0, nf1], left_epoch, left_delegation_id),
            (),
        ))
    }
}
