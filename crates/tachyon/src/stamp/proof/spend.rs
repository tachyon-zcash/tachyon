//! Spend action-binding header and step.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use super::delegation::NullifierHeader;
use crate::{
    constants::NOTE_VALUE_MAX,
    entropy::ActionRandomizer,
    keys::ProofAuthorizingKey,
    note::{Note, Nullifier},
    primitives::{ActionDigest, effect},
    value,
};

/// Header binding an action to a nullifier pair.
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    type Data<'source> = (ActionDigest, (Nullifier, Nullifier));

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 * 2);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1.1).to_repr());
        out
    }
}

/// Fuses two epoch-adjacent nullifier leaves and binds them to an action.
///
/// One `cm`-equality fold ties together same-wallet binding between the
/// two leaves and note-binding for the witnessed `(note, pak)`:
/// `note.commitment() == left_cm == right_cm`. The `DelegationTrapdoor` is
/// not needed — `delegation_id` is consumed only by the sync-service-side
/// rollover steps on `DelegateNullifierHeader`.
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
    );

    const INDEX: Index = Index::new(20);

    fn witness<'source>(
        &self,
        (rcv, alpha, pak, note): Self::Witness<'source>,
        (left_cm, nf0, left_epoch): <Self::Left as Header>::Data<'source>,
        (right_cm, nf1, right_epoch): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if u64::from(note.value) == 0 {
            return Err(mock_ragu::Error("SpendBind: zero-value note"));
        }
        if right_epoch.0 != left_epoch.0 + 1 {
            return Err(mock_ragu::Error("SpendBind: nullifiers not adjacent"));
        }
        if left_cm != right_cm {
            return Err(mock_ragu::Error("SpendBind: nullifiers not related"));
        }
        let cm = note.commitment();
        if cm != left_cm || cm != right_cm {
            return Err(mock_ragu::Error(
                "SpendBind: nullifiers not related to note",
            ));
        }
        if u64::from(note.value) > NOTE_VALUE_MAX {
            return Err(mock_ragu::Error("SpendBind: note value exceeds maximum"));
        }
        if note.pk.0 != pak.derive_payment_key().0 {
            return Err(mock_ragu::Error("SpendBind: pak not related to note"));
        }

        let cv = rcv.commit(i64::from(note.value));
        let rk = pak.ak.derive_action_public(&alpha);
        let action_digest = ActionDigest::new(cv, rk)
            .map_err(|_err| mock_ragu::Error("SpendBind: action digest failed"))?;

        Ok(((action_digest, (nf0, nf1)), ()))
    }
}
