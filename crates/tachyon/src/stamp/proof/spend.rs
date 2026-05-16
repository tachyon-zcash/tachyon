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
    primitives::{ActionDigest, EpochIndex, Tachygram, effect},
    value,
};

/// Header binding an action to a nullifier pair.
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    // (action_digest, nullifiers, epoch)
    type Data<'source> = (ActionDigest, [Nullifier; 2], EpochIndex);

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 * 2 + 4);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1[0]).to_repr());
        out.extend_from_slice(&Fp::from(data.1[1]).to_repr());
        out.extend_from_slice(&data.2.0.to_le_bytes());
        out
    }
}

/// Fuses two epoch-adjacent pre-blind nullifier leaves and binds them to an
/// action.
///
/// Same-wallet binding between the two leaves is established by
/// `cm`-equality; the witnessed `(note, pak)` is bound to the leaves via
/// `note.commitment() == leaf.cm`. The `DelegationTrapdoor` is not needed
/// here — `delegation_id` is only consumed by `SpendableRollover`.
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

    const INDEX: Index = Index::new(5);

    fn witness<'source>(
        &self,
        (rcv, alpha, pak, note): Self::Witness<'source>,
        (left_cm_tg, nf0, left_epoch): <Self::Left as Header>::Data<'source>,
        (right_cm_tg, nf1, right_epoch): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // Same wallet: both leaves share the cm propagated from the
        // pre-blind NfMasterSeed root.
        if left_cm_tg != right_cm_tg {
            return Err(mock_ragu::Error("SpendBind: nullifiers not related"));
        }
        if right_epoch.0 != left_epoch.0 + 1 {
            return Err(mock_ragu::Error("SpendBind: nullifiers not adjacent"));
        }
        // Bind the witnessed note to the leaves' cm.
        let note_cm_tg = Tachygram::from(note.commitment());
        if note_cm_tg != left_cm_tg {
            return Err(mock_ragu::Error(
                "SpendBind: note not related to nullifiers",
            ));
        }
        if u64::from(note.value) == 0 {
            return Err(mock_ragu::Error("SpendBind: zero-value note"));
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

        Ok(((action_digest, [nf0, nf1], left_epoch), ()))
    }
}
