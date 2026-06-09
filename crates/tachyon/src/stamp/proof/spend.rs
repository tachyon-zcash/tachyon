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
    keys::{ProofAuthorizingKey, public},
    note::{Note, Nullifier},
    primitives::effect,
    value,
};

/// Header binding an action to a nullifier pair.
///
/// Publishing `next_nf` one epoch early lets consensus catch a same-note
/// spend made in epoch `e+1`: that spend's present-epoch nullifier would
/// collide with this `next_nf`, which the two-epoch tachygram scan
/// rejects. See the Tachygrams book chapter.
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    /// `(cv, rk, (now_nf, next_nf))`. `cv` and `rk` are derived at
    /// [`SpendBind`] from the witnessed `(rcv, alpha, pak, note)`.
    /// [`SpendStamp`](super::stamp::SpendStamp) hashes `(cv, rk)`
    /// into the per-action `ActionDigest` when committing the
    /// action set. `now_nf` and `next_nf` are computed upstream by
    /// [`NullifierStep`](super::delegation::NullifierStep) on two
    /// [`NullifierHeader`](super::delegation::NullifierHeader)s
    /// that [`SpendBind`] constrains to share a `cm` lineage and
    /// to live on consecutive epochs.
    type Data<'source> = (
        value::Commitment,
        public::ActionVerificationKey,
        (Nullifier, Nullifier),
    );

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 32);
        let cv_bytes: [u8; 32] = data.0.into();
        let rk_bytes: [u8; 32] = data.1.into();
        out.extend_from_slice(&cv_bytes);
        out.extend_from_slice(&rk_bytes);
        out.extend_from_slice(&Fp::from(data.2.0).to_repr());
        out.extend_from_slice(&Fp::from(data.2.1).to_repr());
        out
    }
}

/// Fuses two epoch-adjacent nullifier leaves and binds them to an action.
///
/// The `note.commitment() == left_cm == right_cm` fold is the cv-to-value
/// seam: the witnessed note's value flows into `cv = rcv.commit(note.value)`,
/// which becomes the on-chain action's value commitment. Without binding
/// the witnessed note to the upstream nullifier's `cm`, a prover could
/// publish a nullifier for a high-value note while committing `cv` to a
/// low-value note.
///
/// [`NullifierRolloverHeader`](super::spendable::NullifierRolloverHeader)
/// drops `cm` and cannot expose it without leaking note material via
/// [`DelegateRolloverFuse`](super::spendable::DelegateRolloverFuse), so
/// this step is the only place where `cm` is in scope alongside the
/// action witness.
///
/// Outputs `SpendHeader::Data = (cv, rk, (now_nf, next_nf))`. The
/// `ActionDigest = Poseidon(cv, rk)` derivation lives downstream in
/// [`SpendStamp`](super::stamp::SpendStamp) to keep this step's gate
/// budget under the per-step bound. `SpendBind` and `SpendStamp` are both
/// wallet-private; the `SpendHeader` boundary between them is not exposed
/// to consensus or the sync service.
///
/// The `DelegationTrapdoor` is not needed because `delegation_id` is
/// consumed only by the sync-service rollover steps on
/// `DelegateNullifierHeader`.
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

    const INDEX: Index = Index::new(25);

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

        Ok(((cv, rk, (nf0, nf1)), ()))
    }
}
