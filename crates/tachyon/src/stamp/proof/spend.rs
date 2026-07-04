//! Spend action-binding header and step.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, EpAffine, Eq, Fp, Fq};
use ragu::{
    Header, Index, Step, Suffix,
    constraint::{enforce_nonzero, enforce_zero},
};

use super::spendable::SpendableHeader;
use crate::{
    constants::NOTE_VALUE_MAX,
    entropy::ActionRandomizer,
    keys::{ProofAuthorizingKey, public},
    note::{self, Note, Nullifier},
    primitives::{Anchor, EpochOffset, effect},
    value,
};

/// Header binding an action to its spendable lineage.
///
/// Carries `cv`, `rk`, the lineage's `present_nf`, the pool `anchor`, the
/// note commitment `cm`, and the spend `offset` (`present_epoch −
/// creation_epoch`, derived at [`SpendBind`]); the nullifier pair is completed
/// and published at [`SpendStamp`](super::stamp::SpendStamp).
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    /// `(cm, (cv, rk), present_nf, anchor, offset)`. `cv`/`rk` are derived at
    /// [`SpendBind`]; `present_nf`, `anchor`, and `cm` thread from the
    /// spendable lineage that [`SpendBind`] consumed; `offset` is the spend
    /// offset `present_epoch − creation_epoch`, derived at [`SpendBind`] from
    /// the two pinned lineage epochs and consumed by `SpendStamp`.
    type Data = (
        note::Commitment,
        (value::Commitment, public::ActionVerificationKey),
        Nullifier,
        Anchor,
        EpochOffset,
    );

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, (cv, rk), present_nf, anchor, offset) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(present_nf),
                Fp::from(anchor),
                Fp::from(u64::from(offset.0)),
            ],
            Vec::new(),
            vec![Ep::from(cv.0), Ep::from(EpAffine::from(rk))],
            Vec::new(),
        )
    }
}

/// Binds an action to its spendable lineage's note.
///
/// Witnesses the `note`, `pak`, and the action fields (`rcv`, `alpha`); checks
/// `cm == spendable.cm` (so `cv` commits to the proven-minted value), threads
/// `present_nf`, `anchor`, and `cm`, and derives the spend offset
/// `present_epoch − creation_epoch` onto the output. The live pair is
/// completed at [`SpendStamp`](super::stamp::SpendStamp).
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendHeader;
    type Right = ();
    /// `(note, rcv, alpha, pak)`.
    type Witness<'source> = (
        Note,
        value::CommitmentTrapdoor,
        ActionRandomizer<effect::Spend>,
        ProofAuthorizingKey,
    );

    const INDEX: Index = Index::new(14);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note, rcv, alpha, pak): Self::Witness<'source>,
        (spendable_cm, (present_epoch, present_nf), anchor, creation_epoch): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_nonzero(
            Fp::from(u64::from(note.value)),
            "SpendBind: zero-value note",
        )?;
        if u64::from(note.value) > NOTE_VALUE_MAX {
            return Err(ragu::Error::InvalidWitness(
                "SpendBind: note value exceeds maximum".into(),
            ));
        }
        enforce_zero(
            note.pk.0 - pak.derive_payment_key().0,
            "SpendBind: pak not related to note",
        )?;
        let cm = note.commitment();

        enforce_zero(
            Fp::from(spendable_cm) - Fp::from(cm),
            "SpendBind: note does not match the spendable lineage",
        )?;

        let cv = rcv.commit(i64::from(note.value));
        let rk = pak.ak.derive_action_public(&alpha);

        // The spend offset is the difference of the two pinned lineage epochs;
        // SpendStamp consumes it and re-pins it via `nf_now == present_nf`.
        let offset = present_epoch.offset_from(creation_epoch);

        Ok(((cm, (cv, rk), present_nf, anchor, offset), ()))
    }
}
