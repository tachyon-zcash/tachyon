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
    primitives::{Anchor, effect},
    value,
};

/// Header binding an action to its spendable lineage.
///
/// Carries `cv`, `rk`, the lineage's `present_nf`, the pool `anchor`, and the
/// note commitment `cm`; the nullifier pair is completed and published at
/// [`SpendStamp`](super::stamp::SpendStamp).
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    /// `(cm, (cv, rk), present_nf, anchor)`. `cm` leads; `(cv, rk)` are the
    /// spend's published action pair, derived together at [`SpendBind`];
    /// `present_nf` and `anchor` thread from the spendable lineage that
    /// [`SpendBind`] consumed.
    type Data = (
        note::Commitment,
        (value::Commitment, public::ActionVerificationKey),
        Nullifier,
        Anchor,
    );

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, (cv, rk), present_nf, anchor) = *data;
        (
            vec![Fp::from(cm), Fp::from(present_nf), Fp::from(anchor)],
            Vec::new(),
            vec![Ep::from(cv.0), Ep::from(EpAffine::from(rk))],
            Vec::new(),
        )
    }
}

/// Binds an action to its spendable lineage's note.
///
/// Witnesses the `note` and `pak`, plus the action randomizers (`rcv`,
/// `alpha`); checks `cm == spendable.cm` (so `cv` commits to the proven-minted
/// value) and threads `present_nf`, `anchor`, and `cm` onto the output. The
/// live pair is completed at [`SpendStamp`](super::stamp::SpendStamp).
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

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note, rcv, alpha, pak): Self::Witness<'source>,
        (spendable_cm, present_nf, anchor): <Self::Left as Header>::Data,
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

        Ok(((cm, (cv, rk), present_nf, anchor), ()))
    }
}
