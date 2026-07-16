//! Spend nullifier-binding header and step.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Header, Index, Step, Suffix,
    constraint::{enforce_nonzero, enforce_zero},
};

use super::{delegation::NullifierHeader, spendable::SpendableHeader};
use crate::{
    note::{self, Nullifier},
    primitives::Anchor,
};

/// Header binding a spend to its lineage note and epoch nullifier pair.
///
/// Carries the note commitment `cm`, the present and next nullifiers
/// `(present_nf, nf_next)` confirmed against the covering derivation, and the
/// pool `anchor`. The action pair `(cv, rk)` is produced downstream at
/// [`SpendStamp`](super::stamp::SpendStamp).
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    /// `(cm, present_nf, nf_next, anchor)`. `cm` binds the spent note;
    /// `present_nf`/`nf_next` are the epoch pair [`SpendBind`] confirmed
    /// against the genuine derived range; `anchor` threads the spendable
    /// lineage's pool position.
    type Data = (note::Commitment, Nullifier, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, present_nf, nf_next, anchor) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(present_nf),
                Fp::from(nf_next),
                Fp::from(anchor),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Confirms a spend's epoch nullifier pair against a live two-leaf
/// [`NullifierHeader`] range and binds it to the spendable lineage.
///
/// Witnesses `nf_next` and checks the lineage's genuine `present_nf` and the
/// witnessed `nf_next` are the derived range's boundary leaves (`range.end ==
/// range.start + 2`, `range.cm == cm`). The action pair is produced
/// downstream at [`SpendStamp`](super::stamp::SpendStamp).
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendHeader;
    type Right = NullifierHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (): Self::Witness<'source>,
        (spendable_cm, present_nf, anchor): <Self::Left as Header>::Data,
        (nf_cm, (nf_epoch_start, nf_start), _nf_seq_commit, (nf_epoch_end, nf_end)): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(nf_epoch_end) - (Fp::from(nf_epoch_start) + Fp::from(2u64)),
            "SpendBind: live range must span two epochs",
        )?;
        enforce_zero(
            Fp::from(nf_cm) - Fp::from(spendable_cm),
            "SpendBind: derived range does not match note",
        )?;

        // Bind the published nullifiers to the range's genuine boundary leaves.
        enforce_zero(
            Fp::from(present_nf) - Fp::from(nf_start),
            "SpendBind: present nullifier is not the range's start leaf",
        )?;

        // A zero nullifier would collide with the note's own cm tachygram.
        enforce_nonzero(
            Fp::from(present_nf),
            "SpendBind: present-epoch nullifier is zero",
        )?;
        enforce_nonzero(Fp::from(nf_end), "SpendBind: next-epoch nullifier is zero")?;

        Ok(((spendable_cm, present_nf, nf_end, anchor), ()))
    }
}
