//! Spend nullifier-binding header and step.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Header, Index, Step, Suffix,
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

use super::{delegation::NullifierDerivation, spendable::SpendableHeader};
use crate::{
    digest::poseidon,
    note,
    nullifier::Nullifier,
    primitives::{Anchor, NfMarginPoly, NfSeqPoly, NfTailPoly},
    relations::read::enforce_covering_read_members,
};

/// Header binding a spend to its lineage note and epoch nullifier pair.
///
/// Carries the note commitment `cm`, the present and next nullifiers
/// `(present_nf, nf_next)` confirmed against the covering range, and the pool
/// `anchor`. The action pair `(cv, rk)` is produced downstream at
/// [`SpendStamp`](super::stamp::SpendStamp).
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    /// `(cm, present_nf, nf_next, anchor)`.
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

/// Confirms a spend's epoch nullifier pair against a covering
/// [`NullifierDerivation`] and binds it to the spendable lineage.
///
/// The range is tied to the lineage's note by `nf_cm == spendable_cm` (both
/// are the note commitment, bound where the range was derived and at
/// [`SpendableInit`](super::spendable::SpendableInit) respectively), so no
/// note witness is needed here. Any range covering the two epochs is
/// suitable: the 2-wide covering read at the lineage's epoch confirms the
/// pair, with `present_nf` pinned against the spendable and `nf_next` a
/// witnessed scalar the identity forces. Both nullifiers are emitted on the
/// [`SpendHeader`] for the action-producing step to publish.
///
/// # Soundness
///
/// The read's challenge absorbs both scalar members; left out, a member is
/// solvable after the challenge is known and a garbage `nf_next` would
/// publish. See
/// [`read_challenge`](crate::digest::poseidon::read_challenge).
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendHeader;
    type Right = NullifierDerivation;
    /// `(g, older, tail, nf_next)`.
    type Witness<'source> = (NfSeqPoly, NfMarginPoly, NfTailPoly, Nullifier);

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (g, older, tail, nf_next): Self::Witness<'source>,
        (spendable_cm, (spendable_epoch, present_nf), anchor): <Self::Left as Header>::Data,
        (
            nf_cm,
            (deriv_start, _deriv_nf_start),
            nf_commit,
            (deriv_end, _deriv_nf_end),
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(nf_cm) - Fp::from(spendable_cm),
            "SpendBind: derived range does not match note",
        )?;
        enforce_equal_point(
            Eq::from(g.commit()),
            Eq::from(nf_commit),
            "SpendBind: covering sequence does not match header",
        )?;

        // Native coverage guards over the read window `[e, e + 2)`: mock
        // stand-ins for range constraints over the header-pinned bounds.
        if deriv_start.0 > spendable_epoch.0 {
            return Err(ragu::Error::InvalidWitness(
                "SpendBind: derivation does not cover the lineage epoch".into(),
            ));
        }
        if deriv_end.0 <= spendable_epoch.0 + 1 {
            return Err(ragu::Error::InvalidWitness(
                "SpendBind: derivation does not cover the next epoch".into(),
            ));
        }

        // The 2-wide read at the lineage's epoch, members newest-first. Both
        // enter as scalar monomials, so the challenge must absorb them.
        let margin = u64::from(spendable_epoch - deriv_start);
        let members = [Fp::from(nf_next), Fp::from(present_nf)];
        let z = poseidon::read_challenge(
            g.commit().into(),
            older.commit().into(),
            tail.commit().into(),
            &members,
        );
        enforce_covering_read_members(
            ctx,
            g.as_ref(),
            older.as_ref(),
            tail.as_ref(),
            members,
            margin,
            z,
            "SpendBind: nullifier pair does not match the derivation",
        )?;

        // A zero nullifier would collide with the note's own cm tachygram.
        enforce_nonzero(
            Fp::from(present_nf),
            "SpendBind: present-epoch nullifier is zero",
        )?;
        enforce_nonzero(Fp::from(nf_next), "SpendBind: next-epoch nullifier is zero")?;

        Ok(((spendable_cm, present_nf, nf_next, anchor), ()))
    }
}
