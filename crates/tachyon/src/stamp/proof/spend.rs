//! Spend nullifier-binding header and step.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Header, Index, Polynomial, Step, Suffix,
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

use super::{delegation::NullifierDerivation, spendable::SpendableHeader};
use crate::{
    note::{self, Nullifier},
    primitives::{Anchor, EpochIndex, NfSeqPoly},
    relations::enforce::enforce_shifted_combination,
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
    /// `present_nf`/`nf_next` are the confirmed epoch pair; `anchor` threads
    /// the spendable lineage's pool position.
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
/// The derivation is tied to the lineage's note by `deriv_cm == spendable_cm`
/// (both are the note commitment, bound at
/// [`NullifierDerivationStep`](super::delegation::NullifierDerivationStep) and
/// [`SpendableInit`](super::spendable::SpendableInit) respectively), so no note
/// witness is needed here. `present_nf` (from the lineage) is confirmed to be
/// the derivation's leaf at `present_epoch` (a degree-0 opening of the covered
/// tail), and `nf_next` is the following leaf; both are emitted on the
/// [`SpendHeader`] for the action-producing step to publish.
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendHeader;
    type Right = NullifierDerivation;
    /// `(present_epoch, deriv_seq, prefix_seq, tail_seq, next_tail_seq)`.
    type Witness<'source> = (EpochIndex, NfSeqPoly, NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(16);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (present_epoch, deriv_seq, prefix_seq, tail_seq, next_tail_seq): Self::Witness<'source>,
        (spendable_cm, present_nf, anchor): <Self::Left as Header>::Data,
        (deriv_cm, deriv_start, deriv_end, deriv_seq_commit): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(deriv_cm) - Fp::from(spendable_cm),
            "SpendBind: derivation does not match note",
        )?;
        enforce_equal_point(
            Eq::from(deriv_seq.commit()),
            Eq::from(deriv_seq_commit),
            "SpendBind: derivation polynomial does not match header",
        )?;

        // Coverage: present and next epochs both inside the derivation.
        if deriv_end.0 <= present_epoch.0.saturating_add(1) {
            return Err(ragu::Error::InvalidWitness(
                "SpendBind: derivation does not cover the next epoch".into(),
            ));
        }
        let off = usize::try_from(present_epoch.0.checked_sub(deriv_start.0).ok_or_else(|| {
            ragu::Error::InvalidWitness(
                "SpendBind: derivation does not cover the present epoch".into(),
            )
        })?)
        .map_err(|_too_far| {
            ragu::Error::InvalidWitness("SpendBind: coverage offset exceeds usize".into())
        })?;

        // `present_nf` is the covered tail's degree-0 leaf: `q = prefix ++ tail`
        // (`q(X) = prefix(X) + X^off·tail(X) - X^off`), `present_nf =
        // tail.eval(0)`. `present_nf` is a `SpendableHeader` value, pinned before
        // the challenge.
        let tail_poly = Polynomial::from(tail_seq);
        enforce_shifted_combination(
            ctx,
            [(&Polynomial::from(prefix_seq), 0), (&tail_poly, off)],
            [(-Fp::ONE, off)],
            &Polynomial::from(deriv_seq),
        )
        .map_err(|_relation_err| {
            ragu::Error::InvalidWitness("SpendBind: present leaf not covered".into())
        })?;
        ctx.enforce_poly_query(tail_poly.commit(), Fp::ZERO, Fp::from(present_nf))?;

        // `nf_next` is the next leaf: `tail = [present_nf] ++ next_tail`
        // (`tail(X) = present_nf + X·next_tail(X)`), `nf_next = next_tail.eval(0)`.
        let next_tail_poly = Polynomial::from(next_tail_seq);
        enforce_shifted_combination(
            ctx,
            [(&next_tail_poly, 1)],
            [(Fp::from(present_nf), 0)],
            &tail_poly,
        )
        .map_err(|_relation_err| {
            ragu::Error::InvalidWitness("SpendBind: next leaf not covered".into())
        })?;
        let nf_next_fp = next_tail_poly.eval(Fp::ZERO);
        ctx.enforce_poly_query(next_tail_poly.commit(), Fp::ZERO, nf_next_fp)?;
        let nf_next = Nullifier::from(nf_next_fp);

        // A zero nullifier would collide with the note's own cm tachygram.
        enforce_nonzero(
            Fp::from(present_nf),
            "SpendBind: present-epoch nullifier is zero",
        )?;
        enforce_nonzero(Fp::from(nf_next), "SpendBind: next-epoch nullifier is zero")?;

        Ok(((spendable_cm, present_nf, nf_next, anchor), ()))
    }
}
