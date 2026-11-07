//! Spend nullifier-binding header and step.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ragu::{Header, Index, Step, Suffix};

use super::{
    super::super::{
        keys::PaymentKey,
        note,
        nullifier::Nullifier,
        pasta::{Ep, Eq, Fp, Fq},
        primitives::Anchor,
        ragu_constraint::{enforce_nonzero, enforce_zero},
        value,
    },
    delegation::NoteSecret,
    scale::{self, R, ScaleResult},
    spendable::NoteSpendable,
};

/// Header binding a spend to its lineage note, epoch nullifier pair and value
/// commitment.
///
/// Carries the note commitment `cm`, the lineage's nullifier and its
/// neighbour `(nf_current, nf_next)` derived from the note's master key, the
/// pool `anchor`, the note's payment key `pk` and the value commitment `cv`.
/// [`SpendAction`](super::stamp::SpendAction) publishes the pair unordered,
/// ties its `ak` to `pk`, and produces `rk`.
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    /// `(cm, nf_current, nf_next, anchor, pk, cv)`
    type Data = (
        note::Commitment,
        Nullifier,
        Nullifier,
        Anchor,
        PaymentKey,
        value::Commitment,
    );

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, nf_current, nf_next, anchor, pk, cv) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(nf_current),
                Fp::from(nf_next),
                Fp::from(anchor),
                Fp::from(pk),
            ],
            Vec::new(),
            vec![Ep::from(cv)],
            Vec::new(),
        )
    }
}

/// Wallet-private bounded note and nullifier provenance.
#[derive(Debug)]
pub struct SpendPrepared;

impl Header for SpendPrepared {
    /// `(cm, nf_current, nf_next, anchor, pk, value)`
    type Data = (
        note::Commitment,
        Nullifier,
        Nullifier,
        Anchor,
        PaymentKey,
        value::Positive,
    );

    const SUFFIX: Suffix = Suffix::new(23);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, current, next, anchor, pk, value) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(current),
                Fp::from(next),
                Fp::from(anchor),
                Fp::from(pk),
                Fp::from(u64::from(value)),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Joins the note secret to its spendable lineage and derives both nullifiers.
/// Two sponges run, including at a shared group. No polynomials.
#[derive(Debug)]
pub struct SpendPrepare;

impl Step for SpendPrepare {
    type Aux<'source> = ();
    type Left = NoteSpendable;
    type Output = SpendPrepared;
    type Right = NoteSecret;
    /// `()`
    type Witness<'source> = ();

    const INDEX: Index = Index::new(45);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (): Self::Witness<'source>,
        (spendable_cm, spendable_epoch_current, anchor): <Self::Left as Header>::Data,
        (secret_cm, note, mk): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(secret_cm) - Fp::from(spendable_cm),
            "SpendPrepare: secret does not match note",
        )?;
        scale::amount_bits(note.value)?;

        // The pair needs a following epoch; the final epoch has none.
        let epoch_next = spendable_epoch_current.next().ok_or_else(|| {
            ragu_core::Error::InvalidWitness(
                "SpendPrepare: no epoch follows the spend epoch".into(),
            )
        })?;

        // TODO: a real circuit needs a low-bit decomposition of each epoch for
        // its group start and position; mock ragu computes both natively.
        let nf_current = mk.derive_nullifier(spendable_epoch_current);
        let nf_next = mk.derive_nullifier(epoch_next);

        // A zero nullifier would collide with the note's own cm tachygram.
        enforce_nonzero(
            Fp::from(nf_current),
            "SpendPrepare: current-epoch nullifier is zero",
        )?;
        enforce_nonzero(
            Fp::from(nf_next),
            "SpendPrepare: next-epoch nullifier is zero",
        )?;

        Ok((
            (
                spendable_cm,
                nf_current,
                nf_next,
                anchor,
                note.pk,
                note.value,
            ),
            (),
        ))
    }
}

/// Adds the bounded positive value product to a private R certificate.
/// Seventeen value windows; no polynomials.
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = SpendPrepared;
    type Output = SpendHeader;
    type Right = ScaleResult<R>;
    /// `()`
    type Witness<'source> = ();

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (): Self::Witness<'source>,
        (cm, current, next, anchor, pk, value): <Self::Left as Header>::Data,
        (_lo, _hi, point, identity): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let product = scale::value_product::<false>(value)?;
        let cv = scale::finite(product + scale::decode(point, identity)?)?;
        Ok((
            (cm, current, next, anchor, pk, value::Commitment::from(cv)),
            (),
        ))
    }
}
