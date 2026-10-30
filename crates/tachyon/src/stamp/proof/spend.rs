//! Spend nullifier-binding header and step.

extern crate alloc;
use ragu::{Encoded, Header, Index, Step, StepCtx, pasta::Fp};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};

use super::{delegation::NoteSecret, spendable::NoteSpendable};
pub use crate::stamp::headers::spend::SpendHeader;
use crate::{
    constants::MAX_MONEY,
    ragu_constraint::{enforce_nonzero, enforce_zero},
    value,
};

/// Derives a spend's epoch nullifier pair from the note's master key, commits
/// the note's value, and binds both to the spendable lineage.
///
/// The secret is tied to the lineage's note by `secret_cm == spendable_cm`.
/// The pair is `mk`'s nullifiers at the lineage's epoch $e$ and at $e + 1$,
/// one group sponge each. Both are emitted on the [`SpendHeader`] for the
/// action-producing step to publish, with the note's `pk` and
/// $\mathsf{cv} = \[v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R}$.
///
/// Two permutations (the pair) and two scalar multiplications (`cv`).
///
/// # Soundness
///
/// `mk`, `cm` and the note are threaded from the right header, bound together
/// at [`NoteSeed`](super::delegation::NoteSeed). `epoch_current` is a
/// left-header field, and $e + 1$ comes from
/// [`EpochIndex::next`](crate::primitives::EpochIndex::next). The pair, `pk`
/// and the value are threaded or computed from threaded values, so nothing in
/// them is free. `rcv` is free; it only blinds `cv`.
///
/// Two sponges run whether or not $e$ and $e + 1$ share a group.
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = NoteSpendable;
    type Output = SpendHeader;
    type Right = NoteSecret;
    type Shared = ();
    /// `(rcv,)`
    type Witness<'source> = (value::Trapdoor,);

    const INDEX: Index = Index::new(8);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let (rcv,) = witness.take();
            let (spendable_cm, spendable_epoch_current, anchor) = left.take();
            let (secret_cm, note, mk) = right.take();
            enforce_zero(
                Fp::from(secret_cm) - Fp::from(spendable_cm),
                "SpendBind: secret does not match note",
            )?;
            if u64::from(note.value) > MAX_MONEY {
                return Err(ragu_core::Error::InvalidWitness(
                    "SpendBind: note value exceeds maximum".into(),
                ));
            }

            // The pair needs a following epoch; the final epoch has none.
            let epoch_next = spendable_epoch_current.next().ok_or_else(|| {
                ragu_core::Error::InvalidWitness(
                    "SpendBind: no epoch follows the spend epoch".into(),
                )
            })?;

            // TODO: a real circuit needs a low-bit decomposition of each epoch for
            // its group start and position; mock ragu computes both natively.
            let nf_current = mk.derive_nullifier(spendable_epoch_current);
            let nf_next = mk.derive_nullifier(epoch_next);

            // A zero nullifier would collide with the note's own cm tachygram.
            enforce_nonzero(
                Fp::from(nf_current),
                "SpendBind: current-epoch nullifier is zero",
            )?;
            enforce_nonzero(Fp::from(nf_next), "SpendBind: next-epoch nullifier is zero")?;

            Ok((
                (
                    spendable_cm,
                    nf_current,
                    nf_next,
                    anchor,
                    note.pk,
                    rcv.commit(note.value),
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
    }
}
