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
    constants::NF_DERIVATION_WIDTH,
    note,
    nullifier::{
        NfWhitenedSpectrum, Nullifier,
        derivation::{NF_COSET_ID, NF_COSET_SHIFT, NF_EPOCH_STEP},
    },
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
/// [`WrapStep`](super::delegation::WrapStep) and
/// [`SpendableInit`](super::spendable::SpendableInit) respectively), so no note
/// witness is needed here. Witnesses the whitened trace $W$ (bound to the
/// derivation's `nf_commit`) and a nullifier point $\ell$, pinned to the
/// last-column coset by $\ell^{\mathsf{width}} = \sigma^{\mathsf{width}}$;
/// on the coset $W$ takes exactly the window's genuine nullifiers, so
/// $W(\ell) = \mathsf{present\_nf}$ (a `SpendableHeader` value) pins $\ell$
/// to the present epoch's nullifier point, and $\mathsf{nf\_next} = W(\zeta
/// \ell)$ reads the next epoch's, with $\ell \neq \sigma
/// \zeta^{\mathsf{width}-1}$ rejecting the wrap past the window's last epoch.
/// Both nullifiers are emitted on the [`SpendHeader`] for the
/// action-producing step to publish.
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendHeader;
    type Right = NullifierDerivation;
    /// `(nf_spectrum, nf_point)`.
    type Witness<'source> = (NfWhitenedSpectrum, Fp);

    const INDEX: Index = Index::new(11);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (nf_spectrum, nf_point): Self::Witness<'source>,
        (spendable_cm, present_nf, anchor): <Self::Left as Header>::Data,
        (deriv_cm, deriv_start, deriv_end, nf_commit): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(deriv_cm) - Fp::from(spendable_cm),
            "SpendBind: derivation does not match note",
        )?;
        enforce_equal_point(
            Eq::from(nf_spectrum.commit()),
            Eq::from(nf_commit),
            "SpendBind: whitened trace does not match header",
        )?;
        // Belt-and-braces single-window width check (only `WrapStep` emits
        // the header, always one window wide).
        if deriv_end.0 - deriv_start.0 != NF_DERIVATION_WIDTH {
            return Err(ragu::Error::InvalidWitness(
                "SpendBind: derivation is not a single window".into(),
            ));
        }

        // Pin $\ell$ to the last-column coset $\sigma \langle \zeta \rangle$:
        // $\ell^{\mathsf{width}} = \sigma^{\mathsf{width}}$
        // exactly characterizes the coset (a log-width squaring chain).
        let mut point_power = nf_point;
        for _ in 0..NF_DERIVATION_WIDTH.ilog2() {
            point_power = point_power.square();
        }
        enforce_zero(
            point_power - *NF_COSET_ID,
            "SpendBind: nullifier point is not on the last column",
        )?;

        // The next epoch's nullifier point sits one row on: $\zeta \ell$. Reject the
        // wrap from the window's last epoch back to its first ($\zeta \ell =
        // \sigma$).
        let next_point = *NF_EPOCH_STEP * nf_point;
        enforce_nonzero(
            next_point - *NF_COSET_SHIFT,
            "SpendBind: next epoch is past the derivation",
        )?;

        // On the coset `W` takes exactly the window's genuine nullifiers, so
        // matching the lineage-pinned `present_nf` pins $\ell$ to the present
        // epoch's nullifier point (within-window distinctness).
        let present_at_point = nf_spectrum.as_ref().eval(nf_point);
        ctx.enforce_poly_query(nf_spectrum.commit().into(), nf_point, present_at_point)?;
        enforce_zero(
            present_at_point - Fp::from(present_nf),
            "SpendBind: present nullifier does not match the derivation",
        )?;

        let nf_next_fp = nf_spectrum.as_ref().eval(next_point);
        ctx.enforce_poly_query(nf_spectrum.commit().into(), next_point, nf_next_fp)?;
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
