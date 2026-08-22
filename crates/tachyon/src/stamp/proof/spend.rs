//! Spend nullifier-binding header and step.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Step, Suffix,
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

use super::{delegation::NullifierDerivation, spendable::SpendableHeader};
use crate::{
    note,
    nullifier::Nullifier,
    primitives::{Anchor, NF_FACTOR_RESIDUE, NfSeqPoly},
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
/// The range is tied to the lineage's note by `nf_cm == spendable_cm` (both
/// are the note commitment, bound where the range was derived and at
/// [`SpendableInit`](super::spendable::SpendableInit) respectively), so no
/// note witness is needed here. **Any range covering the lineage's epoch and
/// the next is accepted**: the divisibility
/// $\mathsf{nf\_seq} = F_{e,\mathsf{present\_nf}} \cdot
/// F_{e+1,\mathsf{nf\_next}} \cdot \mathsf{complement}$ confirms the pair
/// at adjacent epochs, with `present_nf` pinned against the spendable. Both
/// nullifiers are emitted on the [`SpendHeader`] for the action-producing
/// step to publish.
///
/// # Soundness
///
/// Both factors are evaluated natively, and neither epoch index is free: the
/// present factor's scalars are left-header fields, fixed by the recursive
/// verification of the spendable PCD before the challenge, and the next
/// factor's index is that epoch plus one. The free `nf_next` is the only
/// scalar needing a pin, and it gets one from the scalar-binding point
/// $G_0 \cdot \mathsf{nf\_next}$, absorbed into the challenge — without it a
/// nullifier is solvable from the identity after the challenge exists, since
/// $\mathsf{nf} = \sqrt\[3\]{t + c} - (e+1)z$. Adjacency is the factor indices
/// `e` and `e + 1`, not a positional convention.
///
/// The step compares no bounds against the derivation's range. Coverage is
/// what the divisibility concludes: an epoch the derivation does not hold has
/// no factor to divide out.
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendHeader;
    type Right = NullifierDerivation;
    /// `(nf_seq, complement_seq, nf_next)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, Nullifier);

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (nf_seq, complement_seq, nf_next): Self::Witness<'source>,
        (spendable_cm, (spendable_epoch, present_nf), anchor): <Self::Left as Header>::Data,
        (nf_cm, _, nf_commit, _): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(nf_cm) - Fp::from(spendable_cm),
            "SpendBind: derived range does not match note",
        )?;
        enforce_equal_point(
            Eq::from(nf_seq.commit()),
            Eq::from(nf_commit),
            "SpendBind: covering sequence does not match header",
        )?;

        // The 2-wide read at the lineage's epoch: the divisibility
        // `nf_seq = present · next · complement` at a challenge absorbing the
        // witnessed commitments and the scalar-binding point of the free
        // `nf_next`; the present factor is native from the spendable header,
        // pinned by the recursive verification of the left PCD.
        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let z = ctx.derive_challenge(&[
            nf_seq.commit().into(),
            complement_seq.commit().into(),
            g0 * Fp::from(nf_next),
        ])?;
        let nf_seq_at_z = nf_seq.eval(z);
        let complement_at_z = complement_seq.eval(z);
        let present_linear = Fp::from(u64::from(spendable_epoch.0) + 1) * z + Fp::from(present_nf);
        let next_linear = Fp::from(u64::from(spendable_epoch.next().0) + 1) * z + Fp::from(nf_next);
        enforce_zero(
            nf_seq_at_z
                - (present_linear.square() * present_linear - NF_FACTOR_RESIDUE)
                    * (next_linear.square() * next_linear - NF_FACTOR_RESIDUE)
                    * complement_at_z,
            "SpendBind: nullifier pair does not match the derivation",
        )?;
        ctx.enforce_poly_query(nf_seq.commit().into(), z, nf_seq_at_z)?;
        ctx.enforce_poly_query(complement_seq.commit().into(), z, complement_at_z)?;

        // Nullifiers are nonzero; zero is reserved.
        enforce_nonzero(
            Fp::from(present_nf),
            "SpendBind: present-epoch nullifier is zero",
        )?;
        enforce_nonzero(Fp::from(nf_next), "SpendBind: next-epoch nullifier is zero")?;

        Ok(((spendable_cm, present_nf, nf_next, anchor), ()))
    }
}
