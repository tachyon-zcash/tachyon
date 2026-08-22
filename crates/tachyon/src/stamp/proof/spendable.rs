//! Spendable bootstrap and lift.
//!
//! The spendable carries `(cm, (epoch, present_nf), anchor)`: the note's
//! current epoch and its nullifier `F_mk(epoch)` there, its pool position,
//! and the minted-note commitment binding the lineage (and its value) across
//! lifts. [`SpendableInit`]
//! bootstraps it from a minted note; [`SpendableLift`] advances it over
//! [`Unspent`] segments.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Step, Suffix,
    constraint::{enforce_equal_point, enforce_zero},
};

use super::{delegation::NullifierDerivation, pool::Unspent};
use crate::{
    note,
    nullifier::Nullifier,
    primitives::{Anchor, EpochIndex, NF_FACTOR_RESIDUE, NfSeqPoly, TachygramSetPoly},
};

/// Wallet's spendable position `(cm, (epoch, present_nf), anchor)`
///
/// The note's current epoch and its nullifier there, plus the pool position
/// (all advanced per lift) and the minted-note commitment, threaded unchanged
/// so the spent value cannot drift to a different same-`mk` note.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    /// `(cm, (epoch, present_nf), anchor)`. `cm` threads unchanged; the rest
    /// advances per lift. The boundary pairing matches
    /// [`Unspent`]'s, which is what a lift checks continuity against.
    type Data = (note::Commitment, (EpochIndex, Nullifier), Anchor);

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, (epoch, present_nf), anchor) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(u64::from(epoch.0)),
                Fp::from(present_nf),
                Fp::from(anchor),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Bootstrap a spendable from a minted note, pinned to the creation epoch.
///
/// Wallet-only, one-child over a wallet [`NullifierDerivation`]. **Any window
/// covering the creation epoch is accepted**, so one derived window feeds
/// init, bind, and spend alike: the divisibility
/// $\mathsf{nf\_seq} = F_{\mathsf{creation\_epoch},\mathsf{present\_nf}}
/// \cdot \mathsf{complement}$ forces `present_nf` to the window's genuine
/// member at the creation epoch, with the complement absorbing the window's
/// remaining span.
/// `cm` is proven among the creation stamp's tachygrams, which is the
/// consensus binding, and the post-cm anchor folds from a free-witnessed
/// predecessor.
///
/// # Soundness
///
/// Every free witness closes through consensus or the read. `pre_cm_anchor`,
/// `creation_epoch` and the creation set close through consensus anchor
/// membership: the fold absorbs the epoch and the set commit, a genuine
/// chain node is `H(prev || epoch || commit)` under the stamp domain, and
/// preimage resistance forces all three once the eventual spend's anchor is
/// consensus-checked — a wrong epoch folds into an anchor off the published
/// sequence. `present_nf` closes through the read identity: its
/// scalar-binding point $G_0 \cdot \mathsf{present\_nf}$ is absorbed into
/// the transcript challenge, fixing the free scalar before the challenge
/// exists, so the identity forces the read factor to the emitted pair.
/// Without that point the nullifier would be solvable once the challenge is
/// known, since $\mathsf{nf} = \sqrt\[3\]{t + c} - (e+1)z$.
///
/// `creation_epoch` needs no bound check against the derivation's range: the
/// divisibility forces $F_{\mathsf{creation\_epoch},\mathsf{present\_nf}}$ to
/// be one of the derivation's own factors, so the epoch is one the derivation
/// actually holds a member for — a stronger statement than lying between its
/// bounds.
///
/// No sameness constraint ties this window to the one the spend later reads:
/// `cm` equality binds every window of the same note to the same lattice.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = NullifierDerivation;
    type Output = SpendableHeader;
    type Right = ();
    /// `(pre_cm_anchor, creation_set, creation_epoch, present_nf, nf_seq,
    /// complement_seq)`.
    type Witness<'source> = (
        Anchor,
        TachygramSetPoly,
        EpochIndex,
        Nullifier,
        NfSeqPoly,
        NfSeqPoly,
    );

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (pre_cm_anchor, creation_set, creation_epoch, present_nf, nf_seq, complement_seq): Self::Witness<
            'source,
        >,
        (cm, _, nf_commit, _): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(nf_seq.commit()),
            Eq::from(nf_commit),
            "SpendableInit: covering sequence does not match header",
        )?;

        // The 1-wide read at the creation epoch: the divisibility
        // `nf_seq = read · complement` at a challenge absorbing the witnessed
        // commitments and the scalar-binding point of the free `present_nf`,
        // with the read factor evaluated natively.
        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let z = ctx.derive_challenge(&[
            nf_seq.commit().into(),
            complement_seq.commit().into(),
            g0 * Fp::from(present_nf),
        ])?;
        let nf_seq_at_z = nf_seq.eval(z);
        let complement_at_z = complement_seq.eval(z);
        let linear = Fp::from(u64::from(creation_epoch.0) + 1) * z + Fp::from(present_nf);
        enforce_zero(
            nf_seq_at_z - (linear.square() * linear - NF_FACTOR_RESIDUE) * complement_at_z,
            "SpendableInit: nullifier does not match the derivation",
        )?;
        ctx.enforce_poly_query(nf_seq.commit().into(), z, nf_seq_at_z)?;
        ctx.enforce_poly_query(complement_seq.commit().into(), z, complement_at_z)?;

        // Inclusion: $\mathsf{cm} \in \mathsf{set}$ iff the set polynomial
        // vanishes at `cm`.
        let cm_in_set = creation_set.eval(cm.into());
        ctx.enforce_poly_query(creation_set.commit().into(), cm.into(), cm_in_set)?;
        enforce_zero(cm_in_set, "SpendableInit: commitment not in set")?;
        let creation_commit = creation_set.commit();

        // The anchor immediately after the creation stamp, computed in-circuit
        // so the proof certifies the fold of `epoch` and `creation_commit`;
        // consensus membership of the eventual spend anchor binds the rest.
        let post_cm_anchor = pre_cm_anchor.next_stamp(creation_epoch, &creation_commit);

        Ok(((cm, (creation_epoch, present_nf), post_cm_anchor), ()))
    }
}

/// Advance the spendable over one [`Unspent`] segment.
///
/// Wallet-only, witness-free. Checks `cm`, the boundary pair `(epoch_start,
/// nf_start) == (epoch, present_nf)`, and anchor adjacency, then advances to
/// the tip `(epoch_last, nf_last, anchor_last)`.
///
/// The segment may span any number of epochs. A lineage resting on its epoch's
/// terminal anchor advances the same way, over a segment that opens with the
/// boundary tick ([`EndEpochUnspentSeed`](super::pool::EndEpochUnspentSeed)).
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (spendable_cm, (spendable_epoch, present_nf), spendable_anchor): <Self::Left as Header>::Data,
        (
            unspent_cm,
            unspent_anchor_prev,
            (unspent_epoch_start, unspent_nf_start),
            (unspent_epoch_last, unspent_nf_last),
            unspent_anchor_last,
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(unspent_cm) - Fp::from(spendable_cm),
            "SpendableLift: unspent cm does not match spendable",
        )?;
        enforce_zero(
            Fp::from(unspent_nf_start) - Fp::from(present_nf),
            "SpendableLift: segment does not start at the lineage nullifier",
        )?;
        enforce_zero(
            Fp::from(unspent_epoch_start) - Fp::from(spendable_epoch),
            "SpendableLift: segment does not start at the lineage epoch",
        )?;
        enforce_zero(
            Fp::from(unspent_anchor_prev) - Fp::from(spendable_anchor),
            "SpendableLift: unspent not adjacent to spendable",
        )?;
        Ok((
            (
                spendable_cm,
                (unspent_epoch_last, unspent_nf_last),
                unspent_anchor_last,
            ),
            (),
        ))
    }
}
