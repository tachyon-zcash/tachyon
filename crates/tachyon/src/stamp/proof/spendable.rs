//! Spendable bootstrap and lift.
//!
//! The spendable carries `(cm, (epoch, present_nf), anchor)`: the note's
//! current epoch and its nullifier `GGM(mk, epoch)` there, its pool position,
//! and the minted-note commitment binding the lineage (and its value) across
//! lifts. [`SpendableInit`]
//! bootstraps it from a minted note; [`SpendableLift`] advances it over
//! [`Unspent`] segments.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix, constraint::enforce_zero};

use super::{delegation::NullifierHeader, pool::Unspent};
use crate::{
    note,
    nullifier::Nullifier,
    primitives::{Anchor, EpochIndex, TachygramSetPoly},
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
/// Wallet-only, one-child over the wallet's single-leaf [`NullifierHeader`]:
/// binds `present_nf` to the proven leaf, checks `cm in creation_set`, and
/// computes the post-cm anchor from a free-witnessed predecessor.
///
/// The emitted anchor binds nothing here: `pre_cm_anchor` is a free witness,
/// so a standalone spendable proves nothing about real chain coverage.
/// Binding closes downstream. [`SpendableLift`] adjacency threads the anchor
/// to the eventual spend, whose anchor consensus checks for chain membership;
/// a genuine chain node is `H(prev || epoch || commit)` under the stamp
/// domain, so preimage resistance forces the witnessed `pre_cm_anchor`,
/// `epoch`, and `creation_commit` to be the real predecessor, the real
/// creation epoch, and the real cm-stamp. The same argument pins the derived
/// range's starting epoch: a wrong `epoch` folds into an anchor off the
/// published sequence.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableHeader;
    type Right = ();
    /// `(pre_cm_anchor, creation_set, present_nf)`.
    type Witness<'source> = (Anchor, TachygramSetPoly, Nullifier);

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (pre_cm_anchor, creation_set, present_nf): Self::Witness<'source>,
        (cm, (nf_epoch_start, nf_start), _nf_seq_commit, (nf_epoch_end, _nf_end)): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Bind `present_nf` to the single derived starting leaf `GGM(mk, epoch)`.
        enforce_zero(
            Fp::from(nf_epoch_end) - (Fp::from(nf_epoch_start) + Fp::ONE),
            "SpendableInit: starting range must span one epoch",
        )?;
        enforce_zero(
            Fp::from(present_nf) - Fp::from(nf_start),
            "SpendableInit: present nullifier does not match the derived leaf",
        )?;
        let epoch = nf_epoch_start;

        // Inclusion: cm ∈ set ⇔ the set polynomial vanishes at cm.
        let cm_point = Fp::from(cm);
        let eval = creation_set.eval(cm_point);
        ctx.enforce_poly_query(creation_set.commit().into(), cm_point, eval)?;
        enforce_zero(eval, "SpendableInit: commitment not in set")?;
        let creation_commit = creation_set.commit();

        // The anchor immediately after the creation stamp, computed in-circuit
        // so the proof certifies the fold of `epoch` and `creation_commit`;
        // consensus membership of the eventual spend anchor binds the rest
        // (see the step doc).
        let post_cm_anchor = pre_cm_anchor.next_stamp(epoch, &creation_commit);

        Ok(((cm, (epoch, present_nf), post_cm_anchor), ()))
    }
}

/// Advance the spendable over one [`Unspent`] segment.
///
/// Wallet-only, witness-free. Checks `cm`, the boundary pair `(epoch_start,
/// nf_start) == (epoch, present_nf)`, and anchor adjacency, then advances to
/// the tip `(epoch_end, nf_end, anchor_last)`.
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

    const INDEX: Index = Index::new(11);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (spendable_cm, (spendable_epoch, present_nf), spendable_anchor): <Self::Left as Header>::Data,
        (
            unspent_cm,
            unspent_anchor_prev,
            (unspent_epoch_start, unspent_nf_start),
            (unspent_epoch_end, unspent_nf_end),
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
                (unspent_epoch_end, unspent_nf_end),
                unspent_anchor_last,
            ),
            (),
        ))
    }
}
