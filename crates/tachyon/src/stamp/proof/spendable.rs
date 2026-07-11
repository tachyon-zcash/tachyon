//! Spendable bootstrap and lift.
//!
//! The spendable carries `(present_nf, anchor, cm)`: the note's current
//! nullifier `GGM(mk, e)`, its pool position, and the minted-note commitment
//! binding the lineage (and its value) across lifts. [`SpendableInit`]
//! bootstraps it from a minted note; [`SpendableLift`] advances it over
//! [`VerifiedUnspent`](super::pool::VerifiedUnspent) segments.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix, constraint::enforce_zero};

use super::{
    delegation::NullifierHeader,
    pool::{AnchorChain, VerifiedUnspent},
};
use crate::{
    note::{self, Nullifier},
    primitives::{Anchor, TachygramSetPoly},
};

/// Wallet's spendable position `(present_nf, anchor, cm)`
///
/// The note's current-epoch nullifier and pool position (advanced per lift)
/// plus the minted-note commitment, threaded unchanged so the spent value
/// cannot drift to a different same-`mk` note.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    /// `(cm, present_nf, anchor)`. `cm` threads unchanged; `present_nf` and
    /// `anchor` advance per lift.
    type Data = (note::Commitment, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm0, cm1): (Fp, Fp) = data.0.into();
        (
            vec![cm0, cm1, Fp::from(data.1), Fp::from(data.2)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Bootstrap a spendable from a minted note, pinned to the creation epoch.
///
/// Wallet-only. Fuses a boundary-rooted [`AnchorChain`] with the wallet's
/// single-leaf [`NullifierHeader`](super::delegation::NullifierHeader): binds
/// `present_nf` to the proven leaf, checks `cm in creation_set`, roots the
/// chain at the epoch boundary, and requires the cm-stamp to be its final link.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = AnchorChain;
    type Output = SpendableHeader;
    type Right = NullifierHeader;
    /// `((pre_epoch_anchor, pre_cm_anchor), creation_set, present_nf)`.
    type Witness<'source> = ((Anchor, Anchor), TachygramSetPoly, Nullifier);

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        ((pre_epoch_anchor, pre_cm_anchor), creation_set, present_nf): Self::Witness<'source>,
        (chain_start, chain_end): <Self::Left as Header>::Data,
        (cm, (nf_epoch_start, nf_start), _nf_seq_commit, (nf_epoch_end, _nf_end)): <Self::Right as Header>::Data,
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

        // Inclusion: both (cm0, cm1) ∈ set ⇔ the set polynomial vanishes at
        // each — an honest output publishes both, so both must be present.
        let (cm0, cm1): (Fp, Fp) = cm.into();
        let eval0 = creation_set.eval(cm0);
        ctx.enforce_poly_query(creation_set.commit().into(), cm0, eval0)?;
        enforce_zero(eval0, "SpendableInit: cm0 not in set")?;
        let eval1 = creation_set.eval(cm1);
        ctx.enforce_poly_query(creation_set.commit().into(), cm1, eval1)?;
        enforce_zero(eval1, "SpendableInit: cm1 not in set")?;
        let creation_commit = creation_set.commit();

        // Pin the lineage's starting epoch to consensus. Consensus anchor
        // membership of the eventual spend anchor requires `chain_start` to be
        // the real epoch boundary. `next_epoch` (`Tachyon-EpochStp`) is the sole
        // epoch-folding domain and the chain is intra-epoch, so matching
        // `pre_epoch_anchor.next_epoch(epoch)` against that boundary forces
        // `epoch == E`, tying the GGM leaf index to the creation epoch.
        enforce_zero(
            Fp::from(chain_start) - Fp::from(pre_epoch_anchor.next_epoch(epoch)),
            "SpendableInit: chain not rooted at epoch boundary",
        )?;

        // The cm-stamp is the chain's final link: `chain_end ==
        // pre_cm_anchor.next_stamp(cm_commit)`. This ties the cm-inclusion to a
        // real, consensus-pinned stamp and yields `post_cm_anchor` as the chain
        // end; a note created first-in-epoch produces a single-link chain.
        let post_cm_anchor = pre_cm_anchor.next_stamp(&creation_commit);
        enforce_zero(
            Fp::from(chain_end) - Fp::from(post_cm_anchor),
            "SpendableInit: cm-stamp is not the chain's final link",
        )?;

        Ok(((cm, present_nf, post_cm_anchor), ()))
    }
}

/// Advance the spendable over one [`VerifiedUnspent`] segment.
///
/// Wallet-only, witness-free. Checks `cm`, `nf_start == present_nf`, and anchor
/// adjacency, then advances to the tip `(nf_end, anchor_last)`.
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = VerifiedUnspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(13);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (cm, present_nf, spendable_anchor): <Self::Left as Header>::Data,
        (verified_cm, anchor_prev, (_epoch_start, nf_start), (_epoch_end, nf_end), anchor_last): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let (verified_cm0, verified_cm1): (Fp, Fp) = verified_cm.into();
        let (cm0, cm1): (Fp, Fp) = cm.into();
        enforce_zero(
            verified_cm0 - cm0,
            "SpendableLift: verified unspent cm0 does not match spendable",
        )?;
        enforce_zero(
            verified_cm1 - cm1,
            "SpendableLift: verified unspent cm1 does not match spendable",
        )?;
        enforce_zero(
            Fp::from(nf_start) - Fp::from(present_nf),
            "SpendableLift: segment does not start at the lineage nullifier",
        )?;
        enforce_zero(
            Fp::from(anchor_prev) - Fp::from(spendable_anchor),
            "SpendableLift: unspent not adjacent to spendable",
        )?;
        Ok(((cm, nf_end, anchor_last), ()))
    }
}
