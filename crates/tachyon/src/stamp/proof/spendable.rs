//! Spendable bootstrap and lift.
//!
//! The spendable carries `(present_nf, anchor, cm)`: the note's current
//! nullifier `GGM(mk, e)`, its pool position, and the minted-note commitment
//! binding the lineage (and its value) across lifts. [`SpendableInit`]
//! bootstraps it from a minted note; [`SpendableLift`] advances it over
//! [`VerifiedUnspent`](super::pool::VerifiedUnspent) segments.

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use pasta_curves::{Eq, Fp};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Step, Suffix,
    constraint::{enforce_equal_point, enforce_zero},
};

use super::{
    delegation::NullifierHeader,
    pool::{AnchorChain, VerifiedUnspent},
};
use crate::{
    note::{self, Nullifier},
    primitives::{Anchor, NfSeqCommit, TachygramSetPoly},
};

/// Wallet's spendable position `(present_nf, anchor, cm)`
///
/// The note's current-epoch nullifier and pool position (advanced per lift)
/// plus the minted-note commitment, threaded unchanged so the spent value
/// cannot drift to a different same-`mk` note.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    /// `(present_nf, anchor, cm)`. `present_nf` and `anchor` advance per lift;
    /// `cm` threads unchanged.
    type Data = (Nullifier, Anchor, note::Commitment);

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out
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
    /// `(pre_epoch_anchor, pre_cm_anchor, creation_set, present_nf)`.
    /// `pre_epoch_anchor` is the prior epoch's terminal anchor (folded into the
    /// boundary); `pre_cm_anchor` the anchor immediately before the cm-stamp.
    type Witness<'source> = (Anchor, Anchor, TachygramSetPoly, Nullifier);

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (pre_epoch_anchor, pre_cm_anchor, creation_set, present_nf): Self::Witness<'source>,
        (chain_start, chain_end): <Self::Left as Header>::Data,
        (range_commit, range_start, range_end, cm): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Bind `present_nf` to the single derived starting leaf `GGM(mk, epoch)`.
        enforce_zero(
            Fp::from(range_end) - (Fp::from(range_start) + Fp::ONE),
            "SpendableInit: starting range must span one epoch",
        )?;
        let generators = Pasta::host_generators(Pasta::baked()).g();

        #[expect(clippy::expect_used, reason = "constant size")]
        let g0 = generators.first().expect("at least one generator");

        let present_commit = NfSeqCommit::from(g0 * Fp::from(present_nf));
        enforce_equal_point(
            Eq::from(range_commit),
            Eq::from(present_commit),
            "SpendableInit: present nullifier does not match the derived leaf",
        )?;
        let epoch = range_start;

        // Inclusion: cm ∈ set ⇔ the set polynomial vanishes at cm.
        let cm_point = Fp::from(cm);
        let eval = creation_set.eval(cm_point);
        ctx.enforce_poly_query(creation_set.commit().into(), cm_point, eval)?;
        enforce_zero(eval, "SpendableInit: commitment not in set")?;
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

        Ok(((present_nf, post_cm_anchor, cm), ()))
    }
}

/// Advance the spendable over one [`VerifiedUnspent`] segment.
///
/// Wallet-only, witness-free. Checks `cm`, `start_nf == present_nf`, and anchor
/// adjacency, then advances to the tip `(end_nf, end_anchor)`.
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
        (present_nf, spendable_anchor, cm): <Self::Left as Header>::Data,
        (start_anchor, start_nf, end_anchor, end_nf, verified_cm, _epoch): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(verified_cm) - Fp::from(cm),
            "SpendableLift: verified unspent cm does not match spendable",
        )?;
        enforce_zero(
            Fp::from(start_nf) - Fp::from(present_nf),
            "SpendableLift: segment does not start at the lineage nullifier",
        )?;
        enforce_zero(
            Fp::from(start_anchor) - Fp::from(spendable_anchor),
            "SpendableLift: unspent not adjacent to spendable",
        )?;
        Ok(((end_nf, end_anchor, cm), ()))
    }
}
