//! Spendable bootstrap and lift.
//!
//! The spendable carries `(present_nf, anchor, cm)`: the note's current
//! nullifier `F_mk(e)`, its pool position, and the minted-note commitment
//! binding the lineage (and its value) across lifts. [`SpendableInit`]
//! bootstraps it from a minted note; [`SpendableLift`] advances it over
//! [`VerifiedUnspent`](super::pool::VerifiedUnspent) segments.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Header, Index, Step, Suffix,
    constraint::{enforce_equal_point, enforce_zero},
};

use super::{
    delegation::NullifierDerivation,
    pool::{AnchorChain, VerifiedUnspent},
};
use crate::{
    constants::NF_DERIVATION_WIDTH,
    note,
    nullifier::{
        NfWhitenedSpectrum, Nullifier,
        derivation::{NF_COSET_SHIFT, NF_EPOCH_STEP},
    },
    primitives::{Anchor, EpochIndex, TachygramSetPoly},
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
        (
            vec![Fp::from(data.0), Fp::from(data.1), Fp::from(data.2)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Bootstrap a spendable from a minted note, pinned to the creation epoch.
///
/// Wallet-only. Fuses a boundary-rooted [`AnchorChain`] with a wallet
/// [`NullifierDerivation`] that *covers* the creation epoch: reads
/// `present_nf` off the whitened trace at the creation epoch's nullifier point
/// $\sigma \zeta^{\mathsf{creation\_epoch} - \mathsf{deriv\_start}}$, checks
/// `cm in creation_set`, roots
/// the chain at the epoch boundary, and requires the cm-stamp to be its final
/// link.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = AnchorChain;
    type Output = SpendableHeader;
    type Right = NullifierDerivation;
    /// `((pre_epoch_anchor, pre_cm_anchor), creation_set, creation_epoch,
    /// nf_spectrum)`.
    type Witness<'source> = (
        (Anchor, Anchor),
        TachygramSetPoly,
        EpochIndex,
        NfWhitenedSpectrum,
    );

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        ((pre_epoch_anchor, pre_cm_anchor), creation_set, creation_epoch, nf_spectrum): Self::Witness<'source>,
        (chain_start, chain_end): <Self::Left as Header>::Data,
        (cm, deriv_start, deriv_end, nf_commit): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(nf_spectrum.commit()),
            Eq::from(nf_commit),
            "SpendableInit: whitened trace does not match header",
        )?;

        // Native coverage guards: mock stand-ins for the range constraint
        // pinning `off` inside the window, plus the belt-and-braces
        // single-window width check (only `WrapStep` emits the header, always
        // one window wide). `creation_epoch` is consensus-pinned by the chain
        // rooting below; `deriv_start` is a header value.
        if deriv_end.0 - deriv_start.0 != NF_DERIVATION_WIDTH {
            return Err(ragu::Error::InvalidWitness(
                "SpendableInit: derivation is not a single window".into(),
            ));
        }
        if deriv_start.0 > creation_epoch.0 || deriv_end.0 <= creation_epoch.0 {
            return Err(ragu::Error::InvalidWitness(
                "SpendableInit: derivation does not cover the creation epoch".into(),
            ));
        }

        // The creation epoch's nullifier point
        //
        // $$ \ell = \sigma \zeta^{\mathsf{off}} $$
        //
        // The power is a native mock stand-in for a fixed-width (log-width bit)
        // exponentiation chain over the pinned `off`.
        let nf_point =
            *NF_COSET_SHIFT * NF_EPOCH_STEP.pow_vartime([u64::from(creation_epoch - deriv_start)]);

        // Read the creation epoch's nullifier off the whitened trace.
        let present_nf_fp = nf_spectrum.as_ref().eval(nf_point);
        ctx.enforce_poly_query(nf_spectrum.commit().into(), nf_point, present_nf_fp)?;
        let present_nf = Nullifier::from(present_nf_fp);
        let epoch = creation_epoch;

        // Inclusion: $\mathsf{cm} \in \mathsf{set}$ iff the set polynomial
        // vanishes at `cm`.
        let cm_in_set = creation_set.eval(cm.into());
        ctx.enforce_poly_query(creation_set.commit().into(), cm.into(), cm_in_set)?;
        enforce_zero(cm_in_set, "SpendableInit: commitment not in set")?;
        let creation_commit = creation_set.commit();

        // Pin the lineage's starting epoch to consensus. Consensus anchor
        // membership of the eventual spend anchor requires `chain_start` to be
        // the real epoch boundary. `next_epoch` (`Tachyon-EpochStp`) is the sole
        // epoch-folding domain and the chain is intra-epoch, so matching
        // `pre_epoch_anchor.next_epoch(epoch)` against that boundary forces
        // `epoch == E`, tying the derived range's starting epoch to the
        // creation epoch.
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

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (cm, present_nf, spendable_anchor): <Self::Left as Header>::Data,
        (verified_cm, anchor_prev, (_epoch_start, nf_start), (_epoch_end, nf_end), anchor_last): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(verified_cm) - Fp::from(cm),
            "SpendableLift: verified unspent cm does not match spendable",
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
