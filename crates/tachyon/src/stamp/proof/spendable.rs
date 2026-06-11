//! Spendable bootstrap and lift.
//!
//! The spendable carries `(present_nf, anchor, cm, creation_epoch,
//! present_epoch)`: the note's current nullifier `E_mk(psi' + e)`, its pool
//! position, the minted-note commitment binding the lineage (and its value),
//! the creation epoch `E_0` (the offset origin), and the present epoch (the
//! absolute epoch at which `present_nf` is active). `present_nf`, `anchor`, and
//! `present_epoch` advance per lift; `cm` and `creation_epoch` thread
//! unchanged. [`SpendableInit`] bootstraps it from a minted note;
//! [`SpendableLift`] advances it over
//! [`VerifiedUnspent`](super::pool::VerifiedUnspent) segments.

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use pasta_curves::{Eq, Fp};
use ragu::{
    Header, Index, Polynomial, Step, Suffix,
    constraint::{enforce_nonzero, enforce_zero},
};

use crate::{
    NfEmitterPoly,
    constants::NF_EMITTERS,
    note::{Commitment as NoteCommitment, Nullifier},
    primitives::{Anchor, EpochIndex, TachygramSetPoly},
    relations::enforce::enforce_nullifier_query,
    stamp::proof::{
        delegation::NullifierDerivation,
        pool::{AnchorChain, VerifiedUnspent},
    },
};

/// Wallet's spendable position
///
/// The note's current-epoch nullifier, pool position, and present epoch
/// (advanced per lift) plus the minted-note commitment and creation epoch,
/// threaded unchanged across lifts.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    /// `(present_nf, anchor, cm, creation_epoch, present_epoch)`. `present_nf`,
    /// `anchor`, and `present_epoch` advance per lift; `cm` and
    /// `creation_epoch` (the offset origin `E_0`, bound at
    /// [`SpendableInit`]) thread unchanged, so the lift's `E_0` can be
    /// reconciled against it. `present_epoch` is the absolute epoch at
    /// which `present_nf` is the active nullifier, so the spend offset is
    /// `present_epoch − creation_epoch`.
    type Data = (Nullifier, Anchor, NoteCommitment, EpochIndex, EpochIndex);

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 4 + 4);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out.extend_from_slice(&data.3.0.to_le_bytes());
        out.extend_from_slice(&data.4.0.to_le_bytes());
        out
    }
}

/// Bootstrap a spendable from a minted note, pinned to the creation epoch.
///
/// Wallet-only. Fuses a boundary-rooted [`AnchorChain`] with the wallet's
/// single-leaf [`NullifierHeader`]: binds
/// `present_nf` to the proven leaf, checks `cm in creation_set`, roots the
/// chain at the epoch boundary, and requires the cm-stamp to be its final link.
///
/// TODO: presently, a spendable can only be lifted by an unspent proof starting
/// at its precise anchor. ideally, a user should request whole-epoch proofs
/// from the sync service to maximize anonymity. so, we need some way to adjust
/// an anchor when necessary.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = AnchorChain;
    type Output = SpendableHeader;
    type Right = NullifierDerivation;
    /// `(pre_epoch_anchor, pre_cm_anchor, creation_set, polys)`.
    /// `pre_epoch_anchor` is the prior epoch's terminal anchor (folded into the
    /// boundary); `pre_cm_anchor` the anchor immediately before the cm-stamp;
    /// `polys` the `N` derivation polynomials, bound to the header commitments
    /// (the present nullifier is computed in-circuit, not witnessed).
    type Witness<'source> = (
        Anchor,
        Anchor,
        TachygramSetPoly,
        [NfEmitterPoly; NF_EMITTERS],
    );

    const INDEX: Index = Index::new(11);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (pre_epoch_anchor, pre_cm_anchor, creation_set, polys): Self::Witness<'source>,
        (chain_start, chain_end): <Self::Left as Header>::Data,
        (commits, _digest, cm, creation_epoch, shift, _ratios): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // The present nullifier is the creation-epoch query `nf_0 = Σ_j T_j(c)`
        // (offset d = 0: unit weights, point = the secret shift c). The query
        // binds the witnessed polys to the certified derivation commitments.
        let commitments: [Eq; NF_EMITTERS] = commits.map(|commit| commit.0);
        let trace_polys: [Polynomial; NF_EMITTERS] = polys.map(|poly| poly.0);
        let present_fp = enforce_nullifier_query(
            ctx,
            &commitments,
            &trace_polys,
            shift.0,
            &[Fp::ONE; NF_EMITTERS],
        )?;
        enforce_nonzero(present_fp, "SpendableInit: creation nullifier is zero")?;
        let present_nf = Nullifier::from(present_fp);

        // Inclusion: cm ∈ set ⇔ the set polynomial vanishes at cm.
        let cm_point = Fp::from(cm);
        let eval = creation_set.eval(cm_point);
        ctx.enforce_poly_query(creation_set.commit().into(), cm_point, eval)?;
        enforce_zero(eval, "SpendableInit: commitment not in set")?;
        let creation_commit = creation_set.commit();

        // Pin the lineage's starting epoch to consensus and bind the header's
        // creation epoch E_0 to it. `next_epoch` (`Tachyon-EpochStp`) is the sole
        // epoch-folding domain and the chain is intra-epoch, so matching
        // `pre_epoch_anchor.next_epoch(creation_epoch)` against that boundary
        // forces `creation_epoch == E` — SpendableInit is the sole gatekeeper
        // pinning E_0 to the real creation epoch.
        enforce_zero(
            Fp::from(chain_start) - Fp::from(pre_epoch_anchor.next_epoch(creation_epoch)),
            "SpendableInit: chain not rooted at the creation-epoch boundary",
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

        // The present nullifier is the creation-epoch query `nf_0` (offset 0),
        // so the present epoch is the creation epoch itself.
        Ok((
            (
                present_nf,
                post_cm_anchor,
                cm,
                creation_epoch,
                creation_epoch,
            ),
            (),
        ))
    }
}

/// Advance the spendable over one [`VerifiedUnspent`] segment.
///
/// Wallet-only, witness-free. Checks `cm`, `start_nf == present_nf`, anchor
/// adjacency, that the lift's certified offset origin `E_0` matches the
/// lineage's consensus-bound `creation_epoch`, and that the segment's
/// `start_epoch` matches the lineage's `present_epoch`, then advances to the
/// tip `(end_nf, last_anchor)` at `present_epoch`. The `E_0` reconciliation is
/// load-bearing: it forbids lifting against a same-`cm` derivation whose `E_0`
/// was witnessed at a shifted origin, which would otherwise test the pool at
/// the wrong offset arc. The `start_epoch == present_epoch` check is an
/// additive, injectivity-independent absolute-epoch continuity guard; the
/// anchor-exact `prev_anchor == spendable_anchor` check (chain identity) is
/// never relaxed.
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = VerifiedUnspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (present_nf, spendable_anchor, cm, creation_epoch, present_epoch): <Self::Left as Header>::Data,
        (
            prev_anchor,
            start_nf,
            last_anchor,
            end_nf,
            verified_cm,
            verified_e0,
            verified_start_epoch,
            verified_present_epoch,
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(verified_cm) - Fp::from(cm),
            "SpendableLift: verified unspent cm does not match spendable",
        )?;
        enforce_zero(
            Fp::from(verified_e0) - Fp::from(creation_epoch),
            "SpendableLift: lift origin E_0 does not match the lineage creation epoch",
        )?;
        enforce_zero(
            Fp::from(start_nf) - Fp::from(present_nf),
            "SpendableLift: segment does not start at the lineage nullifier",
        )?;
        enforce_zero(
            Fp::from(verified_start_epoch) - Fp::from(present_epoch),
            "SpendableLift: segment does not start at the lineage epoch",
        )?;
        enforce_zero(
            Fp::from(prev_anchor) - Fp::from(spendable_anchor),
            "SpendableLift: unspent not adjacent to spendable",
        )?;
        Ok((
            (
                end_nf,
                last_anchor,
                cm,
                creation_epoch,
                verified_present_epoch,
            ),
            (),
        ))
    }
}
