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
    Header, Index, Step, Suffix,
    constraint::{enforce_equal_point, enforce_zero},
};

use super::{delegation::NullifierDerivation, pool::Unspent};
use crate::{
    digest::poseidon,
    note,
    nullifier::Nullifier,
    primitives::{Anchor, EpochIndex, NfMarginPoly, NfSeqPoly, NfTailPoly, TachygramSetPoly},
    relations::read::enforce_covering_read_members,
};

/// Wallet's spendable position `(cm, (epoch, present_nf), anchor)`.
///
/// `cm` is threaded unchanged so the spent value cannot drift to a different
/// same-`mk` note.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    /// `(cm, (epoch, present_nf), anchor)`. The boundary pairing matches
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
/// Wallet-only, one-child over a wallet [`NullifierDerivation`]. Any range
/// covering the creation epoch is suitable: the 1-wide covering read forces
/// `present_nf` to the range's genuine member there and the margins absorb the
/// range's remaining span, so the wallet can derive one range covering from
/// before init to past the expected spend and feed the same PCD to init, lift,
/// and spend. `cm` is proven among the creation stamp's tachygrams, which is
/// the consensus binding, and the post-cm anchor folds from a free-witnessed
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
/// sequence. `present_nf` closes through the read identity, whose challenge
/// absorbs it (see `poseidon::read_challenge`): left out, a scalar member is
/// solvable after the challenge is known.
///
/// No sameness constraint ties this range to the one the spend later reads:
/// `cm` equality binds every range of the same note to the same lattice, so
/// one derivation suffices and none is forced.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = NullifierDerivation;
    type Output = SpendableHeader;
    type Right = ();
    /// `(pre_cm_anchor, creation_set, creation_epoch, present_nf, g, older,
    /// tail)`.
    type Witness<'source> = (
        Anchor,
        TachygramSetPoly,
        EpochIndex,
        Nullifier,
        NfSeqPoly,
        NfMarginPoly,
        NfTailPoly,
    );

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (pre_cm_anchor, creation_set, creation_epoch, present_nf, g, older, tail): Self::Witness<
            'source,
        >,
        (
            cm,
            (deriv_start, _deriv_nf_start),
            nf_commit,
            (deriv_end, _deriv_nf_end),
        ): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(g.commit()),
            Eq::from(nf_commit),
            "SpendableInit: covering sequence does not match header",
        )?;

        // Native coverage guard: mock stand-in for the range constraint over
        // the header-pinned bounds. `creation_epoch` is pinned downstream
        // through the emitted anchor (see the step doc).
        if deriv_start.0 > creation_epoch.0 || deriv_end.0 <= creation_epoch.0 {
            return Err(ragu::Error::InvalidWitness(
                "SpendableInit: derivation does not cover the creation epoch".into(),
            ));
        }

        // The 1-wide read at the creation epoch. `present_nf` enters as a
        // scalar monomial, so the challenge must absorb it.
        let margin = u64::from(creation_epoch - deriv_start);
        let z = poseidon::read_challenge(
            g.commit().into(),
            older.commit().into(),
            tail.commit().into(),
            &[Fp::from(present_nf)],
        );
        enforce_covering_read_members(
            ctx,
            g.as_ref(),
            older.as_ref(),
            tail.as_ref(),
            [Fp::from(present_nf)],
            margin,
            z,
            "SpendableInit: nullifier does not match the derivation",
        )?;

        // Inclusion: $\mathsf{cm} \in \mathsf{set}$ iff the set polynomial
        // vanishes at `cm`.
        let cm_in_set = creation_set.eval(cm.into());
        ctx.enforce_poly_query(creation_set.commit().into(), cm.into(), cm_in_set)?;
        enforce_zero(cm_in_set, "SpendableInit: commitment not in set")?;
        let creation_commit = creation_set.commit();

        // The anchor immediately after the creation stamp, computed in-circuit
        // so the proof certifies the fold of `epoch` and `creation_commit`.
        let post_cm_anchor = pre_cm_anchor.next_stamp(creation_epoch, &creation_commit);

        Ok(((cm, (creation_epoch, present_nf), post_cm_anchor), ()))
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
