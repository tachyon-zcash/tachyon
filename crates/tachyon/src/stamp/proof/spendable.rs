//! Spendable bootstrap and lift.
//!
//! The spendable carries a commitment `future` to the unconsumed coefficients
//! of the nullifier polynomial $N = M + \mathsf{cm}\cdot\mathbb{1}$,
//! Pedersen-trapdoored with `cm`. Pedersen-independence of the coefficient
//! generators from the blinding generator pins both $N$ *and* the `cm` value:
//! any other note would need a different polynomial *and* a different `cm` to
//! satisfy the same point.
//!
//! [`SpendableInit`] witnesses the note and unshifted $M$, derives $\psi =
//! \sum_i M_i G_i$, derives `cm` from `(rcm, pk, value, derived psi)`, checks
//! `cm` is in `creation_set`, anchors the spendable immediately after the
//! creation stamp, and emits the homomorphically shifted-and-trapdoored initial
//! `future` (the cm-shift $M \mapsto N$ then the `cm` trapdoor, two distinct
//! commit-level operations). Each [`SpendableLift`] consumes one composed
//! [`Unspent`] segment, derives `cm` from the witnessed note fields and $M$
//! (never witnessed naked) to verify the trapped commit, validates the
//! segment's polynomial as a prefix of the spendable's current future by
//! commit-binding, shrinks `future` to the trapdoored complement, and advances
//! the anchor.
//!
//! The trapdoor makes the whole spendable lineage wallet-only (the prover must
//! know the note and $M$ to derive `cm` and verify the trapped commit), so
//! [`SpendableLift`] is no longer delegate-safe. Sync-side work moves up to
//! [`Unspent`] composition, which never touches `cm`, $\psi$, or $M$.

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use ragu::{Commitment, Header, Index, Polynomial, Step, StepCtx, Suffix, enforce_poly_concat};

use super::pool::Unspent;
use crate::{
    Note,
    constants::{NOTE_LIFETIME_MAX, NOTE_VALUE_MAX},
    keys::PaymentKey,
    note::{CommitmentTrapdoor, Value},
    primitives::{Anchor, BlindNfSeqCommit, NfSeqPoly, ProNfSeqPoly, TachygramSetPoly},
};

/// Spendable position.
///
/// `(future, anchor)`.
///
/// `future` commits to the unconsumed tail of the nullifier polynomial $N = M +
/// \mathsf{cm}\cdot\mathbb{1}$ re-based to degree 0, Pedersen-trapdoored with
/// the note's `cm`. Pinned through every [`SpendableLift`] by the trapdoor
/// identity.
///
/// `anchor` is the spendable's current pool position. [`SpendableInit`] sets
/// it to `pre_cm_anchor.next_stamp(creation_commit)`, the anchor immediately
/// after the creation (cm) stamp, so the first [`SpendableLift`] can only
/// consume an [`Unspent`] adjacent to the creation context; each later lift
/// advances it to the consumed segment's end.
///
/// Carries no `cm`, $\psi$, `nk`, or $M$ directly — `cm` is hidden inside
/// the trapdoored commit. The spendable is wallet-only: every step that
/// verifies `future` against witnessed coefficients needs `cm` as
/// a witness.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    /// `(future, anchor)`. `future` shrinks per lift, the trapdoor inside it
    /// stays constant; `anchor` advances per lift.
    type Data = (BlindNfSeqCommit, Anchor);

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 2);
        let future_bytes: [u8; 32] = Commitment::from(data.0).into();
        out.extend_from_slice(&future_bytes);
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Bootstrap a spendable from a note's fields and its pronullifier polynomial.
///
/// Wallet-only seed. Witnesses the note's non-psi fields (`pk`, `value`,
/// `rcm`) and the unshifted pronullifier polynomial $M$ — never a `Note` and
/// never a stored `psi`. It derives $\psi = \sum_i M_i G_i$ from the gadget,
/// then `cm = Poseidon(rcm, pk, value, psi)`, so the spendable's identity is
/// bound to the polynomial the prover actually knows. Verifies `cm` is in
/// `creation_set` against the witnessed creation stamp's tachygrams (a
/// divergent $M$ yields a divergent `cm` that misses the set), anchors the
/// spendable at `pre_cm_anchor.next_stamp(&creation_commit)` (the position
/// immediately after the creation stamp), and emits the cm-shifted,
/// cm-trapdoored initial `future` (all of $N$, blinded with `cm`). All
/// witnesses are dropped from the output.
///
/// Claim: *the spendable's initial state is bound to a real note included in
/// a real pool stamp; the trapdoor pins the note's `cm` into every
/// downstream `future`.*
///
/// TODO:
///  - instead of using index 0 for the first nullifier, should we simply modulo
///    the epoch?
///  - what if two identical notes sharing $M$ appear two epochs apart?
///  - what if $M$ contains repeated values?
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = ();
    type Output = SpendableHeader;
    type Right = ();
    /// `(note, creation_set, pre_cm_anchor)` with `note = (pk, value, rcm, M)`.
    type Witness<'source> = (
        (PaymentKey, Value, CommitmentTrapdoor, ProNfSeqPoly),
        TachygramSetPoly,
        Anchor,
    );

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        ((pk, value, rcm, pronf), creation_set, pre_cm_anchor): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if u64::from(value) == 0 {
            return Err(ragu::Error("SpendableInit: zero-value note"));
        }
        if u64::from(value) > NOTE_VALUE_MAX {
            return Err(ragu::Error("SpendableInit: note value exceeds maximum"));
        }

        // psi := commit(M), derived from the gadget. cm derives from psi; the
        // cm-in-set check then binds M to a real note (a divergent M yields a
        // divergent cm that misses the real creation stamp).
        let psi = pronf.commit();
        let cm = Note {
            pk,
            value,
            psi,
            rcm,
        }
        .commitment();
        if creation_set.eval(Fp::from(cm)) != Fp::ZERO {
            return Err(ragu::Error("SpendableInit: cm not in creation stamp"));
        }
        let creation_commit = creation_set.commit();
        let anchor = pre_cm_anchor.next_stamp(&creation_commit);
        // Build the initial `future` from psi as two distinct homomorphic
        // commit-level operations: the cm-shift M -> N (every coefficient + cm,
        // via ProNfSeqCommit::shift) then the cm-trapdoor (blind with cm*H, via
        // NfSeqCommit::blind). The shift basis is the constant full width L
        // (NOTE_LIFETIME_MAX), never a read length: M is full-rank L by type, so
        // every coefficient (including any trailing zero) shifts by cm. cm is a
        // private witnessed scalar, so neither op makes it public.
        let future = psi.shift(cm, NOTE_LIFETIME_MAX).blind(cm);
        Ok(((future, anchor), ()))
    }
}

/// Shrink the spendable's `future` by the [`Unspent`]'s polynomial and
/// advance the anchor to the [`Unspent`]'s end.
///
/// Witnesses `spendable_future` (the lineage's future nullifiers $N_i = M_i +
/// \mathsf{cm}$), the [`Unspent`]'s `unspent_elapsed` nullifiers (also shifted,
/// since the wallet shares shifted nf values with the delegate), the complement
/// `new_future`, and the note's non-psi fields plus $M$, from which it derives
/// `cm` (the trapdoor established at [`SpendableInit`]) — `cm` is never
/// witnessed naked. Trapdooring `spendable_future` with `cm`
/// (`spendable_future.commit().blind(cm) == future`) forces both the nullifier
/// coefficients *and* the `cm` to match the spendable's lineage. The Unspent's
/// commit is zero-blind (it doesn't know `cm`). The new `future` is the
/// trapdoored commit of `new_future`; a commit-binding check confirms
/// `spendable_future = unspent_elapsed || new_future`, so we never strip.
///
/// Soundness: the spendable's `future` is Pedersen-bound through every
/// successive lift, with the trapdoor riding along. The chain traces back to
/// the initial `future` (all of $N = M + \mathsf{cm}\cdot\mathbb{1}$,
/// trapdoored with `cm`) at [`SpendableInit`], so by induction the current
/// `future` pins the same `cm` and is $N$ minus the lineage's consumed prefix.
/// Each consumed coefficient is one of $N$'s, in order, matching the nullifiers
/// the [`Unspent`] threaded through real per-stamp non-membership checks.
///
/// Because deriving and verifying the trapped commit requires the note and
/// $M$, this step is wallet-only.
///
/// # The shift offset comes from the consumed segment's crossing count
///
/// The split `spendable_future = unspent_elapsed || new_future` shifts by the
/// number of epoch-boundary crossings the consumed [`Unspent`] spanned. That
/// count is threaded in the [`Unspent`] header (`elapsed_size`) and passed as
/// the concat offset, so the step never reads a polynomial length, and the
/// faithful opening relation pins the offset to it (a wrong offset cannot
/// pass). The count is delegate-side data and does not propagate onto the
/// spendable header, so the wallet's cumulative position stays private. The
/// tip-tie `present_nf == new_future.eval(0)` then attributes the Unspent's
/// in-progress tip to the spendable's carried-forward present epoch, closing
/// the partial-tip-epoch gap. $M$ stays full length $L$ = `NOTE_LIFETIME_MAX`
/// by its structural rank ([`SpendableInit`]'s shift basis is the const-size
/// $\sum_{i<L} G_i$).
///
/// [`SpendableInit`]: super::spendable::SpendableInit
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = Unspent;
    /// `(note, spendable_future, unspent_elapsed, new_future)` with `note =
    /// (pk, value, rcm, M)`. `spendable_future` is the lineage's future
    /// nullifiers ($N[\text{consumed}..]$); `unspent_elapsed` the consumed
    /// segment's elapsed nullifiers; `new_future` the witnessed complement
    /// left after the split.
    type Witness<'source> = (
        (PaymentKey, Value, CommitmentTrapdoor, ProNfSeqPoly),
        NfSeqPoly,
        NfSeqPoly,
        NfSeqPoly,
    );

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        ((pk, value, rcm, pronf), spendable_future, unspent_elapsed, new_future): Self::Witness<
            'source,
        >,
        (future, spendable_anchor): <Self::Left as Header>::Data,
        ((right_elapsed, right_size), unspent_prev, unspent_end, present_nf): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if u64::from(value) == 0 {
            return Err(ragu::Error("SpendableLift: zero-value note"));
        }
        if u64::from(value) > NOTE_VALUE_MAX {
            return Err(ragu::Error("SpendableLift: note value exceeds maximum"));
        }
        // cm is never witnessed naked: derive it from the witnessed note fields
        // and M so this step is bound to a note the prover actually knows.
        let psi = pronf.commit();
        let cm = Note {
            pk,
            value,
            psi,
            rcm,
        }
        .commitment();
        // Trapdoor the witnessed `spendable_future` with cm (blind with cm*H) and
        // match the spendable's `future`; by Pedersen independence this pins both
        // the nullifier coefficients and cm to the spendable's lineage. The
        // Unspent's commit is zero-blind (it doesn't know cm).
        if future != spendable_future.commit().blind(cm) {
            return Err(ragu::Error(
                "SpendableLift: spendable_future does not match future",
            ));
        }
        if unspent_elapsed.commit() != right_elapsed {
            return Err(ragu::Error(
                "SpendableLift: unspent_elapsed does not match header",
            ));
        }
        if spendable_anchor != unspent_prev {
            return Err(ragu::Error(
                "SpendableLift: unspent not adjacent to spendable",
            ));
        }
        // Shrink `future` by the consumed segment: prove `spendable_future =
        // unspent_elapsed || new_future` at `offset = right.elapsed_size` (the
        // threaded crossing count, never a read length) via the faithful opening
        // relation. `spendable_future` is pinned to the lineage above and
        // `unspent_elapsed` to the absence proof, so the count-pinned offset
        // forces `new_future` to be the genuine complement after exactly the
        // elapsed crossings -- a wrong offset cannot pass.
        let offset = usize::try_from(right_size).map_err(|_too_many_crossings| {
            ragu::Error("SpendableLift: crossing count exceeds usize")
        })?;
        // `spendable_future` is already pinned to the lineage by the future-match
        // above and `unspent_elapsed` to the absence proof, so confirming the
        // concat at the count-pinned offset forces `new_future` to be the genuine
        // complement after exactly the elapsed crossings.
        enforce_poly_concat(
            ctx,
            &Polynomial::from(unspent_elapsed),
            &Polynomial::from(new_future.clone()),
            offset,
            &Polynomial::from(spendable_future),
        )
        .map_err(|_relation_err| {
            ragu::Error("SpendableLift: unspent_elapsed is not a prefix of future")
        })?;
        // Tie the consumed Unspent's in-progress tip to the spendable's
        // carried-forward present epoch: new_future's degree-0 coefficient (the
        // new present nf) must equal the threaded present_nf. Closes the
        // partial-tip-epoch absence gap.
        if Fp::from(present_nf) != new_future.eval(Fp::ZERO) {
            return Err(ragu::Error(
                "SpendableLift: present_nf does not match new future tip",
            ));
        }
        // The new `future` is the complement, re-trapdoored with the same cm.
        let new_future_commit = new_future.commit().blind(cm);
        Ok(((new_future_commit, unspent_end), ()))
    }
}
