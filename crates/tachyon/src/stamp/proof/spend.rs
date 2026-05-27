//! Spend action-binding header and step.

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use pasta_curves::{EqAffine, Fp};
use ragu::{Header, Index, Polynomial, Step, StepCtx, Suffix, enforce_poly_concat, generators};

use super::spendable::SpendableHeader;
use crate::{
    Note,
    constants::NOTE_VALUE_MAX,
    entropy::ActionRandomizer,
    keys::{PaymentKey, ProofAuthorizingKey, public},
    note::{CommitmentTrapdoor, Nullifier, ProNf, Value},
    primitives::{Anchor, NfSeqPoly, ProNfSeqPoly, effect},
    value,
};

/// Header binding an action to a nullifier pair and a pool anchor.
///
/// Publishing `next_nf` one epoch early lets consensus catch a same-note
/// spend made in epoch `e+1`: that spend's present-epoch nullifier would
/// collide with this `next_nf`, which the two-epoch tachygram scan
/// rejects. See the Tachygrams book chapter.
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    /// `(cv, rk, (nf_now, nf_next), anchor)`. All derived at [`SpendBind`]
    /// from the witnessed `(note, nf_pair, rest, nf_tail, live, rcv, alpha,
    /// pak)`; the anchor threads from the spendable that [`SpendBind`]
    /// consumed.
    type Data = (
        value::Commitment,
        public::ActionVerificationKey,
        (Nullifier, Nullifier),
        Anchor,
    );

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 5);
        let cv_bytes: [u8; 32] = data.0.into();
        let rk_bytes: [u8; 32] = data.1.into();
        out.extend_from_slice(&cv_bytes);
        out.extend_from_slice(&rk_bytes);
        out.extend_from_slice(&Fp::from(data.2.0).to_repr());
        out.extend_from_slice(&Fp::from(data.2.1).to_repr());
        out.extend_from_slice(&Fp::from(data.3).to_repr());
        out
    }
}

/// Binds a [`SpendableHeader`] to an action and publishes the spend pair.
///
/// Witnesses the note preimage (`pk`, `value`, `rcm`, and the full pronullifier
/// polynomial $M$ as `pronf`; `cm` is derived, not witnessed), the live pair
/// `nf_pair`, the tail remainder `rest` of the nullifier polynomial $N$ (both
/// already $+\mathsf{cm}$ shifted, prover-side), the prover-supplied
/// concatenation `nf_tail = nf_pair || rest`, and the two live pronullifiers
/// `live = (M_e, M_{e+1})` as scalars.
///
/// A step cannot read a polynomial's runtime length, so nothing here sizes a
/// commitment basis from a witnessed length. The only poly-shaping number is
/// the constant `2` (the published pair's rank).
///
/// # `cm` is derived, not witnessed
///
/// $\psi = \sum_i M_i G_i$ from `pronf`, then `cm = Poseidon(rcm, pk, value,
/// psi)`. This is the preimage half of the `cm` binding: it ties `cm`, and so
/// the published nullifiers and `cv`, to `value` and `pk`. The future match
/// below is the Pedersen half, pinning the same `cm` to the spendable's lineage
/// by the $H$-trapdoor. Poseidon collision-resistance then pins `value`, `pk`,
/// `rcm`, and `psi` to the real note, so `cv = rcv.commit(value)` is bound to
/// the real note's value, and $\psi = \mathrm{commit}(M)$ is the genuine one.
/// `psi` is used *only* as the cm preimage; it is never shifted.
///
/// # The published pair
///
/// `live` shifts up by `cm` into the published nullifiers ($\mathsf{nf}_e =
/// M_e + \mathsf{cm}$, $\mathsf{nf}_{e+1} = M_{e+1} + \mathsf{cm}$). The
/// witnessed `nf_pair` is bound to be their rank-2 nullifier pair: its commit
/// must equal the reference $[\mathsf{nf}_e]\,G_0 + [\mathsf{nf}_{e+1}]\,G_1$
/// (two generator scalar muls, a commitment and never a fabricated polynomial).
/// That reference lives only in $\mathrm{span}\{G_0, G_1\}$, so Pedersen
/// binding forces `nf_pair` to carry no coefficient past degree 1.
/// Commit-equality is length-blind, so a rank-1 `nf_pair = [nf_now]` would pass
/// whenever $\mathsf{nf}_{e+1} = 0$, and then `nf_pair || rest` would shift
/// `rest` by one and hide the real next nullifier; the $\mathsf{nf}_{e+1} \neq
/// 0$ guard closes that, so `nf_pair` occupies degrees 0 and 1 and `rest`
/// follows at degree 2. (In real ragu `nf_pair` is a structural rank-2 gadget
/// and the shift is the constant 2 for free.)
///
/// # The tail is tied by the lineage alone
///
/// `concat1` proves the prover-supplied `nf_tail = nf_pair || rest` at the
/// constant offset 2 and binds its commitment to `future.unblind(cm)`. By
/// Pedersen independence ($G \perp H$) this pins `nf_tail` to the lineage's
/// re-based $N$-suffix and `cm` to its trapdoor, so the spend inherits the
/// anchor and absence coverage, and `nf_pair` is exactly `future`'s degrees 0
/// and 1 (hence `live = (M_e, M_{e+1})`). No N-reassembly is needed: `future`
/// was built from $\psi = \mathrm{commit}(M)$ at [`SpendableInit`] and
/// maintained by each sound [`SpendableLift`], so the lineage already ties
/// `nf_tail` to *this* note's $M$. (The old `n_full = nf_head || nf_tail`
/// "strong $\psi$" concat was vacuous — a free `nf_head` satisfies it for any
/// `nf_tail` — and is removed.)
///
/// Nonzero guards finish the job: each live pronullifier must be nonzero (else
/// $\mathsf{nf} = \mathsf{cm}$, colliding with the note's own `cm` tachygram),
/// and the published next nullifier must be nonzero (closing the rank-1
/// forgery).
///
/// # The consumed offset stays private
///
/// The note's cumulative position never appears: `future` is re-based to degree
/// 0 each lift, and SpendBind reads only its degrees 0/1 (a fixed position).
/// The output `SpendHeader` carries only `cv`, `rk`, the nf pair, and the
/// anchor, so $M$, the tail, and the position never propagate to `SpendStamp`
/// or beyond.
///
/// [`SpendableInit`]: super::spendable::SpendableInit
/// [`SpendableLift`]: super::spendable::SpendableLift
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendHeader;
    type Right = ();
    /// `(note, nf_pair, rest, nf_tail, live, rcv, alpha, pak)` with `note =
    /// (pk, value, rcm, M)` and `live = (M_e, M_{e+1})`. `nf_pair` is the
    /// live nullifier pair (rank 2), `rest` the tail after it of the
    /// nullifier polynomial $N$ (both $+\mathsf{cm}$ shifted prover-side),
    /// and `nf_tail = nf_pair || rest` the prover-supplied concatenation
    /// the opening relation confirms against the lineage's `future`.
    /// `nf_pair` is bound to be the rank-2 nullifier pair of the `live`
    /// scalars.
    type Witness<'source> = (
        // note preimage (cm is derived from it)
        (PaymentKey, Value, CommitmentTrapdoor, ProNfSeqPoly),
        // nullifier polynomial N = M + cm, split as nf_pair || rest
        NfSeqPoly,      // live nullifier pair (rank 2)
        NfSeqPoly,      // remaining future tail
        NfSeqPoly,      // nf_tail = nf_pair || rest (prover-supplied concatenation)
        (ProNf, ProNf), // live pronullifiers (M_e, M_{e+1})
        // action fields
        value::CommitmentTrapdoor,
        ActionRandomizer<effect::Spend>,
        ProofAuthorizingKey,
    );

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        (
            (pk, value, rcm, pronf),
            nf_pair, // live nullifier pair (rank 2)
            rest,    // remaining future tail
            nf_tail, // nf_tail = nf_pair || rest (prover-supplied concatenation)
            live,    // live pronullifiers (M_e, M_{e+1})
            rcv,
            alpha,
            pak,
        ): Self::Witness<'source>,
        (future, anchor): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if u64::from(value) == 0 {
            return Err(ragu::Error("SpendBind: zero-value note"));
        }
        if u64::from(value) > NOTE_VALUE_MAX {
            return Err(ragu::Error("SpendBind: note value exceeds maximum"));
        }
        if pk.0 != pak.derive_payment_key().0 {
            return Err(ragu::Error("SpendBind: pak not related to note"));
        }
        // psi := commit(M) from the full pronullifier gadget; cm is DERIVED from
        // the note preimage (rcm, pk, value, psi), not witnessed. This is the
        // Poseidon half of the cm binding: it ties cm (hence the published
        // nullifiers and `cv`) to value and pk. The future match below is the
        // Pedersen half (the H-trapdoor), pinning the same cm to the spendable's
        // lineage. Witnessing cm separately would add nothing: the value used
        // would have to equal this derivation anyway.
        let psi = pronf.commit();
        let cm = Note {
            pk,
            value,
            psi,
            rcm,
        }
        .commitment();

        // The published nullifiers are the two pronullifier scalars shifted up
        // by cm (nf_now = M_e + cm, nf_next = M_{e+1} + cm). Bind the witnessed
        // `nf_pair` gadget to be exactly their rank-2 nullifier pair: its commit
        // must equal the reference [nf_now]G_0 + [nf_next]G_1 (two generator
        // scalar muls at the commitment level, not a fabricated polynomial).
        // Since that reference lives only in span{G_0, G_1}, Pedersen binding
        // forces `nf_pair` to carry no coefficient at degree >= 2 -- rank 2 is
        // proven, not assumed -- so the concat below shifts `rest` by exactly 2.
        let nf_now = cm.nullify(live.0);
        let nf_next = cm.nullify(live.1);
        let nf_pair_commit: EqAffine =
            *((generators::g(0) * Fp::from(nf_now) + generators::g(1) * Fp::from(nf_next)).inner());
        if EqAffine::from(nf_pair.commit()) != nf_pair_commit {
            return Err(ragu::Error(
                "SpendBind: pair is not the rank-2 nullifier pair of the witnessed scalars",
            ));
        }
        // Future match: bind the prover-supplied `nf_tail` to `future.unblind(cm)`
        // (`nf_tail.commit().blind(cm) == future`). By Pedersen independence (G
        // independent of H) this pins nf_tail to the lineage tail and the same cm,
        // so the spend inherits the anchor and the absence coverage.
        if nf_tail.commit() != future.unblind(cm) {
            return Err(ragu::Error(
                "SpendBind: tail does not match the spendable's future",
            ));
        }
        // Tail concat at offset 2 (a constant -- the rank-2 pair proven above
        // shifts `rest` by exactly 2): confirm `nf_tail = nf_pair ++ rest`.
        enforce_poly_concat(
            ctx,
            &Polynomial::from(nf_pair),
            &Polynomial::from(rest),
            2,
            &Polynomial::from(nf_tail),
        )
        .map_err(|_relation_err| {
            ragu::Error("SpendBind: tail does not match the spendable's future")
        })?;

        // No N-reassembly here. The lineage already pins `nf_tail` to this note's
        // re-based N: `future` was built from psi = commit(M) at SpendableInit and
        // maintained by each sound SpendableLift, so the future-match above
        // (`nf_tail.commit() == future.unblind(cm)`) ties `nf_tail` to the genuine
        // suffix and `cm` to its trapdoor. psi is derived only as the cm preimage;
        // it is never shifted. (The old `n_full = nf_head || nf_tail` concat was
        // vacuous -- a free `nf_head` satisfies it for any `nf_tail`.)

        // A zero pronullifier (M_e = 0) would publish nf = cm, colliding with
        // the note's own commitment in the tachygram set.
        if Fp::from(live.0) == Fp::ZERO {
            return Err(ragu::Error(
                "SpendBind: pronullifier for present epoch should not be zero",
            ));
        }
        if Fp::from(live.1) == Fp::ZERO {
            return Err(ragu::Error(
                "SpendBind: pronullifier for next epoch should not be zero",
            ));
        }
        // Belt-and-braces: the published next nullifier must be nonzero. The
        // constant-offset-2 tail concat already forces nf_next to equal the
        // lineage's next nullifier (a rank-1 pair leaves coefficient 1 at zero,
        // so it fails the folded future match), and that value is nonzero for an
        // honest note -- nf = cm would need M_{e+1} = -cm, an infeasible Poseidon
        // fixed point. This guard stays as defense in depth.
        if Fp::from(nf_next) == Fp::ZERO {
            return Err(ragu::Error(
                "SpendBind: nullifier for next epoch should not be zero",
            ));
        }

        let cv = rcv.commit(i64::from(value));
        let rk = pak.ak.derive_action_public(&alpha);

        Ok(((cv, rk, (nf_now, nf_next), anchor), ()))
    }
}
