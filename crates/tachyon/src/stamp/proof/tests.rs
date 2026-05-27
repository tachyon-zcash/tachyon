//! Proof-step tests for the polynomial-vanishing architecture:
//! pool/anchor, `Unspent`'s polynomial composition, the spendable lineage,
//! and `SpendBind`'s validation of the spend pair against the spendable's
//! `commit_future`.

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::iter;

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Polynomial, Proof};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::{CryptoRng, RngCore};

use super::{PROOF_SYSTEM, pool, spend, spendable, stamp};
use crate::{
    ActionSetCommit, Note, TachygramSetCommit, TachygramSetPoly,
    constants::{EPOCH_SIZE, NOTE_LIFETIME_MAX},
    fixtures::{
        PoolSim, SyncSim, WalletSim, build_anchor_chain_pcd, build_output_stamp, build_unspent_pcd,
        build_unspent_seed_pcd, random_block, random_block_with, spend_witness,
    },
    note::{self, Nullifier, ProNf},
    primitives::{
        Anchor, BlockHeight, EpochIndex, NfSeqCommit, NfSeqPoly, ProNfSeqPoly, Tachygram,
    },
};

fn tg<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Tachygram {
    Tachygram::from(Fp::random(rng))
}

/// Mine one block carrying `note.commitment()` and return its height.
fn mine_cm_block(rng: &mut StdRng, pool: &mut PoolSim, cm: note::Commitment) -> BlockHeight {
    pool.mine(random_block_with(rng, &[alloc::vec![cm]], 4));
    pool.height()
}

/// Shift a full pronullifier polynomial `M` into the `SpendBind` witness pieces
/// for a spend at `consumed = 0`, all under `cm`: `(nf_pair, rest, nf_tail,
/// live)` with `nf_pair` the rank-2 live pair, `rest` the nullifier tail past
/// it, `nf_tail = nf_pair || rest` (= N at consumed 0), and `live = (M_0,
/// M_1)`. Used by negative tests that witness a fake note (its own `M` and
/// `cm`) self-consistently.
fn fresh_spend_parts(
    pronf: &ProNfSeqPoly,
    cm: note::Commitment,
) -> (NfSeqPoly, NfSeqPoly, NfSeqPoly, (ProNf, ProNf)) {
    let poly = Polynomial::from(pronf.clone());
    let coeffs = poly.coefficients();
    assert!(coeffs.len() > 1, "M has at least two live coefficients");
    let live_now = ProNf::from(coeffs[0]);
    let live_next = ProNf::from(coeffs[1]);
    let nullify_from = |from: usize| -> NfSeqPoly {
        NfSeqPoly::from(
            coeffs[from..]
                .iter()
                .map(|&coeff| cm.nullify(ProNf::from(coeff)))
                .collect::<Vec<Nullifier>>()
                .as_slice(),
        )
    };
    let nf_pair = NfSeqPoly::from([cm.nullify(live_now), cm.nullify(live_next)].as_slice());
    let rest = nullify_from(2);
    let nf_tail = nullify_from(0);
    (nf_pair, rest, nf_tail, (live_now, live_next))
}

#[test]
fn stamp_lift_within_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(1, |_| random_block(rng, 1, 4));
    let stamp_anchor = pool.anchor_at(BlockHeight(1));

    let note = user.random_note(rng, 200);
    let (stamp, plan) = build_output_stamp(rng, stamp_anchor, note);

    let action_commit: ActionSetCommit =
        ActionSetCommit::from([plan.digest().expect("valid plan")].as_slice());
    let tachygram_commit: TachygramSetCommit =
        TachygramSetCommit::from(stamp.tachygrams.as_slice());

    pool.advance(usize::try_from(EPOCH_SIZE - 2).expect("fits"), |_| {
        random_block(rng, 1, 4)
    });
    let new_height = pool.height();

    let stamp_pcd = stamp
        .proof
        .carry((action_commit, tachygram_commit, stamp_anchor));
    let anchor_chain = build_anchor_chain_pcd(rng, &pool, BlockHeight(2)..=new_height);

    let (lifted_pcd, ()) = PROOF_SYSTEM
        .fuse(rng, stamp::StampLift, (), stamp_pcd, anchor_chain)
        .expect("stamp lift");
    PROOF_SYSTEM
        .rerandomize(lifted_pcd, rng)
        .expect("rerandomize lifted stamp");
}

#[test]
fn unspent_seed_rejects_tg_present() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let note = user.random_note(rng, 500);
    let nf = user.nf_at(&note, 0);

    let containing_set = TachygramSetPoly::from([nf.into()].as_slice());
    let start = Anchor::default();

    let err = PROOF_SYSTEM
        .seed(rng, pool::UnspentSeed, (start, containing_set, nf))
        .err()
        .unwrap();
    assert_eq!(err.0, "UnspentSeed: found nullifier in set");
}

#[test]
fn unspent_fuse_rejects_invalid_compositions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let stamps_left = vec![tg(rng)];
    let stamps_right = vec![tg(rng)];
    let start = Anchor::default();
    let mid = start.next_stamp(&TachygramSetCommit::from(stamps_left.as_slice()));

    // Different nf at the per-stamp seeds → different present nullifiers at the
    // halves → UnspentFuse rejects.
    {
        let nf_a = Nullifier::from(Fp::random(&mut *rng));
        let nf_b = Nullifier::from(Fp::random(&mut *rng));
        let shard_a = build_unspent_seed_pcd(rng, start, &stamps_left, nf_a);
        let shard_b = build_unspent_seed_pcd(rng, mid, &stamps_right, nf_b);
        let err = PROOF_SYSTEM
            .fuse(rng, pool::UnspentFuse, (), shard_a, shard_b)
            .err()
            .unwrap();
        assert_eq!(
            err.0,
            "UnspentFuse: halves must share the present nullifier"
        );
    }

    // Same nf (so polynomials match), but right's start doesn't equal
    // left's end.
    {
        let nf = Nullifier::from(Fp::random(&mut *rng));
        let shard_a = build_unspent_seed_pcd(rng, start, &stamps_left, nf);
        let shard_b = build_unspent_seed_pcd(rng, start, &stamps_right, nf);
        let err = PROOF_SYSTEM
            .fuse(rng, pool::UnspentFuse, (), shard_a, shard_b)
            .err()
            .unwrap();
        assert_eq!(err.0, "UnspentFuse: left.end must equal right.start");
    }
}

#[test]
fn anchor_chain_fuse_rejects_invalid_compositions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.advance(2, |_| random_block(rng, 1, 2));

    let left = build_anchor_chain_pcd(rng, &pool, BlockHeight(0)..=BlockHeight(0));

    let bogus_start = Anchor(Fp::random(&mut *rng));
    let commit = pool.stamp_commits_at(BlockHeight(1))[0];
    let (right, ()) = PROOF_SYSTEM
        .seed(rng, pool::AnchorSeed, (bogus_start, commit))
        .expect("AnchorSeed");

    let err = PROOF_SYSTEM
        .fuse(rng, pool::AnchorFuse, (), left, right)
        .err()
        .unwrap();
    assert_eq!(err.0, "AnchorFuse: segments not adjacent");
}

#[test]
fn empty_block_anchor_unique_per_height() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.mine(vec![]);
    pool.mine(vec![]);

    let h1 = BlockHeight(1);
    let h2 = BlockHeight(2);
    assert_ne!(pool.anchor_at(h1), pool.anchor_at(h2));
    assert_eq!(pool.anchor_at(h2), pool.anchor_at(h1).next_empty());
}

#[test]
fn spendable_init_rejects_wrong_pronf() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());

    let cm = note.commitment();
    let stamps = pool.tachygrams_at(init_height);
    let cm_idx = stamps
        .iter()
        .position(|tgs| tgs.contains(&cm.into()))
        .expect("cm in block");
    let stamp_commits = pool.stamp_commits_at(init_height);
    let pre_cm_anchor = stamp_commits[..cm_idx]
        .iter()
        .fold(pool.prev_anchor_at(init_height), Anchor::next_stamp);
    let creation_set = TachygramSetPoly::from(stamps[cm_idx].as_slice());
    // A bogus M, full-length but not the note's real polynomial.
    let bogus: Vec<ProNf> = iter::repeat_with(|| ProNf::random(rng))
        .take(NOTE_LIFETIME_MAX)
        .collect();
    let bogus_pronf = ProNfSeqPoly::from(bogus.as_slice());

    let err = PROOF_SYSTEM
        .seed(
            rng,
            spendable::SpendableInit,
            (
                (note.pk, note.value, note.rcm, bogus_pronf),
                creation_set,
                pre_cm_anchor,
            ),
        )
        .err()
        .unwrap();
    // SpendableInit derives `psi = commit(M)` and `cm =
    // Poseidon(rcm, pk, value, derived psi)`. A bogus M yields a different
    // derived cm, which fails the cm-in-creation-set check against the real
    // creation stamp (which contains the note's true cm).
    assert_eq!(err.0, "SpendableInit: cm not in creation stamp");
}

#[test]
fn spendable_init_rejects_cm_not_in_set() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());

    // Real M, but the "creation set" doesn't contain cm.
    let pronf = user.pronfs_poly(&note);
    let absent_set = TachygramSetPoly::from([tg(rng)].as_slice());
    let pre_cm_anchor = pool.prev_anchor_at(init_height);

    let err = PROOF_SYSTEM
        .seed(
            rng,
            spendable::SpendableInit,
            (
                (note.pk, note.value, note.rcm, pronf),
                absent_set,
                pre_cm_anchor,
            ),
        )
        .err()
        .unwrap();
    assert_eq!(err.0, "SpendableInit: cm not in creation stamp");
}

#[test]
fn spendable_lift_rejects_wrong_future() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    // Build any Unspent at the spendable's anchor — content of nf doesn't
    // matter because the future gadget mismatch will fail first.
    let unspent = build_unspent_pcd(
        rng,
        &pool,
        user.nf_at(&note, 0),
        BlockHeight(init_height.0 + 1)..=BlockHeight(init_height.0 + 1),
    );
    // Spoof a future gadget that doesn't match the spendable's commit_future.
    let bogus_future = NfSeqPoly::from(
        iter::repeat_with(|| Nullifier::from(Fp::random(&mut *rng)))
            .take(16)
            .collect::<Vec<_>>()
            .as_slice(),
    );
    let unspent_poly = NfSeqPoly::from([user.nf_at(&note, 0)].as_slice());

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableLift,
            (
                (note.pk, note.value, note.rcm, user.pronfs_poly(&note)),
                bogus_future,
                unspent_poly,
                user.shifted_future(&note, 1),
            ),
            spendable,
            unspent,
        )
        .err()
        .unwrap();
    assert_eq!(
        err.0,
        "SpendableLift: spendable_future does not match future"
    );
}

#[test]
fn spend_bind_rejects_wrong_future() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    // A fully-consistent fake note: a random M whose own cm is witnessed, so
    // the preimage confirm passes. Its re-based nullifier tail lands in a
    // different commitment than the spendable's `future` (built from the real
    // note's M and cm at SpendableInit), so the lineage check rejects it.
    let bogus_pronf = ProNfSeqPoly::from(
        iter::repeat_with(|| ProNf::random(rng))
            .take(NOTE_LIFETIME_MAX)
            .collect::<Vec<ProNf>>()
            .as_slice(),
    );
    let cm_bogus = Note {
        rcm: note.rcm,
        pk: note.pk,
        value: note.value,
        psi: bogus_pronf.commit(),
    }
    .commitment();
    // Shift the bogus M into self-consistent witness pieces under its own cm.
    let (nf_pair, rest, nf_tail, live) = fresh_spend_parts(&bogus_pronf, cm_bogus);
    let (rcv, _theta, alpha) = spend_witness(rng, &note);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (
                (note.pk, note.value, note.rcm, bogus_pronf),
                nf_pair,
                rest,
                nf_tail,
                live,
                rcv,
                alpha,
                user.pak,
            ),
            spendable_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    assert_eq!(
        err.0,
        "SpendBind: tail does not match the spendable's future"
    );
}

#[test]
fn spend_bind_honest() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
    let (rcv, _theta, alpha) = spend_witness(rng, &note);

    let (spend_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (
                (note.pk, note.value, note.rcm, user.pronfs_poly(&note)),
                user.live_pair_nf(&note, 0),
                user.tail_rest_nf(&note, 0),
                user.shifted_future(&note, 0),
                user.live_scalars(&note, 0),
                rcv,
                alpha,
                user.pak,
            ),
            spendable_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("SpendBind honest");
    // SpendBind shifts the live pronullifier scalars into the published pair.
    let (_cv, _rk, (now, next), _anchor) = *spend_pcd.data();
    assert_eq!(now, user.nf_at(&note, 0));
    assert_eq!(next, user.nf_at(&note, 1));
}

#[test]
fn spend_bind_rejects_forged_next() {
    // The two-epoch double-spend scan relies on `next_nf` being the real
    // epoch-(e+1) nullifier. The published pair is built from the witnessed
    // scalars, so a forged `live_next` (here M_1 + M_2, the value the pre-fix
    // `eval(1) - eval(0)` extraction yielded from a degree-2 pair) lands in
    // `nf_tail`'s degree-1 coefficient, which then no longer matches the
    // spendable's `future`.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
    let (rcv, _theta, alpha) = spend_witness(rng, &note);

    // Forge live_next = M_1 + M_2; live_now and the rest of the tail stay honest.
    let (m_0, m_1) = user.live_scalars(&note, 0);
    let m_2 = user.live_scalars(&note, 1).1;
    let forged_next = ProNf::from(Fp::from(m_1) + Fp::from(m_2));
    // The pair is built consistently from the forged scalar, so the rank-2 check
    // passes; the future match is what rejects the forged degree-1 coefficient.
    let cm = note.commitment();
    let forged_pair = NfSeqPoly::from([cm.nullify(m_0), cm.nullify(forged_next)].as_slice());

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (
                (note.pk, note.value, note.rcm, user.pronfs_poly(&note)),
                forged_pair,
                user.tail_rest_nf(&note, 0),
                user.shifted_future(&note, 0),
                (m_0, forged_next),
                rcv,
                alpha,
                user.pak,
            ),
            spendable_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    assert_eq!(
        err.0,
        "SpendBind: tail does not match the spendable's future"
    );
}

#[test]
fn spend_bind_rejects_zero_next_nullifier() {
    // The length-forgery double-spend, now structurally dead under the
    // constant-offset tail concat. A rank-1 `nf_pair = [nf_now]` matches the
    // rank-2 reference only when nf_next = 0. Under the OLD variable-offset concat
    // it shifted `rest` by one and published a forged 0; now `nf_pair || rest`
    // uses a CONSTANT offset 2, so coefficient 1 of `nf_tail` is left at zero,
    // which cannot equal the lineage's nonzero next nullifier -- the future match
    // (folded into the concat) rejects it before any 0 is published. (The
    // explicit nf_next != 0 guard remains as belt-and-braces.)
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
    let (rcv, _theta, alpha) = spend_witness(rng, &note);

    let cm = note.commitment();
    // Rank-1 pair carrying only the real present nullifier; live_next = -cm makes
    // the published next_nf = 0, and a length-1 pair has no degree-1 term so the
    // rank-2 reference still matches. The real tail from epoch 1 fills the slot
    // the short pair vacated.
    let nf_pair = NfSeqPoly::from([user.nf_at(&note, 0)].as_slice());
    let live_now = user.live_scalars(&note, 0).0;
    let live_next = ProNf::from(-Fp::from(cm));
    let rest = user.shifted_future(&note, 1);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (
                (note.pk, note.value, note.rcm, user.pronfs_poly(&note)),
                nf_pair,
                rest,
                user.shifted_future(&note, 0),
                (live_now, live_next),
                rcv,
                alpha,
                user.pak,
            ),
            spendable_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    assert_eq!(
        err.0,
        "SpendBind: tail does not match the spendable's future"
    );
}

#[test]
fn spend_after_lift_publishes_anchor_epoch_nullifiers() {
    // Offset tracks epochs elapsed (the off-by-one check): a note created in
    // epoch 0 and lifted over its creation epoch (consumed = 1) spends at epoch
    // 1, publishing nf_1 / nf_2. nf_0 was consumed by the lift, so it is no
    // longer the spend pair — `spend_bind_honest` covers the fresh case (nf_0 /
    // nf_1) for contrast.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let cm_height = mine_cm_block(rng, &mut pool, note.commitment());
    // Extend into epoch 1 so the lift can cross the creation-epoch boundary.
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let lifted = user.lift_over_creation_epoch(rng, &pool, &note, cm_height, spendable);

    let (rcv, _theta, alpha) = spend_witness(rng, &note);
    let (spend_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (
                (note.pk, note.value, note.rcm, user.pronfs_poly(&note)),
                user.live_pair_nf(&note, 1),
                user.tail_rest_nf(&note, 1),
                user.shifted_future(&note, 1),
                user.live_scalars(&note, 1),
                rcv,
                alpha,
                user.pak,
            ),
            lifted,
            Proof::trivial().carry::<()>(()),
        )
        .expect("SpendBind after a one-epoch lift");
    let (_cv, _rk, (now, next), _anchor) = *spend_pcd.data();
    assert_eq!(now, user.nf_at(&note, 1), "publishes the epoch-1 nf");
    assert_eq!(next, user.nf_at(&note, 2));
    assert_ne!(now, user.nf_at(&note, 0), "nf_0 was consumed by the lift");
}

#[test]
fn spend_bind_rejects_zero_value() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
    let (rcv, _theta, alpha) = spend_witness(rng, &note);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (
                (note.pk, note::Value(0), note.rcm, user.pronfs_poly(&note)),
                user.live_pair_nf(&note, 0),
                user.tail_rest_nf(&note, 0),
                user.shifted_future(&note, 0),
                user.live_scalars(&note, 0),
                rcv,
                alpha,
                user.pak,
            ),
            spendable_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    assert_eq!(err.0, "SpendBind: zero-value note");
}

#[test]
fn spend_stamp_assembles_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
    let (rcv, _theta, alpha) = spend_witness(rng, &note);

    let (spend_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (
                (note.pk, note.value, note.rcm, user.pronfs_poly(&note)),
                user.live_pair_nf(&note, 0),
                user.tail_rest_nf(&note, 0),
                user.shifted_future(&note, 0),
                user.live_scalars(&note, 0),
                rcv,
                alpha,
                user.pak,
            ),
            spendable_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("SpendBind");

    let (stamp_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::SpendStamp,
            (),
            spend_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("SpendStamp");
    let (_actions, tg_commit, _anchor) = *stamp_pcd.data();
    let expected = TachygramSetCommit::from(
        [
            Tachygram::from(user.nf_at(&note, 0)),
            Tachygram::from(user.nf_at(&note, 1)),
        ]
        .as_slice(),
    );
    assert_eq!(tg_commit, expected);
}

#[test]
fn unspent_epoch_fuse_concatenates_polynomials() {
    // Build two intra-epoch Unspents over adjacent epochs and confirm the
    // epoch-fuse splices left's tip into `elapsed` and carries right's tip.
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    // Pool with at least one block in epoch 0 and one in epoch 1.
    pool.advance(usize::try_from(EPOCH_SIZE + 1).expect("fits"), |_| {
        random_block(rng, 1, 2)
    });

    let nf_e0 = Nullifier::from(Fp::random(&mut *rng));
    let nf_e1 = Nullifier::from(Fp::random(&mut *rng));
    let left = build_unspent_pcd(
        rng,
        &pool,
        nf_e0,
        BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1),
    );
    let right = build_unspent_pcd(
        rng,
        &pool,
        nf_e1,
        BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
    );

    // The splice folds left's completing tip (nf_e0) into `elapsed`; both halves
    // are within-epoch (empty elapsed), so combined = [nf_e0].
    let left_poly = NfSeqPoly::from(Vec::<Nullifier>::new().as_slice());
    let right_poly = NfSeqPoly::from(Vec::<Nullifier>::new().as_slice());
    let combined = NfSeqPoly::from([nf_e0].as_slice());
    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (EpochIndex(1), left_poly, right_poly, combined),
            left,
            right,
        )
        .expect("UnspentEpochFuse");

    let ((elapsed, elapsed_size), _prev, _end, present_nf) = *fused.data();
    assert_eq!(elapsed, NfSeqCommit::from([nf_e0].as_slice()));
    assert_eq!(elapsed_size, 1);
    assert_eq!(present_nf, nf_e1, "new tip is the right half's present nf");
}

#[test]
fn spendable_lift_rejects_wrong_cm_trapdoor() {
    // Honest future + honest Unspent, but the lift witnesses a wrong value, so
    // the derived cm is wrong and the cm-trapdoor check catches it.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let unspent = build_unspent_pcd(
        rng,
        &pool,
        user.nf_at(&note, 0),
        BlockHeight(init_height.0 + 1)..=BlockHeight(init_height.0 + 1),
    );
    let future = user.shifted_future(&note, 0);
    let unspent_poly = NfSeqPoly::from([user.nf_at(&note, 0)].as_slice());
    // A wrong (still in-range) value yields a wrong derived cm.
    let wrong_value = note::Value::from(999_999u64);
    assert_ne!(u64::from(wrong_value), u64::from(note.value));

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableLift,
            (
                (note.pk, wrong_value, note.rcm, user.pronfs_poly(&note)),
                future,
                unspent_poly,
                user.shifted_future(&note, 1),
            ),
            spendable,
            unspent,
        )
        .err()
        .unwrap();
    assert_eq!(
        err.0,
        "SpendableLift: spendable_future does not match future"
    );
}

#[test]
fn spend_bind_rejects_wrong_value() {
    // The value-inflation attack: a malicious spender witnesses the note's real
    // `M` and rcm/pk but claims a larger `value`, hoping `cv = rcv.commit(value)`
    // mints. To pass the preimage confirm it must witness the matching `cm =
    // Poseidon(rcm, pk, inflated value, psi)` (a fully-consistent fake note). But
    // `value` is folded into `cm`, so that `cm` differs from the real note's;
    // its shifted-and-trapdoored tail lands in a different commitment than the
    // spendable's `future`, so the lineage check rejects. The same mechanism
    // rejects a wrong `rcm` or `pk`.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
    let (rcv, _theta, alpha) = spend_witness(rng, &note);

    // Real M, real rcm/pk, but an inflated (still in-range) value, with the
    // matching cm so the preimage confirm passes. The published nullifiers are
    // shifted by this wrong cm, so the re-based tail misses the spendable's
    // `future` (built from the real cm).
    let wrong_value = note::Value::from(999_999u64);
    assert_ne!(u64::from(wrong_value), u64::from(note.value));
    let wrong_cm = Note {
        pk: note.pk,
        value: wrong_value,
        psi: note.psi,
        rcm: note.rcm,
    }
    .commitment();
    // Real M shifted self-consistently by the inflated cm.
    let pronf = user.pronfs_poly(&note);
    let (nf_pair, rest, nf_tail, live) = fresh_spend_parts(&pronf, wrong_cm);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (
                (note.pk, wrong_value, note.rcm, pronf),
                nf_pair,
                rest,
                nf_tail,
                live,
                rcv,
                alpha,
                user.pak,
            ),
            spendable_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    assert_eq!(
        err.0,
        "SpendBind: tail does not match the spendable's future"
    );
}

#[test]
fn notes_with_shared_pronf_have_distinct_nullifiers() {
    // Two notes with the same recipient and the same pronullifier polynomial M but
    // distinct (rcm, value) have distinct cms. The cm-shift on published
    // nullifiers (`nf_e = M_e + cm`) makes their nullifier sequences differ at
    // every relative epoch, so each note is independently spendable: spending
    // one does not publish the other's nullifiers.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note_a = user.random_note(rng, 500);
    let note_b = user.note_sharing_pronf(rng, &note_a, 700);
    assert_eq!(note_a.psi, note_b.psi, "shared M yields shared psi");
    assert_ne!(
        note_a.commitment(),
        note_b.commitment(),
        "distinct (rcm, value) yields distinct cm"
    );

    // Nullifiers differ at every relative epoch.
    for epoch in 0..4u32 {
        assert_ne!(
            user.nf_at(&note_a, epoch),
            user.nf_at(&note_b, epoch),
            "cm-shift separates shared-M nullifiers at epoch {epoch}"
        );
    }

    // Both notes spend successfully through the full stamp pipeline.
    pool.mine(random_block_with(
        rng,
        &[vec![note_a.commitment(), note_b.commitment()]],
        4,
    ));
    let height = pool.height();

    for note in [&note_a, &note_b] {
        let spendable_pcd = user.fresh_spend(rng, &pool, height, note);
        let (rcv, _theta, alpha) = spend_witness(rng, note);
        let (spend_pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spend::SpendBind,
                (
                    (note.pk, note.value, note.rcm, user.pronfs_poly(note)),
                    user.live_pair_nf(note, 0),
                    user.tail_rest_nf(note, 0),
                    user.shifted_future(note, 0),
                    user.live_scalars(note, 0),
                    rcv,
                    alpha,
                    user.pak,
                ),
                spendable_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("SpendBind succeeds for each shared-M note");
        let (_cv, _rk, (now, next), _anchor) = *spend_pcd.data();
        assert_eq!(now, user.nf_at(note, 0));
        assert_eq!(next, user.nf_at(note, 1));
    }
}

#[test]
fn sync_sim_builds_unspent_for_wallet_lift_across_epochs() {
    // End-to-end demonstration of the delegate flow:
    // - Wallet creates note + spendable via SpendableInit.
    // - Wallet shares nf values with SyncSim.
    // - Pool advances across an epoch boundary.
    // - SyncSim composes a multi-epoch Unspent (no cm).
    // - Wallet runs SpendableLift over it (with cm witness).
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    // Locate the cm-stamp index in init_height.
    let cm_idx = pool
        .tachygrams_at(init_height)
        .iter()
        .position(|tgs| tgs.contains(&note.commitment().into()))
        .expect("cm in block");

    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().1;

    // Wallet shares nf values for the relative epoch range covered by the
    // delegation (epochs 0 and 1 = inclusion + one cross-epoch span).
    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![user.nf_at(&note, 0), user.nf_at(&note, 1)],
        init_height,
        cm_idx,
        start_anchor,
    );

    // Advance the pool past one epoch boundary so the Unspent spans both
    // epoch 0 and epoch 1.
    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    assert_eq!(sync.consumed(0), 1);

    // Wallet runs SpendableLift with cm as witness. The span crosses one epoch
    // boundary (epoch 0 -> 1), so `elapsed = [nf_0]` and the new present is nf_1.
    let future = user.shifted_future(&note, 0);
    let consumed_poly = NfSeqPoly::from([user.nf_at(&note, 0)].as_slice());
    let (lifted, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableLift,
            (
                (note.pk, note.value, note.rcm, user.pronfs_poly(&note)),
                future,
                consumed_poly,
                user.shifted_future(&note, 1),
            ),
            spendable,
            unspent,
        )
        .expect("SpendableLift across an epoch boundary");

    // The lifted spendable's anchor matches the pool's anchor at the
    // target height (= the Unspent's end anchor).
    assert_eq!(lifted.data().1, pool.anchor_at(target_height));
}

#[test]
fn unspent_fuse_rejects_nonzero_forward_half() {
    // UnspentFuse extends within one epoch: the forwards (right) half must cross
    // no boundary. A multi-epoch right is rejected (checked before adjacency).
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.advance(usize::try_from(EPOCH_SIZE + 1).expect("fits"), |_| {
        random_block(rng, 1, 2)
    });

    let nf0 = Nullifier::from(Fp::random(&mut *rng));
    let nf1 = Nullifier::from(Fp::random(&mut *rng));
    // A multi-epoch (one-crossing) segment to use as the forwards half.
    let m_left = build_unspent_pcd(
        rng,
        &pool,
        nf0,
        BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1),
    );
    let m_right = build_unspent_pcd(
        rng,
        &pool,
        nf1,
        BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
    );
    let empty = NfSeqPoly::from(Vec::<Nullifier>::new().as_slice());
    let (multi, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (
                EpochIndex(1),
                empty.clone(),
                empty,
                NfSeqPoly::from([nf0].as_slice()),
            ),
            m_left,
            m_right,
        )
        .expect("multi-epoch segment");

    let left = build_unspent_pcd(rng, &pool, nf0, BlockHeight(0)..=BlockHeight(0));
    let err = PROOF_SYSTEM
        .fuse(rng, pool::UnspentFuse, (), left, multi)
        .err()
        .unwrap();
    assert_eq!(
        err.0,
        "UnspentFuse: forwards half must stay within one epoch"
    );
}

#[test]
fn sync_unspent_spans_two_crossings() {
    // Two crossings exercise a multi-epoch LEFT in the epoch-fuse splice (the
    // second crossing fuses an already-multi-epoch chain).
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let cm_idx = pool
        .tachygrams_at(init_height)
        .iter()
        .position(|tgs| tgs.contains(&note.commitment().into()))
        .expect("cm in block");
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().1;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.nf_at(&note, 0),
            user.nf_at(&note, 1),
            user.nf_at(&note, 2)
        ],
        init_height,
        cm_idx,
        start_anchor,
    );

    let target_height = BlockHeight(2 * EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    assert_eq!(sync.consumed(0), 2, "two epoch crossings");

    let (lifted, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableLift,
            (
                (note.pk, note.value, note.rcm, user.pronfs_poly(&note)),
                user.shifted_future(&note, 0),
                NfSeqPoly::from([user.nf_at(&note, 0), user.nf_at(&note, 1)].as_slice()),
                user.shifted_future(&note, 2),
            ),
            spendable,
            unspent,
        )
        .expect("SpendableLift across two epoch boundaries");
    assert_eq!(lifted.data().1, pool.anchor_at(target_height));
}

#[test]
fn spendable_lift_rejects_tip_mismatch() {
    // The Unspent's present_nf (tip) must equal the spendable's carried-forward
    // present epoch (new_future's degree-0 coefficient). A wrong tip nf — even
    // with a genuine completed-epoch prefix — is rejected by the tip-tie.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let cm_idx = pool
        .tachygrams_at(init_height)
        .iter()
        .position(|tgs| tgs.contains(&note.commitment().into()))
        .expect("cm in block");
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().1;

    // Genuine epoch-0 nf (so the future-concat matches) but a wrong tip nf.
    let wrong_tip = Nullifier::from(Fp::random(&mut *rng));
    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![user.nf_at(&note, 0), wrong_tip],
        init_height,
        cm_idx,
        start_anchor,
    );

    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableLift,
            (
                (note.pk, note.value, note.rcm, user.pronfs_poly(&note)),
                user.shifted_future(&note, 0),
                NfSeqPoly::from([user.nf_at(&note, 0)].as_slice()),
                user.shifted_future(&note, 1),
            ),
            spendable,
            unspent,
        )
        .err()
        .unwrap();
    assert_eq!(
        err.0,
        "SpendableLift: present_nf does not match new future tip"
    );
}

/// Build the two adjacent epoch-fuse halves: a left half spanning epoch 0 and a
/// right half spanning epoch 1, over a pool advanced past one boundary.
fn epoch_fuse_setup(
    rng: &mut StdRng,
) -> (
    PoolSim,
    Nullifier,
    Nullifier,
    ragu::Pcd<pool::Unspent>,
    ragu::Pcd<pool::Unspent>,
) {
    let mut pool = PoolSim::genesis(rng);
    pool.advance(usize::try_from(EPOCH_SIZE + 1).expect("fits"), |_| {
        random_block(rng, 1, 2)
    });
    let nf_e0 = Nullifier::from(Fp::random(&mut *rng));
    let nf_e1 = Nullifier::from(Fp::random(&mut *rng));
    let left = build_unspent_pcd(
        rng,
        &pool,
        nf_e0,
        BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1),
    );
    let right = build_unspent_pcd(
        rng,
        &pool,
        nf_e1,
        BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
    );
    (pool, nf_e0, nf_e1, left, right)
}

#[test]
fn unspent_epoch_fuse_rejects_wrong_left_poly() {
    // left_poly's commit does not match the left header's (identity) elapsed.
    let rng = &mut StdRng::seed_from_u64(0);
    let (_pool, nf_e0, nf_e1, left, right) = epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (
                EpochIndex(1),
                NfSeqPoly::from([nf_e1].as_slice()),
                NfSeqPoly::from(Vec::<Nullifier>::new().as_slice()),
                NfSeqPoly::from([nf_e0].as_slice()),
            ),
            left,
            right,
        )
        .err()
        .unwrap();
    assert_eq!(
        err.0,
        "UnspentEpochFuse: left polynomial does not match header"
    );
}

#[test]
fn unspent_epoch_fuse_rejects_wrong_boundary() {
    // Wrong boundary epoch index: next_epoch(2) does not land on right.start.
    let rng = &mut StdRng::seed_from_u64(0);
    let (_pool, nf_e0, _nf_e1, left, right) = epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (
                EpochIndex(2),
                NfSeqPoly::from(Vec::<Nullifier>::new().as_slice()),
                NfSeqPoly::from(Vec::<Nullifier>::new().as_slice()),
                NfSeqPoly::from([nf_e0].as_slice()),
            ),
            left,
            right,
        )
        .err()
        .unwrap();
    assert_eq!(
        err.0,
        "UnspentEpochFuse: boundary anchor does not match right.prev_anchor"
    );
}

#[test]
fn unspent_epoch_fuse_rejects_wrong_combined() {
    // combined is not the splice: it should be [nf_e0] (left's completing tip).
    let rng = &mut StdRng::seed_from_u64(0);
    let (_pool, _nf_e0, nf_e1, left, right) = epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (
                EpochIndex(1),
                NfSeqPoly::from(Vec::<Nullifier>::new().as_slice()),
                NfSeqPoly::from(Vec::<Nullifier>::new().as_slice()),
                NfSeqPoly::from([nf_e1].as_slice()),
            ),
            left,
            right,
        )
        .err()
        .unwrap();
    assert_eq!(
        err.0,
        "UnspentEpochFuse: combined is not the splice of the halves"
    );
}

#[test]
fn spendable_lift_rejects_elapsed_mismatch() {
    // Honest future, but the witnessed `unspent_elapsed` does not match the
    // consumed Unspent's `elapsed` commitment (here identity for an intra-epoch
    // span), so the elapsed-commit check rejects before adjacency.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let unspent = build_unspent_pcd(
        rng,
        &pool,
        user.nf_at(&note, 0),
        BlockHeight(init_height.0 + 1)..=BlockHeight(init_height.0 + 1),
    );
    // A non-empty elapsed poly cannot match the intra-epoch identity elapsed.
    let bogus_elapsed = NfSeqPoly::from([Nullifier::from(Fp::random(&mut *rng))].as_slice());

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableLift,
            (
                (note.pk, note.value, note.rcm, user.pronfs_poly(&note)),
                user.shifted_future(&note, 0),
                bogus_elapsed,
                user.shifted_future(&note, 0),
            ),
            spendable,
            unspent,
        )
        .err()
        .unwrap();
    assert_eq!(
        err.0,
        "SpendableLift: unspent_elapsed does not match header"
    );
}

#[test]
fn spendable_lift_rejects_non_adjacent_unspent() {
    // Honest future and a genuine (identity) elapsed, but the consumed Unspent
    // begins at an anchor the spendable does not sit at, so the adjacency check
    // rejects. The spendable's anchor is in epoch 0; the Unspent starts in
    // epoch 1.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let unspent = build_unspent_pcd(
        rng,
        &pool,
        user.nf_at(&note, 0),
        BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
    );

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableLift,
            (
                (note.pk, note.value, note.rcm, user.pronfs_poly(&note)),
                user.shifted_future(&note, 0),
                NfSeqPoly::from(Vec::<Nullifier>::new().as_slice()),
                user.shifted_future(&note, 0),
            ),
            spendable,
            unspent,
        )
        .err()
        .unwrap();
    assert_eq!(err.0, "SpendableLift: unspent not adjacent to spendable");
}

#[test]
fn spend_bind_rejects_unrelated_pak() {
    // The published nullifiers and `cv` are pinned to the note, but the action
    // verification key is derived from `pak`; an unrelated `pak` (whose payment
    // key does not match the note's `pk`) is rejected.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let other = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
    let (rcv, _theta, alpha) = spend_witness(rng, &note);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (
                (note.pk, note.value, note.rcm, user.pronfs_poly(&note)),
                user.live_pair_nf(&note, 0),
                user.tail_rest_nf(&note, 0),
                user.shifted_future(&note, 0),
                user.live_scalars(&note, 0),
                rcv,
                alpha,
                other.pak,
            ),
            spendable_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    assert_eq!(err.0, "SpendBind: pak not related to note");
}

#[test]
fn spendable_init_rejects_zero_value() {
    // Layered coverage: the zero-value guard at the lineage seed (it is also
    // enforced at SpendBind). Fires before the cm-in-set check.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());

    let pronf = user.pronfs_poly(&note);
    let creation_set = TachygramSetPoly::from([tg(rng)].as_slice());
    let pre_cm_anchor = pool.prev_anchor_at(init_height);

    let err = PROOF_SYSTEM
        .seed(
            rng,
            spendable::SpendableInit,
            (
                (note.pk, note::Value(0), note.rcm, pronf),
                creation_set,
                pre_cm_anchor,
            ),
        )
        .err()
        .unwrap();

    assert_eq!(err.0, "SpendableInit: zero-value note");
}
