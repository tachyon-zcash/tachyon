#![allow(unreachable_pub, reason = "test code")]
#![allow(clippy::type_complexity, reason = "test code")]
#![allow(clippy::partial_pub_fields, reason = "test code")]
#![allow(clippy::too_many_lines, reason = "test code")]
#![allow(clippy::too_many_arguments, reason = "test code")]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::{cell::RefCell, cmp, iter, ops::RangeInclusive};

use ff::Field as _;
use pasta_curves::Fp;
use ragu::Pcd;
use rand_core::{CryptoRng, RngCore};

use crate::{
    ProNfSeqCommit,
    action::{self, Action},
    bundle::{self, Bundle},
    constants::{EPOCH_SIZE, NOTE_LIFETIME_MAX},
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{ProofAuthorizingKey, private},
    note::{self, Note, Nullifier, ProNf},
    primitives::{
        ActionDigest, Anchor, BlockHeight, EpochIndex, NfSeqPoly, ProNfSeqPoly, Tachygram,
        TachygramSetCommit, TachygramSetPoly, effect,
    },
    stamp::{
        Stamp,
        proof::{PROOF_SYSTEM, pool, spendable},
    },
    value,
};

pub fn mock_sighash(bundle_digest: [u8; 64]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend sighash")
        .to_state()
        .update(&bundle_digest)
        .finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub fn action_digests(actions: &[Action]) -> Vec<ActionDigest> {
    actions
        .iter()
        .map(|action| action.digest().expect("valid action"))
        .collect()
}

pub fn random_action(rng: &mut (impl RngCore + CryptoRng)) -> Action {
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(rng, 400);
    let (_, _, plan) = build_output_plan(rng, note);
    let bundle_plan = bundle::Plan::new(alloc::vec![], alloc::vec![plan]);
    let sighash = mock_sighash(bundle_plan.commitment());
    let unproven = bundle_plan
        .sign(&sighash, &ask, rng)
        .expect("sign foreign output");
    unproven.actions[0]
}

pub fn spend_witness(
    rng: &mut (impl RngCore + CryptoRng),
    note: &Note,
) -> (
    value::CommitmentTrapdoor,
    ActionEntropy,
    ActionRandomizer<effect::Spend>,
) {
    let rcv = value::CommitmentTrapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let alpha = theta.randomizer::<effect::Spend>(note.commitment());
    (rcv, theta, alpha)
}

pub fn build_output_plan(
    rng: &mut (impl RngCore + CryptoRng),
    note: Note,
) -> (
    value::CommitmentTrapdoor,
    ActionRandomizer<effect::Output>,
    action::Plan<effect::Output>,
) {
    let rcv = value::CommitmentTrapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let plan = action::Plan::output(note, theta, rcv);
    let alpha = theta.randomizer::<effect::Output>(note.commitment());
    (rcv, alpha, plan)
}

pub fn build_output_stamp(
    rng: &mut (impl RngCore + CryptoRng),
    anchor: Anchor,
    note: Note,
) -> (Stamp, action::Plan<effect::Output>) {
    let (rcv, alpha, plan) = build_output_plan(rng, note);
    let stamp = Stamp::prove_output(rng, rcv, alpha, note, anchor).expect("prove_output");
    (stamp, plan)
}

pub fn build_autonome(
    rng: &mut (impl RngCore + CryptoRng),
    wallet: &WalletSim,
    spend_value: u64,
    output_value: u64,
) -> Bundle<Stamp> {
    let spend_note = wallet.random_note(rng, spend_value);
    let output_note = wallet.random_note(rng, output_value);
    let mut pool = PoolSim::genesis(rng);
    let stamps_cms = vec![vec![spend_note.commitment()]];
    pool.mine(random_block_with(rng, &stamps_cms, 50));
    let height = pool.height();
    let spendable_pcd = wallet.fresh_spend(rng, &pool, height, &spend_note);
    let consumed_head = wallet.consumed_head(&spend_note, 0);
    let remaining_tail = wallet.remaining_tail(&spend_note, 0);
    // The output stamp anchors at the spendable's anchor (the post-cm-stamp
    // anchor, since no lift has advanced it) so MergeStamp's anchor-equality
    // check passes.
    let anchor = spendable_pcd.data().1;
    wallet.autonome(
        rng,
        anchor,
        alloc::vec![(spend_note, spendable_pcd, consumed_head, remaining_tail)],
        alloc::vec![output_note],
    )
}

pub fn random_block(
    rng: &mut (impl RngCore + CryptoRng),
    stamp_size: usize,
    n_stamps: usize,
) -> Vec<Vec<Tachygram>> {
    iter::repeat_with(|| {
        iter::repeat_with(|| Tachygram::from(Fp::random(&mut *rng)))
            .take(stamp_size)
            .collect()
    })
    .take(n_stamps)
    .collect()
}

pub fn random_block_with(
    rng: &mut (impl RngCore + CryptoRng),
    stamps_cms: &[Vec<note::Commitment>],
    n_stamps: usize,
) -> Vec<Vec<Tachygram>> {
    assert!(
        n_stamps >= stamps_cms.len(),
        "n_stamps must accommodate every stamp in stamps_cms"
    );
    let mut stamps: Vec<Vec<Tachygram>> = stamps_cms
        .iter()
        .map(|cms| cms.iter().map(|&cm| Tachygram::from(cm)).collect())
        .collect();
    stamps.extend(
        iter::repeat_with(|| alloc::vec![Tachygram::from(Fp::random(&mut *rng))])
            .take(n_stamps - stamps_cms.len()),
    );
    stamps
}

#[derive(Clone, Debug)]
struct PoolSimBlock {
    prev: Anchor,
    stamps: Vec<Vec<Tachygram>>,
}

pub struct PoolSim {
    history: Vec<PoolSimBlock>,
}

impl PoolSim {
    #[must_use]
    pub fn genesis(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::genesis_with(random_block(rng, 1, 50))
    }

    pub fn genesis_with(stamps: Vec<Vec<Tachygram>>) -> Self {
        Self {
            history: alloc::vec![PoolSimBlock {
                prev: Anchor::default(),
                stamps
            }],
        }
    }

    #[must_use]
    pub fn height(&self) -> BlockHeight {
        BlockHeight::from(self.history.len() - 1)
    }

    #[must_use]
    pub fn anchor(&self) -> Anchor {
        self.anchor_at(self.height())
    }

    #[must_use]
    pub fn tachygrams_at(&self, height: BlockHeight) -> Vec<Vec<Tachygram>> {
        self.history
            .get(usize::try_from(height).expect("fits usize"))
            .expect("query height should exist")
            .stamps
            .clone()
    }

    #[must_use]
    pub fn stamp_commits_at(&self, height: BlockHeight) -> Vec<TachygramSetCommit> {
        self.tachygrams_at(height)
            .iter()
            .map(|tgs| TachygramSetCommit::from(tgs.as_slice()))
            .collect()
    }

    #[must_use]
    pub fn prev_anchor_at(&self, height: BlockHeight) -> Anchor {
        self.history
            .get(usize::try_from(height).expect("fits usize"))
            .expect("query height should exist")
            .prev
    }

    #[must_use]
    pub fn anchor_at(&self, height: BlockHeight) -> Anchor {
        let prev = self.prev_anchor_at(height);
        let commits = self.stamp_commits_at(height);
        if commits.is_empty() {
            prev.next_empty()
        } else {
            commits.iter().fold(prev, Anchor::next_stamp)
        }
    }

    pub fn advance(
        &mut self,
        count: usize,
        mut block_factory: impl FnMut(&Self) -> Vec<Vec<Tachygram>>,
    ) {
        for _ in 0..count {
            let block = block_factory(self);
            self.mine(block);
        }
    }

    pub fn mine(&mut self, stamps: Vec<Vec<Tachygram>>) {
        let new_height = BlockHeight::from(self.history.len());
        let old_tip = self.anchor();
        // Epoch-first blocks are preceded by a boundary anchor lift;
        // intra-epoch blocks advance directly from the previous tip.
        let prev = if new_height.is_epoch_first() {
            old_tip.next_epoch(new_height.epoch())
        } else {
            old_tip
        };
        self.history.push(PoolSimBlock { prev, stamps });
    }
}

/// Build an [`AnchorChain`] covering blocks `range`, rooted at the
/// block-start anchor of `*range.start()`.
///
/// Per non-empty block: one [`AnchorSeed`] per stamp, fused via
/// [`AnchorFuse`]. Per empty block: one [`EmptyBlockSeed`].
/// All segments fused linearly.
pub(crate) fn build_anchor_chain_pcd(
    rng: &mut (impl RngCore + CryptoRng),
    pool: &PoolSim,
    range: RangeInclusive<BlockHeight>,
) -> Pcd<pool::AnchorChain> {
    let start = *range.start();
    let end = *range.end();
    assert_eq!(start.epoch(), end.epoch(), "AnchorChain single-epoch range");
    assert!(start <= end);

    let mut state = pool.prev_anchor_at(start);
    let mut chain: Option<Pcd<pool::AnchorChain>> = None;
    let mut height = start;
    loop {
        let commits = pool.stamp_commits_at(height);
        if commits.is_empty() {
            let next_state = state.next_empty();
            let (seed, ()) = PROOF_SYSTEM
                .seed(rng, pool::EmptyBlockSeed, (state,))
                .expect("EmptyBlockSeed");
            chain = Some(match chain.take() {
                | None => seed,
                | Some(left) => {
                    let (fused, ()) = PROOF_SYSTEM
                        .fuse(rng, pool::AnchorFuse, (), left, seed)
                        .expect("AnchorFuse");
                    fused
                },
            });
            state = next_state;
        } else {
            for commit in commits {
                let next_state = state.next_stamp(&commit);
                let (seed, ()) = PROOF_SYSTEM
                    .seed(rng, pool::AnchorSeed, (state, commit))
                    .expect("AnchorSeed");
                chain = Some(match chain.take() {
                    | None => seed,
                    | Some(left) => {
                        let (fused, ()) = PROOF_SYSTEM
                            .fuse(rng, pool::AnchorFuse, (), left, seed)
                            .expect("AnchorFuse");
                        fused
                    },
                });
                state = next_state;
            }
        }
        if height >= end {
            break;
        }
        height = height.next().expect("height < max");
    }

    chain.expect("AnchorChain range must cover at least one block")
}

pub(crate) fn build_unspent_seed_pcd(
    rng: &mut (impl RngCore + CryptoRng),
    start: Anchor,
    tgs: &[Tachygram],
    nf: Nullifier,
) -> Pcd<pool::Unspent> {
    let tg_set = TachygramSetPoly::from(tgs);
    let (pcd, ()) = PROOF_SYSTEM
        .seed(rng, pool::UnspentSeed, (start, tg_set, nf))
        .expect("UnspentSeed");
    pcd
}

/// Build an [`Unspent`] for `nf` covering blocks `range`. Per non-empty
/// block: one [`UnspentSeed`] per stamp. Per empty block: one
/// [`EmptyBlockUnspentSeed`]. All segments fused linearly via
/// [`UnspentFuse`].
pub(crate) fn build_unspent_pcd(
    rng: &mut (impl RngCore + CryptoRng),
    pool: &PoolSim,
    nf: Nullifier,
    range: RangeInclusive<BlockHeight>,
) -> Pcd<pool::Unspent> {
    let start = *range.start();
    let end = *range.end();
    assert_eq!(start.epoch(), end.epoch(), "Unspent single-epoch range");
    assert!(start <= end);

    let mut state = pool.prev_anchor_at(start);
    let mut chain: Option<Pcd<pool::Unspent>> = None;
    let mut height = start;
    loop {
        let stamps = pool.tachygrams_at(height);
        let stamp_commits = pool.stamp_commits_at(height);
        if stamps.is_empty() {
            let next_state = state.next_empty();
            let (seed, ()) = PROOF_SYSTEM
                .seed(rng, pool::EmptyBlockUnspentSeed, (state, nf))
                .expect("EmptyBlockUnspentSeed");
            chain = Some(match chain.take() {
                | None => seed,
                | Some(left) => {
                    let (fused, ()) = PROOF_SYSTEM
                        .fuse(rng, pool::UnspentFuse, (), left, seed)
                        .expect("UnspentFuse");
                    fused
                },
            });
            state = next_state;
        } else {
            for (tgs, commit) in stamps.iter().zip(stamp_commits.iter()) {
                let next_state = state.next_stamp(commit);
                let seed = build_unspent_seed_pcd(rng, state, tgs, nf);
                chain = Some(match chain.take() {
                    | None => seed,
                    | Some(left) => {
                        let (fused, ()) = PROOF_SYSTEM
                            .fuse(rng, pool::UnspentFuse, (), left, seed)
                            .expect("UnspentFuse");
                        fused
                    },
                });
                state = next_state;
            }
        }
        if height >= end {
            break;
        }
        height = height.next().expect("height < max");
    }

    chain.expect("Unspent range must cover at least one block")
}

fn epoch_final_of(epoch: EpochIndex) -> BlockHeight {
    let next_first = (epoch.0 + 1) * EPOCH_SIZE;
    BlockHeight(next_first - 1)
}

/// Locate the block-internal position of `cm`: the stamp index, the
/// per-stamp tachygram lists and commits at `height`, and the anchor running
/// into the block (its `prev`).
fn locate_cm(
    pool: &PoolSim,
    height: BlockHeight,
    cm: note::Commitment,
) -> (usize, Vec<Vec<Tachygram>>, Vec<TachygramSetCommit>, Anchor) {
    let stamps = pool.tachygrams_at(height);
    let stamp_commits = pool.stamp_commits_at(height);
    let cm_idx = stamps
        .iter()
        .position(|tgs| tgs.contains(&cm.into()))
        .expect("cm not found in any stamp at the cm-block");
    let prev_anchor = pool.prev_anchor_at(height);
    (cm_idx, stamps, stamp_commits, prev_anchor)
}

pub struct WalletSim {
    pub sk: private::SpendingKey,
    pub pak: ProofAuthorizingKey,
    /// Per-note pronullifier polynomial `M` (degree-order coefficients), keyed
    /// by the note's commitment. Forward-chronological: coefficient `i` is the
    /// pronullifier `M[i]` for relative epoch `i`; the published nullifier is
    /// `M[i] + cm`. `psi = commit(M)`.
    pronfs: RefCell<Vec<(note::Commitment, Vec<ProNf>)>>,
}

impl WalletSim {
    pub fn new(sk: private::SpendingKey) -> Self {
        Self {
            sk,
            pak: sk.derive_proof_private(),
            pronfs: RefCell::new(Vec::new()),
        }
    }

    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::new(private::SpendingKey::random(rng))
    }

    pub fn random_note(&self, rng: &mut (impl RngCore + CryptoRng), value_amount: u64) -> Note {
        // M_i = 0 would publish `nf_e = cm`, colliding with the creation
        // stamp's cm tachygram inside the 2-epoch consensus window — that
        // note's epoch-`e` spend would be unspendable. Probability is ~L/p ~=
        // 2^{-241} per coefficient over a uniform-random M; we treat it as
        // statistically impossible alongside hash preimages and discrete-log
        // collisions, so no runtime check is required here.
        let pronfs = iter::repeat_with(|| ProNf::random(rng))
            .take(NOTE_LIFETIME_MAX)
            .collect::<Vec<ProNf>>();
        let note = Note {
            pk: self.sk.derive_payment_key(),
            value: note::Value::from(value_amount),
            psi: ProNfSeqCommit::from(pronfs.as_slice()),
            rcm: note::CommitmentTrapdoor::random(rng),
        };
        self.pronfs.borrow_mut().push((note.commitment(), pronfs));
        note
    }

    /// Build a note that reuses an existing `note`'s pronullifier polynomial
    /// `M`. The two notes share `psi = commit(M)` but get distinct
    /// `(rcm, value)`, so
    /// their `cm`s differ. With the cm-shift on published nullifiers, their
    /// nullifier sequences also differ at every relative epoch.
    pub fn note_sharing_pronf(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        existing: &Note,
        value_amount: u64,
    ) -> Note {
        let pronfs = self.pronfs(existing);
        let note = Note {
            pk: self.sk.derive_payment_key(),
            value: note::Value::from(value_amount),
            psi: existing.psi,
            rcm: note::CommitmentTrapdoor::random(rng),
        };
        self.pronfs.borrow_mut().push((note.commitment(), pronfs));
        note
    }

    /// The note's pronullifier polynomial `M` coefficients (degree order).
    fn pronfs(&self, note: &Note) -> Vec<ProNf> {
        let cm = note.commitment();
        self.pronfs
            .borrow()
            .iter()
            .find(|entry| entry.0 == cm)
            .expect("expected pronullifier polynomial for note")
            .1
            .clone()
    }

    /// The note's nullifier for relative epoch `epoch`: `nf_e = M[e] + cm`.
    /// The polynomial is laid out forward-chronologically, so epoch `i` is
    /// coefficient `i` of `M`; the `+cm` shift makes each note's nullifier
    /// sequence distinct even when two notes share the same `M`.
    pub fn nf_at(&self, note: &Note, epoch: u32) -> Nullifier {
        let pronfs = self.pronfs(note);
        let epoch_idx = usize::try_from(epoch).expect("epoch fits usize");
        assert!(epoch_idx < pronfs.len(), "epoch within note lifetime");
        note.commitment().nullify(pronfs[epoch_idx])
    }

    /// The note's full raw pronullifier polynomial `M` as a [`ProNfSeqPoly`].
    /// Unshifted — the `+cm` shift only enters at spend time. Witnessed by both
    /// [`SpendableInit`] and [`SpendBind`], which derive `psi = commit(M)`
    /// from it.
    ///
    /// [`SpendableInit`]: spendable::SpendableInit
    /// [`SpendBind`]: crate::stamp::proof::spend::SpendBind
    pub fn pronfs_poly(&self, note: &Note) -> ProNfSeqPoly {
        let pronfs = self.pronfs(note);
        ProNfSeqPoly::from(pronfs.as_slice())
    }

    /// The already-vanished head of `M` after `consumed` epochs:
    /// `M[0..consumed]`, raw. Passed to [`Plan::prove`] alongside the remaining
    /// tail; `prove` reassembles `M = consumed_head || remaining_tail`.
    ///
    /// [`Plan::prove`]: crate::stamp::Plan::prove
    pub fn consumed_head(&self, note: &Note, consumed: u32) -> ProNfSeqPoly {
        let pronfs = self.pronfs(note);
        let from = usize::try_from(consumed).expect("epoch fits usize");
        assert!(from <= pronfs.len(), "consumed within note lifetime");
        ProNfSeqPoly::from(&pronfs[..from])
    }

    /// The remaining raw tail of `M` after `consumed` epochs: `M[consumed..]`,
    /// rebased to degree 0. Passed to [`Plan::prove`], which peels the live
    /// pair off its front and shifts the rest into nullifier values.
    ///
    /// [`Plan::prove`]: crate::stamp::Plan::prove
    pub fn remaining_tail(&self, note: &Note, consumed: u32) -> ProNfSeqPoly {
        let pronfs = self.pronfs(note);
        let from = usize::try_from(consumed).expect("epoch fits usize");
        assert!(from < pronfs.len(), "consumed within note lifetime");
        ProNfSeqPoly::from(&pronfs[from..])
    }

    /// The live nullifier tail after the published pair: `(nf_at(consumed + 2),
    /// ...)`, already `+cm` shifted. `SpendBind` concatenates it after the
    /// rank-2 `nf_pair` to rebuild the re-based live tail `nf_tail`.
    pub fn tail_rest_nf(&self, note: &Note, consumed: u32) -> NfSeqPoly {
        let pronfs = self.pronfs(note);
        let i = usize::try_from(consumed).expect("epoch fits usize");
        assert!(
            i + 1 < pronfs.len(),
            "two epochs remain within note lifetime"
        );
        let cm = note.commitment();
        NfSeqPoly::from(
            pronfs[i + 2..]
                .iter()
                .map(|&pronf| cm.nullify(pronf))
                .collect::<Vec<Nullifier>>()
                .as_slice(),
        )
    }

    /// The live nullifier pair `(nf_at(consumed), nf_at(consumed + 1))` as a
    /// rank-2 [`NfSeqPoly`]. The prover witnesses it to `SpendBind`, which
    /// proves it is the rank-2 nullifier pair of the witnessed live
    /// pronullifier scalars and concatenates it with `rest` to rebuild the
    /// re-based tail.
    pub fn live_pair_nf(&self, note: &Note, consumed: u32) -> NfSeqPoly {
        let pronfs = self.pronfs(note);
        let i = usize::try_from(consumed).expect("epoch fits usize");
        assert!(
            i + 1 < pronfs.len(),
            "two epochs remain within note lifetime"
        );
        let cm = note.commitment();
        NfSeqPoly::from([cm.nullify(pronfs[i]), cm.nullify(pronfs[i + 1])].as_slice())
    }

    /// The two live pronullifier scalars `(M[consumed], M[consumed+1])`. The
    /// honest prover witnesses these to `SpendBind`, which shifts them by `cm`
    /// into the published nullifier pair.
    pub fn live_scalars(&self, note: &Note, consumed: u32) -> (ProNf, ProNf) {
        let pronfs = self.pronfs(note);
        let i = usize::try_from(consumed).expect("epoch fits usize");
        assert!(
            i + 1 < pronfs.len(),
            "two epochs remain within note lifetime"
        );
        (pronfs[i], pronfs[i + 1])
    }

    /// The spendable's `future` nullifiers after `consumed` epochs have been
    /// lifted away: the shifted tail `[M[consumed]+cm, ..., M[L-1]+cm]`
    /// re-based to degree 0. This is the `spendable_future` a
    /// [`SpendableLift`] witnesses (the chain commits to its trapdoored
    /// commit), and the `nf_tail` a [`SpendBind`] witnesses.
    ///
    /// [`SpendableLift`]: spendable::SpendableLift
    /// [`SpendBind`]: crate::stamp::proof::spend::SpendBind
    pub fn shifted_future(&self, note: &Note, consumed: u32) -> NfSeqPoly {
        let pronfs = self.pronfs(note);
        let from = usize::try_from(consumed).expect("epoch fits usize");
        assert!(from < pronfs.len(), "consumed within note lifetime");
        let cm = note.commitment();
        let shifted: Vec<Nullifier> = pronfs[from..]
            .iter()
            .map(|&pronf| cm.nullify(pronf))
            .collect();
        NfSeqPoly::from(shifted.as_slice())
    }

    /// Seed a spendable at the cm-block via [`SpendableInit`]: witness the
    /// note's fields, unshifted `M`, the creation stamp's tachygrams, and the
    /// anchor running into that stamp; the step derives `psi = commit(M)`
    /// and `cm = Poseidon(rcm, pk, value, psi)`, verifies `cm` is in
    /// `creation_set`, and outputs the homomorphically shifted-and-trapdoored
    /// initial commit `(future, anchor)`. No rest-of-cm-block lift is performed
    /// (the spendable sits at the anchor immediately after the cm-stamp).
    pub fn spendable_init(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: &Note,
        pool: &PoolSim,
        init_height: BlockHeight,
    ) -> Pcd<spendable::SpendableHeader> {
        let cm = note.commitment();
        let (cm_idx, stamps, stamp_commits, prev_anchor) = locate_cm(pool, init_height, cm);
        let pre_cm_anchor = stamp_commits[..cm_idx]
            .iter()
            .fold(prev_anchor, Anchor::next_stamp);
        let creation_set = TachygramSetPoly::from(stamps[cm_idx].as_slice());
        let pronf = self.pronfs_poly(note);

        let (spendable, ()) = PROOF_SYSTEM
            .seed(
                rng,
                spendable::SpendableInit,
                (
                    (note.pk, note.value, note.rcm, pronf),
                    creation_set,
                    pre_cm_anchor,
                ),
            )
            .expect("SpendableInit");
        spendable
    }

    /// Build the spendable for a note whose cm sits at `height`, spending in
    /// the same block (no prior epochs consumed). Returns just the
    /// spendable PCD; the caller already holds the note and passes
    /// `consumed = 0` to [`autonome`](Self::autonome), which derives the
    /// `M` split itself.
    pub fn fresh_spend(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        pool: &PoolSim,
        height: BlockHeight,
        spend_note: &Note,
    ) -> Pcd<spendable::SpendableHeader> {
        self.spendable_init(rng, spend_note, pool, height)
    }

    /// Lift a freshly-init'd spendable across its creation epoch's boundary,
    /// consuming that one epoch (one crossing, `consumed = 1`) and landing in
    /// the next epoch. `pool` must already extend into the epoch after
    /// creation. The matching spend then witnesses `consumed = 1` (present
    /// pair `nf_at(note, 1)` / `nf_at(note, 2)`).
    pub fn lift_over_creation_epoch(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        pool: &PoolSim,
        note: &Note,
        cm_height: BlockHeight,
        spendable: Pcd<spendable::SpendableHeader>,
    ) -> Pcd<spendable::SpendableHeader> {
        let cm_idx = pool
            .tachygrams_at(cm_height)
            .iter()
            .position(|tgs| tgs.contains(&note.commitment().into()))
            .expect("cm in creation block");
        let start_anchor = spendable.data().1;
        // Cross the creation epoch's boundary into the next epoch: end one block
        // past the epoch-final, so the span crosses exactly once (elapsed_size 1).
        let end_height = BlockHeight(epoch_final_of(cm_height.epoch()).0 + 1);
        let unspent = build_partial_multi_epoch_unspent(
            rng,
            pool,
            &[self.nf_at(note, 0), self.nf_at(note, 1)],
            cm_height,
            cm_idx + 1,
            start_anchor,
            end_height,
        );
        let (lifted, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spendable::SpendableLift,
                (
                    (note.pk, note.value, note.rcm, self.pronfs_poly(note)),
                    self.shifted_future(note, 0),
                    NfSeqPoly::from([self.nf_at(note, 0)].as_slice()),
                    self.shifted_future(note, 1),
                ),
                spendable,
                unspent,
            )
            .expect("lift over creation epoch");
        lifted
    }

    pub fn autonome(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        anchor: Anchor,
        spends: Vec<(
            Note,
            Pcd<spendable::SpendableHeader>,
            ProNfSeqPoly,
            ProNfSeqPoly,
        )>,
        output_notes: Vec<Note>,
    ) -> Bundle<Stamp> {
        let ask = self.sk.derive_auth_private();

        let mut spend_plans = Vec::with_capacity(spends.len());
        let mut spend_pcds = Vec::with_capacity(spends.len());
        for (note, spendable_pcd, consumed_head, remaining_tail) in spends {
            let rcv = value::CommitmentTrapdoor::random(rng);
            let theta = ActionEntropy::random(rng);
            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                self.pak.ak.derive_action_public(&alpha)
            });
            spend_plans.push(plan);
            spend_pcds.push((spendable_pcd, consumed_head, remaining_tail));
        }

        let output_plans: Vec<action::Plan<effect::Output>> = output_notes
            .into_iter()
            .map(|note| {
                let rcv = value::CommitmentTrapdoor::random(rng);
                let theta = ActionEntropy::random(rng);
                action::Plan::output(note, theta, rcv)
            })
            .collect();

        let bundle_plan = bundle::Plan::new(spend_plans, output_plans);
        let sighash = mock_sighash(bundle_plan.commitment());
        let unproven = bundle_plan
            .sign(&sighash, &ask, rng)
            .expect("sign autonome");

        let stamp_plan = bundle_plan.stamp_plan(anchor);
        let stamp = stamp_plan
            .prove(rng, &self.pak, spend_pcds)
            .expect("prove autonome stamp");

        unproven.stamp(stamp)
    }
}

/// Stand-in for a delegated sync service.
///
/// Holds, per delegated handle, only the nullifier *values* the wallet
/// shared (forward-chronological from the spendable's inclusion epoch), a
/// cursor over uncovered pool segments
/// (`next_height`/`next_stamp_idx`/`cursor_anchor`), and a `consumed`
/// count. Never sees `M`, `psi`, `cm`, the note, or the spendable PCD —
/// "the delegate sees no cm" is what this fixture demonstrates.
///
/// [`build_next_unspent`] composes a multi-epoch `Unspent` PCD covering
/// `[cursor..=target_height]` and advances the cursor. The wallet then
/// runs `SpendableLift` (witnessing `cm`) over the returned `Unspent`.
///
/// [`build_next_unspent`]: SyncSim::build_next_unspent
pub struct SyncSim {
    entries: Vec<SyncEntry>,
}

struct SyncEntry {
    handle: usize,
    nfs: Vec<Nullifier>,
    consumed: u32,
    next_height: BlockHeight,
    next_stamp_idx: usize,
    cursor_anchor: Anchor,
}

impl SyncSim {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register a freshly-init'd spendable's delegation. The spendable
    /// sits at `start_anchor` after the cm-stamp in `cm_height` (so the first
    /// uncovered stamp index is `cm_idx + 1`); `nfs[i]` is the nullifier
    /// for the spendable's `i`-th relative epoch.
    pub fn accept_delegation(
        &mut self,
        handle: usize,
        nfs: Vec<Nullifier>,
        cm_height: BlockHeight,
        cm_idx: usize,
        start_anchor: Anchor,
    ) {
        let entry = SyncEntry {
            handle,
            nfs,
            consumed: 0,
            next_height: cm_height,
            next_stamp_idx: cm_idx + 1,
            cursor_anchor: start_anchor,
        };
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|stored| stored.handle == handle)
        {
            *slot = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// The number of epochs already consumed for `handle` (so the wallet
    /// can read the matching slice of `M` for the next `SpendableLift`'s
    /// `future` witness).
    pub fn consumed(&self, handle: usize) -> u32 {
        self.entry(handle).consumed
    }

    /// Build a composed `Unspent` PCD covering
    /// `[cursor..=target_height]` and advance the cursor past it. Returns
    /// the PCD; the wallet supplies the matching `future` and
    /// `unspent_polynomial` gadgets at `SpendableLift` time using the same
    /// nf values it shared (sliced by [`consumed`] before and after).
    ///
    /// [`consumed`]: SyncSim::consumed
    pub fn build_next_unspent(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
        handle: usize,
        pool: &PoolSim,
        target_height: BlockHeight,
    ) -> Pcd<pool::Unspent> {
        let idx = self.entry_index(handle);
        let entry = &self.entries[idx];
        assert!(
            target_height >= entry.next_height,
            "target_height must be at least the next uncovered height"
        );
        let nfs_from = usize::try_from(entry.consumed).expect("fits usize");
        let unspent = build_partial_multi_epoch_unspent(
            rng,
            pool,
            &entry.nfs[nfs_from..],
            entry.next_height,
            entry.next_stamp_idx,
            entry.cursor_anchor,
            target_height,
        );
        // Crossings within the span = epoch delta (the tip epoch is `present_nf`,
        // not counted).
        let new_consumed = entry.consumed + (target_height.epoch().0 - entry.next_height.epoch().0);
        self.entries[idx].consumed = new_consumed;
        self.entries[idx].next_height = BlockHeight(target_height.0 + 1);
        self.entries[idx].next_stamp_idx = 0;
        self.entries[idx].cursor_anchor = pool.anchor_at(target_height);
        unspent
    }

    fn entry(&self, handle: usize) -> &SyncEntry {
        self.entries
            .iter()
            .find(|entry| entry.handle == handle)
            .expect("no delegation for handle")
    }

    fn entry_index(&self, handle: usize) -> usize {
        self.entries
            .iter()
            .position(|entry| entry.handle == handle)
            .expect("no delegation for handle")
    }
}

impl Default for SyncSim {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a multi-epoch `Unspent` starting partway through `first_height`'s
/// stamps: the chain begins at `start_anchor` (typically the spendable's
/// initial anchor from `SpendableInit`, or a prior lift's end anchor), skips
/// `0..first_stamp_idx` in `first_height`, and covers stamps
/// `first_stamp_idx..` of `first_height` plus all blocks up through
/// `end_height`.
fn build_partial_multi_epoch_unspent(
    rng: &mut (impl RngCore + CryptoRng),
    pool: &PoolSim,
    nfs: &[Nullifier],
    first_height: BlockHeight,
    first_stamp_idx: usize,
    start_anchor: Anchor,
    end_height: BlockHeight,
) -> Pcd<pool::Unspent> {
    let first_epoch = first_height.epoch();
    let first_epoch_final = epoch_final_of(first_epoch);
    let first_epoch_end = cmp::min(end_height, first_epoch_final);
    let nf0 = nfs[0];

    // Per-stamp seeds + fuses across the partial first block.
    let stamps = pool.tachygrams_at(first_height);
    let stamp_commits = pool.stamp_commits_at(first_height);
    assert!(first_stamp_idx <= stamps.len(), "first_stamp_idx in range");
    let mut state = start_anchor;
    let mut first_segment: Option<Pcd<pool::Unspent>> = None;
    for (tgs, commit) in stamps[first_stamp_idx..]
        .iter()
        .zip(stamp_commits[first_stamp_idx..].iter())
    {
        let seed = build_unspent_seed_pcd(rng, state, tgs, nf0);
        state = state.next_stamp(commit);
        first_segment = Some(match first_segment.take() {
            | None => seed,
            | Some(left) => {
                let (fused, ()) = PROOF_SYSTEM
                    .fuse(rng, pool::UnspentFuse, (), left, seed)
                    .expect("UnspentFuse rest-of-block");
                fused
            },
        });
    }
    // Subsequent blocks within the first epoch.
    let mut height = BlockHeight(first_height.0 + 1);
    while height <= first_epoch_end {
        let segment = build_unspent_pcd(rng, pool, nf0, height..=height);
        first_segment = Some(match first_segment.take() {
            | None => segment,
            | Some(left) => {
                let (fused, ()) = PROOF_SYSTEM
                    .fuse(rng, pool::UnspentFuse, (), left, segment)
                    .expect("UnspentFuse subsequent-block");
                fused
            },
        });
        height = BlockHeight(height.0 + 1);
    }

    let mut chain = first_segment.expect("first epoch covers at least one stamp");
    // `elapsed_nfs` are the crossed-epoch nfs (excluding the in-progress tip);
    // `present_nf` is the chain's current tip. Each crossing splices `present_nf`
    // into `elapsed` and advances the tip.
    let mut elapsed_nfs: Vec<Nullifier> = Vec::new();
    let mut present_nf = nf0;

    if first_epoch_end == end_height {
        return chain;
    }

    let mut current_height = BlockHeight(first_epoch_end.0 + 1);
    let mut current_epoch = EpochIndex(first_epoch.0 + 1);
    let mut nfs_idx = 1usize;
    loop {
        let epoch_final = epoch_final_of(current_epoch);
        let epoch_end_height = cmp::min(end_height, epoch_final);
        let nf = nfs[nfs_idx];
        let intra = build_unspent_pcd(rng, pool, nf, current_height..=epoch_end_height);

        // Splice the completing tip (`present_nf`) between the crossed nfs and the
        // (empty) intra-epoch right half: combined = elapsed_nfs ++ [present_nf].
        let left_poly = NfSeqPoly::from(elapsed_nfs.as_slice());
        let right_poly = NfSeqPoly::from(Vec::<Nullifier>::new().as_slice());
        let mut combined_nfs = elapsed_nfs.clone();
        combined_nfs.push(present_nf);
        let combined = NfSeqPoly::from(combined_nfs.as_slice());
        let (fused, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                pool::UnspentEpochFuse,
                (current_epoch, left_poly, right_poly, combined),
                chain,
                intra,
            )
            .expect("UnspentEpochFuse");
        chain = fused;
        elapsed_nfs.push(present_nf);
        present_nf = nf;

        if epoch_end_height == end_height {
            break;
        }
        current_height = BlockHeight(epoch_end_height.0 + 1);
        current_epoch = EpochIndex(current_epoch.0 + 1);
        nfs_idx += 1;
    }

    chain
}
