#![allow(unreachable_pub, reason = "test code")]
#![allow(clippy::type_complexity, reason = "test code")]
#![allow(clippy::partial_pub_fields, reason = "test code")]
#![allow(clippy::too_many_lines, reason = "test code")]
#![allow(clippy::too_many_arguments, reason = "test code")]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::{cmp, iter, ops::RangeInclusive};

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Pcd, Proof};
use rand_core::{CryptoRng, RngCore};

use crate::{
    action::{self, Action},
    bundle::{self, Bundle},
    constants::EPOCH_SIZE,
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{ProofAuthorizingKey, private},
    note::{self, Note, Nullifier},
    primitives::{
        ActionDigest, Anchor, BlockHeight, DelegationId, EpochIndex, Tachygram, TachygramSetCommit,
        TachygramSetPoly, effect,
    },
    stamp::{
        Stamp,
        proof::{PROOF_SYSTEM, delegation, pool, spendable},
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
    let cm = note.commitment();
    let plan = action::Plan::output(note, theta, rcv.clone());
    let alpha = theta.randomizer::<effect::Output>(cm);
    (rcv, alpha, plan)
}

pub fn build_output_stamp(
    rng: &mut (impl RngCore + CryptoRng),
    anchor: Anchor,
    note: Note,
) -> (Stamp, action::Plan<effect::Output>) {
    let (rcv, alpha, plan) = build_output_plan(rng, note.clone());
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
    let anchor = pool.anchor_at(height);
    let spend = wallet.fresh_spend(rng, &pool, height, spend_note);
    wallet.autonome(rng, anchor, alloc::vec![spend], alloc::vec![output_note])
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

    /// Resolve the height at which `anchor` was produced. `block.prev` already
    /// holds the anchor of the preceding block, so a single scan over the
    /// `prev` linkage suffices; only the tip anchor needs recomputing.
    #[must_use]
    pub fn height_at(&self, anchor: Anchor) -> BlockHeight {
        self.history
            .iter()
            .enumerate()
            .skip(1)
            .find(|&(_, block)| block.prev == anchor)
            .map(|(idx, _)| BlockHeight::from(idx - 1))
            .or_else(|| (self.anchor() == anchor).then(|| self.height()))
            .expect("anchor not in pool history")
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
    stamp_tgs: &[Tachygram],
    nf: Nullifier,
) -> Pcd<pool::Unspent> {
    let (pcd, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::UnspentSeed,
            (start, TachygramSetPoly::from(stamp_tgs), nf),
        )
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

pub(crate) fn build_nullifier_rollover_pcd(
    rng: &mut (impl RngCore + CryptoRng),
    user: &WalletSim,
    note: Note,
    epoch: EpochIndex,
) -> Pcd<spendable::NullifierRolloverHeader> {
    let master_old = user.note_master(rng, note.clone());
    let nf_old_pcd = ggm_tools::nullifier_from_master(rng, master_old, epoch);
    let master_new = user.note_master(rng, note);
    let nf_new_pcd = ggm_tools::nullifier_from_master(rng, master_new, EpochIndex(epoch.0 + 1));
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(rng, spendable::RolloverFuse, (), nf_old_pcd, nf_new_pcd)
        .expect("RolloverFuse");
    pcd
}

pub struct WalletSim {
    pub sk: private::SpendingKey,
    pub pak: ProofAuthorizingKey,
}

impl WalletSim {
    pub fn new(sk: private::SpendingKey) -> Self {
        let pak = sk.derive_proof_private();
        Self { sk, pak }
    }

    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::new(private::SpendingKey::random(rng))
    }

    pub fn random_note(&self, rng: &mut (impl RngCore + CryptoRng), value_amount: u64) -> Note {
        Note {
            pk: self.sk.derive_payment_key(),
            value: note::Value::from(value_amount),
            psi: note::NullifierTrapdoor::random(rng),
            rcm: note::CommitmentTrapdoor::random(rng),
        }
    }

    pub fn note_master(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
    ) -> Pcd<delegation::NfMasterHeader> {
        let (pcd, ()) = PROOF_SYSTEM
            .seed(rng, delegation::NfMasterSeed, (note, self.pak))
            .expect("note seed");
        pcd
    }

    pub fn nullifier_pcd(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
        target_epoch: EpochIndex,
    ) -> Pcd<delegation::NullifierHeader> {
        let master = self.note_master(rng, note);
        ggm_tools::nullifier_from_master(rng, master, target_epoch)
    }

    /// User-device nullifier pair for `target_epoch` and `target_epoch + 1`.
    /// Used by the spend path — `SpendBind` consumes two `NullifierHeader`s
    /// carrying the wallet's `cm`.
    pub fn nullifier_pair_pcd(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
        target_epoch: EpochIndex,
    ) -> (
        Pcd<delegation::NullifierHeader>,
        Pcd<delegation::NullifierHeader>,
    ) {
        let nf_now = self.nullifier_pcd(rng, note.clone(), target_epoch);
        let nf_next = self.nullifier_pcd(rng, note, EpochIndex(target_epoch.0 + 1));
        (nf_now, nf_next)
    }

    pub fn fresh_spend(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        pool: &PoolSim,
        height: BlockHeight,
        spend_note: Note,
    ) -> (
        Note,
        Pcd<delegation::NullifierHeader>,
        Pcd<delegation::NullifierHeader>,
        Pcd<spendable::SpendableHeader>,
    ) {
        let nf_for_init = self.nullifier_pcd(rng, spend_note.clone(), height.epoch());
        let spendable = self.spendable_init(rng, spend_note.clone(), pool, height, nf_for_init);

        let (nf_now, nf_next) = self.nullifier_pair_pcd(rng, spend_note.clone(), height.epoch());

        (spend_note, nf_now, nf_next, spendable)
    }

    #[expect(
        clippy::unused_self,
        reason = "method on WalletSim for ergonomics; wallet's keys produced nf_pcd"
    )]
    pub fn spendable_init(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
        pool: &PoolSim,
        height: BlockHeight,
        nf_pcd: Pcd<delegation::NullifierHeader>,
    ) -> Pcd<spendable::SpendableHeader> {
        let cm = note.commitment();

        let stamps = pool.tachygrams_at(height);
        let stamp_commits = pool.stamp_commits_at(height);
        let cm_idx = stamps
            .iter()
            .position(|tgs| tgs.contains(&cm.into()))
            .expect("cm not found in any stamp at the cm-block");

        let pre_cm_anchor = stamp_commits[..cm_idx]
            .iter()
            .fold(pool.prev_anchor_at(height), Anchor::next_stamp);

        let (spendable, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spendable::SpendableInit,
                (
                    pre_cm_anchor,
                    TachygramSetPoly::from(stamps[cm_idx].as_slice()),
                ),
                nf_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("SpendableInit");

        // If cm is the last stamp, post_cm_anchor is already the
        // block-final anchor — no rest-of-block lift needed.
        if cm_idx + 1 == stamps.len() {
            return spendable;
        }

        // Build an Unspent over stamps cm_idx+1..end of the cm-block,
        // chained from post_cm_anchor, then SpendableLift.
        let nf = spendable.data().0;
        let mut state = spendable.data().1;
        let mut acc: Option<Pcd<pool::Unspent>> = None;
        for (tgs, commit) in stamps[cm_idx + 1..]
            .iter()
            .zip(stamp_commits[cm_idx + 1..].iter())
        {
            let next_state = state.next_stamp(commit);
            let seed = build_unspent_seed_pcd(rng, state, tgs, nf);
            acc = Some(match acc.take() {
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
        let rest = acc.expect("rest-of-block has at least one stamp");

        let (lifted, ()) = PROOF_SYSTEM
            .fuse(rng, spendable::SpendableLift, (), spendable, rest)
            .expect("SpendableLift");
        lifted
    }

    pub fn autonome(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        anchor: Anchor,
        spends: Vec<(
            Note,
            Pcd<delegation::NullifierHeader>,
            Pcd<delegation::NullifierHeader>,
            Pcd<spendable::SpendableHeader>,
        )>,
        output_notes: Vec<Note>,
    ) -> Bundle<Stamp> {
        let ask = self.sk.derive_auth_private();

        let mut spend_plans = Vec::with_capacity(spends.len());
        let mut spend_pcds = Vec::with_capacity(spends.len());
        for (note, nf_now, nf_next, spendable) in spends {
            let rcv = value::CommitmentTrapdoor::random(rng);
            let theta = ActionEntropy::random(rng);
            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                self.pak.ak.derive_action_public(&alpha)
            });
            spend_plans.push(plan);
            spend_pcds.push((nf_now, nf_next, spendable));
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

pub struct SyncSim {
    entries: Vec<(
        DelegationId,
        Vec<Pcd<delegation::DelegateNfPrefixHeader>>,
        Pcd<spendable::SpendableHeader>,
    )>,
}

impl SyncSim {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record (or replace) the spendable for the wallet identified by the
    /// `delegates` cover. `delegation_id` is derived from `delegates[0]`;
    /// all delegates must share it.
    pub fn accept_spendable(
        &mut self,
        delegates: Vec<Pcd<delegation::DelegateNfPrefixHeader>>,
        spendable: Pcd<spendable::SpendableHeader>,
    ) {
        let delegation_id = delegates.first().expect("at least one delegate").data().1;
        assert!(
            delegates.iter().all(|del| del.data().1 == delegation_id),
            "delegates must share a single delegation_id"
        );
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.0 == delegation_id)
        {
            entry.1 = delegates;
            entry.2 = spendable;
        } else {
            self.entries.push((delegation_id, delegates, spendable));
        }
    }

    pub fn spendable(&self, delegation_id: DelegationId) -> Pcd<spendable::SpendableHeader> {
        self.entries
            .iter()
            .find(|entry| entry.0 == delegation_id)
            .expect("no maintained spendable for delegation_id")
            .2
            .clone()
    }

    /// Advance every maintained spendable up to `pool`'s current anchor,
    /// composing same-epoch and cross-epoch lifts as needed. Stored
    /// spendables locate their current height by asking `pool` to resolve
    /// the spendable's anchor.
    pub fn lift(&mut self, rng: &mut (impl RngCore + CryptoRng), pool: &PoolSim) {
        let ids: Vec<DelegationId> = self.entries.iter().map(|entry| entry.0).collect();
        for id in ids {
            self.lift_one(rng, id, pool);
        }
    }

    fn lift_one(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
        delegation_id: DelegationId,
        pool: &PoolSim,
    ) {
        loop {
            let target_height = pool.height();
            let idx = self
                .entries
                .iter()
                .position(|entry| entry.0 == delegation_id)
                .expect("no entry for delegation_id");
            let stored_anchor = self.entries[idx].2.data().1;
            let stored_height = pool.height_at(stored_anchor);
            if stored_height == target_height {
                return;
            }
            assert!(stored_height < target_height);

            let (_, delegates, spendable_pcd) = self.entries.swap_remove(idx);
            let stored_epoch = stored_height.epoch();
            let stored_epoch_final = epoch_final_of(stored_epoch);

            // Lift inside the current epoch first, up to either target_height
            // or stored_epoch_final, whichever comes first.
            let same_epoch_target = cmp::min(target_height, stored_epoch_final);

            let after_same_epoch_pcd = if same_epoch_target == stored_height {
                spendable_pcd
            } else {
                let nf = spendable_pcd.data().0;
                let unspent = build_unspent_pcd(
                    rng,
                    pool,
                    nf,
                    BlockHeight(stored_height.0 + 1)..=same_epoch_target,
                );
                let (pcd, ()) = PROOF_SYSTEM
                    .fuse(rng, spendable::SpendableLift, (), spendable_pcd, unspent)
                    .expect("SpendableLift");
                pcd
            };

            if same_epoch_target == target_height {
                self.entries
                    .push((delegation_id, delegates, after_same_epoch_pcd));
                continue;
            }

            // Cross the epoch boundary. Walk the local delegates cover
            // directly so we don't have to re-insert the popped entry.
            let new_epoch = EpochIndex(stored_epoch.0 + 1);
            let old_nf_pcd = walk_delegate_for_epoch(rng, &delegates, stored_epoch);
            let new_nf_pcd = walk_delegate_for_epoch(rng, &delegates, new_epoch);
            let new_nf = new_nf_pcd.data().0;

            let (rollover_pcd, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    spendable::DelegateRolloverFuse,
                    (),
                    old_nf_pcd,
                    new_nf_pcd,
                )
                .expect("DelegateRolloverFuse");

            let (rollover_header_pcd, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    spendable::SpendableRollover,
                    (),
                    after_same_epoch_pcd,
                    rollover_pcd,
                )
                .expect("SpendableRollover");

            let next_target = cmp::min(target_height, epoch_final_of(new_epoch));
            let new_epoch_first = BlockHeight(stored_epoch_final.0 + 1);
            let unspent = build_unspent_pcd(rng, pool, new_nf, new_epoch_first..=next_target);
            let (landed, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    spendable::SpendableEpochLift,
                    (),
                    rollover_header_pcd,
                    unspent,
                )
                .expect("SpendableEpochLift");
            self.entries.push((delegation_id, delegates, landed));
        }
    }
}

impl Default for SyncSim {
    fn default() -> Self {
        Self::new()
    }
}

fn walk_delegate_for_epoch(
    rng: &mut (impl RngCore + CryptoRng),
    delegates: &[Pcd<delegation::DelegateNfPrefixHeader>],
    target_epoch: EpochIndex,
) -> Pcd<delegation::DelegateNullifierHeader> {
    let delegate = delegates
        .iter()
        .find(|pcd| pcd.data().0.range().contains(&target_epoch.0))
        .expect("no delegate covers target_epoch")
        .clone();
    ggm_tools::walk_delegate_to_delegate_nullifier(rng, delegate, target_epoch)
}

fn epoch_final_of(epoch: EpochIndex) -> BlockHeight {
    let next_first = (epoch.0 + 1) * EPOCH_SIZE;
    BlockHeight(next_first - 1)
}

pub mod ggm_tools {
    extern crate alloc;
    use alloc::vec::Vec;
    use core::ops::RangeInclusive;

    use ragu::{Pcd, Proof};
    use rand_core::{CryptoRng, RngCore};

    use crate::{
        EpochIndex,
        keys::{GGM_CHUNK_SIZE, GGM_TREE_DEPTH},
        primitives::DelegationTrapdoor,
        stamp::proof::{PROOF_SYSTEM, delegation},
    };

    pub fn walk_master_to_depth(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<delegation::NfMasterHeader>,
        epoch_bits: u32,
        target_depth: u8,
    ) -> Pcd<delegation::NfPrefixHeader> {
        assert!(
            (1..=GGM_TREE_DEPTH).contains(&target_depth),
            "target_depth must be in 1..=GGM_DEPTH",
        );

        let first_chunk = chunk_at(epoch_bits, 1);
        let (mut pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                delegation::NfMasterStep,
                (first_chunk,),
                master_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("note master step");

        while pcd.data().0.depth.get() < target_depth {
            let next_step = pcd.data().0.depth.get() + 1;
            let chunk = chunk_at(epoch_bits, next_step);
            let (next_pcd, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    delegation::NfPrefixStep,
                    (chunk,),
                    pcd,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("note step");
            pcd = next_pcd;
        }

        pcd
    }

    pub fn delegate_range(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: &Pcd<delegation::NfMasterHeader>,
        trap: DelegationTrapdoor,
        epoch_range: RangeInclusive<u32>,
    ) -> Vec<Pcd<delegation::DelegateNfPrefixHeader>> {
        let mk = master_pcd.data().0;
        mk.derive_note_delegates(epoch_range)
            .into_iter()
            .map(|target_key| {
                let target_depth = target_key.depth.get();
                let span_bits = (GGM_TREE_DEPTH - target_depth) * GGM_CHUNK_SIZE;
                let epoch_bits = target_key.index << span_bits;
                let prefix_pcd =
                    walk_master_to_depth(rng, master_pcd.clone(), epoch_bits, target_depth);
                blind_prefix(rng, prefix_pcd, trap)
            })
            .collect()
    }

    pub fn nullifier_from_master(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<delegation::NfMasterHeader>,
        target_epoch: EpochIndex,
    ) -> Pcd<delegation::NullifierHeader> {
        let prefix_pcd = walk_master_to_depth(rng, master_pcd, target_epoch.0, GGM_TREE_DEPTH);
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                delegation::NullifierStep,
                (),
                prefix_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("nullifier step");
        pcd
    }

    pub fn delegate_nullifier_from_master(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<delegation::NfMasterHeader>,
        trap: DelegationTrapdoor,
        target_epoch: EpochIndex,
    ) -> Pcd<delegation::DelegateNullifierHeader> {
        let depth_one = walk_master_to_depth(rng, master_pcd, target_epoch.0, 1);
        let blinded = blind_prefix(rng, depth_one, trap);
        walk_delegate_to_delegate_nullifier(rng, blinded, target_epoch)
    }

    /// Apply [`DelegationStep`](delegation::DelegationStep) to a
    /// pre-blind prefix PCD, returning a post-blind delegate PCD.
    pub fn blind_prefix(
        rng: &mut (impl RngCore + CryptoRng),
        prefix_pcd: Pcd<delegation::NfPrefixHeader>,
        trap: DelegationTrapdoor,
    ) -> Pcd<delegation::DelegateNfPrefixHeader> {
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                delegation::DelegationStep,
                (trap,),
                prefix_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("delegation blind step");
        pcd
    }

    pub fn walk_delegate_to_delegate_nullifier(
        rng: &mut (impl RngCore + CryptoRng),
        delegate_pcd: Pcd<delegation::DelegateNfPrefixHeader>,
        target_epoch: EpochIndex,
    ) -> Pcd<delegation::DelegateNullifierHeader> {
        let mut pcd = delegate_pcd;

        while pcd.data().0.depth.get() < GGM_TREE_DEPTH {
            let next_step = pcd.data().0.depth.get() + 1;
            let chunk = chunk_at(target_epoch.0, next_step);
            let (next_pcd, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    delegation::DelegateNfPrefixStep,
                    (chunk,),
                    pcd,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("delegation step");
            pcd = next_pcd;
        }

        let (nf_pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                delegation::DelegateNullifierStep,
                (),
                pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("delegate nullifier step");
        nf_pcd
    }

    fn chunk_at(epoch_bits: u32, level: u8) -> u8 {
        let shift = (GGM_TREE_DEPTH * GGM_CHUNK_SIZE) - level * GGM_CHUNK_SIZE;
        let chunk_mask = (1u32 << GGM_CHUNK_SIZE) - 1u32;
        let chunk_u32 = (epoch_bits >> shift) & chunk_mask;
        u8::try_from(chunk_u32).expect("chunk fits in u8")
    }
}
