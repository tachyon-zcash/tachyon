//! Shared test-support: simulators for the three real roles.
//!
//! - [`PoolSim`] — consensus's evolving pool state, the public chain that
//!   everyone observes.
//! - [`WalletSim`] — the wallet. Holds `sk`/`pak`. Constructs notes and
//!   actions, derives delegate keys for sync, bootstraps delegation seeds and
//!   spendable PCDs (these steps take `pak` in their witness), authorizes
//!   spends.
//! - [`SyncSim`] — the sync-service observer. Constructed from a `Vec` of
//!   [`NotePrefixedKey`] delegates handed over by the wallet; holds no other
//!   key material. Walks delegation PCDs down to nullifier leaves but cannot
//!   derive nullifiers outside a delegated prefix.
//!
//! Tests construct `pool`, `user`, and `sync` individually — `sync` needs
//! the delegate keys at construction, which the wallet must produce first.

#![allow(unreachable_pub, reason = "test support")]
#![allow(clippy::partial_pub_fields, reason = "test support")]

extern crate alloc;

use alloc::vec::Vec;
use core::iter;

use ff::Field as _;
use mock_ragu::{Pcd, Polynomial, Proof};
use pasta_curves::Fp;
use rand_core::{CryptoRng, RngCore};

use crate::{
    BlockSet,
    action::{self, Action, Signature},
    bundle::{self, Stamped},
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    primitives::{
        ActionDigest, Anchor, BlockAcc, BlockCommit, BlockHeight, DelegationId, DelegationTrapdoor,
        EpochIndex, PoolChain, effect,
    },
    stamp::proof::{PROOF_SYSTEM, delegation, spendable},
    value,
};

pub fn mock_sighash(bundle_digest: [u8; 64]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend sighash")
        .to_state()
        .update(&bundle_digest)
        .finalize();

    // truncate to 32 bytes
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub fn action_digests(actions: &[Action]) -> Vec<ActionDigest> {
    actions
        .iter()
        .map(|action| ActionDigest::try_from(action).expect("valid action"))
        .collect()
}

/// Build a block with `size` random tachygrams. The canonical height
/// tachygram is added by [`PoolSim::mine`] — callers don't include it.
pub fn random_block(rng: &mut (impl RngCore + CryptoRng), size: usize) -> BlockAcc {
    let roots: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
        .take(size)
        .collect();
    BlockSet(Polynomial::from_roots(&roots))
}

pub fn build_output_action(
    rng: &mut (impl RngCore + CryptoRng),
    note: Note,
) -> (
    value::CommitmentTrapdoor,
    ActionRandomizer<effect::Output>,
    Action,
) {
    let rcv = value::CommitmentTrapdoor::random(&mut *rng);
    let theta = ActionEntropy::random(&mut *rng);
    let plan = action::Plan::output(note, theta, rcv);
    let alpha = theta.randomizer::<effect::Output>(&note.commitment());

    let action = Action {
        cv: plan.cv(),
        rk: plan.rk,
        sig: Signature::from([0u8; 64]),
    };

    (rcv, alpha, action)
}

/// Build a block containing every commitment in `cms` plus enough random
/// tachygrams to reach `size` total roots.
pub fn random_block_with(
    rng: &mut (impl RngCore + CryptoRng),
    cms: &[note::Commitment],
    size: usize,
) -> BlockAcc {
    assert!(
        size >= cms.len(),
        "size must accommodate every commitment in cms"
    );
    let mut roots: Vec<Fp> = cms.iter().map(Fp::from).collect();
    roots.extend(iter::repeat_with(|| Fp::random(&mut *rng)).take(size - cms.len()));
    BlockSet(Polynomial::from_roots(&roots))
}

#[derive(Clone, Debug)]
struct HistoryEntry {
    block: BlockAcc,
    prev_chain: PoolChain,
    height: BlockHeight,
}

pub struct PoolSim {
    history: Vec<HistoryEntry>,
}

impl PoolSim {
    pub fn new() -> Self {
        // Genesis: a single block at height 0 carrying only the canonical
        // height tachygram, prev_chain = PoolChain::genesis().
        let height = BlockHeight(0);
        let prev_chain = PoolChain::genesis();
        let height_root = Fp::from(&height.tachygram(prev_chain));
        let block = BlockSet(Polynomial::from_roots(&[height_root]));
        Self {
            history: alloc::vec![HistoryEntry {
                block,
                prev_chain,
                height,
            }],
        }
    }

    pub fn tip(&self) -> BlockHeight {
        self.history
            .last()
            .expect("history always has genesis entry")
            .height
    }

    pub fn anchor(&self) -> Anchor {
        self.anchor_at(self.tip())
    }

    pub fn block_at(&self, height: BlockHeight) -> BlockAcc {
        self.history[usize::try_from(height.0).expect("fits usize")]
            .block
            .clone()
    }

    pub fn prev_chain_at(&self, height: BlockHeight) -> PoolChain {
        self.history[usize::try_from(height.0).expect("fits usize")].prev_chain
    }

    pub fn anchor_at(&self, height: BlockHeight) -> Anchor {
        let entry = &self.history[usize::try_from(height.0).expect("fits usize")];
        let block_commit = BlockCommit(entry.block.0.commit(Fp::ZERO));
        Anchor(entry.prev_chain.advance(entry.height, &block_commit))
    }

    pub fn advance(
        &mut self,
        count: usize,
        mut block_factory: impl FnMut(&Self) -> BlockAcc,
    ) -> Vec<BlockAcc> {
        let start_idx = self.history.len();
        for _ in 0..count {
            self.mine(&block_factory(self));
        }
        self.history[start_idx..]
            .iter()
            .map(|entry| entry.block.clone())
            .collect()
    }

    /// Append a block. `PoolSim` automatically embeds the canonical height
    /// tachygram and advances the chain.
    pub fn mine(&mut self, block: &BlockAcc) {
        let prev_entry = self
            .history
            .last()
            .expect("history always has genesis entry");
        let prev_block_commit = BlockCommit(prev_entry.block.0.commit(Fp::ZERO));
        let prev_chain_after_prev = prev_entry
            .prev_chain
            .advance(prev_entry.height, &prev_block_commit);

        let height = BlockHeight(prev_entry.height.0 + 1);
        let height_root = Fp::from(&height.tachygram(prev_chain_after_prev));
        let block_with_height = BlockSet(block.0.multiply(&Polynomial::from_roots(&[height_root])));

        self.history.push(HistoryEntry {
            block: block_with_height,
            prev_chain: prev_chain_after_prev,
            height,
        });
    }
}

pub struct SyncSim<'source> {
    delegates: Vec<Pcd<'source, delegation::DelegationHeader>>,
    /// `(spendable PCD, height that the spendable currently anchors at)`.
    /// Height isn't carried on `SpendableHeader`; the sync service tracks it
    /// alongside.
    spendables: Vec<(Pcd<'source, spendable::SpendableHeader>, BlockHeight)>,
}

impl<'source> SyncSim<'source> {
    pub fn new(delegates: Vec<Pcd<'source, delegation::DelegationHeader>>) -> Self {
        Self {
            delegates,
            spendables: Vec::new(),
        }
    }

    pub fn accept_spendable(
        &mut self,
        spendable: Pcd<'source, spendable::SpendableHeader>,
        height: BlockHeight,
    ) {
        self.spendables.push((spendable, height));
    }

    pub fn spendable(
        &self,
        delegation_id: DelegationId,
    ) -> Pcd<'source, spendable::SpendableHeader> {
        self.spendables
            .iter()
            .find(|entry| entry.0.data.0 == delegation_id)
            .expect("no maintained spendable for delegation_id")
            .0
            .clone()
    }

    /// Advance every maintained spendable to `pool.tip()`, chaining
    /// same-epoch and cross-epoch lifts one block at a time.
    pub fn lift(&mut self, rng: &mut (impl RngCore + CryptoRng), pool: &PoolSim) {
        let ids: Vec<DelegationId> = self
            .spendables
            .iter()
            .map(|entry| entry.0.data.0)
            .collect();
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
        let target_height = pool.tip();
        loop {
            let idx = self
                .spendables
                .iter()
                .position(|entry| entry.0.data.0 == delegation_id)
                .expect("no maintained spendable for delegation_id");
            let stored_height = self.spendables[idx].1;
            if stored_height == target_height {
                return;
            }
            assert!(
                stored_height <= target_height,
                "target_height is behind stored height"
            );

            let (spendable_pcd, _) = self.spendables.swap_remove(idx);
            let stored_epoch = stored_height.epoch();
            let new_height = BlockHeight(stored_height.0 + 1);
            let new_epoch = new_height.epoch();

            let lifted = if new_epoch == stored_epoch {
                Self::same_epoch_lift(rng, spendable_pcd, pool, stored_height, new_height)
            } else {
                let old_nf_pcd = self.nullifier(rng, delegation_id, stored_epoch);
                let new_nf_pcd = self.nullifier(rng, delegation_id, new_epoch);
                Self::epoch_lift(
                    rng,
                    spendable_pcd,
                    old_nf_pcd,
                    new_nf_pcd,
                    pool,
                    stored_height,
                    new_height,
                )
            };
            self.spendables.push((lifted, new_height));
        }
    }

    fn same_epoch_lift(
        rng: &mut (impl RngCore + CryptoRng),
        spendable_pcd: Pcd<'source, spendable::SpendableHeader>,
        pool: &PoolSim,
        old_height: BlockHeight,
        new_height: BlockHeight,
    ) -> Pcd<'source, spendable::SpendableHeader> {
        let (delegation_id, nf, _) = spendable_pcd.data;
        let new_anchor = pool.anchor_at(new_height);
        let old_prev_chain = pool.prev_chain_at(old_height);
        let old_block = pool.block_at(old_height);
        let new_block = pool.block_at(new_height);
        let (proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &spendable::SpendableLift,
                (
                    old_prev_chain,
                    old_block.into(),
                    old_height,
                    new_block.into(),
                    new_height,
                    new_anchor,
                ),
                spendable_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("spendable lift");
        proof.carry::<spendable::SpendableHeader>((delegation_id, nf, new_anchor))
    }

    fn epoch_lift(
        rng: &mut (impl RngCore + CryptoRng),
        spendable_pcd: Pcd<'source, spendable::SpendableHeader>,
        old_nf_pcd: Pcd<'source, delegation::NullifierHeader>,
        new_nf_pcd: Pcd<'source, delegation::NullifierHeader>,
        pool: &PoolSim,
        old_height: BlockHeight,
        new_height: BlockHeight,
    ) -> Pcd<'source, spendable::SpendableHeader> {
        let (delegation_id, ..) = spendable_pcd.data;
        assert!(
            old_height.is_epoch_final(),
            "epoch lift requires spendable at epoch-final"
        );
        let old_nf = old_nf_pcd.data.0;
        let new_nf = new_nf_pcd.data.0;
        let new_anchor = pool.anchor_at(new_height);

        // Build a SpendableRollover PCD against the new block.
        let new_block = pool.block_at(new_height);
        let new_prev_chain = pool.prev_chain_at(new_height);
        let (rollover_proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &spendable::SpendableRollover,
                (
                    new_prev_chain,
                    new_block.clone().into(),
                    new_height,
                    new_anchor,
                ),
                old_nf_pcd,
                new_nf_pcd,
            )
            .expect("spendable rollover");
        let rollover_pcd = rollover_proof.carry::<spendable::SpendableRolloverHeader>((
            delegation_id,
            old_nf,
            new_nf,
            new_anchor,
        ));

        // Apply the cross-epoch lift.
        let old_prev_chain = pool.prev_chain_at(old_height);
        let old_block = pool.block_at(old_height);
        let (epoch_lift_proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &spendable::SpendableEpochLift,
                (
                    old_prev_chain,
                    old_block.into(),
                    old_height,
                    new_block.into(),
                    new_height,
                    new_anchor,
                ),
                spendable_pcd,
                rollover_pcd,
            )
            .expect("spendable epoch lift");
        epoch_lift_proof.carry::<spendable::SpendableHeader>((delegation_id, new_nf, new_anchor))
    }

    pub fn nullifier(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        delegation_id: DelegationId,
        target_epoch: EpochIndex,
    ) -> Pcd<'source, delegation::NullifierHeader> {
        let delegate = self
            .delegates
            .iter()
            .find(|pcd| pcd.data.1 == delegation_id && pcd.data.0.range().contains(&target_epoch.0))
            .expect("no delegate covers (delegation_id, target_epoch)")
            .clone();
        ggm_tools::walk_delegate_to_nullifier(rng, delegate, target_epoch)
    }
}

pub struct WalletSim {
    pub sk: private::SpendingKey,
    pub pak: ProofAuthorizingKey,
}

impl WalletSim {
    pub fn new(sk: private::SpendingKey) -> Self {
        Self {
            sk,
            pak: sk.derive_proof_private(),
        }
    }

    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::new(private::SpendingKey::random(rng))
    }

    pub fn random_note(&self, rng: &mut (impl RngCore + CryptoRng), value_amount: u64) -> Note {
        Note {
            pk: self.sk.derive_payment_key(),
            value: note::Value::from(value_amount),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut *rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut *rng)),
        }
    }

    pub fn note_master<'source>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
    ) -> Pcd<'source, delegation::NoteMasterHeader> {
        let mk = self.pak.nk.derive_note_private(&note.psi);
        let cm = note.commitment();
        let (proof, ()) = PROOF_SYSTEM
            .seed(rng, &delegation::NoteSeedStep, (note, self.pak))
            .expect("note seed");
        proof.carry::<delegation::NoteMasterHeader>((mk, cm))
    }

    #[expect(clippy::type_complexity, reason = "test-support tuple")]
    pub fn fresh_spend<'source>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        pool: &PoolSim,
        height: BlockHeight,
        spend_note: Note,
    ) -> (
        Note,
        DelegationTrapdoor,
        Pcd<'source, delegation::NullifierHeader>,
        Pcd<'source, delegation::NullifierHeader>,
        Pcd<'source, spendable::SpendableHeader>,
        PoolChain,
        BlockAcc,
        BlockHeight,
    ) {
        let trap = DelegationTrapdoor::random(rng);
        let master = self.note_master(rng, spend_note);
        let (nf_e, nf_e1) =
            ggm_tools::nullifier_pair_from_master(rng, master, trap, height.epoch());
        let spendable_pcd = self.spendable_init(rng, spend_note, trap, pool, height, nf_e.clone());
        let prev_chain = pool.prev_chain_at(height);
        let block = pool.block_at(height);
        (
            spend_note,
            trap,
            nf_e,
            nf_e1,
            spendable_pcd,
            prev_chain,
            block,
            height,
        )
    }

    pub fn spendable_init<'source>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
        trap: DelegationTrapdoor,
        pool: &PoolSim,
        height: BlockHeight,
        nf_pcd: Pcd<'source, delegation::NullifierHeader>,
    ) -> Pcd<'source, spendable::SpendableHeader> {
        let (nf, _epoch, delegation_id) = nf_pcd.data;
        let prev_chain = pool.prev_chain_at(height);
        let block = pool.block_at(height);
        let anchor = pool.anchor_at(height);
        let (spendable_proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &spendable::SpendableInit,
                (
                    note,
                    self.pak,
                    trap,
                    prev_chain,
                    block.into(),
                    height,
                    anchor,
                ),
                nf_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("spendable init");
        spendable_proof.carry::<spendable::SpendableHeader>((delegation_id, nf, anchor))
    }

    #[expect(clippy::type_complexity, reason = "test-support tuple")]
    pub fn autonome<'source>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        anchor: Anchor,
        spends: Vec<(
            Note,
            DelegationTrapdoor,
            Pcd<'source, delegation::NullifierHeader>,
            Pcd<'source, delegation::NullifierHeader>,
            Pcd<'source, spendable::SpendableHeader>,
            PoolChain,
            BlockAcc,
            BlockHeight,
        )>,
        output_notes: Vec<Note>,
    ) -> Stamped {
        let ask = self.sk.derive_auth_private();

        let mut spend_plans = Vec::with_capacity(spends.len());
        let mut traps = Vec::with_capacity(spends.len());
        let mut spend_pcds = Vec::with_capacity(spends.len());
        for (note, trap, nf_now_pcd, nf_next_pcd, spendable_pcd, prev_chain, block, height) in
            spends
        {
            let rcv = value::CommitmentTrapdoor::random(&mut *rng);
            let theta = ActionEntropy::random(&mut *rng);
            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                self.pak.ak.derive_action_public(&alpha)
            });
            spend_plans.push(plan);
            traps.push(trap);
            spend_pcds.push((
                nf_now_pcd,
                nf_next_pcd,
                spendable_pcd,
                prev_chain,
                block,
                height,
            ));
        }

        let output_plans: Vec<action::Plan<effect::Output>> = output_notes
            .into_iter()
            .map(|note| {
                let rcv = value::CommitmentTrapdoor::random(&mut *rng);
                let theta = ActionEntropy::random(&mut *rng);
                action::Plan::output(note, theta, rcv)
            })
            .collect();

        let bundle_plan = bundle::Plan::new(spend_plans, output_plans);
        let sighash = mock_sighash(bundle_plan.commitment());
        let unproven = bundle_plan
            .sign(&sighash, &ask, &mut *rng)
            .expect("sign autonome");

        let stamp_plan = bundle_plan.stamp_plan(anchor, &traps);
        let stamp = stamp_plan
            .prove(&mut *rng, &self.pak, spend_pcds)
            .expect("prove autonome stamp");

        unproven.stamp(stamp)
    }
}

pub mod ggm_tools {
    use alloc::vec::Vec;
    use core::ops::RangeInclusive;

    use ff::PrimeField as _;
    use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
    use mock_ragu::{Pcd, Proof};
    use pasta_curves::Fp;
    use rand_core::{CryptoRng, RngCore};

    use crate::{
        EpochIndex,
        constants::DELEGATION_ID_DOMAIN,
        keys::{GGM_CHUNK_SIZE, GGM_TREE_ARITY, GGM_TREE_DEPTH},
        primitives::{DelegationId, DelegationTrapdoor},
        stamp::proof::{PROOF_SYSTEM, delegation},
    };

    /// Walk a pre-blind master PCD down `target_depth` GGM levels, interpreting
    /// `epoch_bits` as an epoch-space index (top `(u32::from(GGM_DEPTH) *
    /// GGM_CHUNK_SIZE)` bits populated, low bits zero for a
    /// prefix).
    pub fn walk_master_to_depth<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<'source, delegation::NoteMasterHeader>,
        epoch_bits: u32,
        target_depth: u8,
    ) -> Pcd<'source, delegation::NoteStepHeader> {
        assert!(
            (1..=GGM_TREE_DEPTH).contains(&target_depth),
            "target_depth must be in 1..=GGM_DEPTH",
        );
        let (mk, cm) = master_pcd.data;

        let first_chunk = chunk_at(epoch_bits, 1);
        let (mut proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &delegation::NoteMasterStep,
                (first_chunk,),
                master_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("note master step");
        let mut key = mk.step(first_chunk);

        while key.depth.get() < target_depth {
            let next_step = key.depth.get() + 1;
            let chunk = chunk_at(epoch_bits, next_step);
            let pcd = proof.carry::<delegation::NoteStepHeader>((key, mk, cm));
            let (next_proof, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    &delegation::NoteStep,
                    (chunk,),
                    pcd,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("note step");
            key = key.step(chunk);
            proof = next_proof;
        }

        proof.carry::<delegation::NoteStepHeader>((key, mk, cm))
    }

    /// Fan the pre-blind master into the post-blind prefix delegates that
    /// tightly cover `epoch_range`. Each prefix is pre-blind walked to its
    /// depth, then a fresh
    /// [`DelegationBlindStep`](delegation::DelegationBlindStep)
    /// attaches `trap` to produce a
    /// [`DelegationHeader`](delegation::DelegationHeader).
    pub fn delegate_range<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: &Pcd<'source, delegation::NoteMasterHeader>,
        trap: DelegationTrapdoor,
        epoch_range: RangeInclusive<u32>,
    ) -> Vec<Pcd<'source, delegation::DelegationHeader>> {
        let mk = master_pcd.data.0;
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

    /// Walk from a pre-blind master header to the nullifier leaf for
    /// `target_epoch`, applying
    /// [`DelegationBlindStep`](delegation::DelegationBlindStep)
    /// and [`NullifierStep`](delegation::NullifierStep) at the end.
    pub fn nullifier_from_master<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<'source, delegation::NoteMasterHeader>,
        trap: DelegationTrapdoor,
        target_epoch: EpochIndex,
    ) -> Pcd<'source, delegation::NullifierHeader> {
        let depth_one = walk_master_to_depth(rng, master_pcd, target_epoch.0, 1);
        let blinded = blind_prefix(rng, depth_one, trap);
        walk_delegate_to_nullifier(rng, blinded, target_epoch)
    }

    /// Produce the `(nf_E, nf_{E+1})` pair from one pre-blind master header,
    /// sharing the GGM walk prefix up to the first chunk where `E` and `E+1`
    /// diverge.
    pub fn nullifier_pair_from_master<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<'source, delegation::NoteMasterHeader>,
        trap: DelegationTrapdoor,
        target_epoch: EpochIndex,
    ) -> (
        Pcd<'source, delegation::NullifierHeader>,
        Pcd<'source, delegation::NullifierHeader>,
    ) {
        let e0 = target_epoch;
        let e1 = EpochIndex(e0.0 + 1);
        let shared_depth = shared_chunk_prefix_depth(e0.0, e1.0);

        if shared_depth == 0 {
            let clone = master_pcd.clone();
            (
                nullifier_from_master(rng, master_pcd, trap, e0),
                nullifier_from_master(rng, clone, trap, e1),
            )
        } else {
            let shared_prefix = walk_master_to_depth(rng, master_pcd, e0.0, shared_depth);
            let blinded = blind_prefix(rng, shared_prefix, trap);
            (
                walk_delegate_to_nullifier(rng, blinded.clone(), e0),
                walk_delegate_to_nullifier(rng, blinded, e1),
            )
        }
    }

    /// Apply [`DelegationBlindStep`](delegation::DelegationBlindStep) to a
    /// pre-blind prefix PCD, returning a post-blind delegate PCD.
    pub fn blind_prefix<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        prefix_pcd: Pcd<'source, delegation::NoteStepHeader>,
        trap: DelegationTrapdoor,
    ) -> Pcd<'source, delegation::DelegationHeader> {
        let (key, mk, cm) = prefix_pcd.data;
        let (proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &delegation::DelegationBlindStep,
                (trap,),
                prefix_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("delegation blind step");
        let domain = Fp::from_u128(u128::from_le_bytes(*DELEGATION_ID_DOMAIN));
        let delegation_id = DelegationId::from(
            &Hash::<_, P128Pow5T3, ConstantLength<4>, 3, 2>::init().hash([
                domain,
                mk.0,
                Fp::from(&cm),
                Fp::from(&trap),
            ]),
        );
        proof.carry::<delegation::DelegationHeader>((key, delegation_id))
    }

    pub fn walk_delegate_to_nullifier<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        delegate_pcd: Pcd<'source, delegation::DelegationHeader>,
        target_epoch: EpochIndex,
    ) -> Pcd<'source, delegation::NullifierHeader> {
        let (mut key, delegation_id) = delegate_pcd.data;
        let mut proof = delegate_pcd.proof;

        while key.depth.get() < GGM_TREE_DEPTH {
            let next_step = key.depth.get() + 1;
            let chunk = chunk_at(target_epoch.0, next_step);
            let pcd = proof.carry::<delegation::DelegationHeader>((key, delegation_id));
            let (next_proof, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    &delegation::DelegationStep,
                    (chunk,),
                    pcd,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("delegation step");
            key = key.step(chunk);
            proof = next_proof;
        }

        let pcd = proof.carry::<delegation::DelegationHeader>((key, delegation_id));
        let (nf_proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &delegation::NullifierStep,
                (),
                pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("nullifier step");

        nf_proof.carry::<delegation::NullifierHeader>((
            key.derive_nullifier(target_epoch),
            target_epoch,
            delegation_id,
        ))
    }

    /// Extract the `GGM_CHUNK_SIZE`-bit chunk absorbed at `level`
    /// (1-indexed) of a walk indexing into an `(u32::from(GGM_DEPTH) *
    /// GGM_CHUNK_SIZE)`-wide epoch space.
    fn chunk_at(epoch_bits: u32, level: u8) -> u8 {
        let shift = (GGM_TREE_DEPTH * GGM_CHUNK_SIZE) - level * GGM_CHUNK_SIZE;
        let chunk_mask = (1u32 << GGM_CHUNK_SIZE) - 1u32;
        let chunk_u32 = (epoch_bits >> shift) & chunk_mask;
        u8::try_from(chunk_u32).expect("chunk fits in u8")
    }

    /// Number of leading chunks (of `GGM_CHUNK_SIZE` bits each)
    /// shared between `lhs` and `rhs` when viewed as `(u32::from(GGM_DEPTH)
    /// * GGM_CHUNK_SIZE)`-wide indices.
    fn shared_chunk_prefix_depth(lhs: u32, rhs: u32) -> u8 {
        let diff = lhs ^ rhs;
        if diff == 0 {
            return GGM_TREE_DEPTH;
        }
        #[expect(clippy::as_conversions, reason = "safe")]
        #[expect(clippy::cast_possible_truncation, reason = "safe")]
        let msb_pos = (u32::BITS as u8) - 1 - (diff.leading_zeros() as u8);
        assert!(
            msb_pos < (GGM_TREE_DEPTH * GGM_CHUNK_SIZE),
            "epoch index out of (u32::from(GGM_DEPTH) * GGM_CHUNK_SIZE) range"
        );
        let shared_bits = (GGM_TREE_DEPTH * GGM_CHUNK_SIZE) - 1 - msb_pos;
        shared_bits
            .checked_div(GGM_CHUNK_SIZE)
            .expect("GGM_CHUNK_SIZE is non-zero")
    }

    #[expect(unused, reason = "exported for future benches")]
    pub const fn arity() -> u8 {
        GGM_TREE_ARITY
    }
}
