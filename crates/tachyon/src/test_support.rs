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
    constants::EPOCH_SIZE,
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    primitives::{
        ActionDigest, Anchor, BlockAcc, BlockHeight, DelegationId, DelegationTrapdoor, EpochIndex,
        PoolAcc, PoolCommit, PoolDelta, PoolSet, effect, epoch_seed_hash,
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

pub fn random_block_with(
    rng: &mut (impl RngCore + CryptoRng),
    cm: note::Commitment,
    size: usize,
) -> BlockAcc {
    assert!(size >= 1, "size must include at least the commitment");
    let mut roots: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
        .take(size - 1)
        .collect();
    roots.push(Fp::from(&cm));
    BlockSet(Polynomial::from_roots(&roots))
}

pub struct PoolSim {
    pub history: Vec<(BlockAcc, PoolAcc)>,
}

impl PoolSim {
    pub fn new() -> Self {
        Self {
            history: alloc::vec![(
                BlockSet(Polynomial::default()),
                PoolSet(Polynomial::default()),
            )],
        }
    }

    pub fn state(&self) -> &PoolAcc {
        &self
            .history
            .last()
            .expect("history always has genesis entry")
            .1
    }

    pub fn anchor(&self) -> Anchor {
        let height =
            BlockHeight(u32::try_from(self.history.len() - 1).expect("block height fits u32"));
        self.anchor_at(height)
    }

    pub fn state_at(&self, height: BlockHeight) -> PoolAcc {
        self.history[usize::try_from(height.0).expect("block height fits usize")]
            .1
            .clone()
    }

    pub fn anchor_at(&self, height: BlockHeight) -> Anchor {
        let state = &self.history[usize::try_from(height.0).expect("block height fits usize")].1;
        Anchor(height, PoolCommit(state.0.commit(Fp::ZERO)))
    }

    #[expect(unused, reason = "test support")]
    pub fn block_at(&self, height: BlockHeight) -> BlockAcc {
        self.history[usize::try_from(height.0).expect("block height fits usize")]
            .0
            .clone()
    }

    pub fn delta(&self, from: BlockHeight, to: BlockHeight) -> PoolDelta<Polynomial> {
        assert!(from <= to, "delta: from > to");
        assert_eq!(from.epoch(), to.epoch(), "delta spans an epoch boundary");
        let from_idx = usize::try_from(from.0).expect("block height fits usize") + 1;
        let to_idx_exclusive = usize::try_from(to.0).expect("block height fits usize") + 1;
        let product = self.history[from_idx..to_idx_exclusive]
            .iter()
            .map(|entry| entry.0.0.clone())
            .reduce(|acc, next| acc.multiply(&next))
            .unwrap_or_default();
        PoolDelta(product)
    }

    pub fn advance(
        &mut self,
        count: usize,
        mut block_factory: impl FnMut(&Self) -> BlockAcc,
    ) -> Vec<BlockAcc> {
        let start_idx = self.history.len();
        for _ in 0..count {
            self.mine(block_factory(self));
        }
        self.history[start_idx..]
            .iter()
            .map(|entry| entry.0.clone())
            .collect()
    }

    pub fn mine(&mut self, block: BlockAcc) {
        let current_anchor = self.anchor();
        let current_state = &self
            .history
            .last()
            .expect("history always has genesis entry")
            .1;
        let prior_pool: Polynomial = if current_anchor.0.is_epoch_final() {
            Polynomial::from_roots(&[epoch_seed_hash(&current_anchor.1)])
        } else {
            current_state.0.clone()
        };
        let new_state = PoolSet(prior_pool.multiply(&block.0));
        self.history.push((block, new_state));
    }
}

pub struct SyncSim<'source> {
    delegates: Vec<Pcd<'source, delegation::DelegationHeader>>,
    spendables: Vec<Pcd<'source, spendable::SpendableHeader>>,
}

impl<'source> SyncSim<'source> {
    pub fn new(delegates: Vec<Pcd<'source, delegation::DelegationHeader>>) -> Self {
        Self {
            delegates,
            spendables: Vec::new(),
        }
    }

    pub fn accept_spendable(&mut self, spendable: Pcd<'source, spendable::SpendableHeader>) {
        self.spendables.push(spendable);
    }

    pub fn spendable(
        &self,
        delegation_id: DelegationId,
    ) -> Pcd<'source, spendable::SpendableHeader> {
        self.spendables
            .iter()
            .find(|pcd| pcd.data.0 == delegation_id)
            .expect("no maintained spendable for delegation_id")
            .clone()
    }

    /// Advance every maintained spendable to `pool.anchor()`, chaining
    /// same-epoch and cross-epoch lifts as needed.
    pub fn lift(&mut self, rng: &mut (impl RngCore + CryptoRng), pool: &PoolSim) {
        let ids: Vec<DelegationId> = self.spendables.iter().map(|pcd| pcd.data.0).collect();
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
        let target_anchor = pool.anchor();
        loop {
            let idx = self
                .spendables
                .iter()
                .position(|pcd| pcd.data.0 == delegation_id)
                .expect("no maintained spendable for delegation_id");
            let stored_anchor = self.spendables[idx].data.2;
            if stored_anchor.1 == target_anchor.1 {
                return;
            }
            assert!(
                stored_anchor.0 <= target_anchor.0,
                "target_anchor is behind stored anchor"
            );

            let spendable_pcd = self.spendables.swap_remove(idx);
            let stored_epoch = stored_anchor.0.epoch();
            let lifted = if stored_epoch == target_anchor.0.epoch() {
                let left_pool = pool.state_at(stored_anchor.0);
                let delta = pool.delta(stored_anchor.0, target_anchor.0);
                Self::same_epoch_lift(rng, spendable_pcd, left_pool, delta, target_anchor)
            } else {
                let epoch_final_h = BlockHeight(stored_epoch.0.saturating_add(1) * EPOCH_SIZE - 1);
                let at_final = if stored_anchor.0 < epoch_final_h {
                    let intermediate = pool.anchor_at(epoch_final_h);
                    let left_pool = pool.state_at(stored_anchor.0);
                    let delta = pool.delta(stored_anchor.0, epoch_final_h);
                    Self::same_epoch_lift(rng, spendable_pcd, left_pool, delta, intermediate)
                } else {
                    spendable_pcd
                };
                let new_epoch = EpochIndex(stored_epoch.0 + 1);
                let new_epoch_first_h = BlockHeight(new_epoch.0 * EPOCH_SIZE);
                let new_epoch_first_anchor = pool.anchor_at(new_epoch_first_h);
                let new_pool = pool.state_at(new_epoch_first_h);
                let old_nf_pcd = self.nullifier(rng, delegation_id, stored_epoch);
                let new_nf_pcd = self.nullifier(rng, delegation_id, new_epoch);
                Self::next_epoch_lift(
                    rng,
                    at_final,
                    old_nf_pcd,
                    new_nf_pcd,
                    new_pool,
                    new_epoch_first_anchor,
                )
            };
            self.spendables.push(lifted);
        }
    }

    fn same_epoch_lift(
        rng: &mut (impl RngCore + CryptoRng),
        spendable_pcd: Pcd<'source, spendable::SpendableHeader>,
        left_pool: PoolAcc,
        delta: PoolDelta<Polynomial>,
        target_anchor: Anchor,
    ) -> Pcd<'source, spendable::SpendableHeader> {
        let (delegation_id, nf, _) = spendable_pcd.data;
        let (proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &spendable::SpendableLift,
                (left_pool.into(), delta.into(), target_anchor),
                spendable_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("spendable lift");
        proof.carry::<spendable::SpendableHeader>((delegation_id, nf, target_anchor))
    }

    fn next_epoch_lift(
        rng: &mut (impl RngCore + CryptoRng),
        spendable_pcd: Pcd<'source, spendable::SpendableHeader>,
        old_nf_pcd: Pcd<'source, delegation::NullifierHeader>,
        new_nf_pcd: Pcd<'source, delegation::NullifierHeader>,
        new_pool: PoolAcc,
        new_anchor: Anchor,
    ) -> Pcd<'source, spendable::SpendableHeader> {
        let (delegation_id, _, stored_anchor) = spendable_pcd.data;
        assert!(
            stored_anchor.0.is_epoch_final(),
            "rollover requires spendable at epoch-final"
        );
        let old_nf = old_nf_pcd.data.0;
        let new_nf = new_nf_pcd.data.0;

        let (rollover_proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &spendable::SpendableRollover,
                (new_pool.clone().into(), new_anchor),
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

        let (epoch_lift_proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &spendable::SpendableEpochLift,
                (new_pool.into(),),
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

    /// Produce a master header PCD via `DelegationSeed` — the GGM tree root
    /// at depth 0.
    pub fn delegate_master<'source>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
        trap: DelegationTrapdoor,
    ) -> Pcd<'source, delegation::DelegationMasterHeader> {
        let mk = self.pak.nk.derive_note_private(&note.psi);
        let delegation_id = self.pak.nk.derive_delegation_id(&note, trap);
        let (proof, ()) = PROOF_SYSTEM
            .seed(rng, &delegation::DelegationSeed, (note, self.pak, trap))
            .expect("delegation seed");
        proof.carry::<delegation::DelegationMasterHeader>((mk, delegation_id))
    }

    pub fn fresh_spend<'source>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        anchor: Anchor,
        pool_state: PoolAcc,
        spend_note: Note,
    ) -> (
        Note,
        DelegationTrapdoor,
        Pcd<'source, delegation::NullifierHeader>,
        Pcd<'source, delegation::NullifierHeader>,
        Pcd<'source, spendable::SpendableHeader>,
    ) {
        let trap = DelegationTrapdoor::random(rng);
        let master = self.delegate_master(rng, spend_note, trap);
        let (nf_e, nf_e1) = ggm_tools::nullifier_pair_from_master(rng, master, anchor.0.epoch());
        let spendable_pcd =
            self.spendable_init(rng, spend_note, trap, anchor, pool_state, nf_e.clone());
        (spend_note, trap, nf_e, nf_e1, spendable_pcd)
    }

    pub fn spendable_init<'source>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
        trap: DelegationTrapdoor,
        anchor: Anchor,
        pool_state: PoolAcc,
        nf_pcd: Pcd<'source, delegation::NullifierHeader>,
    ) -> Pcd<'source, spendable::SpendableHeader> {
        let (nf, _epoch, delegation_id) = nf_pcd.data;
        let (spendable_proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &spendable::SpendableInit,
                (note, self.pak, trap, pool_state.into(), anchor),
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
        )>,
        output_notes: Vec<Note>,
    ) -> Stamped {
        let ask = self.sk.derive_auth_private();

        let mut spend_plans = Vec::with_capacity(spends.len());
        let mut traps = Vec::with_capacity(spends.len());
        let mut spend_pcds = Vec::with_capacity(spends.len());
        for (note, trap, nf_now_pcd, nf_next_pcd, spendable_pcd) in spends {
            let rcv = value::CommitmentTrapdoor::random(&mut *rng);
            let theta = ActionEntropy::random(&mut *rng);
            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                self.pak.ak.derive_action_public(&alpha)
            });
            spend_plans.push(plan);
            traps.push(trap);
            spend_pcds.push((nf_now_pcd, nf_next_pcd, spendable_pcd));
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

    use mock_ragu::{Pcd, Proof};
    use rand_core::{CryptoRng, RngCore};

    use crate::{
        EpochIndex,
        keys::GGM_TREE_DEPTH,
        stamp::proof::{PROOF_SYSTEM, delegation},
    };

    pub fn walk_master_to_depth<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<'source, delegation::DelegationMasterHeader>,
        epoch_bits: u32,
        target_depth: u8,
    ) -> Pcd<'source, delegation::DelegationHeader> {
        assert!(
            (1..=GGM_TREE_DEPTH).contains(&target_depth),
            "target_depth must be in 1..=GGM_TREE_DEPTH",
        );
        let (mk, delegation_id) = master_pcd.data;

        let first_bit = (epoch_bits >> (GGM_TREE_DEPTH - 1)) & 1 != 0;
        let (mut proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &delegation::DelegationMasterStep,
                (first_bit,),
                master_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("delegation master step");
        let mut key = mk.step(first_bit);

        while key.depth.get() < target_depth {
            let next_step = key.depth.get() + 1;
            let direction = (epoch_bits >> (GGM_TREE_DEPTH - next_step)) & 1 != 0;
            let pcd = proof.carry::<delegation::DelegationHeader>((key, delegation_id));
            let (next_proof, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    &delegation::DelegationStep,
                    (direction,),
                    pcd,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("delegation step");
            key = key.step(direction);
            proof = next_proof;
        }

        proof.carry::<delegation::DelegationHeader>((key, delegation_id))
    }

    /// Fan the master header into the prefix delegates that tightly cover
    /// `epoch_range`. Clones `master_pcd` once per prefix and descends to the
    /// prefix's depth.
    pub fn delegate_range<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: &Pcd<'source, delegation::DelegationMasterHeader>,
        epoch_range: RangeInclusive<u32>,
    ) -> Vec<Pcd<'source, delegation::DelegationHeader>> {
        let mk = master_pcd.data.0;
        mk.derive_note_delegates(epoch_range)
            .into_iter()
            .map(|target_key| {
                let target_depth = target_key.depth.get();
                let epoch_bits = target_key.index << (GGM_TREE_DEPTH - target_depth);
                walk_master_to_depth(rng, master_pcd.clone(), epoch_bits, target_depth)
            })
            .collect()
    }

    /// Walk from a master header to the leaf for `target_epoch` and apply
    /// `NullifierStep`. The wallet-side counterpart to [`SyncSim::nullifier`],
    /// which walks from a delegated prefix instead.
    pub fn nullifier_from_master<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<'source, delegation::DelegationMasterHeader>,
        target_epoch: EpochIndex,
    ) -> Pcd<'source, delegation::NullifierHeader> {
        let depth_one = walk_master_to_depth(rng, master_pcd, target_epoch.0, 1);
        walk_delegate_to_nullifier(rng, depth_one, target_epoch)
    }

    /// Produce the `(nf_E, nf_{E+1})` pair from one master header, sharing the
    /// GGM walk prefix up to the first bit where E and E+1 diverge.
    pub fn nullifier_pair_from_master<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<'source, delegation::DelegationMasterHeader>,
        target_epoch: EpochIndex,
    ) -> (
        Pcd<'source, delegation::NullifierHeader>,
        Pcd<'source, delegation::NullifierHeader>,
    ) {
        let e0 = target_epoch;
        let e1 = EpochIndex(e0.0 + 1);
        let shared_depth =
            u8::try_from((e0.0 ^ e1.0).leading_zeros()).expect("u32 leading_zeros fits u8");

        if shared_depth == 0 {
            // Bits diverge at the MSB — no shared walk; two independent walks
            // from cloned masters.
            let clone = master_pcd.clone();
            (
                nullifier_from_master(rng, master_pcd, e0),
                nullifier_from_master(rng, clone, e1),
            )
        } else {
            let shared = walk_master_to_depth(rng, master_pcd, e0.0, shared_depth);
            (
                walk_delegate_to_nullifier(rng, shared.clone(), e0),
                walk_delegate_to_nullifier(rng, shared, e1),
            )
        }
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
            let direction = (target_epoch.0 >> (GGM_TREE_DEPTH - next_step)) & 1 != 0;
            let pcd = proof.carry::<delegation::DelegationHeader>((key, delegation_id));
            let (next_proof, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    &delegation::DelegationStep,
                    (direction,),
                    pcd,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("delegation step");
            key = key.step(direction);
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
}
