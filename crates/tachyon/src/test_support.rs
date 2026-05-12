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
        ActionDigest, Anchor, BlockAcc, BlockHeight, DelegationId, EpochIndex, PoolAcc, PoolCommit,
        PoolDelta, PoolSet, effect, epoch_seed_hash,
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
    entries: Vec<(
        DelegationId,
        Vec<Pcd<'source, delegation::DelegateNfPrefixHeader>>,
        Pcd<'source, spendable::SpendableHeader>,
    )>,
}

impl<'source> SyncSim<'source> {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn accept_spendable(
        &mut self,
        delegates: Vec<Pcd<'source, delegation::DelegateNfPrefixHeader>>,
        spendable: Pcd<'source, spendable::SpendableHeader>,
    ) {
        let delegation_id = delegates.first().expect("at least one delegate").data.1;
        assert!(delegates.iter().all(|del| del.data.1 == delegation_id));
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

    pub fn spendable(
        &self,
        delegation_id: DelegationId,
    ) -> Pcd<'source, spendable::SpendableHeader> {
        self.entries
            .iter()
            .find(|entry| entry.0 == delegation_id)
            .map(|entry| entry.2.clone())
            .expect("no maintained spendable for delegation_id")
    }

    /// Advance every maintained spendable to `pool.anchor()`, chaining
    /// same-epoch and cross-epoch lifts as needed.
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
        let target_anchor = pool.anchor();
        loop {
            let stored_anchor = self
                .entries
                .iter()
                .find(|entry| entry.0 == delegation_id)
                .expect("no maintained spendable for delegation_id")
                .2
                .data
                .1;
            if stored_anchor.1 == target_anchor.1 {
                return;
            }
            assert!(
                stored_anchor.0 <= target_anchor.0,
                "target_anchor is behind stored anchor"
            );

            let idx = self
                .entries
                .iter()
                .position(|entry| entry.0 == delegation_id)
                .expect("present");
            let (_, delegates, spendable_pcd) = self.entries.swap_remove(idx);
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
                let old_nf_pcd = Self::nullifier(&delegates, rng, stored_epoch);
                let new_nf_pcd = Self::nullifier(&delegates, rng, new_epoch);
                Self::next_epoch_lift(
                    rng,
                    at_final,
                    old_nf_pcd,
                    new_nf_pcd,
                    new_pool,
                    new_epoch_first_anchor,
                )
            };
            self.entries.push((delegation_id, delegates, lifted));
        }
    }

    fn same_epoch_lift(
        rng: &mut (impl RngCore + CryptoRng),
        spendable_pcd: Pcd<'source, spendable::SpendableHeader>,
        left_pool: PoolAcc,
        delta: PoolDelta<Polynomial>,
        target_anchor: Anchor,
    ) -> Pcd<'source, spendable::SpendableHeader> {
        let (nf, _) = spendable_pcd.data;
        let (proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &spendable::SpendableLift,
                (left_pool.into(), delta.into(), target_anchor),
                spendable_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("spendable lift");
        proof.carry::<spendable::SpendableHeader>((nf, target_anchor))
    }

    fn next_epoch_lift(
        rng: &mut (impl RngCore + CryptoRng),
        spendable_pcd: Pcd<'source, spendable::SpendableHeader>,
        old_nf_pcd: Pcd<'source, delegation::DelegateNullifierHeader>,
        new_nf_pcd: Pcd<'source, delegation::DelegateNullifierHeader>,
        new_pool: PoolAcc,
        new_anchor: Anchor,
    ) -> Pcd<'source, spendable::SpendableHeader> {
        let (_, stored_anchor) = spendable_pcd.data;
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
        let rollover_pcd = rollover_proof
            .carry::<spendable::SpendableRolloverHeader>((old_nf, new_nf, new_anchor));

        let (epoch_lift_proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &spendable::SpendableEpochLift,
                (new_pool.into(),),
                spendable_pcd,
                rollover_pcd,
            )
            .expect("spendable epoch lift");
        epoch_lift_proof.carry::<spendable::SpendableHeader>((new_nf, new_anchor))
    }

    fn nullifier(
        delegates: &[Pcd<'source, delegation::DelegateNfPrefixHeader>],
        rng: &mut (impl RngCore + CryptoRng),
        target_epoch: EpochIndex,
    ) -> Pcd<'source, delegation::DelegateNullifierHeader> {
        let delegate = delegates
            .iter()
            .find(|pcd| pcd.data.0.range().contains(&target_epoch.0))
            .expect("no delegate covers target_epoch")
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

    /// Produce a pre-blind master header PCD via [`NfMasterSeed`] — the GGM
    /// tree root at depth 0 with `(mk, cm)` lineage. The trapdoor is NOT
    /// witnessed here; blinding happens at a terminal
    /// [`DelegationStep`](delegation::DelegationStep).
    pub fn note_master<'source>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
    ) -> Pcd<'source, delegation::NfMasterHeader> {
        let mk = self.pak.nk.derive_note_private(&note.psi);
        let cm = note.commitment();
        let (proof, ()) = PROOF_SYSTEM
            .seed(rng, &delegation::NfMasterSeed, (note, self.pak))
            .expect("note seed");
        proof.carry::<delegation::NfMasterHeader>((mk, cm))
    }

    pub fn fresh_spend<'source>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        anchor: Anchor,
        pool_state: PoolAcc,
        spend_note: Note,
    ) -> (
        Note,
        Pcd<'source, delegation::NullifierHeader>,
        Pcd<'source, delegation::NullifierHeader>,
        Pcd<'source, spendable::SpendableHeader>,
    ) {
        let master = self.note_master(rng, spend_note);
        let (nf_e, nf_e1) =
            ggm_tools::preblind_nullifier_pair_from_master(rng, master, anchor.0.epoch());
        let spendable_pcd = self.spendable_init(rng, anchor, pool_state, nf_e.clone());
        (spend_note, nf_e, nf_e1, spendable_pcd)
    }

    #[expect(clippy::unused_self, reason = "method form for call-site readability")]
    pub fn spendable_init<'source>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        anchor: Anchor,
        pool_state: PoolAcc,
        preblind_nf_pcd: Pcd<'source, delegation::NullifierHeader>,
    ) -> Pcd<'source, spendable::SpendableHeader> {
        let (_cm_tg, nf, _epoch) = preblind_nf_pcd.data;
        let (spendable_proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &spendable::SpendableInit,
                (pool_state.into(), anchor),
                preblind_nf_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("spendable init");
        spendable_proof.carry::<spendable::SpendableHeader>((nf, anchor))
    }

    #[expect(clippy::type_complexity, reason = "test-support tuple")]
    pub fn autonome<'source>(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        anchor: Anchor,
        spends: Vec<(
            Note,
            Pcd<'source, delegation::NullifierHeader>,
            Pcd<'source, delegation::NullifierHeader>,
            Pcd<'source, spendable::SpendableHeader>,
        )>,
        output_notes: Vec<Note>,
    ) -> Stamped {
        let ask = self.sk.derive_auth_private();

        let mut spend_plans = Vec::with_capacity(spends.len());
        let mut spend_pcds = Vec::with_capacity(spends.len());
        for (note, nf_now_pcd, nf_next_pcd, spendable_pcd) in spends {
            let rcv = value::CommitmentTrapdoor::random(&mut *rng);
            let theta = ActionEntropy::random(&mut *rng);
            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                self.pak.ak.derive_action_public(&alpha)
            });
            spend_plans.push(plan);
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

        let stamp_plan = bundle_plan.stamp_plan(anchor);
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
        primitives::{DelegationId, DelegationTrapdoor, Tachygram},
        stamp::proof::{PROOF_SYSTEM, delegation},
    };

    /// Walk a pre-blind master PCD down `target_depth` GGM levels, interpreting
    /// `epoch_bits` as an epoch-space index (top `(u32::from(GGM_DEPTH) *
    /// GGM_CHUNK_SIZE)` bits populated, low bits zero for a
    /// prefix).
    pub fn walk_master_to_depth<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<'source, delegation::NfMasterHeader>,
        epoch_bits: u32,
        target_depth: u8,
    ) -> Pcd<'source, delegation::NfPrefixHeader> {
        assert!(
            (1..=GGM_TREE_DEPTH).contains(&target_depth),
            "target_depth must be in 1..=GGM_DEPTH",
        );
        let (mk, cm) = master_pcd.data;

        let first_chunk = chunk_at(epoch_bits, 1);
        let (mut proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &delegation::NfMasterStep,
                (first_chunk,),
                master_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("note master step");
        let mut key = mk.step(first_chunk);

        while key.depth.get() < target_depth {
            let next_step = key.depth.get() + 1;
            let chunk = chunk_at(epoch_bits, next_step);
            let pcd = proof.carry::<delegation::NfPrefixHeader>((key, mk, cm));
            let (next_proof, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    &delegation::NfPrefixStep,
                    (chunk,),
                    pcd,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("note step");
            key = key.step(chunk);
            proof = next_proof;
        }

        proof.carry::<delegation::NfPrefixHeader>((key, mk, cm))
    }

    /// Fan the pre-blind master into the post-blind prefix delegates that
    /// tightly cover `epoch_range`. Each prefix is pre-blind walked to its
    /// depth, then a fresh
    /// [`DelegationStep`](delegation::DelegationStep)
    /// attaches `trap` to produce a
    /// [`DelegateNfPrefixHeader`](delegation::DelegateNfPrefixHeader).
    pub fn delegate_range<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: &Pcd<'source, delegation::NfMasterHeader>,
        trap: DelegationTrapdoor,
        epoch_range: RangeInclusive<u32>,
    ) -> Vec<Pcd<'source, delegation::DelegateNfPrefixHeader>> {
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

    /// Walk from a pre-blind master header to the pre-blind nullifier leaf
    /// (`NullifierHeader = (cm, nf, epoch)`) for `target_epoch`. No
    /// blinding step is applied — the entire walk stays trapdoor-free.
    pub fn preblind_nullifier_from_master<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<'source, delegation::NfMasterHeader>,
        target_epoch: EpochIndex,
    ) -> Pcd<'source, delegation::NullifierHeader> {
        let prefix_pcd = walk_master_to_depth(rng, master_pcd, target_epoch.0, GGM_TREE_DEPTH);
        walk_preblind_leaf(rng, prefix_pcd)
    }

    /// Produce the pre-blind `(nf_E, nf_{E+1})` pair from one pre-blind
    /// master header. Shares the GGM walk prefix up to the first chunk
    /// where `E` and `E+1` diverge, then descends each branch to a
    /// pre-blind leaf via [`NullifierStep`](delegation::NullifierStep).
    pub fn preblind_nullifier_pair_from_master<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        master_pcd: Pcd<'source, delegation::NfMasterHeader>,
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
                preblind_nullifier_from_master(rng, master_pcd, e0),
                preblind_nullifier_from_master(rng, clone, e1),
            )
        } else if shared_depth == GGM_TREE_DEPTH {
            // Both epochs land in the same leaf — caller error, but we can
            // still emit two leaves from independent walks.
            let clone = master_pcd.clone();
            (
                preblind_nullifier_from_master(rng, master_pcd, e0),
                preblind_nullifier_from_master(rng, clone, e1),
            )
        } else {
            let shared_prefix = walk_master_to_depth(rng, master_pcd, e0.0, shared_depth);
            let left_prefix = walk_step_to_depth(rng, shared_prefix.clone(), e0.0, GGM_TREE_DEPTH);
            let right_prefix = walk_step_to_depth(rng, shared_prefix, e1.0, GGM_TREE_DEPTH);
            (
                walk_preblind_leaf(rng, left_prefix),
                walk_preblind_leaf(rng, right_prefix),
            )
        }
    }

    /// Apply [`NullifierStep`](delegation::NullifierStep) to a depth-final
    /// pre-blind prefix PCD, returning a pre-blind leaf PCD.
    pub fn walk_preblind_leaf<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        prefix_pcd: Pcd<'source, delegation::NfPrefixHeader>,
    ) -> Pcd<'source, delegation::NullifierHeader> {
        let (key, _mk, cm) = prefix_pcd.data;
        let (nf_proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &delegation::NullifierStep,
                (),
                prefix_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("preblind nullifier step");
        let epoch = EpochIndex(key.index);
        let nf = key.derive_nullifier(epoch);
        let cm_tg = Tachygram::from(&Fp::from(&cm));
        nf_proof.carry::<delegation::NullifierHeader>((cm_tg, nf, epoch))
    }

    /// Walk a pre-blind `NfPrefixHeader` from its current depth down to
    /// `target_depth`, decoding chunks from `epoch_bits`.
    pub fn walk_step_to_depth<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        mut prefix_pcd: Pcd<'source, delegation::NfPrefixHeader>,
        epoch_bits: u32,
        target_depth: u8,
    ) -> Pcd<'source, delegation::NfPrefixHeader> {
        while prefix_pcd.data.0.depth.get() < target_depth {
            let next_step = prefix_pcd.data.0.depth.get() + 1;
            let chunk = chunk_at(epoch_bits, next_step);
            let (mut key, mk, cm) = prefix_pcd.data;
            let (next_proof, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    &delegation::NfPrefixStep,
                    (chunk,),
                    prefix_pcd,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("note step");
            key = key.step(chunk);
            prefix_pcd = next_proof.carry::<delegation::NfPrefixHeader>((key, mk, cm));
        }
        prefix_pcd
    }

    /// Apply [`DelegationStep`](delegation::DelegationStep) to a
    /// pre-blind prefix PCD, returning a post-blind delegate PCD.
    pub fn blind_prefix<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        prefix_pcd: Pcd<'source, delegation::NfPrefixHeader>,
        trap: DelegationTrapdoor,
    ) -> Pcd<'source, delegation::DelegateNfPrefixHeader> {
        let (key, mk, cm) = prefix_pcd.data;
        let (proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &delegation::DelegationStep,
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
        proof.carry::<delegation::DelegateNfPrefixHeader>((key, delegation_id))
    }

    pub fn walk_delegate_to_nullifier<'source>(
        rng: &mut (impl RngCore + CryptoRng),
        delegate_pcd: Pcd<'source, delegation::DelegateNfPrefixHeader>,
        target_epoch: EpochIndex,
    ) -> Pcd<'source, delegation::DelegateNullifierHeader> {
        let (mut key, delegation_id) = delegate_pcd.data;
        let mut proof = delegate_pcd.proof;

        while key.depth.get() < GGM_TREE_DEPTH {
            let next_step = key.depth.get() + 1;
            let chunk = chunk_at(target_epoch.0, next_step);
            let pcd = proof.carry::<delegation::DelegateNfPrefixHeader>((key, delegation_id));
            let (next_proof, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    &delegation::DelegateNfPrefixStep,
                    (chunk,),
                    pcd,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("delegation step");
            key = key.step(chunk);
            proof = next_proof;
        }

        let pcd = proof.carry::<delegation::DelegateNfPrefixHeader>((key, delegation_id));
        let (nf_proof, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                &delegation::DelegateNullifierStep,
                (),
                pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("delegate nullifier step");

        nf_proof.carry::<delegation::DelegateNullifierHeader>((
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
