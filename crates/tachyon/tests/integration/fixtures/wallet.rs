extern crate alloc;

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::cell::RefCell;

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    PoseidonPermutation as _,
    pasta::{Pasta, PoseidonFp},
};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, Tachygram,
    action::{self, Action},
    bundle::{self, Bundle},
    effect,
    entropy::ActionEntropy,
    fee,
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    nullifier::{self, NF_DERIVATION_WIDTH, Nullifier},
    pasta::Fp,
    stamp::{
        self, ProofStamp, Unproven,
        proof::{App, delegation, pool, spendable},
    },
    value, witness,
};

use super::{
    mock_sighash,
    pool::{PoolSim, random_block, random_block_with},
    qr::QrBucketEntry,
};

pub fn random_action<RNG: CryptoRng>(rng: &mut RNG) -> Action {
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(400);
    let (_, _, plan) = output_plan(rng, note);
    let bundle_plan = bundle::Plan::new(
        vec![],
        vec![plan],
        WalletSim::new(shared_sk()).random_note(0),
    );
    let sighash = mock_sighash(bundle_plan.commitment().unwrap());
    let unproven = bundle_plan.sign(rng, &sighash, &ask).unwrap();
    unproven.actions[0]
}

pub fn output_plan<RNG: CryptoRng>(
    rng: &mut RNG,
    note: Note,
) -> (value::Trapdoor, ActionEntropy, action::Plan<effect::Output>) {
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let plan = action::Plan::output(note, theta, rcv);
    (rcv, theta, plan)
}

pub fn build_output_stamp<RNG: CryptoRng>(
    rng: &mut RNG,
    app: &App<'_>,
    anchor: Anchor,
    note: Note,
) -> (
    ProofStamp<stamp::Uncompressed>,
    action::Plan<effect::Output>,
    fee::Descriptor,
) {
    let (stamp, plan, max_fee_note) = build_output_stamp_with_fee(rng, app, anchor, note);
    (
        stamp,
        plan,
        fee::Descriptor {
            cv_feemax: max_fee_note.cv_feemax(),
            v_fee: value::Positive::ZERO,
        },
    )
}

pub fn build_output_stamp_with_fee<RNG: CryptoRng>(
    rng: &mut RNG,
    app: &App<'_>,
    anchor: Anchor,
    note: Note,
) -> (
    ProofStamp<stamp::Uncompressed>,
    action::Plan<effect::Output>,
    Note,
) {
    let (rcv, theta, plan) = output_plan(rng, note);
    let pak = WalletSim::new(shared_sk()).pak;
    let max_fee_note = WalletSim::random(rng).random_note(0);
    let stamp = stamp::Plan::new(
        vec![],
        vec![(plan.descriptor(), theta, note, rcv)],
        anchor,
        max_fee_note,
        value::Positive::ZERO,
    )
    .prove(rng, app, &pak, vec![])
    .unwrap();
    (stamp, plan, max_fee_note)
}

pub fn build_autonome<RNG: CryptoRng>(
    rng: &mut RNG,
    app: &App<'_>,
    wallet: &WalletSim,
    spend_value: u64,
    output_value: u64,
) -> Bundle<ProofStamp<stamp::Uncompressed>> {
    let spend_note = wallet.random_note(spend_value);
    let output_note = wallet.random_note(output_value);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let stamps_cms = vec![vec![spend_note.commitment()]];
    pool.mine(random_block_with(rng, &stamps_cms, 50));
    let height = pool.height();
    let spendable_pcd = wallet.spendable_init(rng, app, &spend_note, &pool, height);
    let anchor = spendable_pcd.data().2;
    wallet.autonome(
        rng,
        app,
        anchor,
        vec![(spend_note, spendable_pcd)],
        vec![output_note],
    )
}

pub(crate) fn shared_sk() -> private::SpendingKey {
    private::SpendingKey::random(&mut StdRng::seed_from_u64(0x7AC0_05EED))
}

pub struct WalletSim {
    pub sk: private::SpendingKey,
    pub pak: ProofAuthorizingKey,
    pub notes: RefCell<BTreeMap<u64, StdRng>>,
    pub secrets:
        RefCell<BTreeMap<Tachygram, ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret>>>,
    pub derivations: RefCell<
        BTreeMap<
            (Tachygram, u32, u32),
            ragu::Pcd<Pasta, ProductionRank, delegation::NoteNullifiers>,
        >,
    >,
}

impl WalletSim {
    pub(crate) fn bucket_unspent<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        bucket: &QrBucketEntry,
        note: &Note,
    ) -> ragu::Pcd<Pasta, ProductionRank, pool::NoteUnspent> {
        let arbitrary = bucket.segment(rng, app, |epoch| {
            self.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch)
        });
        self.unspent_bind(rng, app, arbitrary, note)
    }

    pub fn new(sk: private::SpendingKey) -> Self {
        Self {
            sk,
            pak: sk.derive_proof_private(),
            notes: RefCell::new(BTreeMap::new()),
            secrets: RefCell::new(BTreeMap::new()),
            derivations: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self::new(private::SpendingKey::random(rng))
    }

    pub fn random_note(&self, value_amount: u64) -> Note {
        let pk = self.sk.derive_payment_key();
        let mut streams = self.notes.borrow_mut();
        let notes = streams.entry(value_amount).or_insert_with(|| {
            let digest = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"Tachyon-NoteRnd")
                .to_state()
                .update(&Fp::from(pk).to_bytes())
                .update(&value_amount.to_le_bytes())
                .finalize();
            let mut seed = [0u8; 32];
            seed.copy_from_slice(digest.as_bytes());
            StdRng::from_seed(seed)
        });
        Note {
            pk,
            value: value::Positive::try_from(value_amount).unwrap(),
            psi: nullifier::Trapdoor::random(notes),
            rcm: note::CommitmentTrapdoor::random(notes),
        }
    }

    #[must_use]
    pub fn covering_window(
        &self,
        note: &Note,
        range: &ragu::Pcd<Pasta, ProductionRank, delegation::NoteNullifiers>,
    ) -> Vec<Nullifier> {
        let (_, start, last) = *range.data();
        let mk = self.pak.nk.derive_note_private(note.psi);
        (u32::from(start)..=u32::from(last))
            .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
            .collect()
    }

    pub fn note_secret<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        note: Note,
    ) -> ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret> {
        let cm = Tachygram::from(note.commitment());
        if let Some(pcd) = self.secrets.borrow().get(&cm) {
            return pcd.clone();
        }
        let (pcd, ()) = app
            .seed(
                rng,
                delegation::NoteSeed,
                witness::note_seed(((), ()), note, self.pak),
            )
            .unwrap();

        self.secrets.borrow_mut().insert(cm, pcd.clone());
        pcd
    }

    pub fn note_nullifiers<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        note: Note,
        epoch_start: EpochIndex,
        epoch_end: EpochIndex,
    ) -> ragu::Pcd<Pasta, ProductionRank, delegation::NoteNullifiers> {
        let base = u32::from(epoch_start) - u32::from(epoch_start) % PoseidonFp::RATE as u32;
        let windows = (u32::from(epoch_end) - base + 1).div_ceil(NF_DERIVATION_WIDTH as u32);
        let cover_end = base + windows * NF_DERIVATION_WIDTH as u32 - 1;
        let key = (Tachygram::from(note.commitment()), base, cover_end);
        if let Some(pcd) = self.derivations.borrow().get(&key) {
            return pcd.clone();
        }
        let secret = self.note_secret(rng, app, note);
        let mk = self.pak.nk.derive_note_private(note.psi);

        let mut merged: Option<ragu::Pcd<Pasta, ProductionRank, delegation::NoteNullifiers>> = None;
        for window in 0..windows {
            let chunk_start = EpochIndex::new(base + window * NF_DERIVATION_WIDTH as u32);
            let chunk_end =
                EpochIndex::new(u32::from(chunk_start) + NF_DERIVATION_WIDTH as u32 - 1);
            let (leaf, ()) = app
                .fuse(
                    rng,
                    delegation::NullifierDerive,
                    witness::nullifier_derive((*secret.data(), ()), chunk_start),
                    secret.clone(),
                    app.bootstrap_proof().clone().carry::<()>(()),
                )
                .unwrap();
            merged = Some(match merged {
                None => leaf,
                Some(left) => {
                    let left_nfs: Vec<Nullifier> = (base..u32::from(chunk_start))
                        .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
                        .collect();
                    let right_nfs: Vec<Nullifier> = (u32::from(chunk_start)..=u32::from(chunk_end))
                        .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
                        .collect();
                    let (fused, ()) = app
                        .fuse(
                            rng,
                            delegation::NullifierFuse,
                            witness::nullifier_fuse(
                                (*left.data(), *leaf.data()),
                                &left_nfs,
                                &right_nfs,
                            ),
                            left,
                            leaf,
                        )
                        .unwrap();
                    fused
                },
            });
        }
        let pcd = merged.unwrap();

        self.derivations.borrow_mut().insert(key, pcd.clone());
        pcd
    }

    pub fn spendable_init<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        note: &Note,
        pool: &PoolSim,
        init_height: BlockHeight,
    ) -> ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        let cm = note.commitment();
        let epoch = init_height.epoch();
        let (anchor_prev, creation_tgs) = {
            let stamps = pool
                .block(init_height)
                .stamps
                .iter()
                .map(|stamp| stamp.1.clone())
                .collect::<Vec<_>>();
            let cm_idx = stamps
                .iter()
                .position(|tgs| tgs.contains(&cm.into()))
                .unwrap();

            let anchor_prev = pool.block(init_height).stamps[..cm_idx]
                .iter()
                .fold(pool.block(init_height).prev, |anchor, stamp| {
                    anchor.next_stamp(init_height.epoch(), &stamp.2).unwrap()
                });

            (anchor_prev, stamps[cm_idx].clone())
        };
        let deriv = self.note_nullifiers(rng, app, *note, epoch, epoch);

        let (spendable, ()) = app
            .fuse(
                rng,
                spendable::SpendableInit,
                witness::spendable_init((*deriv.data(), ()), anchor_prev, &creation_tgs, epoch),
                deriv,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        spendable
    }

    pub fn unspent_bind<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        arbitrary: ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent>,
        note: &Note,
    ) -> ragu::Pcd<Pasta, ProductionRank, pool::NoteUnspent> {
        let (_, epoch_start, epoch_next, _) = *arbitrary.data();
        let range = self.note_nullifiers(rng, app, *note, epoch_start, epoch_next);
        let mk = self.pak.nk.derive_note_private(note.psi);
        let elapsed: Vec<Nullifier> = (u32::from(epoch_start)..u32::from(epoch_next))
            .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
            .collect();
        let (unspent, ()) = app
            .fuse(
                rng,
                pool::UnspentBind,
                witness::unspent_bind(
                    (*arbitrary.data(), *range.data()),
                    &self.covering_window(note, &range),
                    &elapsed,
                ),
                arbitrary,
                range,
            )
            .unwrap();
        unspent
    }

    pub fn lift<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        spendable: ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
        arbitrary: ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent>,
        note: &Note,
    ) -> ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        let unspent = self.unspent_bind(rng, app, arbitrary, note);
        let (lifted, ()) = app
            .fuse(rng, spendable::SpendableLift, (), spendable, unspent)
            .unwrap();
        lifted
    }

    pub fn lift_to_epoch<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        pool: &PoolSim,
        note: &Note,
        spendable: ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
        target: EpochIndex,
    ) -> ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        let (_, epoch, _) = *spendable.data();
        let mk = self.pak.nk.derive_note_private(note.psi);
        if epoch == target {
            return spendable;
        }
        let unspent = pool.unspent(rng, app, (epoch, target), |covered| {
            mk.derive_nullifier(covered)
        });
        self.lift(rng, app, spendable, unspent, note)
    }

    pub fn spendable_at<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        pool: &PoolSim,
        note: &Note,
        target: EpochIndex,
    ) -> ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        let creation_height = pool
            .history
            .iter()
            .position(|block| {
                block
                    .stamps
                    .iter()
                    .any(|stamp| stamp.1.contains(&Tachygram::from(note.commitment())))
            })
            .unwrap();
        let creation = BlockHeight::from(creation_height).epoch();
        let bucket = pool.epoch_bucket(rng, app, creation);
        let mk = self.pak.nk.derive_note_private(note.psi);
        let arbitrary = bucket.segment(rng, app, |epoch| mk.derive_nullifier(epoch));
        let unspent = self.unspent_bind(rng, app, arbitrary, note);
        let (spendable, ()) = app
            .fuse(rng, spendable::QrSpendableInit, (), unspent, bucket.pcd)
            .unwrap();
        self.lift_to_epoch(rng, app, pool, note, spendable, target)
    }

    pub fn autonome<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        anchor: Anchor,
        spends: Vec<(
            Note,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
        )>,
        output_notes: Vec<Note>,
    ) -> Bundle<ProofStamp<stamp::Uncompressed>> {
        let (bundle_plan, unproven, spend_pcds) =
            self.signed(rng, app, spends, output_notes, self.random_note(0));
        let stamp_plan = bundle_plan.stamp_plan(anchor, value::Positive::ZERO);
        let stamp = stamp_plan.prove(rng, app, &self.pak, spend_pcds).unwrap();

        unproven.stamp(stamp)
    }

    pub fn signed<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        spends: Vec<(
            Note,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
        )>,
        output_notes: Vec<Note>,
        max_fee_note: Note,
    ) -> (
        bundle::Plan,
        Bundle<Unproven>,
        Vec<(
            ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
            Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
        )>,
    ) {
        let ask = self.sk.derive_auth_private();

        let mut spend_plans = Vec::with_capacity(spends.len());
        let mut spend_pcds = Vec::with_capacity(spends.len());
        for (note, spendable_pcd) in spends {
            let rcv = value::Trapdoor::random(rng);
            let theta = ActionEntropy::random(rng);
            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                self.pak.ak.derive_action_public(&alpha)
            });
            spend_plans.push(plan);
            spend_pcds.push((self.note_secret(rng, app, note), spendable_pcd, vec![]));
        }

        let output_plans: Vec<action::Plan<effect::Output>> = output_notes
            .into_iter()
            .map(|note| {
                let rcv = value::Trapdoor::random(rng);
                let theta = ActionEntropy::random(rng);
                action::Plan::output(note, theta, rcv)
            })
            .collect();

        let bundle_plan = bundle::Plan::new(spend_plans, output_plans, max_fee_note);
        let sighash = mock_sighash(bundle_plan.commitment().unwrap());
        let unproven = bundle_plan.sign(rng, &sighash, &ask).unwrap();

        (bundle_plan, unproven, spend_pcds)
    }

    pub fn fee_bundle<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        spend_value: u64,
        output_value: u64,
        feemax: u64,
    ) -> (
        bundle::Plan,
        Bundle<Unproven>,
        Vec<(
            ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
            Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
        )>,
        Anchor,
        Note,
    ) {
        let spend_note = self.random_note(spend_value);
        let output_note = self.random_note(output_value);
        let max_fee_note = self.random_note(feemax);

        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
        pool.mine(random_block_with(rng, &[vec![spend_note.commitment()]], 50));
        let height = pool.height();
        let spendable_pcd = self.spendable_init(rng, app, &spend_note, &pool, height);
        let anchor = spendable_pcd.data().2;

        let (bundle_plan, signed, spend_pcds) = self.signed(
            rng,
            app,
            vec![(spend_note, spendable_pcd)],
            vec![output_note],
            max_fee_note,
        );
        (bundle_plan, signed, spend_pcds, anchor, max_fee_note)
    }
}
