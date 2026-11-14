extern crate alloc;

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{cell::RefCell, ops::RangeInclusive};

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    PoseidonPermutation as _,
    pasta::{Pasta, PoseidonFp},
};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, Tachygram, action,
    bundle::{self, Bundle},
    effect,
    entropy::ActionEntropy,
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    nullifier::{self, NF_DERIVATION_WIDTH, Nullifier},
    pasta::Fp,
    stamp::{
        self, ProofStamp,
        proof::{App, delegation, pool, spendable},
    },
    value, witness,
};

use super::{Proved, keyed_rng, mock_sighash, mock_txid, pool::PoolSim, qr::QrBucketEntry};

pub fn random_action<RNG: CryptoRng>(rng: &mut RNG) -> (action::Descriptor, action::Signature) {
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
    let (action_sigs, _) = bundle_plan.sign(rng, &sighash, &ask).unwrap();
    action_sigs.into_iter().next().unwrap()
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

pub(crate) fn shared_sk() -> private::SpendingKey {
    private::SpendingKey::random(&mut StdRng::seed_from_u64(0x7AC0_05EED))
}

pub(crate) fn other_sk() -> private::SpendingKey {
    private::SpendingKey::random(&mut StdRng::seed_from_u64(0x0B0B_05EE_D000_0001))
}

fn stamp_key(bundle: &Bundle<ProofStamp<stamp::Uncompressed>>) -> Vec<u8> {
    let stamp = &bundle.stamp;
    let mut key = Fp::from(stamp.anchor).to_bytes().to_vec();
    key.extend_from_slice(&u32::try_from(stamp.adjuncts.len()).unwrap().to_le_bytes());
    for txid in &stamp.adjuncts {
        key.extend_from_slice(txid);
    }
    stamp.tachygram_set.write(&mut key).unwrap();
    // The action digest binds each action's pair; the union does not.
    // Keep the collection passed to merge/lift in the key.
    key.extend_from_slice(&u32::try_from(bundle.actions.len()).unwrap().to_le_bytes());
    for descriptor in &bundle.actions {
        descriptor.write(&mut key).unwrap();
    }
    key.extend_from_slice(&<[u8; 40]>::from(bundle.fee));
    for tachygram in bundle
        .action_auth
        .iter()
        .flat_map(|&(_, pair)| <[Tachygram; 2]>::from(pair))
        .chain([bundle.fee_auth])
    {
        key.extend_from_slice(&Fp::from(tachygram).to_bytes());
    }
    key
}

pub(crate) fn merged(
    app: &App<'_>,
    left: &Bundle<ProofStamp<stamp::Uncompressed>>,
    right: &Bundle<ProofStamp<stamp::Uncompressed>>,
) -> Bundle<ProofStamp<stamp::Uncompressed>> {
    static MERGES: Proved<ProofStamp<stamp::Uncompressed>> = Proved::new("merged_bundle");
    let right_txid = mock_txid(right);
    let mut key = stamp_key(left);
    key.extend_from_slice(&stamp_key(right));
    key.extend_from_slice(&right_txid);
    let stamp = MERGES.get(&key, |rng| {
        left.stamp
            .clone()
            .merge(
                rng,
                app,
                (
                    &left
                        .actions
                        .iter()
                        .copied()
                        .zip(left.action_auth.iter().map(|&(_, pair)| pair))
                        .collect(),
                    &BTreeMap::from([(left.fee, left.fee_auth)]),
                ),
                (
                    right.stamp.clone(),
                    right_txid,
                    &right
                        .actions
                        .iter()
                        .copied()
                        .zip(right.action_auth.iter().map(|&(_, pair)| pair))
                        .collect(),
                    &BTreeMap::from([(right.fee, right.fee_auth)]),
                ),
            )
            .unwrap()
    });
    Bundle {
        stamp,
        ..left.clone()
    }
}

pub(crate) fn lifted(
    app: &App<'_>,
    bundle: &Bundle<ProofStamp<stamp::Uncompressed>>,
    pool: &PoolSim,
    range: RangeInclusive<BlockHeight>,
) -> Bundle<ProofStamp<stamp::Uncompressed>> {
    static LIFTS: Proved<ProofStamp<stamp::Uncompressed>> = Proved::new("lifted_bundle");
    let span = pool.anchor_span(app, range);
    let mut key = stamp_key(bundle);
    key.extend_from_slice(&Fp::from(span.data().0).to_bytes());
    key.extend_from_slice(&Fp::from(span.data().1).to_bytes());
    let stamp = LIFTS.get(&key, |rng| {
        bundle
            .stamp
            .clone()
            .lift(
                rng,
                app,
                &bundle
                    .actions
                    .iter()
                    .copied()
                    .zip(bundle.action_auth.iter().map(|&(_, pair)| pair))
                    .collect(),
                &BTreeMap::from([(bundle.fee, bundle.fee_auth)]),
                vec![span],
            )
            .unwrap()
    });
    Bundle {
        stamp,
        ..bundle.clone()
    }
}

pub(crate) fn spend_max_fee_note() -> Note {
    WalletSim::new(shared_sk()).labelled_note("spend fee", 0)
}

pub(crate) fn spend(app: &App<'_>) -> (bundle::Plan, Bundle<ProofStamp<stamp::Uncompressed>>) {
    let pool = PoolSim::shared();
    let wallet = WalletSim::new(shared_sk());
    wallet.bundle(
        app,
        pool.mint_anchor(),
        &[(PoolSim::shared_note(1000), pool)],
        &[wallet.labelled_note("spend output", 700)],
        spend_max_fee_note(),
        value::Positive::ZERO,
    )
}

pub(crate) fn spend_with_fee_max_fee_note() -> Note {
    WalletSim::new(shared_sk()).labelled_note("spend with fee maximum", 300)
}

pub(crate) fn spend_with_fee(
    app: &App<'_>,
) -> (bundle::Plan, Bundle<ProofStamp<stamp::Uncompressed>>) {
    let pool = PoolSim::shared();
    let wallet = WalletSim::new(shared_sk());
    wallet.bundle(
        app,
        pool.mint_anchor(),
        &[(PoolSim::shared_note(1000), pool)],
        &[wallet.labelled_note("spend with fee output", 700)],
        spend_with_fee_max_fee_note(),
        value::Positive::try_from(120u64).unwrap(),
    )
}

pub(crate) fn alice_max_fee_note() -> Note {
    WalletSim::new(shared_sk()).labelled_note("alice fee", 0)
}

pub(crate) fn alice_output_note() -> Note {
    WalletSim::new(shared_sk()).labelled_note("alice output", 300)
}

pub(crate) fn alice(app: &App<'_>) -> (bundle::Plan, Bundle<ProofStamp<stamp::Uncompressed>>) {
    WalletSim::new(shared_sk()).bundle(
        app,
        PoolSim::shared().mint_anchor(),
        &[],
        &[alice_output_note()],
        alice_max_fee_note(),
        value::Positive::ZERO,
    )
}

pub(crate) fn bob(app: &App<'_>) -> (bundle::Plan, Bundle<ProofStamp<stamp::Uncompressed>>) {
    let wallet = WalletSim::new(other_sk());
    wallet.bundle(
        app,
        PoolSim::shared().mint_anchor(),
        &[],
        &[wallet.labelled_note("bob output", 300)],
        wallet.labelled_note("bob fee", 0),
        value::Positive::ZERO,
    )
}

/// The three fees differ because unmerge_keeps_the_dividend_fee depends on
/// that.
pub(crate) fn outputs_with_fees(
    app: &App<'_>,
) -> [(bundle::Plan, Bundle<ProofStamp<stamp::Uncompressed>>); 3] {
    [
        ("fee output first", "fee maximum first", 40u64),
        ("fee output second", "fee maximum second", 70),
        ("fee output third", "fee maximum third", 90),
    ]
    .map(|(output, maximum, fee)| {
        let wallet = WalletSim::new(shared_sk());
        wallet.bundle(
            app,
            PoolSim::shared().mint_anchor(),
            &[],
            &[wallet.labelled_note(output, 500)],
            wallet.labelled_note(maximum, 100),
            value::Positive::try_from(fee).unwrap(),
        )
    })
}

pub(crate) fn zero_action(
    app: &App<'_>,
    anchor: Anchor,
) -> (bundle::Plan, Bundle<ProofStamp<stamp::Uncompressed>>) {
    let wallet = WalletSim::new(shared_sk());
    wallet.bundle(
        app,
        anchor,
        &[],
        &[],
        wallet.labelled_note("zero action fee", 0),
        value::Positive::ZERO,
    )
}

pub(crate) fn entry_spends(
    app: &App<'_>,
) -> [(bundle::Plan, Bundle<ProofStamp<stamp::Uncompressed>>); 3] {
    let pool = PoolSim::shared();
    [
        (1000, 700, "entry first output", "entry first fee"),
        (500, 200, "entry second output", "entry second fee"),
        (800, 400, "entry third output", "entry third fee"),
    ]
    .map(|(input, output, label, fee)| {
        let wallet = WalletSim::new(shared_sk());
        wallet.bundle(
            app,
            pool.entry_anchor(EpochIndex::new(1)),
            &[(PoolSim::shared_note(input), pool)],
            &[wallet.labelled_note(label, output)],
            wallet.labelled_note(fee, 0),
            value::Positive::ZERO,
        )
    })
}

pub(crate) fn later_output(
    app: &App<'_>,
) -> (bundle::Plan, Bundle<ProofStamp<stamp::Uncompressed>>) {
    let wallet = WalletSim::new(shared_sk());
    wallet.bundle(
        app,
        PoolSim::shared().block(BlockHeight(2)).anchor(),
        &[],
        &[wallet.labelled_note("later output", 400)],
        wallet.labelled_note("later fee", 0),
        value::Positive::ZERO,
    )
}

pub struct WalletSim {
    pub sk: private::SpendingKey,
    pub pak: ProofAuthorizingKey,
    pub notes: RefCell<BTreeMap<u64, StdRng>>,
}

impl WalletSim {
    pub fn bundle(
        &self,
        app: &App<'_>,
        anchor: Anchor,
        spends: &[(Note, &PoolSim)],
        outputs: &[Note],
        max_fee_note: Note,
        fee: value::Positive,
    ) -> (bundle::Plan, Bundle<ProofStamp<stamp::Uncompressed>>) {
        static BUNDLES: Proved<(bundle::Plan, Bundle<ProofStamp<stamp::Uncompressed>>)> =
            Proved::new("bundle");
        let mut key = [
            Fp::from(self.pak.derive_payment_key()).to_bytes(),
            Fp::from(anchor).to_bytes(),
        ]
        .concat();
        key.extend_from_slice(&u32::try_from(spends.len()).unwrap().to_le_bytes());
        for &(note, _) in spends {
            key.extend_from_slice(&Fp::from(note.commitment()).to_bytes());
        }
        key.extend_from_slice(&u32::try_from(outputs.len()).unwrap().to_le_bytes());
        for note in outputs {
            key.extend_from_slice(&Fp::from(note.commitment()).to_bytes());
        }
        key.extend_from_slice(&Fp::from(max_fee_note.commitment()).to_bytes());
        key.extend_from_slice(&u64::from(fee).to_le_bytes());
        BUNDLES.get(&key, |rng| {
            let mut spend_plans = Vec::new();
            let mut spend_pcds = Vec::new();
            for &(note, pool) in spends {
                let cm = Tachygram::from(note.commitment());
                let creation = pool
                    .history
                    .iter()
                    .enumerate()
                    .find(|&(_, block)| {
                        block
                            .stamps
                            .iter()
                            .any(|stamp| stamp.3 == anchor && stamp.1.contains(&cm))
                    })
                    .map(|(height, _)| BlockHeight::from(height));
                let spendable = creation.map_or_else(
                    || {
                        let epoch = (0..=u32::from(pool.height().epoch()) + 1)
                            .map(EpochIndex::new)
                            .find(|&epoch| pool.entry_anchor(epoch) == anchor)
                            .unwrap();
                        self.spendable_at(app, pool, &note, epoch)
                    },
                    |height| self.spendable_init(app, pool, &note, height),
                );
                let rcv = value::Trapdoor::random(rng);
                let theta = ActionEntropy::random(rng);
                spend_plans.push(action::Plan::spend(note, theta, rcv, |alpha| {
                    self.pak.ak.derive_action_public(&alpha)
                }));
                spend_pcds.push((self.note_secret(app, note), spendable, vec![]));
            }
            let output_plans = outputs
                .iter()
                .copied()
                .map(|note| {
                    let rcv = value::Trapdoor::random(rng);
                    let theta = ActionEntropy::random(rng);
                    action::Plan::output(note, theta, rcv)
                })
                .collect();
            let plan = bundle::Plan::new(spend_plans, output_plans, max_fee_note);
            let sighash = mock_sighash(plan.commitment().unwrap());
            let signatures = plan
                .sign(rng, &sighash, &self.sk.derive_auth_private())
                .unwrap();
            let proof = plan
                .stamp_plan(anchor, fee)
                .prove(rng, app, &self.pak, spend_pcds)
                .unwrap();
            let bundle = plan.assemble(signatures, proof);
            (plan, bundle)
        })
    }

    pub fn new(sk: private::SpendingKey) -> Self {
        Self {
            sk,
            pak: sk.derive_proof_private(),
            notes: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self::new(private::SpendingKey::random(rng))
    }

    pub(crate) fn bucket_unspent<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        bucket: &QrBucketEntry,
        note: &Note,
    ) -> ragu_pcd::Pcd<Pasta, ProductionRank, pool::NoteUnspent> {
        let arbitrary = bucket.segment(rng, app, |epoch| {
            self.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch)
        });
        self.unspent_bind(rng, app, arbitrary, note)
    }

    /// Family notes are distinct because stamps that share a tachygram cannot
    /// merge.
    pub fn labelled_note(&self, label: &str, value: u64) -> Note {
        let mut key = u32::try_from(label.len()).unwrap().to_le_bytes().to_vec();
        key.extend_from_slice(label.as_bytes());
        key.extend_from_slice(&value.to_le_bytes());
        let mut rng = keyed_rng("labelled note", &key);
        Note {
            pk: self.sk.derive_payment_key(),
            value: value::Positive::try_from(value).unwrap(),
            psi: nullifier::Trapdoor::random(&mut rng),
            rcm: note::CommitmentTrapdoor::random(&mut rng),
        }
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
        range: &ragu_pcd::Pcd<Pasta, ProductionRank, delegation::NoteNullifiers>,
    ) -> Vec<Nullifier> {
        let (_, start, last) = *range.data();
        let mk = self.pak.nk.derive_note_private(note.psi);
        (u32::from(start)..=u32::from(last))
            .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
            .collect()
    }

    pub fn note_secret(
        &self,
        app: &App<'_>,
        note: Note,
    ) -> ragu_pcd::Pcd<Pasta, ProductionRank, delegation::NoteSecret> {
        static SECRETS: Proved<ragu_pcd::Pcd<Pasta, ProductionRank, delegation::NoteSecret>> =
            Proved::new("note_secret");

        let key = [
            Fp::from(self.pak.derive_payment_key()).to_bytes(),
            Fp::from(note.commitment()).to_bytes(),
        ]
        .concat();
        SECRETS.get(&key, |rng| {
            let (pcd, ()) = app
                .seed(
                    rng,
                    delegation::NoteSeed,
                    witness::note_seed(((), ()), note, self.pak),
                )
                .unwrap();
            pcd
        })
    }

    pub fn note_nullifiers(
        &self,
        app: &App<'_>,
        note: Note,
        epoch_start: EpochIndex,
        epoch_end: EpochIndex,
    ) -> ragu_pcd::Pcd<Pasta, ProductionRank, delegation::NoteNullifiers> {
        static WINDOWS: Proved<ragu_pcd::Pcd<Pasta, ProductionRank, delegation::NoteNullifiers>> =
            Proved::new("note_nullifiers_window");
        static RANGES: Proved<ragu_pcd::Pcd<Pasta, ProductionRank, delegation::NoteNullifiers>> =
            Proved::new("note_nullifiers_range");

        let base = u32::from(epoch_start) - u32::from(epoch_start) % PoseidonFp::RATE as u32;
        let windows = (u32::from(epoch_end) - base + 1).div_ceil(NF_DERIVATION_WIDTH as u32);
        let cover_end = base + windows * NF_DERIVATION_WIDTH as u32 - 1;
        let mut key = [
            Fp::from(self.pak.derive_payment_key()).to_bytes(),
            Fp::from(note.commitment()).to_bytes(),
        ]
        .concat();
        key.extend_from_slice(&base.to_le_bytes());
        if windows == 1 {
            return WINDOWS.get(&key, |rng| {
                let secret = self.note_secret(app, note);
                let (leaf, ()) = app
                    .fuse(
                        rng,
                        delegation::NullifierDerive,
                        witness::nullifier_derive((*secret.data(), ()), EpochIndex::new(base)),
                        secret,
                        app.bootstrap_proof().clone().carry::<()>(()),
                    )
                    .unwrap();
                leaf
            });
        }
        key.extend_from_slice(&windows.to_le_bytes());
        RANGES.get(&key, |rng| {
            let chunk_start = base + (windows - 1) * NF_DERIVATION_WIDTH as u32;
            let left = self.note_nullifiers(
                app,
                note,
                EpochIndex::new(base),
                EpochIndex::new(chunk_start - 1),
            );
            let leaf = self.note_nullifiers(
                app,
                note,
                EpochIndex::new(chunk_start),
                EpochIndex::new(cover_end),
            );
            let mk = self.pak.nk.derive_note_private(note.psi);
            let left_nfs: Vec<Nullifier> = (base..chunk_start)
                .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
                .collect();
            let right_nfs: Vec<Nullifier> = (chunk_start..=cover_end)
                .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
                .collect();
            let (fused, ()) = app
                .fuse(
                    rng,
                    delegation::NullifierFuse,
                    witness::nullifier_fuse((*left.data(), *leaf.data()), &left_nfs, &right_nfs),
                    left,
                    leaf,
                )
                .unwrap();
            fused
        })
    }

    pub fn spendable_init(
        &self,
        app: &App<'_>,
        pool: &PoolSim,
        note: &Note,
        init_height: BlockHeight,
    ) -> ragu_pcd::Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        static SPENDABLE: Proved<ragu_pcd::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>> =
            Proved::new("spendable_init");

        let cm = note.commitment();
        let epoch = init_height.epoch();
        let (anchor_prev, anchor_after, creation_tgs) = {
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

            (
                anchor_prev,
                pool.block(init_height).stamps[cm_idx].3,
                stamps[cm_idx].clone(),
            )
        };
        let key = [
            Fp::from(self.pak.derive_payment_key()).to_bytes(),
            Fp::from(cm).to_bytes(),
            Fp::from(anchor_prev).to_bytes(),
            Fp::from(anchor_after).to_bytes(),
        ]
        .concat();
        SPENDABLE.get(&key, |rng| {
            let deriv = self.note_nullifiers(app, *note, epoch, epoch);
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
        })
    }

    pub fn note_unspent(
        &self,
        app: &App<'_>,
        pool: &PoolSim,
        note: &Note,
        (epoch_start, epoch_next): (EpochIndex, EpochIndex),
    ) -> ragu_pcd::Pcd<Pasta, ProductionRank, pool::NoteUnspent> {
        static UNSPENT: Proved<ragu_pcd::Pcd<Pasta, ProductionRank, pool::NoteUnspent>> =
            Proved::new("note_unspent");

        assert!(u32::from(epoch_start) < u32::from(epoch_next));
        let first = pool.entry_anchor(epoch_start);
        let last = EpochIndex::new(u32::from(epoch_next) - 1);
        let final_anchor = pool.block(last.last_block()).anchor();
        let mut key = [
            Fp::from(self.pak.derive_payment_key()).to_bytes(),
            Fp::from(note.commitment()).to_bytes(),
            Fp::from(first).to_bytes(),
            Fp::from(final_anchor).to_bytes(),
        ]
        .concat();
        key.extend_from_slice(&u32::from(epoch_start).to_le_bytes());
        key.extend_from_slice(&u32::from(epoch_next).to_le_bytes());
        UNSPENT.get(&key, |rng| {
            let mk = self.pak.nk.derive_note_private(note.psi);
            let arbitrary = pool.unspent(app, (epoch_start, epoch_next), |epoch| {
                mk.derive_nullifier(epoch)
            });
            self.unspent_bind(rng, app, arbitrary, note)
        })
    }

    pub fn unspent_bind<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        arbitrary: ragu_pcd::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent>,
        note: &Note,
    ) -> ragu_pcd::Pcd<Pasta, ProductionRank, pool::NoteUnspent> {
        let (_, epoch_start, epoch_next, _) = *arbitrary.data();
        let range = self.note_nullifiers(app, *note, epoch_start, epoch_next);
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
        spendable: ragu_pcd::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
        arbitrary: ragu_pcd::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent>,
        note: &Note,
    ) -> ragu_pcd::Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        let unspent = self.unspent_bind(rng, app, arbitrary, note);
        let (lifted, ()) = app
            .fuse(rng, spendable::SpendableLift, (), spendable, unspent)
            .unwrap();
        lifted
    }

    pub fn spendable_at(
        &self,
        app: &App<'_>,
        pool: &PoolSim,
        note: &Note,
        target: EpochIndex,
    ) -> ragu_pcd::Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        static SPENDABLE: Proved<ragu_pcd::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>> =
            Proved::new("spendable_at");

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
        let first_target = creation.next().unwrap();
        assert!(u32::from(target) >= u32::from(first_target));
        let mut key = [
            Fp::from(self.pak.derive_payment_key()).to_bytes(),
            Fp::from(note.commitment()).to_bytes(),
        ]
        .concat();
        key.extend_from_slice(&u32::from(target).to_le_bytes());
        key.extend_from_slice(&Fp::from(pool.entry_anchor(target)).to_bytes());
        SPENDABLE.get(&key, |rng| {
            if target == first_target {
                let unspent = self.note_unspent(app, pool, note, (creation, first_target));
                let bucket = pool.epoch_bucket(app, creation);
                let (spendable, ()) = app
                    .fuse(rng, spendable::QrSpendableInit, (), unspent, bucket.pcd)
                    .unwrap();
                spendable
            } else {
                let base = self.spendable_at(app, pool, note, first_target);
                let unspent = self.note_unspent(app, pool, note, (first_target, target));
                let (lifted, ()) = app
                    .fuse(rng, spendable::SpendableLift, (), base, unspent)
                    .unwrap();
                lifted
            }
        })
    }
}
