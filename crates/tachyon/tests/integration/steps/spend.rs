//! The spendable lineage and the spend: `SpendableInit`, `QrSpendableInit`,
//! `SpendableLift`, `SpendBind` and `SpendAction`.

extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::Fp;
use proptest::{option, prelude::*};
use ragu::{Pcd, Proof};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionSetPoly, Anchor, BlockHeight, EpochIndex, QrDiscriminant, Tachygram, TachygramSetPoly,
    action,
    constants::{EPOCH_SIZE, MAX_MONEY},
    entropy::ActionEntropy,
    note::{self, Note},
    nullifier::NF_DERIVATION_WIDTH,
    stamp::proof::{PROOF_SYSTEM, pool, qr, spend, spendable, stamp},
    value, witness,
};

use crate::{
    fixtures::{
        PoolSim, QrBucketEntry, QrIntakeEntry, WalletSim, build_unspent_pcd_over_epochs,
        detached_segment, mine_sparse, qr_bucket_at, qr_epoch_unspent, random_block,
        random_block_with, seal_qr_intake, shared_sk,
    },
    strategies::{assert_rejections, check, tachygrams},
};

/// A pool publishing `notes` in one stamp of a block in `creation`, then
/// mined sparsely through `through`'s first block, `silent` publishing
/// nothing. Returns the pool and the height of the notes' block.
fn pool_with(
    rng: &mut StdRng,
    notes: &[Note],
    creation: EpochIndex,
    through: EpochIndex,
    silent: Option<EpochIndex>,
) -> (PoolSim, BlockHeight) {
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    mine_sparse(rng, &mut pool, creation, None);
    let commitments: Vec<note::Commitment> = notes.iter().map(Note::commitment).collect();
    pool.mine(random_block_with(rng, &[commitments], 1));
    let cm_height = pool.height();
    mine_sparse(rng, &mut pool, through, silent);
    (pool, cm_height)
}

/// Bind `spendable` to `note`'s secret under `rcv`, and prove its action
/// under `theta`; returns both headers.
fn bind_and_spend(
    rng: &mut StdRng,
    wallet: &WalletSim,
    note: Note,
    spendable: Pcd<spendable::NoteSpendable>,
    (theta, rcv): (ActionEntropy, value::Trapdoor),
) -> (
    <spend::SpendHeader as ragu::Header>::Data,
    <stamp::Actions as ragu::Header>::Data,
) {
    let secret = wallet.secret_pcd(rng, note);
    let (bind, ()) = PROOF_SYSTEM
        .fuse(rng, spend::SpendBind, (rcv,), spendable, secret)
        .expect("SpendBind");
    let bound = *bind.data();
    let (action, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::SpendAction,
            witness::spend_action((bound, ()), theta, wallet.pak),
            bind,
            Proof::trivial().carry::<()>(()),
        )
        .expect("SpendAction");
    (bound, *action.data())
}

/// A note's spendable lineage starts in its creation epoch, either fresh
/// from the stamp that published it or bootstrapped from the creation
/// epoch's QR bucket, and lifts over any number of later epochs, silent
/// ones included, in one segment or one per epoch; one segment may span
/// more than a derivation window. Wherever it rests, the bind derives the
/// live pair of that epoch and the next from the note's master key, across
/// a sponge group's boundary too, with the note's value committed under the
/// planned `rcv`, and the spend publishes that pair and the planned action.
/// The action is bound to its note: a same-value note of the same wallet
/// under the planned `theta` and `rcv` proves another action.
#[test]
fn spendable_lineage_binds_the_live_pair() {
    let far = u32::try_from(NF_DERIVATION_WIDTH).expect("the window width fits u32") + 1;
    let strategy = (
        any::<u64>(),
        prop_oneof![Just(0), 0..=MAX_MONEY],
        0u32..=3,
        prop_oneof![3 => 0u32..=3, 1 => Just(far)],
        any::<bool>(),
        option::of(1u32..=3),
    );
    check(
        6,
        strategy,
        |(seed, amount, creation_index, lifts, chunked, silent_offset)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let wallet = WalletSim::new(shared_sk());
            let note = Note {
                value: value::Positive::try_from(amount).unwrap(),
                ..wallet.random_note(0)
            };
            let swapped = Note {
                value: note.value,
                ..wallet.random_note(0)
            };
            let creation = EpochIndex::new(creation_index);
            let target = EpochIndex::new(u32::from(creation) + lifts);
            let silent = silent_offset
                .filter(|&offset| offset < lifts)
                .map(|offset| EpochIndex::new(u32::from(creation) + offset));
            let (pool, cm_height) = pool_with(rng, &[note, swapped], creation, target, silent);

            let spendable_pcd = if lifts == 0 {
                wallet.spendable_init(rng, &note, &pool, cm_height)
            } else if chunked && lifts < far {
                let first = EpochIndex::new(u32::from(creation) + 1);
                let mut lineage = wallet.spendable_at(rng, &pool, &note, first);
                for epoch in u32::from(first)..u32::from(target) {
                    let segment = build_unspent_pcd_over_epochs(
                        rng,
                        &pool,
                        |covered| wallet.nf_at(&note, covered),
                        (EpochIndex::new(epoch), EpochIndex::new(epoch + 1)),
                    );
                    lineage = wallet.lift(rng, lineage, segment, &note);
                }
                lineage
            } else {
                wallet.spendable_at(rng, &pool, &note, target)
            };
            let (_, resting_epoch, resting_anchor) = *spendable_pcd.data();
            prop_assert_eq!(
                *spendable_pcd.data(),
                (note.commitment(), target, resting_anchor)
            );
            if lifts > 0 {
                prop_assert_eq!(resting_anchor, pool.block(target.first_block()).prev);
            }

            let (rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
            let (bound, (action_set, tachygram_set, action_anchor)) =
                bind_and_spend(rng, &wallet, note, spendable_pcd, (theta, rcv));
            let next = resting_epoch
                .next()
                .expect("a spendable epoch has a successor");
            let (nf_current, nf_next) = (wallet.nf_at(&note, target), wallet.nf_at(&note, next));
            let (cm, bound_current, bound_next, bound_anchor, pk, cv) = bound;
            prop_assert_eq!(cm, note.commitment());
            prop_assert_eq!((bound_current, bound_next), (nf_current, nf_next));
            prop_assert_eq!(bound_anchor, resting_anchor);
            prop_assert_eq!(Fp::from(pk), Fp::from(note.pk));
            prop_assert_eq!(cv, rcv.commit(note.value));

            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                wallet.pak.ak.derive_action_public(&alpha)
            });
            let planned =
                ActionSetPoly::from_iter([plan.digest().expect("action digest")]).commit();
            let pair = TachygramSetPoly::from_iter([
                Tachygram::from(nf_current),
                Tachygram::from(nf_next),
            ]);
            prop_assert_eq!(action_set, planned);
            prop_assert_eq!(tachygram_set, pair.commit());
            prop_assert_eq!(action_anchor, resting_anchor);

            if lifts == 0 {
                let swapped_spendable = wallet.spendable_init(rng, &swapped, &pool, cm_height);
                let (_, (swapped_set, ..)) =
                    bind_and_spend(rng, &wallet, swapped, swapped_spendable, (theta, rcv));
                prop_assert_ne!(swapped_set, planned);
            }
            Ok(())
        },
    );
}

/// `SpendableInit` refuses a creation stamp without the note's commitment;
/// `SpendBind` refuses the secret of any other note, a forged value or
/// trapdoor included; `SpendAction` refuses another wallet's pak, a
/// tachygram set other than the live pair and an action set other than the
/// action it derives.
#[test]
fn spend_steps_reject_corruptions() {
    let strategy = (any::<u64>(), 0..=MAX_MONEY, 0..MAX_MONEY, 1usize..=3);
    check(
        12,
        strategy,
        |(seed, amount, forged_amount, foreign_count)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let wallet = WalletSim::new(shared_sk());
            let note = Note {
                value: value::Positive::try_from(amount).unwrap(),
                ..wallet.random_note(0)
            };
            let creation = EpochIndex::new(0);
            let (pool, cm_height) = pool_with(rng, &[note], creation, creation, None);
            let spendable_pcd = wallet.spendable_init(rng, &note, &pool, cm_height);

            let derivation = wallet.derivation_pcd(rng, note, creation, creation);
            let absent = tachygrams(rng, foreign_count);
            let init_without_cm = PROOF_SYSTEM.fuse(
                rng,
                spendable::SpendableInit,
                witness::spendable_init(
                    (*derivation.data(), ()),
                    Anchor::default(),
                    &absent,
                    creation,
                ),
                derivation,
                Proof::trivial().carry::<()>(()),
            );

            let forged_value =
                value::Positive::try_from(forged_amount + u64::from(forged_amount >= amount))
                    .unwrap();
            let rcv = value::Trapdoor::random(rng);
            let bind_with = |bind_rng: &mut StdRng, forged: Note| {
                let secret = wallet.secret_pcd(bind_rng, forged);
                PROOF_SYSTEM
                    .fuse(
                        bind_rng,
                        spend::SpendBind,
                        (rcv,),
                        spendable_pcd.clone(),
                        secret,
                    )
                    .map(drop)
            };
            let retrapdoored_note = Note {
                rcm: note::CommitmentTrapdoor::random(rng),
                ..note
            };
            let inflated = bind_with(
                rng,
                Note {
                    value: forged_value,
                    ..note
                },
            );
            let retrapdoored = bind_with(rng, retrapdoored_note);
            let other_note = bind_with(rng, wallet.random_note(amount));

            let secret = wallet.secret_pcd(rng, note);
            let (bind, ()) = PROOF_SYSTEM
                .fuse(rng, spend::SpendBind, (rcv,), spendable_pcd, secret)
                .expect("SpendBind");
            let theta = ActionEntropy::random(rng);
            let (.., action_set, tachygram_set) =
                witness::spend_action((*bind.data(), ()), theta, wallet.pak);
            let (.., foreign_action_set, _) =
                witness::spend_action((*bind.data(), ()), ActionEntropy::random(rng), wallet.pak);
            let foreign_tachygrams = tachygrams(rng, foreign_count)
                .into_iter()
                .collect::<TachygramSetPoly>();
            let stranger = WalletSim::random(rng);
            let act = |act_rng: &mut StdRng, action_witness| {
                PROOF_SYSTEM
                    .fuse(
                        act_rng,
                        stamp::SpendAction,
                        action_witness,
                        bind.clone(),
                        Proof::trivial().carry::<()>(()),
                    )
                    .map(drop)
            };
            let foreign_pak = act(
                rng,
                (
                    theta,
                    stranger.pak,
                    action_set.clone(),
                    tachygram_set.clone(),
                ),
            );

            assert_rejections([
                (
                    "a creation stamp without the commitment",
                    init_without_cm.map(drop),
                    "SpendableInit: commitment not in set",
                ),
                (
                    "an inflated value",
                    inflated,
                    "SpendBind: secret does not match note",
                ),
                (
                    "another trapdoor",
                    retrapdoored,
                    "SpendBind: secret does not match note",
                ),
                (
                    "another note",
                    other_note,
                    "SpendBind: secret does not match note",
                ),
                (
                    "another wallet's pak",
                    foreign_pak,
                    "SpendAction: pak not related to note",
                ),
                (
                    "a tachygram set other than the live pair",
                    act(rng, (theta, wallet.pak, action_set, foreign_tachygrams)),
                    "SpendAction: tachygram set does not commit to the nullifier pair",
                ),
                (
                    "an action set under another theta",
                    act(rng, (theta, wallet.pak, foreign_action_set, tachygram_set)),
                    "SpendAction: action set does not commit to the action",
                ),
            ]);
            Ok(())
        },
    );
}

/// `SpendableLift` refuses a segment bound to another note, a segment that
/// opens on an anchor the lineage does not rest on (detached, or after a
/// short bucket's unpublished crossing), and a segment of a later epoch.
/// `QrSpendableInit` refuses a bucket without the commitment, a bucket that
/// closes, opens or lies elsewhere than the segment, and contents other
/// than the bucket's.
#[test]
fn lineage_steps_reject_corruptions() {
    check(4, any::<u64>(), |seed| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::new(shared_sk());
        let note = wallet.random_note(300);
        let unpublished = wallet.random_note(400);
        let phantom = Note {
            value: value::Positive::try_from(700u64).unwrap(),
            rcm: note::CommitmentTrapdoor::random(rng),
            ..note
        };
        let (epoch0, epoch1, epoch2, epoch3) = (
            EpochIndex::new(0),
            EpochIndex::new(1),
            EpochIndex::new(2),
            EpochIndex::new(3),
        );
        let mut pool =
            PoolSim::genesis_with([[Tachygram::from(note.commitment())].to_vec()].to_vec());
        let short_end = pool.anchor();
        mine_sparse(rng, &mut pool, epoch3, None);
        let final0 = pool.block(epoch0.last_block()).anchor();
        let final1 = pool.block(epoch1.last_block()).anchor();
        let epoch0_span = (Anchor::default(), final0);
        let epoch1_span = (final0.next_epoch(epoch1).unwrap(), final1);
        let capacity = usize::try_from(EPOCH_SIZE).unwrap();
        let discriminant =
            || QrDiscriminant::from(Fp::random(&mut StdRng::seed_from_u64(seed ^ 7)));
        let bucket = |bucket_rng: &mut StdRng, span, value: Fp, prev| {
            qr_bucket_at(
                bucket_rng,
                &pool,
                span,
                (discriminant(), capacity, 0),
                value,
                prev,
            )
        };
        let nf = |epoch| Fp::from(wallet.nf_at(&note, epoch));

        let lineage = wallet.spendable_at(rng, &pool, &note, epoch1);
        let segment = |segment_rng: &mut StdRng, from: EpochIndex, to: EpochIndex| {
            build_unspent_pcd_over_epochs(
                segment_rng,
                &pool,
                |covered| wallet.nf_at(&note, covered),
                (from, to),
            )
        };
        let lift = |lift_rng: &mut StdRng, onto: Pcd<spendable::NoteSpendable>, unspent| {
            PROOF_SYSTEM
                .fuse(lift_rng, spendable::SpendableLift, (), onto, unspent)
                .map(drop)
        };
        let phantom_segment = segment(rng, epoch1, epoch2);
        let phantom_unspent = wallet.unspent_bind(rng, phantom_segment, &phantom);
        let detached = detached_segment(rng, epoch1, |covered| wallet.nf_at(&note, covered));
        let detached_unspent = wallet.unspent_bind(rng, detached, &note);
        let later_segment = segment(rng, epoch2, epoch3);
        let later_unspent = wallet.unspent_bind(rng, later_segment, &note);

        let short_bucket = bucket(
            rng,
            (Anchor::default(), short_end),
            Fp::from(Tachygram::from(note.commitment())),
            Anchor::from(Fp::ZERO),
        );
        let short_unspent = qr_epoch_unspent(rng, &wallet, &note, &short_bucket);
        let (short_lineage, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spendable::QrSpendableInit,
                witness::qr_spendable_init(
                    (*short_unspent.data(), *short_bucket.pcd.data()),
                    &short_bucket.members,
                ),
                short_unspent,
                short_bucket.pcd,
            )
            .expect("QrSpendableInit over the short extent");
        let next_segment = segment(rng, epoch1, epoch2);
        let next_unspent = wallet.unspent_bind(rng, next_segment, &note);

        let cm_bucket = bucket(
            rng,
            epoch0_span,
            Fp::from(Tachygram::from(note.commitment())),
            Anchor::from(Fp::ZERO),
        );
        let nf_bucket = bucket(rng, epoch0_span, nf(epoch0), Anchor::from(Fp::ZERO));
        let qr_init = |init_rng: &mut StdRng,
                       unspent: Pcd<pool::NoteUnspent>,
                       target: &QrBucketEntry,
                       members: &[Tachygram]| {
            PROOF_SYSTEM
                .fuse(
                    init_rng,
                    spendable::QrSpendableInit,
                    witness::qr_spendable_init((*unspent.data(), *target.pcd.data()), members),
                    unspent,
                    target.pcd.clone(),
                )
                .map(drop)
        };
        let unpublished_bucket = bucket(
            rng,
            epoch0_span,
            Fp::from(wallet.nf_at(&unpublished, epoch0)),
            Anchor::from(Fp::ZERO),
        );
        let unpublished_unspent = qr_epoch_unspent(rng, &wallet, &unpublished, &unpublished_bucket);
        let whole_unspent = qr_epoch_unspent(rng, &wallet, &note, &nf_bucket);
        let prefix_bucket = bucket(
            rng,
            (Anchor::default(), pool.block(BlockHeight(1)).anchor()),
            Fp::from(Tachygram::from(note.commitment())),
            Anchor::from(Fp::ZERO),
        );
        let later_bucket = bucket(
            rng,
            epoch1_span,
            Fp::from(Tachygram::from(note.commitment())),
            final0,
        );

        let epoch1_nf_bucket = bucket(rng, epoch1_span, nf(epoch1), final0);
        let epoch1_unspent = qr_epoch_unspent(rng, &wallet, &note, &epoch1_nf_bucket);
        let fake_prev = Anchor::from(Fp::ONE);
        let elsewhere = {
            let members = [Tachygram::from(note.commitment())];
            let (intake, ()) = PROOF_SYSTEM
                .seed(
                    rng,
                    qr::QrStampIntakeSeed,
                    witness::qr_stamp_intake_seed(
                        ((), ()),
                        fake_prev.next_epoch(epoch1).unwrap(),
                        epoch1,
                        discriminant(),
                        &members,
                    ),
                )
                .expect("QrStampIntakeSeed");
            seal_qr_intake(
                rng,
                QrIntakeEntry {
                    pcd: intake,
                    members: members.to_vec(),
                },
                fake_prev,
            )
        };
        let foreign_members = tachygrams(rng, 1);

        assert_rejections([
            (
                "a segment bound to another note",
                lift(rng, lineage.clone(), phantom_unspent),
                "SpendableLift: unspent cm does not match spendable",
            ),
            (
                "a detached segment",
                lift(rng, lineage.clone(), detached_unspent),
                "SpendableLift: unspent not adjacent to spendable",
            ),
            (
                "a segment of a later epoch",
                lift(rng, lineage, later_unspent),
                "SpendableLift: segment does not start at the lineage epoch",
            ),
            (
                "a lineage resting on a short bucket's crossing",
                lift(rng, short_lineage, next_unspent),
                "SpendableLift: unspent not adjacent to spendable",
            ),
            (
                "a bucket without the commitment",
                qr_init(rng, unpublished_unspent, &cm_bucket, &cm_bucket.members),
                "QrSpendableInit: commitment not in bucket",
            ),
            (
                "a bucket that closes before the segment",
                qr_init(
                    rng,
                    whole_unspent.clone(),
                    &prefix_bucket,
                    &prefix_bucket.members,
                ),
                "QrSpendableInit: segment does not close where the bucket does",
            ),
            (
                "a bucket of the next epoch",
                qr_init(
                    rng,
                    whole_unspent.clone(),
                    &later_bucket,
                    &later_bucket.members,
                ),
                "QrSpendableInit: segment does not start in the bucket's epoch",
            ),
            (
                "a bucket opening on an invented boundary",
                qr_init(rng, epoch1_unspent, &elsewhere, &elsewhere.members),
                "QrSpendableInit: segment does not open where the bucket does",
            ),
            (
                "contents other than the bucket's",
                qr_init(rng, whole_unspent, &cm_bucket, &foreign_members),
                "QrSpendableInit: contents do not match the bucket",
            ),
        ]);
        Ok(())
    });
}
