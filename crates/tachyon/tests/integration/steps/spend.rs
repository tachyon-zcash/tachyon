extern crate alloc;

use alloc::vec::Vec;
use core::iter;

use ragu::{Pcd, Proof};
use ragu_core::{PoseidonPermutation as _, pasta::PoseidonFp};
use rand::{SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    ActionSetPoly, Anchor, BlockHeight, EpochIndex, QrDiscriminant, Tachygram, TachygramSetPoly,
    action,
    constants::{EPOCH_MAX, EPOCH_SIZE},
    entropy::ActionEntropy,
    note::{self, Note},
    nullifier::NF_DERIVATION_WIDTH,
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, pool, qr, spend, spendable, stamp},
    value, witness,
};

use crate::fixtures::{
    PoolSim, QrBucketEntry, QrIntakeEntry, WalletSim, assert_rejected,
    build_unspent_pcd_over_epochs, detached_segment, mine_sparse, qr_bucket_at, qr_epoch_unspent,
    qr_profile_of, random_block, random_block_with, seal_qr_intake, tachygrams,
};

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
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    (bound, *action.data())
}

#[test]
fn spendable_lineage_binds_the_live_pair() {
    let rate = u32::try_from(PoseidonFp::RATE).unwrap();
    let far = u32::try_from(NF_DERIVATION_WIDTH).unwrap() + 1;
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);

    for (creation_index, silent_offset) in [(0, 1), (2, 2), (rate - 1, 3)] {
        let note = wallet.random_note(500);
        let swapped = wallet.random_note(500);
        let creation = EpochIndex::new(creation_index);
        let silent = EpochIndex::new(creation_index + silent_offset);
        let (pool, cm_height) = pool_with(
            rng,
            &[note, swapped],
            creation,
            EpochIndex::new(creation_index + far),
            Some(silent),
        );
        // A group's last epoch makes the bound pair straddle two groups.
        let crossing = match rate - 1 - creation_index {
            0 => rate,
            lifts => lifts,
        };

        for (lifts, chunked) in [(0, false), (crossing, false), (3, true), (far, false)] {
            let case = format!(
                "created in epoch {creation_index}, epoch {silent:?} silent, {lifts} lifts{}",
                if chunked { " one per epoch" } else { "" }
            );
            let target = EpochIndex::new(creation_index + lifts);
            let spendable_pcd = if lifts == 0 {
                wallet.spendable_init(rng, &note, &pool, cm_height)
            } else if chunked {
                let first = EpochIndex::new(creation_index + 1);
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
            let resting_anchor = if lifts == 0 {
                pool.block(cm_height).anchor()
            } else {
                pool.block(target.first_block()).prev
            };
            assert_eq!(
                *spendable_pcd.data(),
                (note.commitment(), target, resting_anchor),
                "{case}: the spendable"
            );

            let (rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
            let (bound, (action_set, tachygram_set, action_anchor)) =
                bind_and_spend(rng, &wallet, note, spendable_pcd, (theta, rcv));
            let next = target.next().unwrap();
            let (nf_current, nf_next) = (wallet.nf_at(&note, target), wallet.nf_at(&note, next));
            let (cm, bound_current, bound_next, bound_anchor, pk, cv) = bound;
            assert_eq!(cm, note.commitment(), "{case}: the bound commitment");
            assert_eq!(
                (bound_current, bound_next),
                (nf_current, nf_next),
                "{case}: the bound pair"
            );
            assert_eq!(bound_anchor, resting_anchor, "{case}: the bound anchor");
            assert_eq!(Fp::from(pk), Fp::from(note.pk), "{case}: the bound key");
            assert_eq!(cv, rcv.commit(note.value), "{case}: the value commitment");

            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                wallet.pak.ak.derive_action_public(&alpha)
            });
            let planned = ActionSetPoly::from_iter([plan.digest().unwrap()]).commit();
            let pair = TachygramSetPoly::from_iter([
                Tachygram::from(nf_current),
                Tachygram::from(nf_next),
            ]);
            assert_eq!(action_set, planned, "{case}: the action set");
            assert_eq!(tachygram_set, pair.commit(), "{case}: the tachygram set");
            assert_eq!(action_anchor, resting_anchor, "{case}: the action anchor");

            if lifts == 0 {
                let swapped_spendable = wallet.spendable_init(rng, &swapped, &pool, cm_height);
                let (_, (swapped_set, ..)) =
                    bind_and_spend(rng, &wallet, swapped, swapped_spendable, (theta, rcv));
                assert_ne!(swapped_set, planned, "{case}: the swapped note's action");
            }
        }
    }
}

#[test]
fn qr_spendable_init_starts_a_spendable_that_reaches_spend_bind() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let note = wallet.random_note(400);
    let [epoch0, epoch1, epoch2, epoch3] = [0, 1, 2, 3].map(EpochIndex::new);
    let mut pool = PoolSim::genesis_with([[Tachygram::from(note.commitment())].to_vec()].to_vec());
    mine_sparse(rng, &mut pool, epoch2, None);

    let cm_value = Fp::from(Tachygram::from(note.commitment()));
    let nf_value = Fp::from(wallet.nf_at(&note, epoch0));
    let discriminant = iter::repeat_with(|| QrDiscriminant::random(rng))
        .take(1024)
        .find(|&drawn| qr_profile_of(cm_value, drawn, 2) != qr_profile_of(nf_value, drawn, 2))
        .unwrap();
    let span = (Anchor::default(), pool.block(epoch0.last_block()).anchor());
    let capacity = usize::try_from(EPOCH_SIZE).unwrap();
    let init = |init_rng: &mut StdRng, nf_depth: u32, cm_depth: u32| {
        let cm_bucket = qr_bucket_at(
            init_rng,
            &pool,
            span,
            (discriminant, capacity, cm_depth),
            cm_value,
            Anchor::from(Fp::ZERO),
        );
        let nf_bucket = qr_bucket_at(
            init_rng,
            &pool,
            span,
            (discriminant, capacity, nf_depth),
            nf_value,
            Anchor::from(Fp::ZERO),
        );
        let unspent = qr_epoch_unspent(init_rng, &wallet, &note, &nf_bucket);
        PROOF_SYSTEM
            .fuse(
                init_rng,
                spendable::QrSpendableInit,
                witness::qr_spendable_init(
                    (*unspent.data(), *cm_bucket.pcd.data()),
                    &cm_bucket.members,
                ),
                unspent,
                cm_bucket.pcd,
            )
            .unwrap()
            .0
    };
    // The QR segment already crossed, so it rests at epoch one's entry anchor.
    let entry = (
        note.commitment(),
        epoch1,
        pool.block(epoch1.first_block()).prev,
    );
    let spendable = init(rng, 2, 2);
    assert_eq!(*spendable.data(), entry);
    assert_eq!(*init(rng, 1, 0).data(), entry);

    let lifted = wallet.lift_to_epoch(rng, &pool, &note, spendable, epoch2);
    let (rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let ((cm, nf_current, nf_next, anchor, ..), _) =
        bind_and_spend(rng, &wallet, note, lifted, (theta, rcv));
    assert_eq!(cm, note.commitment());
    assert_eq!(
        (nf_current, nf_next),
        (wallet.nf_at(&note, epoch2), wallet.nf_at(&note, epoch3))
    );
    assert_eq!(anchor, pool.block(epoch2.first_block()).prev);
}

#[test]
fn spend_steps_reject_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let note = wallet.random_note(500);
    let creation = EpochIndex::new(0);
    let (pool, cm_height) = pool_with(rng, &[note], creation, creation, None);
    let spendable_pcd = wallet.spendable_init(rng, &note, &pool, cm_height);

    let derivation = wallet.derivation_pcd(rng, note, creation, creation);
    let init = |init_rng: &mut StdRng, tgs: &[Tachygram], epoch: EpochIndex| {
        PROOF_SYSTEM.fuse(
            init_rng,
            spendable::SpendableInit,
            witness::spendable_init((*derivation.data(), ()), Anchor::default(), tgs, epoch),
            derivation.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
    };
    let absent = tachygrams(rng, 2);
    assert_rejected(
        init(rng, &absent, creation).map(drop),
        "SpendableInit: commitment not in set",
    );
    let (final_spendable, ()) = init(
        rng,
        &[Tachygram::from(note.commitment())],
        EpochIndex::new(EPOCH_MAX),
    )
    .unwrap();

    let rcv = value::Trapdoor::random(rng);
    let bind_with =
        |bind_rng: &mut StdRng, onto: Pcd<spendable::NoteSpendable>, secret_of: Note| {
            let secret = wallet.secret_pcd(bind_rng, secret_of);
            PROOF_SYSTEM
                .fuse(bind_rng, spend::SpendBind, (rcv,), onto, secret)
                .map(drop)
        };
    let richer = Note {
        value: value::Positive::try_from(501u64).unwrap(),
        ..note
    };
    assert_rejected(
        bind_with(rng, spendable_pcd.clone(), richer),
        "SpendBind: secret does not match note",
    );
    assert_rejected(
        bind_with(rng, final_spendable, note),
        "SpendBind: no epoch follows the spend epoch",
    );

    let secret = wallet.secret_pcd(rng, note);
    let (bind, ()) = PROOF_SYSTEM
        .fuse(rng, spend::SpendBind, (rcv,), spendable_pcd, secret)
        .expect("SpendBind");
    let theta = ActionEntropy::random(rng);
    let (.., action_set, tachygram_set) =
        witness::spend_action((*bind.data(), ()), theta, wallet.pak);
    let (.., foreign_action_set, _) =
        witness::spend_action((*bind.data(), ()), ActionEntropy::random(rng), wallet.pak);
    let foreign_tachygrams = tachygrams(rng, 2).into_iter().collect::<TachygramSetPoly>();
    let stranger = WalletSim::random(rng);
    let act = |act_rng: &mut StdRng, action_witness| {
        PROOF_SYSTEM
            .fuse(
                act_rng,
                stamp::SpendAction,
                action_witness,
                bind.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
    };
    assert_rejected(
        act(
            rng,
            (
                theta,
                stranger.pak,
                action_set.clone(),
                tachygram_set.clone(),
            ),
        ),
        "SpendAction: pak not related to note",
    );
    assert_rejected(
        act(rng, (theta, wallet.pak, action_set, foreign_tachygrams)),
        "SpendAction: tachygram set does not commit to the nullifier pair",
    );
    assert_rejected(
        act(rng, (theta, wallet.pak, foreign_action_set, tachygram_set)),
        "SpendAction: action set does not commit to the action",
    );
}

#[test]
fn lineage_steps_reject_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
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
    let mut pool = PoolSim::genesis_with([[Tachygram::from(note.commitment())].to_vec()].to_vec());
    let short_end = pool.anchor();
    mine_sparse(rng, &mut pool, epoch3, None);
    let final0 = pool.block(epoch0.last_block()).anchor();
    let final1 = pool.block(epoch1.last_block()).anchor();
    let epoch0_span = (Anchor::default(), final0);
    let epoch1_span = (final0.next_epoch(epoch1).unwrap(), final1);
    let capacity = usize::try_from(EPOCH_SIZE).unwrap();
    let discriminant = QrDiscriminant::random(rng);
    let bucket = |bucket_rng: &mut StdRng, span, value: Fp, prev| {
        qr_bucket_at(
            bucket_rng,
            &pool,
            span,
            (discriminant, capacity, 0),
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
    let short_crossing = short_end.next_epoch(epoch1).unwrap();
    assert_eq!(
        *short_lineage.data(),
        (note.commitment(), epoch1, short_crossing)
    );
    assert_ne!(short_crossing, pool.block(epoch1.first_block()).prev);
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
                    discriminant,
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

    assert_rejected(
        lift(rng, lineage.clone(), phantom_unspent),
        "SpendableLift: unspent cm does not match spendable",
    );
    assert_rejected(
        lift(rng, lineage.clone(), detached_unspent),
        "SpendableLift: unspent not adjacent to spendable",
    );
    assert_rejected(
        lift(rng, lineage, later_unspent),
        "SpendableLift: segment does not start at the lineage epoch",
    );
    assert_rejected(
        lift(rng, short_lineage, next_unspent),
        "SpendableLift: unspent not adjacent to spendable",
    );
    assert_rejected(
        qr_init(rng, unpublished_unspent, &cm_bucket, &cm_bucket.members),
        "QrSpendableInit: commitment not in bucket",
    );
    assert_rejected(
        qr_init(
            rng,
            whole_unspent.clone(),
            &prefix_bucket,
            &prefix_bucket.members,
        ),
        "QrSpendableInit: segment does not close where the bucket does",
    );
    assert_rejected(
        qr_init(
            rng,
            whole_unspent.clone(),
            &later_bucket,
            &later_bucket.members,
        ),
        "QrSpendableInit: segment does not start in the bucket's epoch",
    );
    assert_rejected(
        qr_init(rng, epoch1_unspent, &elsewhere, &elsewhere.members),
        "QrSpendableInit: segment does not open where the bucket does",
    );
    assert_rejected(
        qr_init(rng, whole_unspent, &cm_bucket, &foreign_members),
        "QrSpendableInit: contents do not match the bucket",
    );
}
