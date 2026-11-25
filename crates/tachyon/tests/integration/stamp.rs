extern crate alloc;

use alloc::{boxed::Box, collections::BTreeSet, string::ToString as _, vec, vec::Vec};
use core::assert_matches;

use corez::io;
use ragu::{WalletRank, pasta::Pasta};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use zcash_tachyon::{
    ActionDigest, ActionSetPoly, BlockHeight, CompactSize, ProofStamp, Tachygram, TachygramSetPoly,
    action, bundle,
    entropy::ActionEntropy,
    fee,
    stamp::{
        self, ProveError,
        proof::{
            App,
            stamp::{Stamp, StampMerge},
        },
    },
    value, witness,
};

use super::fixtures::application;
use crate::fixtures::{
    mock_sighash, mock_txid,
    pool::PoolSim,
    wallet::{
        WalletSim, alice, alice_output_note, bob, later_output, lifted, merged, output_plan,
        random_action, shared_sk, spend,
    },
};

fn forge_overlapping_merge<RNG: CryptoRng>(
    rng: &mut RNG,
    app: &App<'_>,
    (stamp_a, stamp_b): (
        &ProofStamp<stamp::Uncompressed>,
        &ProofStamp<stamp::Uncompressed>,
    ),
    (digests, tachygrams): (&[ActionDigest], &[Tachygram]),
) -> ragu::Pcd<Pasta, WalletRank, Stamp> {
    let left_pcd = stamp_a.proof.clone().carry::<Stamp>((
        app.bridge_hash(stamp_a.tachygram_set.into())
            .unwrap()
            .into(),
        stamp_a.anchor,
    ));
    let right_pcd = stamp_b.proof.clone().carry::<Stamp>((
        app.bridge_hash(stamp_b.tachygram_set.into())
            .unwrap()
            .into(),
        stamp_b.anchor,
    ));

    let merged_acts = digests.iter().copied().collect::<ActionSetPoly>();
    let merged_tg = tachygrams.iter().copied().collect::<TachygramSetPoly>();

    let (pcd, ()) = app
        .fuse(
            rng,
            StampMerge,
            witness::stamp_merge(
                (*left_pcd.data(), *right_pcd.data()),
                merged_acts,
                merged_tg,
            ),
            left_pcd,
            right_pcd,
        )
        .unwrap();

    pcd
}

#[test]
fn plan_prove_rejects_invalid_inputs() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let other = WalletSim::random(rng);
    let pool = PoolSim::shared();
    let note_a = PoolSim::shared_note(500);
    let note_b = PoolSim::shared_note(700);
    let height = BlockHeight(1);

    let sp_a = user.spendable_init(app, pool, &note_a, height);
    let sp_b = user.spendable_init(app, pool, &note_b, height);
    let anchor = sp_a.data().2;

    let (rcv_a, theta_a) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let plan_a = action::Plan::spend(note_a, theta_a, rcv_a, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });
    let (rcv_b, theta_b) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let plan_b = action::Plan::spend(note_b, theta_b, rcv_b, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });
    let max_fee_note = user.random_note(0);
    let fee_digest = fee::Descriptor {
        cv_feemax: max_fee_note.cv_feemax(),
        v_fee: value::Positive::ZERO,
    }
    .digest(max_fee_note.commitment().into());
    let secret_a = user.note_secret(app, note_a);
    let secret_b = user.note_secret(app, note_b);
    let plan = stamp::Plan::new(
        vec![plan_a, plan_b],
        vec![],
        anchor,
        max_fee_note,
        value::Positive::ZERO,
    );

    for (pcds, expected) in [
        (
            vec![(secret_a.clone(), sp_a.clone(), vec![])],
            "cannot prove 2 spend actions with 1 spendbind inputs",
        ),
        (
            vec![
                (secret_a.clone(), sp_a.clone(), vec![]),
                (secret_b.clone(), sp_b.clone(), vec![]),
                (secret_a.clone(), sp_a.clone(), vec![]),
            ],
            "cannot prove 2 spend actions with 3 spendbind inputs",
        ),
    ] {
        assert_matches!(
            plan.clone().prove(rng, app, &user.pak, pcds),
            Err(ProveError::MissingPcd(reason)) if reason.to_string() == expected
        );
    }

    let [pair_a, pair_b] = [
        (secret_a.data().2, sp_a.data().1),
        (secret_b.data().2, sp_b.data().1),
    ]
    .map(|(master, epoch)| {
        (
            master.derive_nullifier(epoch).into(),
            master.derive_nullifier(epoch.next().unwrap()).into(),
        )
    });
    let swapped = plan
        .prove(
            rng,
            app,
            &user.pak,
            vec![
                (secret_b, sp_b, vec![]),
                (secret_a.clone(), sp_a.clone(), vec![]),
            ],
        )
        .unwrap();
    assert!(
        !swapped
            .verify_proof(
                rng,
                app,
                [plan_a.digest(pair_b), plan_b.digest(pair_a), fee_digest]
            )
            .unwrap()
    );

    let foreign_a = action::Plan::spend(note_a, theta_a, rcv_a, |alpha| {
        other.pak.ak.derive_action_public(&alpha)
    });
    let foreign = stamp::Plan::new(
        vec![foreign_a],
        vec![],
        anchor,
        max_fee_note,
        value::Positive::ZERO,
    )
    .prove(rng, app, &user.pak, vec![(secret_a, sp_a, vec![])])
    .unwrap();
    assert!(
        !foreign
            .verify_proof(rng, app, [foreign_a.digest(pair_a), fee_digest])
            .unwrap()
    );
}

#[test]
fn plan_prove_lifts_a_spend_along_spans() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let pool = PoolSim::shared();
    let note = PoolSim::shared_note(500);
    let cm_height = BlockHeight(1);
    let middle = BlockHeight(2);
    let plan_height = BlockHeight(3);
    let spendable = user.spendable_init(app, pool, &note, cm_height);
    let plan_anchor = pool.block(plan_height).anchor();

    let (rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let spend = action::Plan::spend(note, theta, rcv, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });
    let output = output_plan(rng, user.random_note(200));
    let secret = user.note_secret(app, note);
    let max_fee_note = user.random_note(0);
    let plan = stamp::Plan::new(
        vec![spend],
        vec![output],
        plan_anchor,
        max_fee_note,
        value::Positive::ZERO,
    );

    let master = secret.data().2;
    let epoch = spendable.data().1;
    let spend_pair = (
        master.derive_nullifier(epoch).into(),
        master.derive_nullifier(epoch.next().unwrap()).into(),
    );
    let fee_descriptor = plan.fee_descriptor();
    let change = plan.fee_change_commitment();
    let digests = [
        spend.digest(spend_pair),
        output.digest((
            output.note.commitment().into(),
            output.note.commitment_pad(),
        )),
        fee_descriptor.digest(change),
    ];
    for spans in [
        vec![pool.anchor_span(app, cm_height..=plan_height)],
        vec![
            pool.anchor_span(app, cm_height..=middle),
            pool.anchor_span(app, plan_height..=plan_height),
        ],
        vec![
            pool.anchor_span(app, cm_height..=middle),
            pool.anchor_span(app, middle..=plan_height),
        ],
    ] {
        let stamp = plan
            .clone()
            .prove(
                rng,
                app,
                &user.pak,
                vec![(secret.clone(), spendable.clone(), spans)],
            )
            .unwrap();
        assert_eq!(stamp.anchor, plan_anchor);
        assert!(stamp.verify_proof(rng, app, digests).unwrap());
    }

    for spans in [vec![], vec![pool.anchor_span(app, cm_height..=middle)]] {
        assert_matches!(
            plan.clone().prove(
                rng,
                app,
                &user.pak,
                vec![(secret.clone(), spendable.clone(), spans)],
            ),
            Err(ProveError::MissingPcd(reason))
                if reason.to_string() == "spend 0 does not reach the plan's anchor"
        );
    }

    let gapped = vec![
        pool.anchor_span(app, cm_height..=cm_height),
        pool.anchor_span(app, plan_height..=plan_height),
    ];
    let forged = plan
        .prove(rng, app, &user.pak, vec![(secret, spendable, gapped)])
        .unwrap();
    assert!(!forged.verify_proof(rng, app, digests).unwrap());
}

#[test]
fn overlapping_stamps_cannot_aggregate() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let pool = PoolSim::shared();
    let anchor = pool.mint_anchor();
    let (_, alice_bundle) = alice(app);
    let alice_note = alice_output_note();
    let fees_a = [(alice_bundle.fee, alice_bundle.fee_auth)];
    let output_a = alice_bundle.stamp;
    let (_, output_b) = wallet.bundle(
        app,
        anchor,
        &[],
        &[alice_note],
        wallet.random_note(0),
        value::Positive::ZERO,
    );
    let fees_b = [(output_b.fee, output_b.fee_auth)];
    let (_, spend_a) = spend(app);
    let note = PoolSim::shared_note(1000);
    let spendable = wallet.spendable_init(app, pool, &note, BlockHeight(1));
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let spend_plan = action::Plan::spend(note, theta, rcv, |alpha| {
        wallet.pak.ak.derive_action_public(&alpha)
    });
    let output = output_plan(rng, wallet.random_note(600));
    let plan = bundle::Plan::new(vec![spend_plan], vec![output], wallet.random_note(0));
    let sighash = mock_sighash(plan.commitment().unwrap());
    let secret = wallet.note_secret(app, note);
    let master = secret.data().2;
    let epoch = spendable.data().1;
    let pair = (
        master.derive_nullifier(epoch).into(),
        master.derive_nullifier(epoch.next().unwrap()).into(),
    );
    let signatures = plan
        .sign(rng, &sighash, &wallet.sk.derive_auth_private())
        .unwrap();
    let stamp_plan = plan.stamp_plan(anchor, value::Positive::ZERO);
    let fee_change = stamp_plan.fee_change_commitment();
    let spend_stamp = stamp_plan
        .prove(rng, app, &wallet.pak, vec![(secret, spendable, vec![])])
        .unwrap();
    let spend_b = plan
        .assemble(
            signatures,
            |_| Some(pair),
            value::Positive::ZERO,
            fee_change,
            spend_stamp,
        )
        .unwrap();
    let fixture_fees = [(spend_a.fee, spend_a.fee_auth)];
    let overlap_fees = [(spend_b.fee, spend_b.fee_auth)];

    for ((left, left_covered), (right, right_covered), expected) in [
        (
            (output_a.clone(), (&alice_bundle.actions, fees_a)),
            (output_b.stamp, (&output_b.actions, fees_b)),
            "two outputs of the same note",
        ),
        (
            (spend_a.stamp, (&spend_a.actions, fixture_fees)),
            (spend_b.stamp, (&spend_b.actions, overlap_fees)),
            "a spend reproven in both stamps",
        ),
        (
            (output_a.clone(), (&alice_bundle.actions, fees_a)),
            (output_a, (&alice_bundle.actions, fees_a)),
            "a stamp merged with itself",
        ),
    ] {
        let merged = left
            .clone()
            .merge(
                rng,
                app,
                left_covered,
                (right.clone(), [0; 32], right_covered.0, right_covered.1),
            )
            .unwrap();

        let mut digests = Vec::new();
        let mut merged_tachygrams = Vec::new();
        for (actions, fees) in [left_covered, right_covered] {
            for action in actions {
                merged_tachygrams.extend(<[Tachygram; 2]>::from(action.tachygrams));
                digests.push(action.digest());
            }
            for (descriptor, change) in fees {
                merged_tachygrams.push(change);
                digests.push(descriptor.digest(change));
            }
        }
        let union: BTreeSet<ActionDigest> = digests.iter().copied().collect();
        assert!(!merged.verify_proof(rng, app, union).unwrap(), "{expected}");

        let forged =
            forge_overlapping_merge(rng, app, (&left, &right), (&digests, &merged_tachygrams));
        let stamp = ProofStamp {
            anchor: forged.data().1,
            tachygram_set: merged_tachygrams
                .iter()
                .copied()
                .collect::<BTreeSet<Tachygram>>()
                .into_iter()
                .collect::<TachygramSetPoly>()
                .commit(),
            adjuncts: BTreeSet::new(),
            proof: Box::new(forged.proof().clone()),
        };
        assert!(!stamp.verify_proof(rng, app, digests).unwrap());
    }
}

#[test]
fn verify_proof_action_multiset_invariants() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, stamped) = spend(app);

    let (digests, _) = stamped.verify_covered(&[]).unwrap();

    assert!(
        stamped
            .stamp
            .verify_proof(rng, app, digests.iter().rev().copied())
            .unwrap()
    );

    for edited in [
        digests[1..].to_vec(),
        digests[..digests.len() - 1].to_vec(),
        [digests.as_slice(), &digests[..1]].concat(),
        [
            digests.as_slice(),
            &[random_action(rng)
                .0
                .digest((Tachygram::random(rng), Tachygram::random(rng)))],
        ]
        .concat(),
        [
            &[random_action(rng)
                .0
                .digest((Tachygram::random(rng), Tachygram::random(rng)))],
            &digests[1..],
        ]
        .concat(),
    ] {
        assert!(!stamped.stamp.verify_proof(rng, app, edited).unwrap());
    }
}

#[test]
fn read_rejects_wrong_proof_size() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(app);
    let stamp = alice.stamp;
    let compressed_size = <stamp::Compressed as stamp::Proof>::encoded_len();
    let uncompressed_size = <stamp::Uncompressed as stamp::Proof>::encoded_len();

    {
        let proof = stamp.proof.to_bytes().unwrap();
        let mut bytes = Vec::new();
        stamp.write(&mut bytes).unwrap();
        let mut prefix = Vec::new();
        CompactSize::try_from(proof.len())
            .unwrap()
            .write(&mut prefix)
            .unwrap();
        bytes.truncate(bytes.len() - proof.len() - prefix.len());
        CompactSize::try_from(compressed_size)
            .unwrap()
            .write(&mut bytes)
            .unwrap();
        bytes.extend_from_slice(&proof);
        let mut reader = bytes.as_slice();
        let err = ProofStamp::<stamp::Uncompressed>::read(&mut reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(reader.len(), proof.len() - compressed_size);
    }

    let compressed = stamp.compress(rng, app).unwrap();
    {
        let proof = compressed.proof.to_bytes().unwrap();
        let mut bytes = Vec::new();
        compressed.write(&mut bytes).unwrap();
        let mut prefix = Vec::new();
        CompactSize::try_from(proof.len())
            .unwrap()
            .write(&mut prefix)
            .unwrap();
        bytes.truncate(bytes.len() - proof.len() - prefix.len());
        CompactSize::try_from(uncompressed_size)
            .unwrap()
            .write(&mut bytes)
            .unwrap();
        let err = ProofStamp::<stamp::Compressed>::read(&*bytes).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "proof size exceeds transport bound");
    }
}

#[test]
fn output_stamp_round_trips_and_binds_its_tachygram_set() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(app);
    let (digests, _) = alice.verify_covered(&[]).unwrap();
    let stamp = alice.stamp;

    let mut buf: Vec<u8> = Vec::new();
    stamp.write(&mut buf).unwrap();
    let decoded = ProofStamp::<stamp::Uncompressed>::read(&*buf).unwrap();
    assert_eq!(decoded.adjuncts, stamp.adjuncts);
    assert_eq!(decoded.anchor, stamp.anchor);
    assert_eq!(decoded.tachygram_set, stamp.tachygram_set);
    assert!(
        decoded
            .verify_proof(rng, app, digests.iter().copied())
            .unwrap()
    );

    let forged = ProofStamp {
        tachygram_set: TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit(),
        ..stamp
    };
    assert!(!forged.verify_proof(rng, app, digests).unwrap());
}

#[test]
fn lift_moves_the_anchor_and_keeps_the_proof_valid() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let (_, alice) = alice(app);
    let (digests, _) = alice.verify_covered(&[]).unwrap();
    let fees = [(alice.fee, alice.fee_auth)];
    let fee_digest = alice.fee.digest(alice.fee_auth);
    let stamp = alice.stamp.clone();
    let lifted_to = BlockHeight(2);

    let span = pool.anchor_span(app, BlockHeight(1)..=lifted_to);
    let lifted = lifted(app, &alice, pool, BlockHeight(1)..=lifted_to).stamp;
    assert_eq!(lifted.anchor, pool.block(lifted_to).anchor());
    assert_eq!(lifted.adjuncts, stamp.adjuncts);
    assert_eq!(lifted.tachygram_set, stamp.tachygram_set);
    assert!(
        lifted
            .verify_proof(rng, app, digests.iter().copied())
            .unwrap()
    );

    let mut bytes = Vec::new();
    stamp.write(&mut bytes).unwrap();
    let decoded = ProofStamp::<stamp::Uncompressed>::read(&*bytes).unwrap();
    let lifted_decoded = decoded
        .lift(rng, app, &alice.actions, fees, vec![span.clone()])
        .unwrap();
    assert_eq!(lifted_decoded.anchor, pool.block(lifted_to).anchor());
    assert_eq!(lifted_decoded.adjuncts, stamp.adjuncts);
    assert!(lifted_decoded.verify_proof(rng, app, digests).unwrap());

    let foreign = random_action(rng).0;
    let mismatched_action = action::Action {
        descriptor: foreign,
        ..alice.actions[0]
    };
    let mismatched = stamp
        .lift(rng, app, [&mismatched_action], fees, vec![span])
        .unwrap();
    assert!(
        !mismatched
            .verify_proof(rng, app, [mismatched_action.digest(), fee_digest],)
            .unwrap()
    );
}

#[test]
fn empty_lift_does_not_digest_invalid_coverage() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, bundle) = alice(app);
    let mut invalid = bundle.clone().strip();
    invalid.actions[0].descriptor.cv = value::Trapdoor::ZERO.commit(value::Positive::ZERO);
    invalid.fee.cv_feemax = invalid.actions[0].descriptor.cv;
    let fees = [(invalid.fee, invalid.fee_auth)];

    // Even unusable coverage must not be inspected for an empty lift.
    bundle
        .stamp
        .clone()
        .lift(rng, app, &invalid.actions, fees, vec![])
        .unwrap();
    bundle.lift(rng, app, &[invalid.as_dyn()], vec![]).unwrap();
}

#[test]
fn merge_after_lift() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let (_, bundle_a) = alice(app);
    let (_, bundle_b) = later_output(app);
    let stamp_a = &bundle_a.stamp;
    let stamp_b = &bundle_b.stamp;
    let fees_a = [(bundle_a.fee, bundle_a.fee_auth)];
    let fees_b = [(bundle_b.fee, bundle_b.fee_auth)];

    let digests: Vec<ActionDigest> = bundle_a
        .verify_covered(&[])
        .unwrap()
        .0
        .into_iter()
        .chain(bundle_b.verify_covered(&[]).unwrap().0)
        .collect();
    let unlifted = stamp_a
        .clone()
        .merge(
            rng,
            app,
            (&bundle_a.actions, fees_a),
            (
                stamp_b.clone(),
                mock_txid(&bundle_b),
                &bundle_b.actions,
                fees_b,
            ),
        )
        .unwrap();
    assert!(
        !unlifted
            .verify_proof(rng, app, digests.iter().copied())
            .unwrap()
    );

    let lifted_a = lifted(app, &bundle_a, pool, BlockHeight(1)..=BlockHeight(2));

    assert_eq!(lifted_a.stamp.anchor, stamp_b.anchor);
    let combined = merged(app, &lifted_a, &bundle_b);
    assert_eq!(combined.stamp.anchor, lifted_a.stamp.anchor);
    assert!(combined.stamp.verify_proof(rng, app, digests).unwrap());
}

#[test]
fn mismatched_merge_descriptors_fail_verification() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, bundle_a) = alice(app);
    let (_, bundle_b) = bob(app);
    let foreign = random_action(rng).0;
    let fees_a = [(bundle_a.fee, bundle_a.fee_auth)];
    let foreign_action = action::Action {
        descriptor: foreign,
        ..bundle_b.actions[0]
    };
    let fees_b = [(bundle_b.fee, bundle_b.fee_auth)];

    let digests: Vec<ActionDigest> = bundle_a
        .verify_covered(&[])
        .unwrap()
        .0
        .into_iter()
        .chain(bundle_b.verify_covered(&[]).unwrap().0)
        .collect();

    let mismatched = bundle_a
        .stamp
        .clone()
        .merge(
            rng,
            app,
            (&bundle_a.actions, fees_a),
            (
                bundle_b.stamp.clone(),
                mock_txid(&bundle_b),
                [&foreign_action],
                fees_b,
            ),
        )
        .unwrap();
    let mismatched_digests: Vec<ActionDigest> = bundle_a
        .verify_covered(&[])
        .unwrap()
        .0
        .into_iter()
        .chain([
            foreign_action.digest(),
            bundle_b.fee.digest(bundle_b.fee_auth),
        ])
        .collect();
    assert!(
        !mismatched
            .verify_proof(rng, app, mismatched_digests)
            .unwrap()
    );

    let honest = merged(app, &bundle_a, &bundle_b).stamp;
    assert!(honest.verify_proof(rng, app, digests).unwrap());
}
