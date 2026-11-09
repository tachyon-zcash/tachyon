extern crate alloc;

use alloc::vec;
use core::{assert_matches, iter};

use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionSetPoly, Anchor, TachygramSetPoly, VerificationError, VerifyCoverageError, bundle,
    stamp::{
        self, ProofStamp, ProveError,
        proof::{
            PROOF_SYSTEM,
            stamp::{Stamp, StampUnmerge},
        },
    },
    value, witness,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_lift_span, build_output_plan, mock_sighash, mock_wtxid, random_block,
    shared_sk,
};

#[test]
fn unmerge_removes_a_divisor_across_merge_boundaries() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let alice = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);
    let bob = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);
    let carol = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);

    let all_three = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                [alice.fee_descriptor()].into(),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                [bob.fee_descriptor()].into(),
            ),
        )
        .unwrap()
        .merge(
            rng,
            (
                alice.descriptors().chain(bob.descriptors()).collect(),
                [alice.fee_descriptor(), bob.fee_descriptor()].into(),
            ),
            (
                carol.stamp.clone(),
                carol.descriptors().collect(),
                [carol.fee_descriptor()].into(),
            ),
        )
        .unwrap();

    let decoded_aggregate = {
        let mut bytes = Vec::new();
        all_three.write(&mut bytes).unwrap();
        ProofStamp::<stamp::Uncompressed>::read(&*bytes).unwrap()
    };
    for (divisor, divisor_descriptors, divisor_fees, adjuncts) in [
        (
            bob.stamp.clone(),
            bob.descriptors().collect(),
            [bob.fee_descriptor()].into(),
            vec![carol.clone()],
        ),
        (
            bob.stamp
                .clone()
                .merge(
                    rng,
                    (bob.descriptors().collect(), [bob.fee_descriptor()].into()),
                    (
                        carol.stamp.clone(),
                        carol.descriptors().collect(),
                        [carol.fee_descriptor()].into(),
                    ),
                )
                .unwrap(),
            bob.descriptors().chain(carol.descriptors()).collect(),
            [bob.fee_descriptor(), carol.fee_descriptor()].into(),
            vec![],
        ),
    ] {
        let mut unmerged = alice.clone();
        unmerged.stamp = decoded_aggregate
            .clone()
            .unmerge(
                rng,
                (
                    alice
                        .descriptors()
                        .chain(bob.descriptors())
                        .chain(carol.descriptors())
                        .collect(),
                    [
                        alice.fee_descriptor(),
                        bob.fee_descriptor(),
                        carol.fee_descriptor(),
                    ]
                    .into(),
                ),
                (divisor, divisor_descriptors, divisor_fees),
            )
            .unwrap();
        let wtxid = mock_wtxid(&unmerged);
        let stripped: Vec<_> = adjuncts
            .into_iter()
            .map(|adjunct| adjunct.strip(wtxid))
            .collect();
        unmerged
            .verify(
                rng,
                &mock_sighash(unmerged.commitment()),
                &wtxid.into(),
                &stripped.iter().collect::<Vec<_>>(),
            )
            .unwrap();
    }
}

#[test]
fn unmerge_keeps_the_dividend_fee() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let alice_fee = value::Positive::try_from(40u64).unwrap();
    let bob_fee = value::Positive::try_from(70u64).unwrap();
    let carol_fee = value::Positive::try_from(90u64).unwrap();
    let [alice, bob, mut carol] = [alice_fee, bob_fee, carol_fee].map(|fee| {
        let (plan, signed, spend_pcds) = wallet.signed(
            rng,
            vec![],
            vec![wallet.random_note(500)],
            wallet.random_note(100),
        );
        signed.stamp(
            plan.stamp_plan(anchor, fee)
                .prove(rng, &wallet.pak, spend_pcds)
                .unwrap(),
        )
    });

    let on_alice = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                [alice.fee_descriptor()].into(),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                [bob.fee_descriptor()].into(),
            ),
        )
        .unwrap();

    let mut kept = alice.clone();
    kept.stamp = on_alice
        .clone()
        .unmerge(
            rng,
            (
                alice.descriptors().chain(bob.descriptors()).collect(),
                [alice.fee_descriptor(), bob.fee_descriptor()].into(),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                [bob.fee_descriptor()].into(),
            ),
        )
        .unwrap();
    let kept_wtxid = mock_wtxid(&kept);
    kept.verify(
        rng,
        &mock_sighash(kept.commitment()),
        &kept_wtxid.into(),
        &[],
    )
    .unwrap();

    let mut hostless = bob.clone();
    hostless.stamp = on_alice
        .unmerge(
            rng,
            (
                alice.descriptors().chain(bob.descriptors()).collect(),
                [alice.fee_descriptor(), bob.fee_descriptor()].into(),
            ),
            (
                alice.stamp.clone(),
                alice.descriptors().collect(),
                [alice.fee_descriptor()].into(),
            ),
        )
        .unwrap();
    assert_eq!(hostless.stamp.fee, alice_fee);
    let hostless_wtxid = mock_wtxid(&hostless);
    assert_matches!(
        hostless.verify(
            rng,
            &mock_sighash(hostless.commitment()),
            &hostless_wtxid.into(),
            &[],
        ),
        Err(VerificationError::Coverage(
            VerifyCoverageError::StampActionsMismatch
        ))
    );

    carol.stamp = carol
        .stamp
        .clone()
        .merge(
            rng,
            (
                carol.descriptors().collect(),
                [carol.fee_descriptor()].into(),
            ),
            (
                hostless.stamp,
                bob.descriptors().collect(),
                [bob.fee_descriptor()].into(),
            ),
        )
        .unwrap();
    let carol_wtxid = mock_wtxid(&carol);
    carol
        .verify(
            rng,
            &mock_sighash(carol.commitment()),
            &carol_wtxid.into(),
            &[&bob.strip(carol_wtxid)],
        )
        .unwrap();
}

#[test]
fn unmerge_by_a_lifted_divisor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));

    pool.advance(3, |_| random_block(rng, 1, 4));
    let bob = wallet.autonome(rng, pool.anchor(), vec![], vec![wallet.random_note(300)]);
    let stamped_at = pool.height();

    pool.advance(2, |_| random_block(rng, 1, 4));
    let mut alice = wallet.autonome(rng, pool.anchor(), vec![], vec![wallet.random_note(300)]);

    let span = build_lift_span(rng, &pool, stamped_at.next().unwrap()..=pool.height());
    let lifted_bob = bob
        .stamp
        .clone()
        .lift(
            rng,
            &bob.descriptors().collect(),
            &[bob.fee_descriptor()].into(),
            vec![span],
        )
        .unwrap();

    let alice_bob = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                [alice.fee_descriptor()].into(),
            ),
            (
                lifted_bob.clone(),
                bob.descriptors().collect(),
                [bob.fee_descriptor()].into(),
            ),
        )
        .unwrap();

    assert_matches!(
        alice_bob.clone().unmerge(
            rng,
            (
                alice.descriptors().chain(bob.descriptors()).collect(),
                [alice.fee_descriptor(), bob.fee_descriptor()].into(),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                [bob.fee_descriptor()].into(),
            ),
        ),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err)))
            if err.to_string() == "StampUnmerge: anchors must match"
    );

    alice.stamp = alice_bob
        .unmerge(
            rng,
            (
                alice.descriptors().chain(bob.descriptors()).collect(),
                [alice.fee_descriptor(), bob.fee_descriptor()].into(),
            ),
            (
                lifted_bob,
                bob.descriptors().collect(),
                [bob.fee_descriptor()].into(),
            ),
        )
        .unwrap();
    let wtxid = mock_wtxid(&alice);
    alice
        .verify(rng, &mock_sighash(alice.commitment()), &wtxid.into(), &[])
        .unwrap();
}

#[test]
fn unmerge_by_itself_leaves_no_leaves() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let mut alice = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);

    let quotient = alice
        .stamp
        .clone()
        .unmerge(
            rng,
            (
                alice.descriptors().collect(),
                [alice.fee_descriptor()].into(),
            ),
            (
                alice.stamp.clone(),
                alice.descriptors().collect(),
                [alice.fee_descriptor()].into(),
            ),
        )
        .unwrap();
    assert!(quotient.tachygrams.is_empty());
    assert!(quotient.verify_proof(rng, []).unwrap());

    alice.stamp = quotient;
    let wtxid = mock_wtxid(&alice);
    assert_matches!(
        alice.verify(rng, &mock_sighash(alice.commitment()), &wtxid.into(), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::StampActionsMismatch
        ))
    );
}

#[test]
fn unmerge_splitting_a_bundle() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);

    let (_, _, kept_plan) = build_output_plan(rng, wallet.random_note(300));
    let removed_note = wallet.random_note(300);
    let (removed_rcv, removed_theta, removed_plan) = build_output_plan(rng, removed_note);
    let removed_descriptor = removed_plan.descriptor();
    let kept_descriptor = kept_plan.descriptor();

    let max_fee_note = wallet.random_note(0);
    let plan = bundle::Plan::new(vec![], vec![kept_plan, removed_plan], max_fee_note);
    let mut whole = plan
        .sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap()
        .stamp(
            plan.stamp_plan(anchor, value::Positive::ZERO)
                .prove(rng, &wallet.pak, vec![])
                .unwrap(),
        );

    let part = stamp::Plan::new(
        vec![],
        vec![(removed_descriptor, removed_theta, removed_note, removed_rcv)],
        anchor,
        max_fee_note,
        value::Positive::ZERO,
    )
    .prove(rng, &wallet.pak, vec![])
    .unwrap();

    let quotient = whole
        .stamp
        .clone()
        .unmerge(
            rng,
            (
                whole.descriptors().collect(),
                [whole.fee_descriptor()].into(),
            ),
            (
                part,
                [removed_descriptor].into(),
                [whole.fee_descriptor()].into(),
            ),
        )
        .unwrap();
    assert!(
        quotient
            .verify_proof(rng, [kept_descriptor.digest().unwrap()])
            .unwrap()
    );

    whole.stamp = quotient;
    let wtxid = mock_wtxid(&whole);
    assert_matches!(
        whole.verify(rng, &mock_sighash(whole.commitment()), &wtxid.into(), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::StampActionsMismatch
        ))
    );
}

#[test]
fn unmerge_binds_its_sets() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let alice = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);
    let bob = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);
    let alice_bob = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                [alice.fee_descriptor()].into(),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                [bob.fee_descriptor()].into(),
            ),
        )
        .unwrap();

    let alice_bob_tachygrams: TachygramSetPoly = alice_bob.tachygrams.iter().copied().collect();
    let alice_actions: ActionSetPoly = alice
        .descriptors()
        .map(|desc| desc.digest().unwrap())
        .chain(iter::once(alice.fee_descriptor().digest().unwrap()))
        .collect();
    let alice_tachygrams: TachygramSetPoly = alice.stamp.tachygrams.iter().copied().collect();
    let bob_actions: ActionSetPoly = bob
        .descriptors()
        .map(|desc| desc.digest().unwrap())
        .chain(iter::once(bob.fee_descriptor().digest().unwrap()))
        .collect();
    let bob_tachygrams: TachygramSetPoly = bob.stamp.tachygrams.iter().copied().collect();
    let dividend_header = Stamp::header(alice_bob_tachygrams.commit(), alice_bob.anchor).unwrap();
    let divisor_header = Stamp::header(bob_tachygrams.commit(), bob.stamp.anchor).unwrap();
    let valid = witness::stamp_unmerge(
        (dividend_header, divisor_header),
        alice_actions,
        alice_tachygrams,
    );

    for (corrupt, expected) in [
        (
            {
                let mut corrupt = valid.clone();
                corrupt.0 = bob_actions;
                corrupt
            },
            "StampUnmerge: dividend action set must be the product of divisor and quotient action sets",
        ),
        (
            {
                let mut corrupt = valid;
                let dropped = *alice.stamp.tachygrams.first().unwrap();
                corrupt.1 = alice
                    .stamp
                    .tachygrams
                    .iter()
                    .copied()
                    .filter(|&tachygram| tachygram != dropped)
                    .chain([*bob.stamp.tachygrams.first().unwrap()])
                    .collect();
                corrupt
            },
            "StampUnmerge: dividend tachygram set must be the product of divisor and quotient tachygram sets",
        ),
    ] {
        assert_matches!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    StampUnmerge,
                    corrupt,
                    alice_bob.proof.clone().carry::<Stamp>(dividend_header),
                    bob.stamp.proof.clone().carry::<Stamp>(divisor_header),
                )
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
    }
}
