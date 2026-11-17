extern crate alloc;

use alloc::vec;
use core::{assert_matches, iter};

use rand::{SeedableRng as _, rngs::StdRng};
use udon::curve::Projective as _;
use zcash_tachyon::{
    ActionSetPoly, BlockHeight, TachygramSetPoly, VerificationError, VerifyCoverageError, bundle,
    stamp::{
        self, ProofStamp, ProveError,
        proof::stamp::{Stamp, StampUnmerge},
    },
    value, witness,
};

use super::fixtures::application;
use crate::fixtures::{
    mock_sighash, mock_wtxid,
    pool::PoolSim,
    wallet::{
        WalletSim, alice, alice_max_fee_note, bob, later_output, lifted, merged, output_plan,
        outputs_with_fees, shared_sk,
    },
};

#[test]
fn unmerge_removes_a_divisor_across_merge_boundaries() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(app);
    let (_, bob) = bob(app);
    let [(_, carol), _, _] = outputs_with_fees(app);
    let all_three = merged(app, &alice, &bob)
        .stamp
        .merge(
            rng,
            app,
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
                    app,
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
                app,
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
                app,
                &mock_sighash(unmerged.commitment()),
                &wtxid.into(),
                &stripped.iter().collect::<Vec<_>>(),
            )
            .unwrap();
    }
}

#[test]
fn unmerge_keeps_the_dividend_fee() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let [(_, alice), (_, bob), (_, mut carol)] = outputs_with_fees(app);
    let alice_fee = alice.stamp.fee;

    let on_alice = alice
        .stamp
        .clone()
        .merge(
            rng,
            app,
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
            app,
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
        app,
        &mock_sighash(kept.commitment()),
        &kept_wtxid.into(),
        &[],
    )
    .unwrap();

    let mut hostless = bob.clone();
    hostless.stamp = on_alice
        .unmerge(
            rng,
            app,
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
            app,
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
            app,
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
            app,
            &mock_sighash(carol.commitment()),
            &carol_wtxid.into(),
            &[&bob.strip(carol_wtxid)],
        )
        .unwrap();
}

#[test]
fn unmerge_by_a_lifted_divisor() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let (_, earlier) = alice(app);
    let (_, mut later) = later_output(app);
    let lifted_bundle = lifted(app, &earlier, pool, BlockHeight(1)..=BlockHeight(2));
    let lifted_divisor = lifted_bundle.stamp.clone();
    let dividend = merged(app, &later, &lifted_bundle).stamp;

    assert_matches!(
        dividend.clone().unmerge(
            rng,
            app,
            (
                later.descriptors().chain(earlier.descriptors()).collect(),
                [later.fee_descriptor(), earlier.fee_descriptor()].into(),
            ),
            (
                earlier.stamp.clone(),
                earlier.descriptors().collect(),
                [earlier.fee_descriptor()].into(),
            ),
        ),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err)))
            if err.to_string() == "StampUnmerge: anchors must match"
    );

    later.stamp = dividend
        .unmerge(
            rng,
            app,
            (
                later.descriptors().chain(earlier.descriptors()).collect(),
                [later.fee_descriptor(), earlier.fee_descriptor()].into(),
            ),
            (
                lifted_divisor,
                earlier.descriptors().collect(),
                [earlier.fee_descriptor()].into(),
            ),
        )
        .unwrap();
    let wtxid = mock_wtxid(&later);
    later
        .verify(
            rng,
            app,
            &mock_sighash(later.commitment()),
            &wtxid.into(),
            &[],
        )
        .unwrap();
}

#[test]
fn unmerge_by_itself_leaves_no_leaves() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, mut alice) = alice(app);

    let quotient = alice
        .stamp
        .clone()
        .unmerge(
            rng,
            app,
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
    assert!(quotient.verify_proof(rng, app, []).unwrap());

    alice.stamp = quotient;
    let wtxid = mock_wtxid(&alice);
    assert_matches!(
        alice.verify(
            rng,
            app,
            &mock_sighash(alice.commitment()),
            &wtxid.into(),
            &[]
        ),
        Err(VerificationError::Coverage(
            VerifyCoverageError::StampActionsMismatch
        ))
    );
}

#[test]
fn unmerge_splitting_a_bundle() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::shared().mint_anchor();
    let (alice_plan, alice) = alice(app);
    let (_, _, kept_plan) = output_plan(rng, wallet.random_note(300));
    let removed_plan = alice_plan
        .iter_actions(|_| None, |plan| Some(*plan))
        .flatten()
        .next()
        .unwrap();
    let removed_descriptor = removed_plan.descriptor();
    let kept_descriptor = kept_plan.descriptor();

    let max_fee_note = alice_max_fee_note();
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
                .prove(rng, app, &wallet.pak, vec![])
                .unwrap(),
        );

    let part = alice.stamp;

    let quotient = whole
        .stamp
        .clone()
        .unmerge(
            rng,
            app,
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
            .verify_proof(rng, app, [kept_descriptor.digest().unwrap()])
            .unwrap()
    );

    whole.stamp = quotient;
    let wtxid = mock_wtxid(&whole);
    assert_matches!(
        whole.verify(
            rng,
            app,
            &mock_sighash(whole.commitment()),
            &wtxid.into(),
            &[]
        ),
        Err(VerificationError::Coverage(
            VerifyCoverageError::StampActionsMismatch
        ))
    );
}

#[test]
fn unmerge_binds_its_sets() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(app);
    let (_, bob) = bob(app);
    let alice_bob = merged(app, &alice, &bob).stamp;

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
    let dividend_header = (
        app.bridge_hash(alice_bob_tachygrams.commit().as_ref().to_affine())
            .unwrap()
            .into(),
        alice_bob.anchor,
    );
    let divisor_header = (
        app.bridge_hash(bob_tachygrams.commit().as_ref().to_affine())
            .unwrap()
            .into(),
        bob.stamp.anchor,
    );
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
            app
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
