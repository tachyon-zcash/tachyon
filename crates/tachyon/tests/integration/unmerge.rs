extern crate alloc;

use alloc::{collections::BTreeSet, vec};
use core::assert_matches;

use rand::{SeedableRng as _, rngs::StdRng};
use udon::curve::Projective as _;
use zcash_tachyon::{
    ActionSetPoly, Anchor, BlockHeight, TachygramSetPoly, VerificationError, VerifyCoverageError,
    bundle,
    stamp::{
        self, ProofStamp, ProveError,
        proof::stamp::{Stamp, StampUnmerge},
    },
    value, witness,
};

use super::fixtures::application;
use crate::fixtures::{
    mock_sighash, mock_txid,
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
    let (bob_txid, carol_txid) = (mock_txid(&bob), mock_txid(&carol));
    let all_three = merged(app, &alice, &bob)
        .stamp
        .merge(
            rng,
            app,
            vec![alice.covered(), bob.covered()],
            (carol.stamp.clone(), carol_txid, vec![carol.covered()]),
        )
        .unwrap();
    assert_eq!(all_three.adjuncts, BTreeSet::from([bob_txid, carol_txid]));

    let decoded_aggregate = {
        let mut bytes = Vec::new();
        all_three.write(&mut bytes).unwrap();
        ProofStamp::<stamp::Uncompressed>::read(&*bytes, (all_three.tachygrams.len() - 1) / 2)
            .unwrap()
    };
    assert_eq!(decoded_aggregate.adjuncts, all_three.adjuncts);
    for (divisor, divisor_covered, adjuncts) in [
        (bob.stamp.clone(), vec![bob.covered()], vec![carol.clone()]),
        (
            bob.stamp
                .clone()
                .merge(
                    rng,
                    app,
                    vec![bob.covered()],
                    (carol.stamp.clone(), carol_txid, vec![carol.covered()]),
                )
                .unwrap(),
            vec![bob.covered(), carol.covered()],
            vec![],
        ),
    ] {
        let mut unmerged = alice.clone();
        unmerged.stamp = decoded_aggregate
            .clone()
            .unmerge(
                rng,
                app,
                vec![alice.covered(), bob.covered(), carol.covered()],
                (divisor, bob_txid, divisor_covered),
            )
            .unwrap();
        let stripped: Vec<_> = adjuncts.into_iter().map(bundle::Bundle::strip).collect();
        assert_eq!(
            unmerged.stamp.adjuncts,
            stripped.iter().map(mock_txid).collect()
        );
        unmerged
            .verify(
                rng,
                app,
                &mock_sighash(unmerged.commitment()),
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
    let (alice_txid, bob_txid) = (mock_txid(&alice), mock_txid(&bob));

    let on_alice = alice
        .stamp
        .clone()
        .merge(
            rng,
            app,
            vec![alice.covered()],
            (bob.stamp.clone(), bob_txid, vec![bob.covered()]),
        )
        .unwrap();
    assert_eq!(on_alice.adjuncts, BTreeSet::from([bob_txid]));

    let mut kept = alice.clone();
    kept.stamp = on_alice
        .clone()
        .unmerge(
            rng,
            app,
            vec![alice.covered(), bob.covered()],
            (bob.stamp.clone(), bob_txid, vec![bob.covered()]),
        )
        .unwrap();
    assert!(kept.is_autonome());
    kept.verify(rng, app, &mock_sighash(kept.commitment()), &[])
        .unwrap();

    let mut hostless = bob.clone();
    hostless.stamp = on_alice
        .clone()
        .unmerge(
            rng,
            app,
            vec![alice.covered(), bob.covered()],
            (alice.stamp.clone(), alice_txid, vec![alice.covered()]),
        )
        .unwrap();
    assert_eq!(hostless.stamp.fee, alice_fee);
    assert_eq!(hostless.stamp.adjuncts, BTreeSet::from([bob_txid]));
    assert_matches!(
        hostless.verify(rng, app, &mock_sighash(hostless.commitment()), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::WrongTachygramSet
        ))
    );

    let carol_fee = carol.stamp.fee;
    let rehosted = carol
        .stamp
        .clone()
        .merge(
            rng,
            app,
            vec![carol.covered()],
            (on_alice, alice_txid, vec![alice.covered(), bob.covered()]),
        )
        .unwrap();
    assert_eq!(rehosted.adjuncts, BTreeSet::from([alice_txid, bob_txid]));
    carol.stamp = rehosted
        .unmerge(
            rng,
            app,
            vec![carol.covered(), alice.covered(), bob.covered()],
            (alice.stamp.clone(), alice_txid, vec![alice.covered()]),
        )
        .unwrap();
    assert_eq!(carol.stamp.fee, carol_fee);
    assert_eq!(carol.stamp.adjuncts, BTreeSet::from([bob_txid]));
    let stripped_bob = bob.strip();
    carol
        .verify(
            rng,
            app,
            &mock_sighash(carol.commitment()),
            &[&stripped_bob],
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
    let earlier_txid = mock_txid(&earlier);
    let dividend = merged(app, &later, &lifted_bundle).stamp;

    assert_matches!(
        dividend.clone().unmerge(
            rng,
            app,
            vec![later.covered(), earlier.covered()],
            (earlier.stamp.clone(), earlier_txid, vec![earlier.covered()]),
        ),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err)))
            if err.to_string() == "StampUnmerge: anchors must match"
    );

    later.stamp = dividend
        .unmerge(
            rng,
            app,
            vec![later.covered(), earlier.covered()],
            (lifted_divisor, earlier_txid, vec![earlier.covered()]),
        )
        .unwrap();
    later
        .verify(rng, app, &mock_sighash(later.commitment()), &[])
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
            vec![alice.covered()],
            (
                alice.stamp.clone(),
                mock_txid(&alice),
                vec![alice.covered()],
            ),
        )
        .unwrap();
    assert!(quotient.verify_proof(rng, app, []).unwrap());
    assert!(quotient.adjuncts.is_empty());

    alice.stamp = quotient;
    assert_matches!(
        alice.verify(rng, app, &mock_sighash(alice.commitment()), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::WrongTachygramSet
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
    let kept_descriptor = kept_plan.descriptor();

    let max_fee_note = alice_max_fee_note();
    let plan = bundle::Plan::new(vec![], vec![kept_plan, removed_plan], max_fee_note);
    let stamp = plan
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(rng, app, &wallet.pak, vec![])
        .unwrap();
    let mut whole = plan
        .sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap()
        .stamp(stamp);
    let kept_index = whole
        .descriptors()
        .position(|descriptor| descriptor == kept_descriptor)
        .unwrap();
    let kept_digest = whole.verify_covered(&[]).unwrap().0[kept_index];

    let (_, part_pairs) = alice.stamp.tachygrams.split_last().unwrap();
    let part_covered = vec![(
        alice.descriptors().collect(),
        whole.fee_descriptor(),
        part_pairs
            .iter()
            .copied()
            .chain(whole.stamp.tachygrams.last().copied())
            .collect(),
    )];
    let part_txid = mock_txid(&alice);
    let part = alice.stamp;

    let quotient = whole
        .stamp
        .clone()
        .unmerge(
            rng,
            app,
            vec![whole.covered()],
            (part, part_txid, part_covered),
        )
        .unwrap();
    assert!(quotient.verify_proof(rng, app, [kept_digest]).unwrap());
    assert!(quotient.adjuncts.is_empty());

    whole.stamp = quotient;
    assert_matches!(
        whole.verify(rng, app, &mock_sighash(whole.commitment()), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::WrongTachygramSet
        ))
    );
}

#[test]
fn unmerge_rejects_a_reproven_note_as_divisor() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let note = wallet.random_note(300);
    let max_fee_note = wallet.random_note(100);
    let fee = value::Positive::try_from(40u64).unwrap();
    let [original, reproven] = [(), ()].map(|()| {
        let output = output_plan(rng, note).2;
        let plan = bundle::Plan::new(vec![], vec![output], max_fee_note);
        let signed = plan
            .sign(
                rng,
                &mock_sighash(plan.commitment().unwrap()),
                &wallet.sk.derive_auth_private(),
            )
            .unwrap();
        let stamp = plan
            .stamp_plan(anchor, fee)
            .prove(rng, app, &wallet.pak, vec![])
            .unwrap();
        signed.stamp(stamp)
    });
    let (_, other) = wallet.bundle(
        app,
        anchor,
        &[],
        &[wallet.random_note(200)],
        wallet.random_note(0),
        value::Positive::ZERO,
    );
    let dividend = original
        .stamp
        .clone()
        .merge(
            rng,
            app,
            vec![original.covered()],
            (
                other.stamp.clone(),
                mock_txid(&other),
                vec![other.covered()],
            ),
        )
        .unwrap();
    let divisor_txid = mock_txid(&reproven);
    let divisor_covered = vec![reproven.covered()];
    assert_matches!(
        dividend.unmerge(
            rng,
            app,
            vec![original.covered(), other.covered()],
            (reproven.stamp, divisor_txid, divisor_covered),
        ),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(_)))
    );
}

#[test]
fn unmerge_binds_its_sets() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(app);
    let (_, bob) = bob(app);
    let alice_bob = merged(app, &alice, &bob).stamp;

    let alice_members = alice.stamp.tachygrams.iter().copied();
    let bob_members = bob.stamp.tachygrams.iter().copied();
    let alice_bob_tachygrams: TachygramSetPoly =
        alice_members.clone().chain(bob_members.clone()).collect();
    let alice_actions: ActionSetPoly = alice.verify_covered(&[]).unwrap().0.into_iter().collect();
    let alice_tachygrams: TachygramSetPoly = alice_members.clone().collect();
    let bob_actions: ActionSetPoly = bob.verify_covered(&[]).unwrap().0.into_iter().collect();
    let bob_tachygrams: TachygramSetPoly = bob_members.clone().collect();
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
                let dropped = alice_members.clone().next().unwrap();
                corrupt.1 = alice_members
                    .filter(|&tachygram| tachygram != dropped)
                    .chain(bob_members.take(1))
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
