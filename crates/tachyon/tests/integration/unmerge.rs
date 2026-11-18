extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
};
use core::assert_matches;

use rand::{SeedableRng as _, rngs::StdRng};
use udon::curve::Projective as _;
use zcash_tachyon::{
    ActionSetPoly, Anchor, BlockHeight, Tachygram, TachygramSetPoly, VerificationError,
    VerifyCoverageError, bundle,
    stamp::{
        self, ProofStamp,
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
    let [alice_pairs, bob_pairs, carol_pairs]: [BTreeMap<_, _>; 3] =
        [&alice, &bob, &carol].map(|bundle| {
            bundle
                .actions
                .iter()
                .zip(&bundle.action_auth)
                .map(|(&desc, &(_, pair))| (desc, pair))
                .collect()
        });
    let [alice_fees, bob_fees, carol_fees] =
        [&alice, &bob, &carol].map(|bundle| BTreeMap::from([(bundle.fee, bundle.fee_auth)]));
    let pair_union = alice_pairs
        .iter()
        .chain(&bob_pairs)
        .map(|(&desc, &pair)| (desc, pair))
        .collect();
    let fee_union = alice_fees
        .iter()
        .chain(&bob_fees)
        .map(|(&desc, &change)| (desc, change))
        .collect();
    let all_pairs = alice_pairs
        .iter()
        .chain(&bob_pairs)
        .chain(&carol_pairs)
        .map(|(&desc, &pair)| (desc, pair))
        .collect();
    let all_fees = alice_fees
        .iter()
        .chain(&bob_fees)
        .chain(&carol_fees)
        .map(|(&desc, &change)| (desc, change))
        .collect();
    let divisor_pairs = bob_pairs
        .iter()
        .chain(&carol_pairs)
        .map(|(&desc, &pair)| (desc, pair))
        .collect();
    let divisor_fees = bob_fees
        .iter()
        .chain(&carol_fees)
        .map(|(&desc, &change)| (desc, change))
        .collect();
    let (bob_txid, carol_txid) = (mock_txid(&bob), mock_txid(&carol));
    let all_three = merged(app, &alice, &bob)
        .stamp
        .merge(
            rng,
            app,
            (&pair_union, &fee_union),
            (carol.stamp.clone(), carol_txid, &carol_pairs, &carol_fees),
        )
        .unwrap();
    assert_eq!(all_three.adjuncts, BTreeSet::from([bob_txid, carol_txid]));

    let decoded_aggregate = {
        let mut bytes = Vec::new();
        all_three.write(&mut bytes).unwrap();
        ProofStamp::<stamp::Uncompressed>::read(&*bytes).unwrap()
    };
    assert_eq!(decoded_aggregate.adjuncts, all_three.adjuncts);
    for (divisor, divisor_covered, adjuncts) in [
        (
            bob.stamp.clone(),
            (&bob_pairs, &bob_fees),
            vec![carol.clone()],
        ),
        (
            bob.stamp
                .merge(
                    rng,
                    app,
                    (&bob_pairs, &bob_fees),
                    (carol.stamp, carol_txid, &carol_pairs, &carol_fees),
                )
                .unwrap(),
            (&divisor_pairs, &divisor_fees),
            vec![],
        ),
    ] {
        let mut unmerged = alice.clone();
        unmerged.stamp = decoded_aggregate
            .clone()
            .unmerge(
                rng,
                app,
                (&all_pairs, &all_fees),
                (divisor, bob_txid, divisor_covered.0, divisor_covered.1),
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
fn unmerge_hostless_quotient_fails_coverage_on_its_host() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let [(_, alice), (_, bob), (_, mut carol)] = outputs_with_fees(app);
    let [alice_pairs, bob_pairs, carol_pairs]: [BTreeMap<_, _>; 3] =
        [&alice, &bob, &carol].map(|bundle| {
            bundle
                .actions
                .iter()
                .zip(&bundle.action_auth)
                .map(|(&desc, &(_, pair))| (desc, pair))
                .collect()
        });
    let [alice_fees, bob_fees, carol_fees] =
        [&alice, &bob, &carol].map(|bundle| BTreeMap::from([(bundle.fee, bundle.fee_auth)]));
    let pair_union = alice_pairs
        .iter()
        .chain(&bob_pairs)
        .map(|(&desc, &pair)| (desc, pair))
        .collect();
    let fee_union = alice_fees
        .iter()
        .chain(&bob_fees)
        .map(|(&desc, &change)| (desc, change))
        .collect();
    let all_pairs = alice_pairs
        .iter()
        .chain(&bob_pairs)
        .chain(&carol_pairs)
        .map(|(&desc, &pair)| (desc, pair))
        .collect();
    let all_fees = alice_fees
        .iter()
        .chain(&bob_fees)
        .chain(&carol_fees)
        .map(|(&desc, &change)| (desc, change))
        .collect();
    let (alice_txid, bob_txid) = (mock_txid(&alice), mock_txid(&bob));

    let on_alice = alice
        .stamp
        .clone()
        .merge(
            rng,
            app,
            (&alice_pairs, &alice_fees),
            (bob.stamp.clone(), bob_txid, &bob_pairs, &bob_fees),
        )
        .unwrap();
    assert_eq!(on_alice.adjuncts, BTreeSet::from([bob_txid]));

    let mut kept = alice.clone();
    kept.stamp = on_alice
        .clone()
        .unmerge(
            rng,
            app,
            (&pair_union, &fee_union),
            (bob.stamp.clone(), bob_txid, &bob_pairs, &bob_fees),
        )
        .unwrap();
    assert!(kept.is_autonome());
    kept.verify(rng, app, &mock_sighash(kept.commitment()), &[])
        .unwrap();

    let mut hostless = alice.clone();
    hostless.stamp = on_alice
        .clone()
        .unmerge(
            rng,
            app,
            (&pair_union, &fee_union),
            (alice.stamp.clone(), alice_txid, &alice_pairs, &alice_fees),
        )
        .unwrap();
    assert_eq!(hostless.stamp.adjuncts, BTreeSet::from([bob_txid]));
    assert_matches!(
        hostless.verify(rng, app, &mock_sighash(hostless.commitment()), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::WrongTachygramSet
        ))
    );

    let carol_fee = carol.fee.v_fee;
    let rehosted = carol
        .stamp
        .clone()
        .merge(
            rng,
            app,
            (&carol_pairs, &carol_fees),
            (on_alice, alice_txid, &pair_union, &fee_union),
        )
        .unwrap();
    assert_eq!(rehosted.adjuncts, BTreeSet::from([alice_txid, bob_txid]));
    carol.stamp = rehosted
        .unmerge(
            rng,
            app,
            (&all_pairs, &all_fees),
            (alice.stamp, alice_txid, &alice_pairs, &alice_fees),
        )
        .unwrap();
    assert_eq!(carol.fee.v_fee, carol_fee);
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
    let [early_desc, late_desc]: [BTreeMap<_, _>; 2] = [&earlier, &later].map(|bundle| {
        bundle
            .actions
            .iter()
            .zip(&bundle.action_auth)
            .map(|(&desc, &(_, pair))| (desc, pair))
            .collect()
    });
    let early_fees = BTreeMap::from([(earlier.fee, earlier.fee_auth)]);
    let all_desc = late_desc
        .iter()
        .chain(&early_desc)
        .map(|(&desc, &pair)| (desc, pair))
        .collect();
    let all_fees = BTreeMap::from([(later.fee, later.fee_auth), (earlier.fee, earlier.fee_auth)]);

    let unaligned = dividend
        .clone()
        .unmerge(
            rng,
            app,
            (&all_desc, &all_fees),
            (earlier.stamp, earlier_txid, &early_desc, &early_fees),
        )
        .unwrap();
    assert!(
        !unaligned
            .verify_proof(rng, app, later.verify_covered(&[]).unwrap().0)
            .unwrap()
    );

    later.stamp = dividend
        .unmerge(
            rng,
            app,
            (&all_desc, &all_fees),
            (lifted_divisor, earlier_txid, &early_desc, &early_fees),
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
    let desc = alice
        .actions
        .iter()
        .zip(&alice.action_auth)
        .map(|(&desc, &(_, pair))| (desc, pair))
        .collect();
    let fees = BTreeMap::from([(alice.fee, alice.fee_auth)]);

    let quotient = alice
        .stamp
        .clone()
        .unmerge(
            rng,
            app,
            (&desc, &fees),
            (alice.stamp.clone(), mock_txid(&alice), &desc, &fees),
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
    let kept_plan = output_plan(rng, wallet.random_note(300));
    let removed_plan = alice_plan
        .iter_actions(|_| None, |plan| Some(*plan))
        .flatten()
        .next()
        .unwrap();
    let kept_descriptor = kept_plan.descriptor();

    let max_fee_note = alice_max_fee_note();
    let plan = bundle::Plan::new(vec![], vec![kept_plan, removed_plan], max_fee_note);
    let proof = plan
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(rng, app, &wallet.pak, vec![])
        .unwrap();
    let signatures = plan
        .sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap();
    let mut whole = plan.assemble(signatures, proof);
    let kept_index = whole
        .actions
        .iter()
        .position(|&descriptor| descriptor == kept_descriptor)
        .unwrap();
    let kept_digest = whole.verify_covered(&[]).unwrap().0[kept_index];

    let part_desc = alice
        .actions
        .iter()
        .zip(&alice.action_auth)
        .map(|(&desc, &(_, pair))| (desc, pair))
        .collect();
    let part_fees = BTreeMap::from([(whole.fee, whole.fee_auth)]);
    let whole_desc = whole
        .actions
        .iter()
        .zip(&whole.action_auth)
        .map(|(&desc, &(_, pair))| (desc, pair))
        .collect();
    let whole_fees = BTreeMap::from([(whole.fee, whole.fee_auth)]);
    let part_txid = mock_txid(&alice);
    let part = alice.stamp;

    let quotient = whole
        .stamp
        .clone()
        .unmerge(
            rng,
            app,
            (&whole_desc, &whole_fees),
            (part, part_txid, &part_desc, &part_fees),
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
        let output = output_plan(rng, note);
        let plan = bundle::Plan::new(vec![], vec![output], max_fee_note);
        let signatures = plan
            .sign(
                rng,
                &mock_sighash(plan.commitment().unwrap()),
                &wallet.sk.derive_auth_private(),
            )
            .unwrap();
        let proof = plan
            .stamp_plan(anchor, fee)
            .prove(rng, app, &wallet.pak, vec![])
            .unwrap();
        plan.assemble(signatures, proof)
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
            (
                &original
                    .actions
                    .iter()
                    .zip(&original.action_auth)
                    .map(|(&desc, &(_, pair))| (desc, pair))
                    .collect(),
                &BTreeMap::from([(original.fee, original.fee_auth)]),
            ),
            (
                other.stamp.clone(),
                mock_txid(&other),
                &other
                    .actions
                    .iter()
                    .zip(&other.action_auth)
                    .map(|(&desc, &(_, pair))| (desc, pair))
                    .collect(),
                &BTreeMap::from([(other.fee, other.fee_auth)]),
            ),
        )
        .unwrap();
    let divisor_txid = mock_txid(&reproven);
    let divisor_desc = reproven
        .actions
        .iter()
        .zip(&reproven.action_auth)
        .map(|(&desc, &(_, pair))| (desc, pair))
        .collect();
    let divisor_fees = BTreeMap::from([(reproven.fee, reproven.fee_auth)]);
    let (original_digests, _) = original.verify_covered(&[]).unwrap();
    let (_, original_action_digests) = original_digests.split_last().unwrap();
    let (other_digests, _) = other.verify_covered(&[]).unwrap();
    let quotient = dividend
        .unmerge(
            rng,
            app,
            (
                &[&original, &other]
                    .into_iter()
                    .flat_map(|bundle| {
                        bundle
                            .actions
                            .iter()
                            .zip(&bundle.action_auth)
                            .map(|(&desc, &(_, pair))| (desc, pair))
                    })
                    .collect(),
                &BTreeMap::from([
                    (original.fee, original.fee_auth),
                    (other.fee, other.fee_auth),
                ]),
            ),
            (reproven.stamp, divisor_txid, &divisor_desc, &divisor_fees),
        )
        .unwrap();
    assert!(
        !quotient
            .verify_proof(
                rng,
                app,
                original_action_digests.iter().copied().chain(other_digests),
            )
            .unwrap()
    );
}

#[test]
fn unmerge_binds_its_sets() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(app);
    let (_, bob) = bob(app);
    let alice_bob = merged(app, &alice, &bob).stamp;

    let alice_members = alice
        .action_auth
        .iter()
        .flat_map(|&(_, pair)| <[Tachygram; 2]>::from(pair))
        .chain([alice.fee_auth]);
    let bob_members = bob
        .action_auth
        .iter()
        .flat_map(|&(_, pair)| <[Tachygram; 2]>::from(pair))
        .chain([bob.fee_auth]);
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
            "a substituted quotient action set",
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
            "a quotient tachygram set with a swapped member",
        ),
    ] {
        let (forged, ()) = app
            .fuse(
                rng,
                StampUnmerge,
                corrupt,
                alice_bob.proof.clone().carry::<Stamp>(dividend_header),
                bob.stamp.proof.clone().carry::<Stamp>(divisor_header),
            )
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
            "{expected}"
        );
    }
}
