extern crate alloc;

use alloc::{collections::BTreeSet, vec, vec::Vec};

use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, Anchor, Bundle, ProofStamp, TachygramSetPoly, VerificationError,
    VerifyCoverageError, action, bundle,
    constants::MAX_MONEY,
    fee,
    stamp::{self, ProveError},
    value,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_lift_span, build_output_plan, fee_digests, mock_sighash, mock_wtxid,
    random_block,
};

fn claims(
    bundles: &[&Bundle<ProofStamp>],
) -> (BTreeSet<action::Descriptor>, BTreeSet<fee::Descriptor>) {
    (
        bundles
            .iter()
            .flat_map(|bundle| bundle.descriptors())
            .collect(),
        bundles
            .iter()
            .map(|bundle| bundle.fee_descriptor())
            .collect(),
    )
}

fn side(
    stamp: ProofStamp,
    bundles: &[&Bundle<ProofStamp>],
) -> (
    ProofStamp,
    BTreeSet<action::Descriptor>,
    BTreeSet<fee::Descriptor>,
) {
    let (descriptors, fees) = claims(bundles);
    (stamp, descriptors, fees)
}

fn autonome_paying(
    rng: &mut StdRng,
    wallet: &WalletSim,
    anchor: Anchor,
    (max_fee, fee): (u64, u64),
) -> Bundle<ProofStamp> {
    let (plan, signed, spend_pcds) = wallet.signed(
        rng,
        vec![],
        vec![wallet.random_note(500)],
        wallet.random_note(max_fee),
    );
    signed.stamp(
        plan.stamp_plan(
            anchor,
            value::Positive::try_from(fee).expect("fee in range"),
        )
        .prove(rng, &wallet.pak, spend_pcds)
        .expect("prove with the fee"),
    )
}

fn digests_of(bundle: &Bundle<ProofStamp>) -> Vec<ActionDigest> {
    bundle
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([bundle.fee_descriptor()]))
        .collect()
}

#[test]
fn unmerge_removes_a_divisor_across_merge_boundaries() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let anchor = Anchor::random(rng);
    let [alice, bob, carol] =
        [(); 3].map(|()| wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]));
    let alice_bob = alice
        .stamp
        .clone()
        .merge(rng, claims(&[&alice]), side(bob.stamp.clone(), &[&bob]))
        .expect("merge A and B");
    let mined = bob
        .stamp
        .clone()
        .merge(rng, claims(&[&bob]), side(carol.stamp.clone(), &[&carol]))
        .expect("merge B and C");
    let all_three = alice_bob
        .merge(
            rng,
            claims(&[&alice, &bob]),
            side(carol.stamp.clone(), &[&carol]),
        )
        .expect("merge AB and C");
    let divide = |divide_rng: &mut StdRng, divisor| Bundle {
        stamp: all_three
            .clone()
            .unmerge(divide_rng, claims(&[&alice, &bob, &carol]), divisor)
            .expect("divide out of the three"),
        ..alice.clone()
    };

    let without_bob = divide(rng, side(bob.stamp.clone(), &[&bob]));
    let with_carol = mock_wtxid(&without_bob);
    without_bob
        .verify(
            rng,
            &mock_sighash(without_bob.commitment()),
            &with_carol.into(),
            &[&carol.clone().strip(with_carol)],
        )
        .expect("dividing B out leaves A and its adjunct C");

    let without_mined = divide(rng, side(mined, &[&bob, &carol]));
    let alone = mock_wtxid(&without_mined);
    without_mined
        .verify(
            rng,
            &mock_sighash(without_mined.commitment()),
            &alone.into(),
            &[],
        )
        .expect("dividing the mined BC out leaves A alone");
}

#[test]
fn unmerge_keeps_the_dividend_fee() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let anchor = Anchor::random(rng);
    let alice = autonome_paying(rng, &wallet, anchor, (MAX_MONEY - 1000, MAX_MONEY - 1000));
    let bob = autonome_paying(rng, &wallet, anchor, (0, 0));
    let on_alice = alice
        .stamp
        .clone()
        .merge(rng, claims(&[&alice]), side(bob.stamp.clone(), &[&bob]))
        .expect("merge B into A");

    let divide = |divide_rng: &mut StdRng, divisor: &Bundle<ProofStamp>| {
        on_alice
            .clone()
            .unmerge(
                divide_rng,
                claims(&[&alice, &bob]),
                side(divisor.stamp.clone(), &[divisor]),
            )
            .expect("divide out of the aggregate on A")
    };
    let kept = divide(rng, &bob);
    let hostless = divide(rng, &alice);

    for (label, quotient, other) in [
        ("dividing B out", &kept, &alice),
        ("dividing A out", &hostless, &bob),
    ] {
        assert_eq!(quotient.fee, alice.stamp.fee, "{label}");
        assert_eq!(quotient.anchor, anchor, "{label}");
        assert_eq!(quotient.coverage, other.stamp.coverage, "{label}");
        assert_eq!(&quotient.tachygrams, &other.stamp.tachygrams, "{label}");
        assert_eq!(quotient.tachygram_set, other.stamp.tachygram_set, "{label}");
        assert!(
            quotient
                .verify_proof(rng, digests_of(other))
                .expect("proof system verification"),
            "{label}: the quotient verifies against the other side's actions"
        );
    }

    let on_a = Bundle {
        stamp: kept,
        ..alice.clone()
    };
    let wtxid = mock_wtxid(&on_a);
    on_a.verify(rng, &mock_sighash(on_a.commitment()), &wtxid.into(), &[])
        .unwrap_or_else(|err| panic!("dividing B out does not verify on A: {err:?}"));
}

#[test]
fn unmerge_refuses_a_non_divisor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let anchor = Anchor::random(rng);
    let [alice, bob, carol] =
        [(); 3].map(|()| wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]));
    let alice_bob = alice
        .stamp
        .clone()
        .merge(rng, claims(&[&alice]), side(bob.stamp.clone(), &[&bob]))
        .expect("merge B into A");
    let bob_carol = bob
        .stamp
        .clone()
        .merge(rng, claims(&[&bob]), side(carol.stamp.clone(), &[&carol]))
        .expect("merge C into B");

    for (label, divisor) in [
        ("sharing no actions", side(carol.stamp.clone(), &[&carol])),
        ("sharing some actions", side(bob_carol, &[&bob, &carol])),
    ] {
        let err = alice_bob
            .clone()
            .unmerge(rng, claims(&[&alice, &bob]), divisor)
            .expect_err("a non-divisor must not unmerge");
        let ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner)) = err else {
            panic!("{label}: expected ProofFailed(InvalidWitness), got {err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "StampUnmerge: dividend action set must be the product of divisor and quotient \
             action sets",
            "{label}"
        );
    }
}

#[test]
fn unmerge_of_the_receiver_leaves_its_fee() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (case, alice_fees, bob_fees, carol_fees) in [
        ("equal fees", (MAX_MONEY - 1000, 500), (1000, 500), (0, 0)),
        (
            "unequal fees",
            (MAX_MONEY - 1000, MAX_MONEY - 1000),
            (0, 0),
            (MAX_MONEY - 1000, 1),
        ),
    ] {
        let wallet = WalletSim::random(rng);
        let anchor = Anchor::random(rng);
        let alice = autonome_paying(rng, &wallet, anchor, alice_fees);
        let bob = autonome_paying(rng, &wallet, anchor, bob_fees);
        let mut carol = autonome_paying(rng, &wallet, anchor, carol_fees);
        let hostless = Bundle {
            stamp: alice
                .stamp
                .clone()
                .merge(rng, claims(&[&alice]), side(bob.stamp.clone(), &[&bob]))
                .expect("merge B into A")
                .unmerge(
                    rng,
                    claims(&[&alice, &bob]),
                    side(alice.stamp.clone(), &[&alice]),
                )
                .expect("divide A out"),
            ..bob.clone()
        };

        let hostless_wtxid = mock_wtxid(&hostless);
        let verified = hostless.verify(
            rng,
            &mock_sighash(hostless.commitment()),
            &hostless_wtxid.into(),
            &[],
        );
        if alice.stamp.fee == bob.stamp.fee {
            verified.unwrap_or_else(|err| {
                panic!("{case}: dividing A out does not verify on B: {err:?}")
            });
        } else {
            let Err(VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch)) =
                verified
            else {
                panic!("{case}: expected Coverage(StampActionsMismatch), got {verified:?}");
            };
        }

        let carol_fee = carol.stamp.fee;
        carol.stamp = carol
            .stamp
            .clone()
            .merge(rng, claims(&[&carol]), side(hostless.stamp, &[&bob]))
            .expect("merge the quotient into C");
        assert_eq!(carol.stamp.fee, carol_fee, "{case}");
        let carol_wtxid = mock_wtxid(&carol);
        carol
            .verify(
                rng,
                &mock_sighash(carol.commitment()),
                &carol_wtxid.into(),
                &[&bob.strip(carol_wtxid)],
            )
            .unwrap_or_else(|err| {
                panic!("{case}: the quotient merged into C does not verify: {err:?}")
            });
    }
}

#[test]
fn unmerge_by_a_lifted_divisor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    for _ in 0..3 {
        pool.mine(random_block(rng, 1, 4));
    }
    let bob = wallet.autonome(rng, pool.anchor(), vec![], vec![wallet.random_note(300)]);
    let stamped_at = pool.height();

    for _ in 0..2 {
        pool.mine(random_block(rng, 1, 4));
    }
    let mut alice = wallet.autonome(rng, pool.anchor(), vec![], vec![wallet.random_note(300)]);

    let span = build_lift_span(rng, &pool, stamped_at.next().unwrap()..=pool.height());
    let (bob_descriptors, bob_fees) = claims(&[&bob]);
    let lifted_bob = bob
        .stamp
        .clone()
        .lift(rng, &bob_descriptors, &bob_fees, vec![span])
        .expect("lift B onto A's anchor");
    let alice_bob = alice
        .stamp
        .clone()
        .merge(rng, claims(&[&alice]), side(lifted_bob.clone(), &[&bob]))
        .expect("merge A and the lifted B");

    let err = alice_bob
        .clone()
        .unmerge(
            rng,
            claims(&[&alice, &bob]),
            side(bob.stamp.clone(), &[&bob]),
        )
        .expect_err("an unlifted divisor must not unmerge");
    let ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner)) = err else {
        panic!("expected ProofFailed(InvalidWitness), got {err:?}");
    };
    assert_eq!(inner.to_string(), "StampUnmerge: anchors must match");

    alice.stamp = alice_bob
        .unmerge(rng, claims(&[&alice, &bob]), side(lifted_bob, &[&bob]))
        .expect("divide the lifted B out");
    let wtxid = mock_wtxid(&alice);
    alice
        .verify(rng, &mock_sighash(alice.commitment()), &wtxid.into(), &[])
        .expect("the quotient covers A alone");
}

#[test]
fn unmerge_by_itself_leaves_no_leaves() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let anchor = Anchor::random(rng);
    let mut alice = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);

    let quotient = alice
        .stamp
        .clone()
        .unmerge(rng, claims(&[&alice]), side(alice.stamp.clone(), &[&alice]))
        .expect("divide A by itself");
    assert!(
        quotient.tachygrams.is_empty(),
        "the quotient publishes no tachygrams"
    );
    assert_eq!(
        quotient.tachygram_set,
        TachygramSetPoly::from_iter([]).commit(),
        "the quotient commits to the empty tachygram set"
    );
    assert!(
        quotient
            .verify_proof(rng, [])
            .expect("proof system verification"),
        "the quotient commits to the empty action set"
    );

    alice.stamp = quotient;
    let wtxid = mock_wtxid(&alice);
    let err = alice
        .verify(rng, &mock_sighash(alice.commitment()), &wtxid.into(), &[])
        .expect_err("an empty stamp covers no bundle");
    let VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch) = err else {
        panic!("expected Coverage(StampActionsMismatch), got {err:?}");
    };
}

/// The divisor carries the bundle's fee, so the quotient holds the kept action.
#[test]
fn unmerge_splitting_a_bundle() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
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
            &mock_sighash(plan.commitment().expect("bundle commitment")),
            &wallet.sk.derive_auth_private(),
        )
        .expect("sign")
        .stamp(
            plan.stamp_plan(anchor, value::Positive::ZERO)
                .prove(rng, &wallet.pak, vec![])
                .expect("prove the whole bundle"),
        );

    let part = stamp::Plan::new(
        vec![],
        vec![(removed_descriptor, removed_theta, removed_note, removed_rcv)],
        anchor,
        max_fee_note,
        value::Positive::ZERO,
    )
    .prove(rng, &wallet.pak, vec![])
    .expect("prove the removed action with the bundle's fee");

    let quotient = whole
        .stamp
        .clone()
        .unmerge(
            rng,
            claims(&[&whole]),
            (
                part,
                [removed_descriptor].into(),
                [whole.fee_descriptor()].into(),
            ),
        )
        .expect("divide the removed action out");
    assert!(
        quotient
            .verify_proof(rng, [kept_descriptor.digest().expect("action digest")])
            .expect("proof system verification"),
        "the quotient verifies against the kept action's digest"
    );

    whole.stamp = quotient;
    let wtxid = mock_wtxid(&whole);
    let err = whole
        .verify(rng, &mock_sighash(whole.commitment()), &wtxid.into(), &[])
        .expect_err("a split bundle must not verify");
    let VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch) = err else {
        panic!("expected Coverage(StampActionsMismatch), got {err:?}");
    };
}
