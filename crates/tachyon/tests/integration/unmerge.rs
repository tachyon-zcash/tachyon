extern crate alloc;

use alloc::{collections::BTreeSet, vec, vec::Vec};

use ff::Field as _;
use pasta_curves::Fp;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, ActionSetPoly, Anchor, TachygramSetPoly, VerificationError, VerifyCoverageError,
    bundle,
    stamp::{
        self,
        proof::{
            PROOF_SYSTEM,
            stamp::{Stamp, StampUnmerge},
        },
    },
    value,
};

use crate::{
    fixtures::{
        PoolSim, WalletSim, build_lift_span, build_output_plan, fee_digests, mock_sighash,
        mock_wtxid, random_block, shared_sk,
    },
    qr::invalid_witness,
};

/// Removing one contributor from an aggregate leaves a stamp that covers the
/// others.
#[test]
fn unmerge_removes_one_contributor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::random(&mut *rng));
    let [mut alice, bob, carol] =
        [(); 3].map(|()| wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]));

    let alice_bob = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                BTreeSet::from([alice.fee_descriptor()]),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                BTreeSet::from([bob.fee_descriptor()]),
            ),
        )
        .expect("merge A and B");
    let all_three = alice_bob
        .merge(
            rng,
            (
                alice.descriptors().chain(bob.descriptors()).collect(),
                BTreeSet::from([alice.fee_descriptor(), bob.fee_descriptor()]),
            ),
            (
                carol.stamp.clone(),
                carol.descriptors().collect(),
                BTreeSet::from([carol.fee_descriptor()]),
            ),
        )
        .expect("merge AB and C");

    let quotient = all_three
        .unmerge(
            rng,
            (
                alice
                    .descriptors()
                    .chain(bob.descriptors())
                    .chain(carol.descriptors())
                    .collect(),
                BTreeSet::from([
                    alice.fee_descriptor(),
                    bob.fee_descriptor(),
                    carol.fee_descriptor(),
                ]),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                BTreeSet::from([bob.fee_descriptor()]),
            ),
        )
        .expect("divide B out");
    let remaining: Vec<ActionDigest> = alice
        .descriptors()
        .chain(carol.descriptors())
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([
            alice.fee_descriptor(),
            carol.fee_descriptor(),
        ]))
        .collect();
    assert!(
        quotient
            .verify_proof(rng, remaining)
            .expect("proof system verification"),
        "the quotient verifies against the remaining digests"
    );

    alice.stamp = quotient;
    let wtxid = mock_wtxid(&alice);
    alice
        .verify(
            rng,
            &mock_sighash(alice.commitment()),
            &wtxid.into(),
            &[&carol.strip(wtxid)],
        )
        .expect("the quotient covers A and its adjunct C");
}

/// Dividing by a merged stamp removes all of its contributors.
#[test]
fn unmerge_removes_a_product() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::random(&mut *rng));
    let [mut alice, bob, carol] =
        [(); 3].map(|()| wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]));

    let bob_carol = bob
        .stamp
        .clone()
        .merge(
            rng,
            (
                bob.descriptors().collect(),
                BTreeSet::from([bob.fee_descriptor()]),
            ),
            (
                carol.stamp.clone(),
                carol.descriptors().collect(),
                BTreeSet::from([carol.fee_descriptor()]),
            ),
        )
        .expect("merge B and C");
    let all_three = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                BTreeSet::from([alice.fee_descriptor()]),
            ),
            (
                bob_carol.clone(),
                bob.descriptors().chain(carol.descriptors()).collect(),
                BTreeSet::from([bob.fee_descriptor(), carol.fee_descriptor()]),
            ),
        )
        .expect("merge A and BC");

    alice.stamp = all_three
        .unmerge(
            rng,
            (
                alice
                    .descriptors()
                    .chain(bob.descriptors())
                    .chain(carol.descriptors())
                    .collect(),
                BTreeSet::from([
                    alice.fee_descriptor(),
                    bob.fee_descriptor(),
                    carol.fee_descriptor(),
                ]),
            ),
            (
                bob_carol,
                bob.descriptors().chain(carol.descriptors()).collect(),
                BTreeSet::from([bob.fee_descriptor(), carol.fee_descriptor()]),
            ),
        )
        .expect("divide BC out");
    let wtxid = mock_wtxid(&alice);
    alice
        .verify(rng, &mock_sighash(alice.commitment()), &wtxid.into(), &[])
        .expect("the quotient covers A alone");
}

/// An intermediate that matches no bundle boundary: multiply the complement
/// of a mined aggregate in, then divide the mined aggregate out.
#[test]
fn unmerge_through_a_hidden_intermediate() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::random(&mut *rng));
    let [mut alice, bob, carol] =
        [(); 3].map(|()| wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]));

    let alice_bob = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                BTreeSet::from([alice.fee_descriptor()]),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                BTreeSet::from([bob.fee_descriptor()]),
            ),
        )
        .expect("merge A and B");
    let mined = bob
        .stamp
        .clone()
        .merge(
            rng,
            (
                bob.descriptors().collect(),
                BTreeSet::from([bob.fee_descriptor()]),
            ),
            (
                carol.stamp.clone(),
                carol.descriptors().collect(),
                BTreeSet::from([carol.fee_descriptor()]),
            ),
        )
        .expect("merge B and C");
    let all_three = alice_bob
        .merge(
            rng,
            (
                alice.descriptors().chain(bob.descriptors()).collect(),
                BTreeSet::from([alice.fee_descriptor(), bob.fee_descriptor()]),
            ),
            (
                carol.stamp.clone(),
                carol.descriptors().collect(),
                BTreeSet::from([carol.fee_descriptor()]),
            ),
        )
        .expect("merge AB and C");

    alice.stamp = all_three
        .unmerge(
            rng,
            (
                alice
                    .descriptors()
                    .chain(bob.descriptors())
                    .chain(carol.descriptors())
                    .collect(),
                BTreeSet::from([
                    alice.fee_descriptor(),
                    bob.fee_descriptor(),
                    carol.fee_descriptor(),
                ]),
            ),
            (
                mined,
                bob.descriptors().chain(carol.descriptors()).collect(),
                BTreeSet::from([bob.fee_descriptor(), carol.fee_descriptor()]),
            ),
        )
        .expect("divide the mined BC out");
    let wtxid = mock_wtxid(&alice);
    alice
        .verify(rng, &mock_sighash(alice.commitment()), &wtxid.into(), &[])
        .expect("the quotient covers A alone");
}

/// A divisor proved at an earlier anchor divides once lifted to the
/// dividend's anchor.
#[test]
fn unmerge_by_a_lifted_divisor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);

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
            &BTreeSet::from([bob.fee_descriptor()]),
            vec![span],
        )
        .expect("lift B onto A's anchor");

    let alice_bob = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                BTreeSet::from([alice.fee_descriptor()]),
            ),
            (
                lifted_bob.clone(),
                bob.descriptors().collect(),
                BTreeSet::from([bob.fee_descriptor()]),
            ),
        )
        .expect("merge A and the lifted B");

    alice.stamp = alice_bob
        .unmerge(
            rng,
            (
                alice.descriptors().chain(bob.descriptors()).collect(),
                BTreeSet::from([alice.fee_descriptor(), bob.fee_descriptor()]),
            ),
            (
                lifted_bob,
                bob.descriptors().collect(),
                BTreeSet::from([bob.fee_descriptor()]),
            ),
        )
        .expect("divide the lifted B out");
    let wtxid = mock_wtxid(&alice);
    alice
        .verify(rng, &mock_sighash(alice.commitment()), &wtxid.into(), &[])
        .expect("the quotient covers A alone");
}

/// Dividing a stamp by itself proves a stamp over no leaves, which no bundle
/// covers.
#[test]
fn unmerge_by_itself_leaves_no_leaves() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::random(&mut *rng));
    let mut alice = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);

    let quotient = alice
        .stamp
        .clone()
        .unmerge(
            rng,
            (
                alice.descriptors().collect(),
                BTreeSet::from([alice.fee_descriptor()]),
            ),
            (
                alice.stamp.clone(),
                alice.descriptors().collect(),
                BTreeSet::from([alice.fee_descriptor()]),
            ),
        )
        .expect("divide A by itself");
    assert!(quotient.tachygrams.is_empty());
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

/// A divisor holding some of one bundle's leaves splits it. The quotient
/// proves over the remaining leaves, and the bundle no longer verifies.
#[test]
fn unmerge_splitting_a_bundle() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::random(&mut *rng));

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
            (
                whole.descriptors().collect(),
                BTreeSet::from([whole.fee_descriptor()]),
            ),
            (
                part,
                BTreeSet::from([removed_descriptor]),
                BTreeSet::from([whole.fee_descriptor()]),
            ),
        )
        .expect("divide the removed action out");
    assert!(
        quotient
            .verify_proof(rng, [kept_descriptor.digest().expect("action digest")])
            .expect("proof system verification"),
        "the quotient verifies against the remaining digest"
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

/// Dividing `A·B` by `B` with honest operands proves, so each rejection below
/// isolates one fault.
#[test]
fn unmerge_accepts_honest_operands() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::random(&mut *rng));
    let [alice, bob] =
        [(); 2].map(|()| wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]));
    let alice_bob = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                BTreeSet::from([alice.fee_descriptor()]),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                BTreeSet::from([bob.fee_descriptor()]),
            ),
        )
        .expect("merge A and B");

    let dividend_actions: ActionSetPoly = alice
        .descriptors()
        .chain(bob.descriptors())
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([alice.fee_descriptor(), bob.fee_descriptor()]))
        .collect();
    let dividend_tachygrams: TachygramSetPoly = alice_bob.tachygrams.iter().copied().collect();
    let quotient_actions: ActionSetPoly = alice
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([alice.fee_descriptor()]))
        .collect();
    let quotient_tachygrams: TachygramSetPoly = alice.stamp.tachygrams.iter().copied().collect();
    let divisor_actions: ActionSetPoly = bob
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([bob.fee_descriptor()]))
        .collect();
    let divisor_tachygrams: TachygramSetPoly = bob.stamp.tachygrams.iter().copied().collect();

    let dividend = alice_bob.proof.clone().carry::<Stamp>((
        dividend_actions.commit(),
        dividend_tachygrams.commit(),
        alice_bob.anchor,
    ));
    let divisor = bob.stamp.proof.clone().carry::<Stamp>((
        divisor_actions.commit(),
        divisor_tachygrams.commit(),
        bob.stamp.anchor,
    ));
    PROOF_SYSTEM
        .fuse(
            rng,
            StampUnmerge,
            (
                (dividend_actions, dividend_tachygrams),
                (quotient_actions, quotient_tachygrams),
                (divisor_actions, divisor_tachygrams),
            ),
            dividend,
            divisor,
        )
        .expect("honest operands prove");
}

#[test]
fn unmerge_rejects_mismatched_anchors() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::random(&mut *rng));
    let [alice, bob] =
        [(); 2].map(|()| wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]));
    let alice_bob = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                BTreeSet::from([alice.fee_descriptor()]),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                BTreeSet::from([bob.fee_descriptor()]),
            ),
        )
        .expect("merge A and B");

    let dividend_actions: ActionSetPoly = alice
        .descriptors()
        .chain(bob.descriptors())
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([alice.fee_descriptor(), bob.fee_descriptor()]))
        .collect();
    let dividend_tachygrams: TachygramSetPoly = alice_bob.tachygrams.iter().copied().collect();
    let quotient_actions: ActionSetPoly = alice
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([alice.fee_descriptor()]))
        .collect();
    let quotient_tachygrams: TachygramSetPoly = alice.stamp.tachygrams.iter().copied().collect();
    let divisor_actions: ActionSetPoly = bob
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([bob.fee_descriptor()]))
        .collect();
    let divisor_tachygrams: TachygramSetPoly = bob.stamp.tachygrams.iter().copied().collect();

    let dividend = alice_bob.proof.clone().carry::<Stamp>((
        dividend_actions.commit(),
        dividend_tachygrams.commit(),
        alice_bob.anchor,
    ));
    // B's proof carried at an anchor other than the dividend's.
    let divisor = bob.stamp.proof.carry::<Stamp>((
        divisor_actions.commit(),
        divisor_tachygrams.commit(),
        Anchor::from(Fp::random(&mut *rng)),
    ));
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            StampUnmerge,
            (
                (dividend_actions, dividend_tachygrams),
                (quotient_actions, quotient_tachygrams),
                (divisor_actions, divisor_tachygrams),
            ),
            dividend,
            divisor,
        )
        .err()
        .expect("mismatched anchors must not unmerge");
    assert_eq!(invalid_witness(err), "StampUnmerge: anchors must match");
}

#[test]
fn unmerge_rejects_a_wrong_action_quotient() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::random(&mut *rng));
    let [alice, bob] =
        [(); 2].map(|()| wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]));
    let alice_bob = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                BTreeSet::from([alice.fee_descriptor()]),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                BTreeSet::from([bob.fee_descriptor()]),
            ),
        )
        .expect("merge A and B");

    let dividend_actions: ActionSetPoly = alice
        .descriptors()
        .chain(bob.descriptors())
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([alice.fee_descriptor(), bob.fee_descriptor()]))
        .collect();
    let dividend_tachygrams: TachygramSetPoly = alice_bob.tachygrams.iter().copied().collect();
    let divisor_actions: ActionSetPoly = bob
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([bob.fee_descriptor()]))
        .collect();
    let divisor_tachygrams: TachygramSetPoly = bob.stamp.tachygrams.iter().copied().collect();
    // The action quotient removes A's leaves instead of B's.
    let quotient_actions = divisor_actions.clone();
    let quotient_tachygrams: TachygramSetPoly = alice.stamp.tachygrams.iter().copied().collect();

    let dividend = alice_bob.proof.clone().carry::<Stamp>((
        dividend_actions.commit(),
        dividend_tachygrams.commit(),
        alice_bob.anchor,
    ));
    let divisor = bob.stamp.proof.clone().carry::<Stamp>((
        divisor_actions.commit(),
        divisor_tachygrams.commit(),
        bob.stamp.anchor,
    ));
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            StampUnmerge,
            (
                (dividend_actions, dividend_tachygrams),
                (quotient_actions, quotient_tachygrams),
                (divisor_actions, divisor_tachygrams),
            ),
            dividend,
            divisor,
        )
        .err()
        .expect("a wrong action quotient must not unmerge");
    assert_eq!(
        invalid_witness(err),
        "StampUnmerge: dividend action set must be the product of divisor and quotient action sets"
    );
}

/// The action quotient is honest, but the tachygram quotient removes one of
/// A's tachygrams in place of one of B's.
#[test]
fn unmerge_rejects_independent_column_removal() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::random(&mut *rng));
    let [alice, bob] =
        [(); 2].map(|()| wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]));
    let alice_bob = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                BTreeSet::from([alice.fee_descriptor()]),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                BTreeSet::from([bob.fee_descriptor()]),
            ),
        )
        .expect("merge A and B");

    let dividend_actions: ActionSetPoly = alice
        .descriptors()
        .chain(bob.descriptors())
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([alice.fee_descriptor(), bob.fee_descriptor()]))
        .collect();
    let dividend_tachygrams: TachygramSetPoly = alice_bob.tachygrams.iter().copied().collect();
    let divisor_actions: ActionSetPoly = bob
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([bob.fee_descriptor()]))
        .collect();
    let divisor_tachygrams: TachygramSetPoly = bob.stamp.tachygrams.iter().copied().collect();
    let quotient_actions: ActionSetPoly = alice
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([alice.fee_descriptor()]))
        .collect();
    let alice_tachygram = *alice.stamp.tachygrams.first().expect("A has tachygrams");
    let bob_tachygram = *bob.stamp.tachygrams.first().expect("B has tachygrams");
    let quotient_tachygrams: TachygramSetPoly = alice
        .stamp
        .tachygrams
        .iter()
        .copied()
        .filter(|&tachygram| tachygram != alice_tachygram)
        .chain([bob_tachygram])
        .collect();

    let dividend = alice_bob.proof.clone().carry::<Stamp>((
        dividend_actions.commit(),
        dividend_tachygrams.commit(),
        alice_bob.anchor,
    ));
    let divisor = bob.stamp.proof.clone().carry::<Stamp>((
        divisor_actions.commit(),
        divisor_tachygrams.commit(),
        bob.stamp.anchor,
    ));
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            StampUnmerge,
            (
                (dividend_actions, dividend_tachygrams),
                (quotient_actions, quotient_tachygrams),
                (divisor_actions, divisor_tachygrams),
            ),
            dividend,
            divisor,
        )
        .err()
        .expect("independent-column removal must not unmerge");
    assert_eq!(
        invalid_witness(err),
        "StampUnmerge: dividend tachygram set must be the product of divisor and quotient tachygram sets"
    );
}

#[test]
fn unmerge_rejects_a_divisor_set_off_its_header() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::random(&mut *rng));
    let [alice, bob, carol] =
        [(); 3].map(|()| wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]));
    let alice_bob = alice
        .stamp
        .clone()
        .merge(
            rng,
            (
                alice.descriptors().collect(),
                BTreeSet::from([alice.fee_descriptor()]),
            ),
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                BTreeSet::from([bob.fee_descriptor()]),
            ),
        )
        .expect("merge A and B");

    let dividend_actions: ActionSetPoly = alice
        .descriptors()
        .chain(bob.descriptors())
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([alice.fee_descriptor(), bob.fee_descriptor()]))
        .collect();
    let dividend_tachygrams: TachygramSetPoly = alice_bob.tachygrams.iter().copied().collect();
    let quotient_actions: ActionSetPoly = alice
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([alice.fee_descriptor()]))
        .collect();
    let quotient_tachygrams: TachygramSetPoly = alice.stamp.tachygrams.iter().copied().collect();
    let bob_actions: ActionSetPoly = bob
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([bob.fee_descriptor()]))
        .collect();
    let bob_tachygrams: TachygramSetPoly = bob.stamp.tachygrams.iter().copied().collect();
    let carol_actions: ActionSetPoly = carol
        .descriptors()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([carol.fee_descriptor()]))
        .collect();
    let carol_tachygrams: TachygramSetPoly = carol.stamp.tachygrams.iter().copied().collect();

    let dividend = alice_bob.proof.clone().carry::<Stamp>((
        dividend_actions.commit(),
        dividend_tachygrams.commit(),
        alice_bob.anchor,
    ));
    let divisor = bob.stamp.proof.clone().carry::<Stamp>((
        bob_actions.commit(),
        bob_tachygrams.commit(),
        bob.stamp.anchor,
    ));
    // C's sets against B's header.
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            StampUnmerge,
            (
                (dividend_actions, dividend_tachygrams),
                (quotient_actions, quotient_tachygrams),
                (carol_actions, carol_tachygrams),
            ),
            dividend,
            divisor,
        )
        .err()
        .expect("a divisor set off its header must not unmerge");
    assert_eq!(
        invalid_witness(err),
        "StampUnmerge: divisor action accumulator must commit to header commit"
    );
}
