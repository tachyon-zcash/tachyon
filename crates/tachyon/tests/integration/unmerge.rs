extern crate alloc;

use alloc::vec;

use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionSetPoly, Anchor, TachygramSetPoly, VerificationError, VerifyCoverageError, bundle,
    stamp::{
        self, ProveError,
        proof::{
            PROOF_SYSTEM,
            stamp::{Stamp, StampUnmerge},
        },
    },
    value,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_lift_span, build_output_plan, fee_digests, mock_sighash, mock_wtxid,
    random_block, shared_sk,
};

/// Removing one contributor from an aggregate leaves a stamp that covers the
/// others.
#[test]
fn unmerge_removes_one_contributor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let mut alice = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);
    let bob = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);
    let carol = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);

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
    let all_three = alice_bob
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

    alice.stamp = all_three
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
            (
                bob.stamp.clone(),
                bob.descriptors().collect(),
                [bob.fee_descriptor()].into(),
            ),
        )
        .unwrap();
    let wtxid = mock_wtxid(&alice);
    alice
        .verify(
            rng,
            &mock_sighash(alice.commitment()),
            &wtxid.into(),
            &[&carol.strip(wtxid)],
        )
        .unwrap();
}

/// The quotient keeps the dividend's fee. Dividing `B` out of `B` merged into
/// `A` undoes the merge, leaving a stamp that verifies on `A`. Dividing `A`
/// out instead leaves `A`'s fee on a stamp covering `B`, which fails on `B`
/// and verifies once merged into `C`'s stamp at `C`'s fee.
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
    assert_eq!(kept.stamp.fee, alice_fee);
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
    let err = hostless
        .verify(
            rng,
            &mock_sighash(hostless.commitment()),
            &hostless_wtxid.into(),
            &[],
        )
        .unwrap_err();
    let VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch) = err else {
        panic!("expected Coverage(StampActionsMismatch), got {err:?}");
    };

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
    assert_eq!(carol.stamp.fee, carol_fee);
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

/// Sub-aggregate boundaries do not bound removal. Merging `C`, the complement
/// of a mined `B·C`, into `A·B` and dividing `B·C` out leaves `A`, though no
/// merge produced `B·C` as a part of `(A·B)·C`.
#[test]
fn unmerge_by_a_divisor_across_merge_boundaries() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let mut alice = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);
    let bob = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);
    let carol = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);

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
    let mined = bob
        .stamp
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
        .unwrap();
    let all_three = alice_bob
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

    alice.stamp = all_three
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
            (
                mined,
                bob.descriptors().chain(carol.descriptors()).collect(),
                [bob.fee_descriptor(), carol.fee_descriptor()].into(),
            ),
        )
        .unwrap();
    let wtxid = mock_wtxid(&alice);
    alice
        .verify(rng, &mock_sighash(alice.commitment()), &wtxid.into(), &[])
        .unwrap();
}

/// A divisor proved at an earlier anchor divides only once lifted to the
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

    if let Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err))) =
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
        )
    {
        assert_eq!(err.to_string(), "StampUnmerge: anchors must match");
    } else {
        panic!();
    }

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

/// Dividing a stamp by itself proves a stamp over no leaves, which no bundle
/// covers.
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
    assert_eq!(
        quotient.tachygram_set,
        TachygramSetPoly::from_iter([]).commit()
    );
    assert!(quotient.verify_proof(rng, []).unwrap());

    alice.stamp = quotient;
    let wtxid = mock_wtxid(&alice);
    let err = alice
        .verify(rng, &mock_sighash(alice.commitment()), &wtxid.into(), &[])
        .unwrap_err();
    let VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch) = err else {
        panic!("expected Coverage(StampActionsMismatch), got {err:?}");
    };
}

/// A divisor holding some of one bundle's leaves splits it. The divisor must
/// carry the bundle's fee, so the quotient proves over the kept action alone,
/// and the bundle no longer verifies.
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
    let err = whole
        .verify(rng, &mock_sighash(whole.commitment()), &wtxid.into(), &[])
        .unwrap_err();
    let VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch) = err else {
        panic!("expected Coverage(StampActionsMismatch), got {err:?}");
    };
}

/// `StampUnmerge` divides `A·B` by `B` with honest operands. It binds the
/// dividend and divisor sets to their headers, and rejects a quotient whose
/// product with the divisor is not the dividend.
#[test]
fn unmerge_binds_its_sets() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let alice = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);
    let bob = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);
    let carol = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);
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

    let alice_bob_actions: ActionSetPoly = alice
        .descriptors()
        .chain(bob.descriptors())
        .map(|desc| desc.digest().unwrap())
        .chain(fee_digests([alice.fee_descriptor(), bob.fee_descriptor()]))
        .collect();
    let alice_bob_tachygrams: TachygramSetPoly = alice_bob.tachygrams.iter().copied().collect();
    let alice_actions: ActionSetPoly = alice
        .descriptors()
        .map(|desc| desc.digest().unwrap())
        .chain(fee_digests([alice.fee_descriptor()]))
        .collect();
    let alice_tachygrams: TachygramSetPoly = alice.stamp.tachygrams.iter().copied().collect();
    let bob_actions: ActionSetPoly = bob
        .descriptors()
        .map(|desc| desc.digest().unwrap())
        .chain(fee_digests([bob.fee_descriptor()]))
        .collect();
    let bob_tachygrams: TachygramSetPoly = bob.stamp.tachygrams.iter().copied().collect();
    let carol_actions: ActionSetPoly = carol
        .descriptors()
        .map(|desc| desc.digest().unwrap())
        .chain(fee_digests([carol.fee_descriptor()]))
        .collect();
    let carol_tachygrams: TachygramSetPoly = carol.stamp.tachygrams.iter().copied().collect();

    let dividend_header = (
        alice_bob_actions.commit(),
        alice_bob_tachygrams.commit(),
        alice_bob.anchor,
    );
    let divisor_header = (
        bob_actions.commit(),
        bob_tachygrams.commit(),
        bob.stamp.anchor,
    );
    let valid = (
        (alice_bob_actions, alice_bob_tachygrams),
        (alice_actions, alice_tachygrams),
        (bob_actions.clone(), bob_tachygrams),
    );
    #[expect(
        clippy::redundant_clone,
        reason = "false positive: the loop below carries both proofs again"
    )]
    PROOF_SYSTEM
        .fuse(
            rng,
            StampUnmerge,
            valid.clone(),
            alice_bob.proof.clone().carry::<Stamp>(dividend_header),
            bob.stamp.proof.clone().carry::<Stamp>(divisor_header),
        )
        .unwrap();

    let mut wrong_dividend_actions = valid.clone();
    wrong_dividend_actions.0.0 = carol_actions.clone();
    let mut wrong_dividend_tachygrams = valid.clone();
    wrong_dividend_tachygrams.0.1 = carol_tachygrams.clone();
    let mut wrong_divisor_actions = valid.clone();
    wrong_divisor_actions.2.0 = carol_actions;
    let mut wrong_divisor_tachygrams = valid.clone();
    wrong_divisor_tachygrams.2.1 = carol_tachygrams;
    // The action quotient removes A's leaves instead of B's.
    let mut wrong_action_quotient = valid.clone();
    wrong_action_quotient.1.0 = bob_actions;
    // The tachygram quotient removes one of A's tachygrams in place of one of
    // B's, under an honest action quotient.
    let alice_tachygram = *alice.stamp.tachygrams.first().unwrap();
    let bob_tachygram = *bob.stamp.tachygrams.first().unwrap();
    let mut wrong_tachygram_quotient = valid;
    wrong_tachygram_quotient.1.1 = alice
        .stamp
        .tachygrams
        .iter()
        .copied()
        .filter(|&tachygram| tachygram != alice_tachygram)
        .chain([bob_tachygram])
        .collect();

    for (corrupt, expected) in [
        (
            wrong_dividend_actions,
            "StampUnmerge: dividend action accumulator must commit to header commit",
        ),
        (
            wrong_divisor_actions,
            "StampUnmerge: divisor action accumulator must commit to header commit",
        ),
        (
            wrong_dividend_tachygrams,
            "StampUnmerge: dividend tachygram accumulator must commit to header commit",
        ),
        (
            wrong_divisor_tachygrams,
            "StampUnmerge: divisor tachygram accumulator must commit to header commit",
        ),
        (
            wrong_action_quotient,
            "StampUnmerge: dividend action set must be the product of divisor and quotient action sets",
        ),
        (
            wrong_tachygram_quotient,
            "StampUnmerge: dividend tachygram set must be the product of divisor and quotient tachygram sets",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            StampUnmerge,
            corrupt,
            alice_bob.proof.clone().carry::<Stamp>(dividend_header),
            bob.stamp.proof.clone().carry::<Stamp>(divisor_header),
        ) {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }
}
