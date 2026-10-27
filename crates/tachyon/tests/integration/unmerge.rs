extern crate alloc;

use alloc::{collections::BTreeSet, vec, vec::Vec};

use ff::Field as _;
use pasta_curves::Fp;
use ragu::Pcd;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Action, ActionDigest, ActionSetPoly, Anchor, Bundle, ProofStamp, TachygramSetPoly,
    VerificationError, VerifyCoverageError, action, bundle, fee,
    stamp::{self, proof::stamp::Stamp},
    value,
};

use crate::{
    fixtures::{
        PoolSim, WalletSim, build_lift_span, build_output_plan, fee_digests, forge_unmerge,
        mock_sighash, mock_wtxid, random_block, shared_sk,
    },
    qr::invalid_witness,
};

/// An output-only autonome at `anchor`.
fn output_autonome(rng: &mut StdRng, wallet: &WalletSim, anchor: Anchor) -> Bundle<ProofStamp> {
    let note = wallet.random_note(300);
    wallet.autonome(rng, anchor, vec![], vec![note])
}

/// A bundle's own action and fee descriptors.
fn leaves(
    bundle: &Bundle<ProofStamp>,
) -> (BTreeSet<action::Descriptor>, BTreeSet<fee::Descriptor>) {
    (
        bundle.actions.iter().map(Action::descriptor).collect(),
        BTreeSet::from([bundle.fee_descriptor()]),
    )
}

/// The action digests of the given leaves.
fn digests(
    leaf_sets: &(BTreeSet<action::Descriptor>, BTreeSet<fee::Descriptor>),
) -> Vec<ActionDigest> {
    leaf_sets
        .0
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests(leaf_sets.1.iter().copied()))
        .collect()
}

/// The union of several bundles' leaves.
fn union_of(
    parts: &[&(BTreeSet<action::Descriptor>, BTreeSet<fee::Descriptor>)],
) -> (BTreeSet<action::Descriptor>, BTreeSet<fee::Descriptor>) {
    (
        parts
            .iter()
            .flat_map(|part| part.0.iter().copied())
            .collect(),
        parts
            .iter()
            .flat_map(|part| part.1.iter().copied())
            .collect(),
    )
}

/// Merges two stamps over their leaves.
fn merge(
    rng: &mut StdRng,
    (left, left_leaves): (
        &ProofStamp,
        &(BTreeSet<action::Descriptor>, BTreeSet<fee::Descriptor>),
    ),
    (right, right_leaves): (
        &ProofStamp,
        &(BTreeSet<action::Descriptor>, BTreeSet<fee::Descriptor>),
    ),
) -> ProofStamp {
    left.clone()
        .merge(
            rng,
            left_leaves.clone(),
            (
                right.clone(),
                right_leaves.0.clone(),
                right_leaves.1.clone(),
            ),
        )
        .expect("merge")
}

/// Divides a stamp by another over their leaves.
fn unmerge(
    rng: &mut StdRng,
    (dividend, dividend_leaves): (
        &ProofStamp,
        &(BTreeSet<action::Descriptor>, BTreeSet<fee::Descriptor>),
    ),
    (divisor, divisor_leaves): (
        &ProofStamp,
        &(BTreeSet<action::Descriptor>, BTreeSet<fee::Descriptor>),
    ),
) -> ProofStamp {
    dividend
        .clone()
        .unmerge(
            rng,
            dividend_leaves.clone(),
            (
                divisor.clone(),
                divisor_leaves.0.clone(),
                divisor_leaves.1.clone(),
            ),
        )
        .expect("unmerge")
}

/// A stamp's set polynomials over the given action digests.
fn sets(digest_list: &[ActionDigest], stamp: &ProofStamp) -> (ActionSetPoly, TachygramSetPoly) {
    (
        digest_list.iter().copied().collect(),
        stamp.tachygrams.iter().copied().collect(),
    )
}

/// A stamp's PCD over the given set polynomials.
fn carry(stamp: &ProofStamp, set_polys: &(ActionSetPoly, TachygramSetPoly)) -> Pcd<Stamp> {
    stamp
        .proof
        .clone()
        .carry::<Stamp>((set_polys.0.commit(), set_polys.1.commit(), stamp.anchor))
}

/// Verifies `bundle` as an aggregate over `adjuncts`, stripped against it.
fn verify_aggregate(
    rng: &mut StdRng,
    bundle: &Bundle<ProofStamp>,
    adjuncts: Vec<Bundle<ProofStamp>>,
) -> Result<(), VerificationError> {
    let wtxid = mock_wtxid(bundle);
    let stripped: Vec<_> = adjuncts
        .into_iter()
        .map(|adjunct| adjunct.strip(wtxid))
        .collect();
    bundle.verify(
        rng,
        &mock_sighash(bundle.commitment()),
        &wtxid.into(),
        &stripped.iter().collect::<Vec<_>>(),
    )
}

/// Three autonomes at one anchor, with their leaves.
fn three_autonomes(
    rng: &mut StdRng,
) -> [(
    Bundle<ProofStamp>,
    (BTreeSet<action::Descriptor>, BTreeSet<fee::Descriptor>),
); 3] {
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::random(&mut *rng));
    [(); 3].map(|()| {
        let bundle = output_autonome(rng, &wallet, anchor);
        let bundle_leaves = leaves(&bundle);
        (bundle, bundle_leaves)
    })
}

/// Removing one contributor from an aggregate leaves a stamp that covers the
/// others.
#[test]
fn unmerge_removes_one_contributor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let [
        (mut alice, alice_leaves),
        (bob, bob_leaves),
        (carol, carol_leaves),
    ] = three_autonomes(rng);

    let alice_bob = merge(
        rng,
        (&alice.stamp, &alice_leaves),
        (&bob.stamp, &bob_leaves),
    );
    let alice_bob_leaves = union_of(&[&alice_leaves, &bob_leaves]);
    let all_three = merge(
        rng,
        (&alice_bob, &alice_bob_leaves),
        (&carol.stamp, &carol_leaves),
    );
    let all_three_leaves = union_of(&[&alice_bob_leaves, &carol_leaves]);

    let quotient = unmerge(
        rng,
        (&all_three, &all_three_leaves),
        (&bob.stamp, &bob_leaves),
    );
    assert!(
        quotient
            .verify_proof(rng, digests(&union_of(&[&alice_leaves, &carol_leaves])))
            .expect("proof system verification"),
        "the quotient verifies against the remaining digests"
    );

    alice.stamp = quotient;
    verify_aggregate(rng, &alice, vec![carol]).expect("the quotient covers A and its adjunct C");
}

/// Dividing by a merged stamp removes all of its contributors.
#[test]
fn unmerge_removes_a_product() {
    let rng = &mut StdRng::seed_from_u64(0);
    let [
        (mut alice, alice_leaves),
        (bob, bob_leaves),
        (carol, carol_leaves),
    ] = three_autonomes(rng);

    let bob_carol = merge(
        rng,
        (&bob.stamp, &bob_leaves),
        (&carol.stamp, &carol_leaves),
    );
    let bob_carol_leaves = union_of(&[&bob_leaves, &carol_leaves]);
    let all_three = merge(
        rng,
        (&alice.stamp, &alice_leaves),
        (&bob_carol, &bob_carol_leaves),
    );
    let all_three_leaves = union_of(&[&alice_leaves, &bob_carol_leaves]);

    alice.stamp = unmerge(
        rng,
        (&all_three, &all_three_leaves),
        (&bob_carol, &bob_carol_leaves),
    );
    verify_aggregate(rng, &alice, vec![]).expect("the quotient covers A alone");
}

/// An intermediate that matches no bundle boundary: multiply the complement
/// of a mined aggregate in, then divide the mined aggregate out.
#[test]
fn unmerge_through_a_hidden_intermediate() {
    let rng = &mut StdRng::seed_from_u64(0);
    let [
        (mut alice, alice_leaves),
        (bob, bob_leaves),
        (carol, carol_leaves),
    ] = three_autonomes(rng);

    let alice_bob = merge(
        rng,
        (&alice.stamp, &alice_leaves),
        (&bob.stamp, &bob_leaves),
    );
    let alice_bob_leaves = union_of(&[&alice_leaves, &bob_leaves]);
    let mined = merge(
        rng,
        (&bob.stamp, &bob_leaves),
        (&carol.stamp, &carol_leaves),
    );
    let mined_leaves = union_of(&[&bob_leaves, &carol_leaves]);

    let all_three = merge(
        rng,
        (&alice_bob, &alice_bob_leaves),
        (&carol.stamp, &carol_leaves),
    );
    let all_three_leaves = union_of(&[&alice_bob_leaves, &carol_leaves]);

    alice.stamp = unmerge(
        rng,
        (&all_three, &all_three_leaves),
        (&mined, &mined_leaves),
    );
    verify_aggregate(rng, &alice, vec![]).expect("the quotient covers A alone");
}

/// A divisor proved at an earlier anchor divides once lifted to the
/// dividend's anchor.
#[test]
fn unmerge_by_a_lifted_divisor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);

    pool.advance(3, |_| random_block(rng, 1, 4));
    let bob = output_autonome(rng, &wallet, pool.anchor());
    let bob_leaves = leaves(&bob);
    let stamped_at = pool.height();

    pool.advance(2, |_| random_block(rng, 1, 4));
    let mut alice = output_autonome(rng, &wallet, pool.anchor());
    let alice_leaves = leaves(&alice);

    let span = build_lift_span(rng, &pool, stamped_at.next().unwrap()..=pool.height());
    let lifted_bob = bob
        .stamp
        .lift(rng, &bob_leaves.0, &bob_leaves.1, vec![span])
        .expect("lift B onto A's anchor");

    let alice_bob = merge(
        rng,
        (&alice.stamp, &alice_leaves),
        (&lifted_bob, &bob_leaves),
    );
    let alice_bob_leaves = union_of(&[&alice_leaves, &bob_leaves]);

    alice.stamp = unmerge(
        rng,
        (&alice_bob, &alice_bob_leaves),
        (&lifted_bob, &bob_leaves),
    );
    verify_aggregate(rng, &alice, vec![]).expect("the quotient covers A alone");
}

/// Dividing a stamp by itself proves a stamp over no leaves, which no bundle
/// covers.
#[test]
fn unmerge_by_itself_leaves_no_leaves() {
    let rng = &mut StdRng::seed_from_u64(0);
    let [(mut alice, alice_leaves), ..] = three_autonomes(rng);

    let quotient = unmerge(
        rng,
        (&alice.stamp, &alice_leaves),
        (&alice.stamp, &alice_leaves),
    );
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
    let err = verify_aggregate(rng, &alice, vec![]).expect_err("an empty stamp covers no bundle");
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
    let whole_leaves = leaves(&whole);

    let part = stamp::Plan::new(
        vec![],
        vec![(removed_descriptor, removed_theta, removed_note, removed_rcv)],
        anchor,
        max_fee_note,
        value::Positive::ZERO,
    )
    .prove(rng, &wallet.pak, vec![])
    .expect("prove the removed action with the bundle's fee");
    let part_leaves = (BTreeSet::from([removed_descriptor]), whole_leaves.1.clone());

    let quotient = unmerge(rng, (&whole.stamp, &whole_leaves), (&part, &part_leaves));
    assert!(
        quotient
            .verify_proof(rng, [kept_descriptor.digest().expect("action digest")])
            .expect("proof system verification"),
        "the quotient verifies against the remaining digest"
    );

    whole.stamp = quotient;
    let err = verify_aggregate(rng, &whole, vec![]).expect_err("a split bundle must not verify");
    let VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch) = err else {
        panic!("expected Coverage(StampActionsMismatch), got {err:?}");
    };
}

/// The honest operands of dividing `A·B` by `B`: the dividend and divisor
/// PCDs with their sets, and the quotient sets.
struct Operands {
    dividend: (ProofStamp, Vec<ActionDigest>),
    divisor: (ProofStamp, Vec<ActionDigest>),
    quotient: (ActionSetPoly, TachygramSetPoly),
    alice: ProofStamp,
    bob: ProofStamp,
    carol: (ProofStamp, Vec<ActionDigest>),
}

fn operands(rng: &mut StdRng) -> Operands {
    let [
        (alice, alice_leaves),
        (bob, bob_leaves),
        (carol, carol_leaves),
    ] = three_autonomes(rng);
    let alice_bob = merge(
        rng,
        (&alice.stamp, &alice_leaves),
        (&bob.stamp, &bob_leaves),
    );
    let alice_bob_leaves = union_of(&[&alice_leaves, &bob_leaves]);
    let quotient = sets(&digests(&alice_leaves), &alice.stamp);
    Operands {
        dividend: (alice_bob, digests(&alice_bob_leaves)),
        divisor: (bob.stamp.clone(), digests(&bob_leaves)),
        quotient,
        alice: alice.stamp,
        bob: bob.stamp,
        carol: (carol.stamp, digests(&carol_leaves)),
    }
}

impl Operands {
    fn forge(
        &self,
        rng: &mut StdRng,
        quotient: (ActionSetPoly, TachygramSetPoly),
        divisor: (&ProofStamp, (ActionSetPoly, TachygramSetPoly)),
    ) -> ragu_core::Result<Pcd<Stamp>> {
        let dividend_sets = sets(&self.dividend.1, &self.dividend.0);
        let honest_divisor = sets(&self.divisor.1, &self.divisor.0);
        forge_unmerge(
            rng,
            (carry(&self.dividend.0, &dividend_sets), dividend_sets),
            quotient,
            (carry(divisor.0, &honest_divisor), divisor.1),
        )
    }
}

/// The honest operands prove, so each rejection below isolates one fault.
#[test]
fn forge_unmerge_accepts_honest_operands() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ops = operands(rng);
    let divisor_sets = sets(&ops.divisor.1, &ops.divisor.0);
    ops.forge(rng, ops.quotient.clone(), (&ops.divisor.0, divisor_sets))
        .expect("honest operands prove");
}

#[test]
fn unmerge_rejects_mismatched_anchors() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ops = operands(rng);
    let mut elsewhere = ops.divisor.0.clone();
    elsewhere.anchor = Anchor::from(Fp::random(&mut *rng));
    let divisor_sets = sets(&ops.divisor.1, &elsewhere);

    let err = ops
        .forge(rng, ops.quotient.clone(), (&elsewhere, divisor_sets))
        .err()
        .expect("mismatched anchors must not unmerge");
    assert_eq!(invalid_witness(err), "StampUnmerge: anchors must match");
}

#[test]
fn unmerge_rejects_a_wrong_action_quotient() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ops = operands(rng);
    let divisor_sets = sets(&ops.divisor.1, &ops.divisor.0);
    // The action quotient removes A's leaves instead of B's.
    let quotient = (
        ops.divisor.1.iter().copied().collect(),
        ops.quotient.1.clone(),
    );

    let err = ops
        .forge(rng, quotient, (&ops.divisor.0, divisor_sets))
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
    let ops = operands(rng);
    let divisor_sets = sets(&ops.divisor.1, &ops.divisor.0);
    let alice_tachygram = *ops.alice.tachygrams.first().expect("A has tachygrams");
    let bob_tachygram = *ops.bob.tachygrams.first().expect("B has tachygrams");
    let quotient = (
        ops.quotient.0.clone(),
        ops.alice
            .tachygrams
            .iter()
            .copied()
            .filter(|&tachygram| tachygram != alice_tachygram)
            .chain([bob_tachygram])
            .collect(),
    );

    let err = ops
        .forge(rng, quotient, (&ops.divisor.0, divisor_sets))
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
    let ops = operands(rng);
    // C's sets against B's header.
    let foreign = sets(&ops.carol.1, &ops.carol.0);

    let err = ops
        .forge(rng, ops.quotient.clone(), (&ops.divisor.0, foreign))
        .err()
        .expect("a divisor set off its header must not unmerge");
    assert_eq!(
        invalid_witness(err),
        "StampUnmerge: divisor action accumulator must commit to header commit"
    );
}
