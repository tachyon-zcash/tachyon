#![allow(clippy::panic, reason = "test code")]

use alloc::{boxed::Box, string::ToString as _, vec, vec::Vec};

use pasta_curves::Fp;
use ragu::proof::PROOF_SIZE_COMPRESSED;
use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    constants::{EPOCH_SIZE, MAX_MONEY},
    digest::blake2b::{COMMIT_NO_BUNDLE, action_descriptor_digest, bundle_commitment},
    entropy::ActionEntropy,
    fixtures::{
        PoolSim, WalletSim, build_autonome, build_output_plan, build_output_stamp,
        forge_overlapping_merge, mock_sighash, mock_wtxid, random_action, random_block,
        random_block_with, shared_sk, spend_witness,
    },
    primitives::{BlockHeight, Tachygram},
    value,
};

#[test]
fn plan_value_balance_sums_spends_and_outputs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let spend = spend_plan_at(rng, &wallet, &ask, 300);
    let note = wallet.random_note(200);
    let (_rcv, _alpha, output) = build_output_plan(rng, note);
    let bundle_plan = Plan::new(alloc::vec![spend], alloc::vec![output]);

    assert_eq!(
        bundle_plan.value_balance(),
        Ok(value::Balance::try_from(100).unwrap())
    );
}

#[test]
fn wrong_value_balance_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());

    bundle.value_balance = value::Balance::try_from(999).unwrap();
    let err = bundle.verify_signatures(&sighash).unwrap_err();
    let VerifySignaturesError::Binding(_) = err else {
        panic!("expected SignatureError::Binding, got {err:?}");
    };
}

/// No separate range assertion is needed in `verify_signatures`: even a
/// `value::Balance` built directly with a magnitude far outside
/// `-MAX_MONEY..=MAX_MONEY` (bypassing `TryFrom`'s range check entirely, the
/// same way `read_rejects_value_balance_out_of_range` forges an otherwise
/// unconstructible wire encoding) is caught by the binding signature check
/// alone, same as any other mismatched value.
#[test]
fn verify_signatures_rejects_out_of_range_value_balance_mutation() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());

    bundle.value_balance = value::Balance::new_unchecked(i64::MAX);
    let err = bundle.verify_signatures(&sighash).unwrap_err();
    let VerifySignaturesError::Binding(_) = err else {
        panic!("expected SignatureError::Binding, got {err:?}");
    };
}

#[test]
fn stripped_bundle_retains_signatures() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());

    let covering = build_autonome(rng, &wallet, 500, 300);
    let adjunct = bundle.strip(mock_wtxid(&covering));
    adjunct.verify_signatures(&sighash).unwrap();
}

#[test]
fn plan_commitment_matches_bundle_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(200);
    let pool = PoolSim::genesis(rng);
    let (stamp, output_plan) = build_output_stamp(rng, pool.anchor(), note);

    let bundle_plan = Plan::new(alloc::vec![], alloc::vec![output_plan]);
    let sighash = mock_sighash(bundle_plan.commitment().unwrap());

    let bundle = bundle_plan
        .sign(rng, &sighash, &ask)
        .expect("sign output bundle")
        .stamp(stamp);

    assert_eq!(bundle_plan.commitment().unwrap(), bundle.commitment());
}

/// The output's `rk` is corrupted to an unrelated (but known) key after
/// construction. `sign` signs with the output's own alpha-derived key
/// regardless, producing a real signature under the wrong key — not the
/// signature that would actually match the corrupted key.
#[test]
fn actions_signed_despite_wrong_rk_fail_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();

    let spend = spend_plan_at(rng, &wallet, &ask, 200);

    let mut output = action::Plan::output(
        wallet.random_note(100),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    let unrelated = action::Plan::output(
        wallet.random_note(50),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    output.rk = unrelated.rk;

    let plan = Plan::new(alloc::vec![spend], alloc::vec![output]);

    let bundle = plan
        .sign(rng, &mock_sighash(plan.commitment().unwrap()), &ask)
        .expect("signing works");

    // We've applied a signature from the unrelated key
    let unrelated_alpha = unrelated
        .theta
        .randomizer::<effect::Output>(unrelated.note.commitment());
    assert!(!bundle.actions.iter().any(|action| {
        action.sig
            == private::ActionSigningKey::new(&unrelated_alpha)
                .sign(rng, &mock_sighash(plan.commitment().unwrap()))
    }));

    // so it fails verification
    let err = bundle
        .verify_signatures(&mock_sighash(bundle.commitment()))
        .unwrap_err();
    let VerifySignaturesError::Action(_) = err else {
        panic!("expected SignatureError::Action, got {err:?}");
    };
}

/// The spend's `rk` matches `ask`, but `sign` is called with a different
/// signing key. It signs with whatever key it's given, producing a real
/// signature from the wrong signer, not the one `ask` itself would have
/// produced.
#[test]
fn actions_signed_by_wrong_rsk_fail_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let wrong_ask = WalletSim::random(rng).sk.derive_auth_private();

    let spend = spend_plan_at(rng, &wallet, &ask, 200);
    let note = wallet.random_note(100);
    let (_rcv, _alpha, output) = build_output_plan(rng, note);

    let plan = Plan::new(alloc::vec![spend], alloc::vec![output]);

    let bundle = plan
        .sign(rng, &mock_sighash(plan.commitment().unwrap()), &wrong_ask)
        .expect("signing works");

    // The signature the spend's matching key would have produced.
    let alpha = spend
        .theta
        .randomizer::<effect::Spend>(spend.note.commitment());
    let correct_sig = ask
        .derive_action_private(&alpha)
        .sign(rng, &mock_sighash(bundle.commitment()));
    assert!(
        !bundle
            .actions
            .iter()
            .any(|action| action.sig == correct_sig)
    );

    let err = bundle
        .verify_signatures(&mock_sighash(bundle.commitment()))
        .unwrap_err();
    let VerifySignaturesError::Action(_) = err else {
        panic!("expected SignatureError::Action, got {err:?}");
    };
}

#[test]
fn apply_signatures_rejects_wrong_sig_count() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let ask = wallet.sk.derive_auth_private();
    let spend_a = spend_plan_at(rng, &wallet, &ask, 200);
    let spend_b = spend_plan_at(rng, &wallet, &ask, 100);
    let spend_c = spend_plan_at(rng, &wallet, &ask, 300);
    let plan = Plan::new(alloc::vec![spend_a, spend_b], alloc::vec![]);

    let sig_a = {
        let alpha = spend_a
            .theta
            .randomizer::<effect::Spend>(spend_a.note.commitment());
        ask.derive_action_private(&alpha)
            .sign(rng, &mock_sighash(plan.commitment().unwrap()))
    };

    let sig_b = {
        let alpha = spend_b
            .theta
            .randomizer::<effect::Spend>(spend_b.note.commitment());
        ask.derive_action_private(&alpha)
            .sign(rng, &mock_sighash(plan.commitment().unwrap()))
    };

    let sig_c = {
        let alpha = spend_c
            .theta
            .randomizer::<effect::Spend>(spend_c.note.commitment());
        ask.derive_action_private(&alpha)
            .sign(rng, &mock_sighash(plan.commitment().unwrap()))
    };

    let too_few = plan
        .apply_signatures(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            BTreeMap::from([(spend_a.descriptor(), sig_a)]),
        )
        .unwrap_err();
    assert_eq!(too_few, PlanError::ActionSigMismatch);

    let too_many = plan
        .apply_signatures(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            BTreeMap::from([
                (spend_a.descriptor(), sig_a),
                (spend_b.descriptor(), sig_b),
                (spend_c.descriptor(), sig_c),
            ]),
        )
        .unwrap_err();
    assert_eq!(too_many, PlanError::ActionSigMismatch);
}

#[test]
fn apply_signatures_with_shuffled_sigs_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();

    let spend_a = spend_plan_at(rng, &wallet, &ask, 200);
    let spend_b = spend_plan_at(rng, &wallet, &ask, 100);
    let plan = Plan::new(alloc::vec![spend_a, spend_b], alloc::vec![]);

    // `sign` produces genuinely valid signatures, already in
    // `self.descriptors()`'s canonical order.
    let mut sigs: Vec<action::Signature> = plan
        .sign(rng, &mock_sighash(plan.commitment().unwrap()), &ask)
        .expect("signing works")
        .actions
        .into_iter()
        .map(|action| action.sig)
        .collect();

    // shuffled assembly still succeeds
    sigs.reverse();
    let authorized = plan.descriptors().into_iter().zip(sigs).collect();

    let bundle = plan
        .apply_signatures(rng, &mock_sighash(plan.commitment().unwrap()), authorized)
        .expect("assembly succeeds regardless of sig order");

    // but the mismatched pairing fails verification.
    let err = bundle
        .verify_signatures(&mock_sighash(bundle.commitment()))
        .unwrap_err();
    let VerifySignaturesError::Action(_) = err else {
        panic!("expected SignatureError::Action, got {err:?}");
    };
}

/// Permuting a bundle's actions changes its commitment, so a sighash
/// naturally recomputed for the permuted state doesn't validate.
/// The permuted bundle can't be serialized and read back.
#[test]
fn permuted_actions_change_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let original = build_autonome(rng, &wallet, 1000, 700);

    // it's a good bundle
    original
        .verify_signatures(&mock_sighash(original.commitment()))
        .unwrap();

    let mut permuted = original.clone();
    permuted.actions.swap(0, 1);

    // the commitment changes.
    assert_ne!(
        mock_sighash(original.commitment()),
        mock_sighash(permuted.commitment())
    );

    // and its signatures no longer verify.
    let sig_err = permuted
        .verify_signatures(&mock_sighash(permuted.commitment()))
        .unwrap_err();
    let VerifySignaturesError::Binding(_) = sig_err else {
        panic!("expected SignatureError::Binding, got {sig_err:?}");
    };
}

/// Mutating a bundle's `value_balance` breaks verification.
#[test]
fn tampered_value_balance_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let original = build_autonome(rng, &wallet, 1000, 700);

    // it's a good bundle
    original
        .verify_signatures(&mock_sighash(original.commitment()))
        .unwrap();

    let mut tampered = original.clone();
    tampered.value_balance = value::Balance::try_from(999).unwrap();

    // it fails verification against the new commitment.
    let bind_err = tampered
        .verify_signatures(&mock_sighash(tampered.commitment()))
        .unwrap_err();
    let VerifySignaturesError::Binding(_) = bind_err else {
        panic!("expected SignatureError::Binding, got {bind_err:?}");
    };

    // and it no longer verifies against the original sighash.
    let also_err = tampered
        .verify_signatures(&mock_sighash(original.commitment()))
        .unwrap_err();
    let VerifySignaturesError::Binding(_) = also_err else {
        panic!("expected SignatureError::Binding, got {also_err:?}");
    };
}

/// `sign` and `apply_signatures` go through the real API (not a hand-built
/// `Bundle`) for the boundary shapes of the `iter_actions`/sort/zip
/// machinery: spends-only, outputs-only, and no actions at all.
#[test]
fn sign_and_apply_signatures_handle_one_sided_and_empty_plans() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let ask = wallet.sk.derive_auth_private();

    let spend_plan = Plan::new(
        alloc::vec![spend_plan_at(rng, &wallet, &ask, 200)],
        alloc::vec![],
    );
    spend_plan
        .sign(rng, &mock_sighash(spend_plan.commitment().unwrap()), &ask)
        .expect("spends-only plan signs")
        .verify_signatures(&mock_sighash(spend_plan.commitment().unwrap()))
        .expect("spends-only bundle verifies");

    let note = wallet.random_note(200);
    let (_rcv, _alpha, output) = build_output_plan(rng, note);
    let output_plan = Plan::new(alloc::vec![], alloc::vec![output]);
    output_plan
        .sign(rng, &mock_sighash(output_plan.commitment().unwrap()), &ask)
        .expect("outputs-only plan signs")
        .verify_signatures(&mock_sighash(output_plan.commitment().unwrap()))
        .expect("outputs-only bundle verifies");

    let empty_plan = Plan::new(alloc::vec![], alloc::vec![]);
    empty_plan
        .sign(rng, &mock_sighash(empty_plan.commitment().unwrap()), &ask)
        .expect("empty plan signs")
        .verify_signatures(&mock_sighash(empty_plan.commitment().unwrap()))
        .expect("empty bundle via sign verifies");
    empty_plan
        .apply_signatures(
            rng,
            &mock_sighash(empty_plan.commitment().unwrap()),
            BTreeMap::new(),
        )
        .expect("apply_signatures accepts zero sigs for an empty plan")
        .verify_signatures(&mock_sighash(empty_plan.commitment().unwrap()))
        .expect("empty bundle via apply_signatures verifies");
}

#[test]
fn no_bundle_commitment_differs_from_empty_bundle() {
    let empty_plan = Plan::new(alloc::vec![], alloc::vec![]);
    assert_ne!(
        *COMMIT_NO_BUNDLE,
        empty_plan.commitment().unwrap(),
        "absent bundle must differ from empty bundle"
    );
}

#[test]
fn zero_action_bundle_is_valid() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let covering = build_autonome(rng, &wallet, 1000, 700);

    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let bundle = Bundle {
        actions: alloc::vec![],
        value_balance: value::Balance::ZERO,
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        stamp: mock_wtxid(&covering),
    };

    bundle.verify_signatures(&sighash).unwrap();
}

#[test]
fn payment_bundle_verifies() {
    let rng = &mut StdRng::seed_from_u64(0);
    let sender = WalletSim::random(rng);
    let recipient = WalletSim::random(rng);
    let input_note = sender.random_note(500);
    let output_note = recipient.random_note(200);
    let change_note = sender.random_note(300);

    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(rng, &[vec![input_note.commitment()]], 50));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = sender.fresh_spend(rng, &pool, height, &input_note);
    let anchor = spendable_pcd.data().2;
    let stamped = sender.autonome(
        rng,
        anchor,
        alloc::vec![(input_note, spendable_pcd, spend_epoch)],
        alloc::vec![output_note, change_note],
    );
    let sighash = mock_sighash(stamped.commitment());
    stamped
        .verify_signatures(&sighash)
        .expect("payment bundle must verify");
}

/// `verify_proof` reconstructs the action polynomial from the action digests it
/// is given, as a multiset: the exact covered actions verify (in any order),
/// and any deviation — a dropped, duplicated, extra, or substituted action —
/// reconstructs a different polynomial and does not verify.
#[test]
fn stamp_verify_action_multiset_invariants() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let stamped = build_autonome(rng, &wallet, 1000, 700);

    let digests: Vec<ActionDigest> = stamped
        .actions
        .iter()
        .map(|action| action.descriptor().digest().expect("action digest"))
        .collect();

    // Permutation accepts.
    assert!(
        stamped
            .stamp
            .verify_proof(rng, &[digests[1], digests[0]])
            .expect("proof system verification"),
        "permuted actions must verify"
    );

    // Drop rejects.
    {
        let mut dropped = digests.clone();
        dropped.pop();
        assert!(
            !stamped
                .stamp
                .verify_proof(rng, &dropped)
                .expect("proof system verification"),
            "dropped action must not verify"
        );
    }

    // Duplicate rejects.
    {
        let mut duplicated = digests.clone();
        duplicated.push(digests[0]);
        assert!(
            !stamped
                .stamp
                .verify_proof(rng, &duplicated)
                .expect("proof system verification"),
            "duplicated action must not verify"
        );
    }

    // Foreign-extra rejects.
    {
        let mut extended = digests.clone();
        extended.push(
            random_action(rng)
                .descriptor()
                .digest()
                .expect("action digest"),
        );
        assert!(
            !stamped
                .stamp
                .verify_proof(rng, &extended)
                .expect("proof system verification"),
            "extra action must not verify"
        );
    }

    // Replace-with-foreign rejects.
    {
        let mut replaced = digests;
        replaced[0] = random_action(rng)
            .descriptor()
            .digest()
            .expect("action digest");
        assert!(
            !stamped
                .stamp
                .verify_proof(rng, &replaced)
                .expect("proof system verification"),
            "replaced action must not verify"
        );
    }
}

/// An obvious double spend, two actions with identical descriptors, clears
/// every cheap validator check yet fails proof verification.
#[test]
fn double_spend_obvious() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::genesis(rng).anchor();
    let note = wallet.random_note(200);

    // The Plan API keys actions by descriptor and cannot express a duplicate, so
    // this bundle is assembled by hand from a single output action.
    let (rcv, alpha, plan) = build_output_plan(rng, note);
    let descriptor = plan.descriptor();

    // Two identical output actions net to twice the single-output balance, and
    // the binding key is the doubled trapdoor; the per-action signature is
    // shared because the actions are byte-identical.
    let doubled = -2 * i64::try_from(u64::from(note.value)).expect("note value fits i64");
    let value_balance = value::Balance::try_from(doubled).expect("doubled balance stays in range");
    let action_bytes: Vec<[u8; 64]> = vec![descriptor, descriptor].into_iter().collect();
    let sighash = mock_sighash(bundle_commitment(
        &action_descriptor_digest(&action_bytes),
        doubled,
    ));
    let sig = private::ActionSigningKey::new(&alpha).sign(rng, &sighash);
    let action = Action::from((descriptor, sig));
    let binding_sig = private::BindingSigningKey::from([rcv, rcv]).sign(rng, &sighash);

    // Forge the stamp by merging one output stamp with itself: the merge proof
    // commits to the doubled action and tachygram multisets.
    let (tachygrams, stamp_anchor, proof) =
        ProofStamp::prove_output(rng, rcv, alpha, note, anchor).expect("prove_output");
    let output_stamp = ProofStamp {
        coverage: action_descriptor_digest(
            &vec![descriptor].into_iter().collect::<Vec<[u8; 64]>>(),
        ),
        tachygrams,
        anchor: stamp_anchor,
        proof,
    };
    let evil_pcd = forge_overlapping_merge(
        rng,
        (&output_stamp, &vec![descriptor]),
        (&output_stamp, &vec![descriptor]),
    );
    let coverage = {
        let mut desc_bytes: Vec<[u8; 64]> = vec![descriptor, descriptor].into_iter().collect();
        desc_bytes.sort_unstable();
        action_descriptor_digest(&desc_bytes)
    };

    // A tachygram set with duplicated elements wouldn't be accepted by
    // consensus actors. (see `read_rejects_duplicate_tachygrams`)
    let stamp = ProofStamp {
        coverage,
        anchor: evil_pcd.data().2,
        tachygrams: output_stamp.tachygrams.iter().copied().collect(),
        proof: Box::new(evil_pcd.proof().clone()),
    };

    let bundle = Bundle {
        actions: vec![action, action],
        value_balance,
        binding_sig,
        stamp,
    };

    let mut buf = Vec::new();
    bundle.write(&mut buf).expect("write");

    // The parser accepts the duplicate: the double action is wire-valid.
    let decoded = Bundle::<ProofStamp>::read(&*buf).expect("duplicate descriptors are wire-valid");

    // Every check ahead of the proof passes: the signatures verify and the
    // stamp's coverage matches the duplicated action set.
    decoded
        .verify_signatures(&mock_sighash(decoded.commitment()))
        .expect("binding and action signatures verify");
    assert!(
        decoded.is_autonome(),
        "the forged coverage matches the duplicated action set"
    );
    assert!(
        bundle.actions[0] == bundle.actions[1],
        "the actions are identical"
    );

    // Bundle-level proof verification rejects the duplicate outright: the action
    // set digests into a `BTreeSet`, collapsing the repeat, so the count shrinks.
    let dup_err = decoded
        .verify_proof(rng, &[])
        .expect_err("duplicated actions must be rejected");
    let VerifyProofError::DuplicateActions = dup_err else {
        panic!("expected DuplicateActions, got {dup_err:?}");
    };

    // The proof independently rejects it, but on the tachygram accumulator, not
    // the action one: the forged merge commits to the doubled action multiset
    // (x-d)^2 AND the doubled tachygram (x-cm)^2, so reconstructing the action
    // set from [d, d] matches. A wire-valid stamp must carry a canonical
    // deduplicated tachygram set (see `read_rejects_duplicate_tachygrams`),
    // whose (x-cm) cannot reconstruct the doubled tachygram the proof commits to.
    let digests: Vec<ActionDigest> = decoded
        .descriptors()
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .collect();
    assert!(
        !decoded
            .stamp
            .verify_proof(rng, &digests)
            .expect("proof system verification"),
        "the deduplicated tachygram set cannot reconstruct the doubled proof"
    );
}

/// A duplicated *spend* would mint value, and `verify` catches it by
/// reconstructing the action multiset from the wire.
///
/// The attacker holds one real spendable note worth `v` and its honest
/// single-spend stamp (covering `{d}`, one nullifier pair). By hand they build
/// an autonome whose action list is `[d, d]` — the same spend twice — with
/// `value_balance = 2v` (a valid binding signature over the doubled `cv` and
/// `bsk = 2·rcv`) and `coverage` forged to `digest([d, d])`. Signatures verify
/// and `is_autonome` accepts the forged coverage; the stamp evidences one spent
/// note against a balance that withdraws `2v`, so accepting it would mint `v`.
///
/// It dies at the proof: `verify` reconstructs `(x−d)²` from the wire's
/// `[d, d]`, which the honest single-spend `(x−d)` proof does not commit to →
/// `Disproved`. This defense relies on `verify` seeing the full multiset. A
/// `verify` that deduplicated its input would collapse `[d, d]` to `{d}`, which
/// the honest proof satisfies, and the distinctness check would have to be
/// hoisted to the caller.
#[test]
fn duplicated_spend_cannot_inflate() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let note = wallet.random_note(200);

    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 50));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let init = wallet.spendable_init(rng, &note, &pool, cm_height);
    let spendable = wallet.lift_over_creation_epoch(rng, &pool, &note, cm_height, init);
    let anchor = spendable.data().2;
    let spend_epoch = cm_height.epoch().next();

    // Build one honest spend with a trapdoor and randomizer we control, so the
    // duplicated bundle's binding and action signatures can be reproduced.
    let range = wallet.derived_range(rng, &note, spend_epoch, 2);
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let plan = action::Plan::spend(note, theta, rcv, |alpha| {
        wallet.pak.ak.derive_action_public(&alpha)
    });
    let descriptor = plan.descriptor();
    let honest_stamp = Plan::new(alloc::vec![plan], alloc::vec![])
        .stamp_plan(anchor)
        .prove(rng, &wallet.pak, alloc::vec![(range, spendable)])
        .expect("prove the honest single spend");

    // Assemble the duplicated-spend bundle by hand: two identical spend actions,
    // a value balance and binding key doubled to match, and coverage forged over
    // the doubled action set.
    let doubled = 2 * i64::try_from(u64::from(note.value)).expect("note value fits i64");
    let value_balance = value::Balance::try_from(doubled).expect("doubled balance in range");
    let action_bytes: Vec<[u8; 64]> = vec![descriptor, descriptor].into_iter().collect();
    let sighash = mock_sighash(bundle_commitment(
        &action_descriptor_digest(&action_bytes),
        doubled,
    ));
    let alpha = theta.randomizer::<effect::Spend>(note.commitment());
    let sig = wallet
        .sk
        .derive_auth_private()
        .derive_action_private(&alpha)
        .sign(rng, &sighash);
    let action = Action::from((descriptor, sig));
    let binding_sig = private::BindingSigningKey::from([rcv, rcv]).sign(rng, &sighash);
    let coverage = {
        let mut desc_bytes = Vec::<[u8; 64]>::from_iter([descriptor, descriptor]);
        desc_bytes.sort_unstable();
        action_descriptor_digest(&desc_bytes)
    };
    let bundle = Bundle {
        actions: vec![action, action],
        value_balance,
        binding_sig,
        stamp: ProofStamp {
            coverage,
            anchor: honest_stamp.anchor,
            tachygrams: honest_stamp.tachygrams,
            proof: honest_stamp.proof,
        },
    };

    let mut buf = Vec::new();
    bundle.write(&mut buf).expect("write");
    let decoded = Bundle::<ProofStamp>::read(&*buf).expect("duplicated spend is wire-valid");

    // The cheap checks pass, and the balance would mint: one spent note (one
    // present/next nullifier pair) against a balance that withdraws twice its
    // value.
    decoded
        .verify_signatures(&mock_sighash(decoded.commitment()))
        .expect("binding and action signatures verify");
    assert!(
        decoded.is_autonome(),
        "the forged coverage matches the duplicated action set"
    );
    assert_eq!(
        decoded.stamp.tachygrams.len(),
        2,
        "a single spend contributes exactly one present/next nullifier pair"
    );
    let withdrawn: i64 = decoded.value_balance.into();
    let backed = i64::try_from(u64::from(note.value)).expect("note value fits i64");
    assert_eq!(withdrawn, 2 * backed, "the bundle balances two spends");

    // Bundle-level proof verification rejects the duplicate outright: the action
    // set digests into a `BTreeSet`, collapsing the repeat, so the count shrinks.
    let dup_err = decoded
        .verify_proof(rng, &[])
        .expect_err("the duplicated spend must be rejected");
    let VerifyProofError::DuplicateActions = dup_err else {
        panic!("expected DuplicateActions, got {dup_err:?}");
    };

    // The proof independently rejects it: reconstructing the [d, d] multiset
    // yields an action polynomial the honest single-spend proof does not commit
    // to.
    let digests: Vec<ActionDigest> = decoded
        .descriptors()
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .collect();
    assert!(
        !decoded
            .stamp
            .verify_proof(rng, &digests)
            .expect("proof system verification"),
        "the doubled action must not verify against the single-spend proof"
    );
}

/// A more obfuscated double spend, the same note spent under two independent
/// randomizations, produces distinct descriptors and is not caught at the
/// bundle level. True double-spend prevention is a nullifier/pool-level
/// concern.
#[test]
fn double_spend_secret() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let note = wallet.random_note(200);

    let spend_a = action::Plan::spend(
        note,
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
        |alpha| ask.derive_action_private(&alpha).derive_action_public(),
    );
    let spend_b = action::Plan::spend(
        note,
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
        |alpha| ask.derive_action_private(&alpha).derive_action_public(),
    );
    assert_ne!(
        spend_a.cv(),
        spend_b.cv(),
        "independent rcv gives distinct cv"
    );
    assert_ne!(
        spend_a.rk, spend_b.rk,
        "independent theta gives distinct rk"
    );

    let plan = Plan::new(alloc::vec![spend_a, spend_b], alloc::vec![]);
    let bundle = plan
        .sign(rng, &mock_sighash(plan.commitment().unwrap()), &ask)
        .expect("signing works");

    bundle
        .verify_signatures(&mock_sighash(bundle.commitment()))
        .expect("two independently-randomized spends of the same note still verify");
}

#[test]
fn innocent_aggregate_from_two_autonomes() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let spend_a = wallet.random_note(1000);
    let output_a = wallet.random_note(700);
    let spend_b = wallet.random_note(500);
    let output_b = wallet.random_note(200);

    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(
        rng,
        &[vec![spend_a.commitment()], vec![spend_b.commitment()]],
        50,
    ));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let init_a = wallet.spendable_init(rng, &spend_a, &pool, cm_height);
    let sp_a = wallet.lift_over_creation_epoch(rng, &pool, &spend_a, cm_height, init_a);
    let init_b = wallet.spendable_init(rng, &spend_b, &pool, cm_height);
    let sp_b = wallet.lift_over_creation_epoch(rng, &pool, &spend_b, cm_height, init_b);
    let anchor_a = sp_a.data().2;
    let anchor_b = sp_b.data().2;
    assert_eq!(anchor_a, anchor_b, "lifts land on a common anchor");

    let spend_epoch = cm_height.epoch().next();
    let autonome_a = wallet.autonome(
        rng,
        anchor_a,
        alloc::vec![(spend_a, sp_a, spend_epoch)],
        alloc::vec![output_a],
    );
    let autonome_b = wallet.autonome(
        rng,
        anchor_b,
        alloc::vec![(spend_b, sp_b, spend_epoch)],
        alloc::vec![output_b],
    );

    let descriptors_a: BTreeSet<action::Descriptor> =
        autonome_a.actions.iter().map(Action::descriptor).collect();
    let descriptors_b: BTreeSet<action::Descriptor> =
        autonome_b.actions.iter().map(Action::descriptor).collect();
    let stamp_a = autonome_a.stamp.clone();
    let stamp_b = autonome_b.stamp.clone();

    let innocent = {
        let innocent_plan = Plan::new(alloc::vec![], alloc::vec![]);
        let innocent_sighash = mock_sighash(innocent_plan.commitment().unwrap());

        let stamp = ProofStamp::merge(rng, (stamp_a, descriptors_a), (stamp_b, descriptors_b))
            .expect("merge");

        Bundle {
            actions: alloc::vec![],
            value_balance: value::Balance::ZERO,
            binding_sig: innocent_plan
                .derive_bsk_private()
                .sign(rng, &innocent_sighash),
            stamp,
        }
    };

    let adjunct_a = autonome_a.strip(mock_wtxid(&innocent));
    let adjunct_b = autonome_b.strip(mock_wtxid(&innocent));

    innocent
        .verify_signatures(&mock_sighash(innocent.commitment()))
        .expect("innocent binding sig should verify");

    innocent
        .verify_proof(rng, &[adjunct_a.as_dyn(), adjunct_b.as_dyn()])
        .expect("innocent aggregate proof verifies against its adjuncts");
}

#[test]
fn based_aggregate_with_two_adjuncts() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let based_spend = wallet.random_note(800);
    let based_output = wallet.random_note(400);
    let a_spend = wallet.random_note(1000);
    let a_output = wallet.random_note(700);
    let b_spend = wallet.random_note(500);
    let b_output = wallet.random_note(200);

    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(
        rng,
        &[
            vec![based_spend.commitment()],
            vec![a_spend.commitment()],
            vec![b_spend.commitment()],
        ],
        50,
    ));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let based_init = wallet.spendable_init(rng, &based_spend, &pool, cm_height);
    let based_sp = wallet.lift_over_creation_epoch(rng, &pool, &based_spend, cm_height, based_init);
    let a_init = wallet.spendable_init(rng, &a_spend, &pool, cm_height);
    let a_sp = wallet.lift_over_creation_epoch(rng, &pool, &a_spend, cm_height, a_init);
    let b_init = wallet.spendable_init(rng, &b_spend, &pool, cm_height);
    let b_sp = wallet.lift_over_creation_epoch(rng, &pool, &b_spend, cm_height, b_init);
    let anchor = based_sp.data().2;
    assert_eq!(anchor, a_sp.data().2, "lifts land on a common anchor");
    assert_eq!(anchor, b_sp.data().2, "lifts land on a common anchor");

    let spend_epoch = cm_height.epoch().next();
    let mut becomes_based = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(based_spend, based_sp, spend_epoch)],
        alloc::vec![based_output],
    );
    let autonome_a = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(a_spend, a_sp, spend_epoch)],
        alloc::vec![a_output],
    );
    let autonome_b = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(b_spend, b_sp, spend_epoch)],
        alloc::vec![b_output],
    );

    let sighash = mock_sighash(becomes_based.commitment());

    let based_descriptors: BTreeSet<action::Descriptor> = becomes_based
        .actions
        .iter()
        .map(Action::descriptor)
        .collect();
    let descriptors_a: BTreeSet<action::Descriptor> =
        autonome_a.actions.iter().map(Action::descriptor).collect();
    let descriptors_b: BTreeSet<action::Descriptor> =
        autonome_b.actions.iter().map(Action::descriptor).collect();

    let stamp_a = autonome_a.stamp.clone();
    let stamp_b = autonome_b.stamp.clone();

    let innocent_descriptors: BTreeSet<action::Descriptor> =
        descriptors_a.union(&descriptors_b).copied().collect();
    let innocent_stamp = ProofStamp::merge(rng, (stamp_a, descriptors_a), (stamp_b, descriptors_b))
        .expect("innocent merge");

    let based_stamp = ProofStamp::merge(
        rng,
        (becomes_based.stamp, based_descriptors),
        (innocent_stamp, innocent_descriptors),
    )
    .expect("based merge");

    becomes_based.stamp = based_stamp;

    let adjunct_a = autonome_a.strip(mock_wtxid(&becomes_based));
    let adjunct_b = autonome_b.strip(mock_wtxid(&becomes_based));

    becomes_based
        .verify_signatures(&sighash)
        .expect("based aggregate binding sig should verify");

    becomes_based
        .verify_proof(rng, &[adjunct_a.as_dyn(), adjunct_b.as_dyn()])
        .expect("based aggregate proof verifies against its adjuncts");
}

/// The outer `verify` composes coverage, signatures, and proof for an autonome
/// bundle with no adjuncts: the honest bundle passes, and a corrupted binding
/// signature surfaces as `VerificationError::Signatures`.
#[test]
fn autonome_verify_composes_all_checks() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());
    let auth_digest = bundle.auth_digest();

    bundle
        .verify(rng, &sighash, &auth_digest, &[])
        .expect("honest autonome bundle verifies");

    let mut tampered = bundle.clone();
    let mut sig_bytes: [u8; 64] = tampered.binding_sig.0.into();
    sig_bytes[0] ^= 0xFF;
    tampered.binding_sig = Signature(sig_bytes.into());

    let err = tampered
        .verify(rng, &sighash, &auth_digest, &[])
        .expect_err("a corrupted binding signature must fail verification");
    let VerificationError::Signatures(VerifySignaturesError::Binding(_)) = err else {
        panic!("expected Signatures(Binding), got {err:?}");
    };
}

#[test]
fn invalid_action_sig_fails_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let mut bundle = build_autonome(rng, &wallet, 1000, 700);
    let sighash = mock_sighash(bundle.commitment());

    let mut sig_bytes: [u8; 64] = bundle.actions[0].sig.0.into();
    sig_bytes[0] ^= 0xFF;
    let bad_sig = action::Signature(sig_bytes.into());
    bundle.actions[0].sig = bad_sig;

    let err = bundle.verify_signatures(&sighash).unwrap_err();
    let VerifySignaturesError::Action(sig) = err else {
        panic!("expected SignatureError::Action, got {err:?}");
    };
    assert_eq!(sig, bad_sig);
}

#[test]
fn stamped_read_write_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let original = build_autonome(rng, &wallet, 1000, 700);
    let mut buf = Vec::new();
    original.write(&mut buf).expect("write");
    let deserialized = Bundle::<ProofStamp>::read(&*buf).expect("read");

    assert_eq!(original.actions, deserialized.actions);
    assert_eq!(original.value_balance, deserialized.value_balance);
    assert_eq!(original.stamp.tachygrams, deserialized.stamp.tachygrams);
    assert_eq!(original.stamp.anchor, deserialized.stamp.anchor);

    let sighash = mock_sighash(deserialized.commitment());
    deserialized
        .verify_signatures(&sighash)
        .expect("deserialized bundle must verify");
}

#[test]
fn stripped_read_write_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let covering = build_autonome(rng, &wallet, 500, 300);
    let wtxid = mock_wtxid(&covering);
    let stripped = build_autonome(rng, &wallet, 1000, 700).strip(wtxid);

    let mut buf = Vec::new();
    stripped.write(&mut buf).expect("write");
    let deserialized = Bundle::<PointerStamp>::read(&*buf).expect("read");

    assert_eq!(stripped.commitment(), deserialized.commitment());
    assert_eq!(stripped.auth_digest(), deserialized.auth_digest());
    assert_eq!(deserialized.stamp, wtxid);
}

#[test]
fn tachyon_bundle_conversions() {
    // Stamped Ok: actions, value_balance, tachygrams, anchor preserved.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let original = build_autonome(rng, &wallet, 1000, 700);
        let erased: TachyonBundle = original.clone().into();
        let back = Bundle::<ProofStamp>::try_from(erased).expect("stamped variant");

        assert_eq!(original.actions, back.actions);
        assert_eq!(original.value_balance, back.value_balance);
        assert_eq!(original.stamp.tachygrams, back.stamp.tachygrams);
        assert_eq!(original.stamp.anchor, back.stamp.anchor);
    }

    // Stripped Ok: wtxid preserved.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let covering = build_autonome(rng, &wallet, 500, 300);
        let wtxid = mock_wtxid(&covering);
        let stripped = build_autonome(rng, &wallet, 1000, 700).strip(wtxid);

        let erased: TachyonBundle = stripped.clone().into();
        let back = Bundle::<PointerStamp>::try_from(erased).expect("stripped variant");

        assert_eq!(stripped.commitment(), back.commitment());
        assert_eq!(stripped.auth_digest(), back.auth_digest());
        assert_eq!(back.stamp, wtxid);
    }

    // Err: TryFrom rejects the wrong variant in both directions.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let adjunct = build_autonome(rng, &wallet, 1000, 700).strip(mock_wtxid(&stamped));

        let stamped_erased: TachyonBundle = stamped.into();
        Bundle::<PointerStamp>::try_from(stamped_erased).expect_err("stamped is not an adjunct");

        let adjunct_erased: TachyonBundle = adjunct.into();
        Bundle::<ProofStamp>::try_from(adjunct_erased).expect_err("adjunct is not stamped");
    }
}

#[test]
fn tachyon_bundle_wire_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    // Stamped variant (0x01).
    {
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let erased: TachyonBundle = stamped.clone().into();
        let mut buf = Vec::new();
        erased.write(&mut buf).expect("write");
        let decoded = TachyonBundle::read(&*buf).expect("read");
        let back = Bundle::<ProofStamp>::try_from(decoded).expect("stamped variant");

        // Stamp carries a proof and is not PartialEq, so compare fields.
        assert_eq!(stamped.actions, back.actions);
        assert_eq!(stamped.value_balance, back.value_balance);
        assert_eq!(stamped.stamp.tachygrams, back.stamp.tachygrams);
        assert_eq!(stamped.stamp.anchor, back.stamp.anchor);
    }

    // Stripped variant (0x02).
    {
        let covering = build_autonome(rng, &wallet, 500, 300);
        let stripped = build_autonome(rng, &wallet, 1000, 700).strip(mock_wtxid(&covering));
        let erased: TachyonBundle = stripped.clone().into();
        let mut buf = Vec::new();
        erased.write(&mut buf).expect("write");
        let decoded = TachyonBundle::read(&*buf).expect("read");
        let back = Bundle::<PointerStamp>::try_from(decoded).expect("stripped variant");

        assert_eq!(stripped.commitment(), back.commitment());
        assert_eq!(stripped.auth_digest(), back.auth_digest());
    }
}

#[test]
fn aggregate_id_try_from_rejects_zero() {
    PointerStamp::try_from([0u8; 64]).unwrap_err();
}

#[test]
fn wire_state_byte_dispatch() {
    // Garbage state byte: rejected by every reader.
    {
        let buf: &[u8] = &[0x03];
        for err in [
            Bundle::<ProofStamp>::read(buf).expect_err("invalid state byte must be rejected"),
            Bundle::<PointerStamp>::read(buf).expect_err("invalid state byte must be rejected"),
            TachyonBundle::read(buf).expect_err("invalid state byte must be rejected"),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "invalid bundle state");
        }
    }

    // No-bundle (0x00): the enum reader decodes to NoBundle, not an error.
    {
        let buf: &[u8] = &[0x00];
        let decoded = TachyonBundle::read(buf).expect("read");
        assert!(decoded.is_no_bundle(), "0x00 must decode to NoBundle");
    }

    // Valid-but-mismatched state byte: each definite reader rejects the other's.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());

        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let mut stamped_buf = Vec::new();
        stamped.write(&mut stamped_buf).expect("write stamped");

        let adjunct = build_autonome(rng, &wallet, 1000, 700).strip(mock_wtxid(&stamped));
        let mut adjunct_buf = Vec::new();
        adjunct.write(&mut adjunct_buf).expect("write adjunct");

        let adjunct_on_stamped = Bundle::<PointerStamp>::read(&*stamped_buf)
            .expect_err("Adjunct::read must reject a stamped (0x01) buffer");
        assert_eq!(
            adjunct_on_stamped.to_string(),
            "unexpected tachyonBundleState"
        );
        let stamped_on_adjunct = Bundle::<ProofStamp>::read(&*adjunct_buf)
            .expect_err("Stamped::read must reject a stripped (0x02) buffer");
        assert_eq!(
            stamped_on_adjunct.to_string(),
            "unexpected tachyonBundleState"
        );
    }
}

/// Both wire readers must reject the all-zero wtxid trailer for every stripped
/// bundle, innocent or adjunct: the spec requires each to name a covering
/// aggregate. `AggregateId` cannot construct zero, so forge the invalid shape
/// by zeroing the trailer of a valid encoding.
#[test]
fn read_rejects_zero_wtxid() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let covering = build_autonome(rng, &wallet, 500, 300);
    let wtxid = mock_wtxid(&covering);

    // Adjunct (non-empty actions) and innocent (empty actions) both reject.
    let adjunct = {
        let adjunct = build_autonome(rng, &wallet, 1000, 700).strip(wtxid);
        assert!(!adjunct.actions.is_empty());
        adjunct
    };

    let innocent = {
        let plan = Plan::new(alloc::vec![], alloc::vec![]);
        let sighash = mock_sighash(plan.commitment().unwrap());
        let bundle = Bundle {
            actions: alloc::vec![],
            value_balance: value::Balance::ZERO,
            binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
            stamp: wtxid,
        };
        assert!(bundle.actions.is_empty());
        bundle
    };

    for stripped in [adjunct, innocent] {
        let mut buf = Vec::new();
        stripped.write(&mut buf).expect("write");

        // The wtxid is the trailing 64 bytes; zero it to forge the invalid shape.
        for byte in buf.iter_mut().rev().take(64) {
            *byte = 0;
        }

        let adjunct_err =
            Bundle::<PointerStamp>::read(&*buf).expect_err("Adjunct::read must reject zero wtxid");
        assert_eq!(adjunct_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            adjunct_err.to_string(),
            "aggregate id is zero and refers to no aggregate"
        );

        let enum_err =
            TachyonBundle::read(&*buf).expect_err("TachyonBundle::read must reject zero wtxid");
        assert_eq!(enum_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            enum_err.to_string(),
            "aggregate id is zero and refers to no aggregate"
        );
    }
}

/// A stripped innocent (empty actions) remains representable: assigned a
/// nonzero covering wtxid, it serializes and round-trips through both readers.
#[test]
fn innocent_round_trips_with_nonzero_wtxid() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let covering = build_autonome(rng, &wallet, 1000, 700);

    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let innocent = Bundle {
        actions: alloc::vec![],
        value_balance: value::Balance::ZERO,
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        stamp: mock_wtxid(&covering),
    };

    let mut buf = Vec::new();
    innocent.write(&mut buf).expect("write innocent");

    let via_adjunct = Bundle::<PointerStamp>::read(&*buf).expect("Adjunct::read innocent");
    assert_eq!(innocent.commitment(), via_adjunct.commitment());
    assert_eq!(innocent.auth_digest(), via_adjunct.auth_digest());

    let decoded = TachyonBundle::read(&*buf).expect("TachyonBundle::read");
    let via_enum = Bundle::<PointerStamp>::try_from(decoded).expect("adjunct variant");
    assert_eq!(innocent.commitment(), via_enum.commitment());
    assert_eq!(innocent.auth_digest(), via_enum.auth_digest());
}

#[test]
fn auth_digest_invariants() {
    // Stamped vs stripped: distinct auth_digests — the property that makes
    // wtxid discriminate across aggregation forms.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let stamped = build_autonome(rng, &wallet, 1000, 700);

        let covering = build_autonome(rng, &wallet, 500, 300);
        let stripped = stamped.clone().strip(mock_wtxid(&covering));

        assert_eq!(stamped.commitment(), stripped.commitment());
        assert_ne!(stamped.auth_digest(), stripped.auth_digest());
    }

    // wtxid binds: distinct wtxids on otherwise-identical stripped bundles
    // produce distinct digests.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let autonome = build_autonome(rng, &wallet, 1000, 700);

        let covering_a = build_autonome(rng, &wallet, 500, 300);
        let covering_b = build_autonome(rng, &wallet, 800, 600);
        assert_ne!(mock_wtxid(&covering_a), mock_wtxid(&covering_b));

        let stripped_aa = autonome.clone().strip(mock_wtxid(&covering_a));
        let digest_aa = stripped_aa.auth_digest();
        let stripped_bb = autonome.strip(mock_wtxid(&covering_b));
        let digest_bb = stripped_bb.auth_digest();
        assert_ne!(digest_aa, digest_bb);
    }

    // TachyonBundle dispatch matches the concrete-variant methods, for both
    // stamped and stripped.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let stamped_direct = stamped.auth_digest();
        let covering_wtxid = mock_wtxid(&stamped);
        let erased: TachyonBundle = stamped.into();
        assert_eq!(erased.auth_digest(), stamped_direct);

        let wallet2 = WalletSim::new(shared_sk());
        let stripped = build_autonome(rng, &wallet2, 1000, 700).strip(covering_wtxid);
        let stripped_direct = stripped.auth_digest();
        let erased_stripped: TachyonBundle = stripped.into();
        assert_eq!(erased_stripped.auth_digest(), stripped_direct);
    }

    // The proof stamp's digest commits its contents: perturbing the carried
    // covered-actions digest or the tachygram set changes the auth_digest.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let wallet = WalletSim::new(shared_sk());
        let stamped = build_autonome(rng, &wallet, 1000, 700);
        let baseline = stamped.auth_digest();
        let baseline_commitment = stamped.commitment();

        let mut altered_actions = stamped.clone();
        altered_actions.stamp.coverage[0] ^= 0x01;
        // the commitment does not reach into the stamp: only auth_digest moves.
        assert_eq!(baseline_commitment, altered_actions.commitment());
        assert_ne!(baseline, altered_actions.auth_digest());

        let mut extra_tachygram = stamped;
        extra_tachygram
            .stamp
            .tachygrams
            .insert(Tachygram::from(Fp::from(7u64)));
        // Tachygrams must stay canonically sorted for the stamp digest.
        assert_eq!(baseline_commitment, extra_tachygram.commitment());
        assert_ne!(baseline, extra_tachygram.auth_digest());
    }
}

/// Coverage-check protocol: an observer reconstructs the covered-actions
/// digest from a based aggregate's own actions plus all covered adjuncts'
/// visible actions, and checks it against the stamped aggregate's
/// serialized `hStampActionsTachyon`.
#[test]
fn coverage_check_matches_stamp_actions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);

    let based_spend = wallet.random_note(800);
    let based_output = wallet.random_note(400);
    let a_spend = wallet.random_note(1000);
    let a_output = wallet.random_note(700);
    let b_spend = wallet.random_note(500);
    let b_output = wallet.random_note(200);

    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(
        rng,
        &[
            vec![based_spend.commitment()],
            vec![a_spend.commitment()],
            vec![b_spend.commitment()],
        ],
        50,
    ));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let based_init = wallet.spendable_init(rng, &based_spend, &pool, cm_height);
    let based_sp = wallet.lift_over_creation_epoch(rng, &pool, &based_spend, cm_height, based_init);
    let a_init = wallet.spendable_init(rng, &a_spend, &pool, cm_height);
    let a_sp = wallet.lift_over_creation_epoch(rng, &pool, &a_spend, cm_height, a_init);
    let b_init = wallet.spendable_init(rng, &b_spend, &pool, cm_height);
    let b_sp = wallet.lift_over_creation_epoch(rng, &pool, &b_spend, cm_height, b_init);
    let anchor = based_sp.data().2;

    let spend_epoch = cm_height.epoch().next();
    let mut becomes_based = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(based_spend, based_sp, spend_epoch)],
        alloc::vec![based_output],
    );
    let autonome_a = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(a_spend, a_sp, spend_epoch)],
        alloc::vec![a_output],
    );
    let autonome_b = wallet.autonome(
        rng,
        anchor,
        alloc::vec![(b_spend, b_sp, spend_epoch)],
        alloc::vec![b_output],
    );

    let based_descriptors: BTreeSet<action::Descriptor> = becomes_based
        .actions
        .iter()
        .map(Action::descriptor)
        .collect();
    let descriptors_a: BTreeSet<action::Descriptor> =
        autonome_a.actions.iter().map(Action::descriptor).collect();
    let descriptors_b: BTreeSet<action::Descriptor> =
        autonome_b.actions.iter().map(Action::descriptor).collect();

    let stamp_a = autonome_a.stamp.clone();
    let stamp_b = autonome_b.stamp.clone();

    let innocent_descriptors: BTreeSet<action::Descriptor> =
        descriptors_a.union(&descriptors_b).copied().collect();
    let innocent_stamp = ProofStamp::merge(rng, (stamp_a, descriptors_a), (stamp_b, descriptors_b))
        .expect("innocent merge");

    let based_stamp = ProofStamp::merge(
        rng,
        (becomes_based.stamp, based_descriptors),
        (innocent_stamp, innocent_descriptors),
    )
    .expect("based merge");
    becomes_based.stamp = based_stamp;

    let adjunct_a = autonome_a.strip(mock_wtxid(&becomes_based));
    let adjunct_b = autonome_b.strip(mock_wtxid(&becomes_based));

    // Coverage confirmation: the based aggregate's carried digest matches
    // its own actions plus both covered adjuncts'.
    assert!(
        becomes_based.covers(&[&adjunct_a, &adjunct_b]),
        "full covered set matches hStampActionsTachyon"
    );

    // Missing an adjunct: fewer descriptors, no match.
    assert!(
        !becomes_based.covers(&[&adjunct_a]),
        "missing adjunct must mismatch"
    );

    // Extra (duplicated) adjunct: more descriptors, no match.
    assert!(
        !becomes_based.covers(&[&adjunct_a, &adjunct_b, &adjunct_a]),
        "extra adjunct must mismatch"
    );
}

/// A stamp whose tachygrams are not in canonical order is rejected on read,
/// matching the order the stamp digest commits to.
#[test]
fn read_rejects_noncanonical_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let bundle = build_autonome(rng, &wallet, 1000, 700);
    let n = bundle.stamp.tachygrams.len();
    assert!(n >= 2, "need at least two tachygrams to permute");

    let mut buf = Vec::new();
    bundle.write(&mut buf).expect("write");

    // The stamp's proof is the constant-size trailer; the n 32-byte tachygrams
    // sit immediately before it. A BTreeSet always serializes canonically, so
    // forge a non-canonical encoding by swapping the first and last tachygram
    // blocks directly in the buffer.
    let end = buf.len() - PROOF_SIZE_COMPRESSED;
    let first = end - n * 32;
    let last = end - 32;
    let (head, tail) = buf.split_at_mut(last);
    head[first..first + 32].swap_with_slice(&mut tail[..32]);

    let err =
        Bundle::<ProofStamp>::read(&*buf).expect_err("non-canonical tachygrams must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(err.to_string(), "tachygrams are not canonically sorted");
}

/// Build a spend action plan without a pool/anchor: `Plan::spend`'s
/// `derive_rk` closure recomputes alpha internally, so only `ask` is needed
/// to derive a matching `rk`.
fn spend_plan_at(
    rng: &mut StdRng,
    wallet: &WalletSim,
    ask: &private::SpendAuthorizingKey,
    value: u64,
) -> action::Plan<effect::Spend> {
    let note = wallet.random_note(value);
    let (rcv, theta, _alpha) = spend_witness(rng, &note);
    action::Plan::spend(note, theta, rcv, |alpha| {
        ask.derive_action_private(&alpha).derive_action_public()
    })
}

#[test]
fn plan_value_balance_accepts_boundary_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let spend = spend_plan_at(rng, &wallet, &ask, MAX_MONEY);
    let bundle_plan = Plan::new(alloc::vec![spend], alloc::vec![]);

    assert_eq!(
        bundle_plan.value_balance(),
        Ok(value::Balance::try_from(i64::try_from(MAX_MONEY).unwrap()).unwrap())
    );
}

#[test]
fn plan_value_balance_accepts_boundary_negative_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let note = wallet.random_note(MAX_MONEY);
    let (_rcv, _alpha, output) = build_output_plan(rng, note);
    let bundle_plan = Plan::new(alloc::vec![], alloc::vec![output]);

    assert_eq!(
        bundle_plan.value_balance(),
        Ok(value::Balance::try_from(-i64::try_from(MAX_MONEY).unwrap()).unwrap())
    );
}

#[test]
fn plan_value_balance_rejects_overflow_above_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let spend_a = spend_plan_at(rng, &wallet, &ask, MAX_MONEY);
    let spend_b = spend_plan_at(rng, &wallet, &ask, MAX_MONEY);
    let bundle_plan = Plan::new(alloc::vec![spend_a, spend_b], alloc::vec![]);

    assert_eq!(bundle_plan.value_balance(), Err(value::OutOfRange));
    {
        let err = bundle_plan.commitment().unwrap_err();
        assert_eq!(err, value::OutOfRange);
    }
    let sighash = [0u8; 32];
    {
        let err = bundle_plan.sign(rng, &sighash, &ask).unwrap_err();
        assert_eq!(err, PlanError::BalanceOverflow);
    }
}

#[test]
fn plan_value_balance_rejects_overflow_below_negative_max_money() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let note_a = wallet.random_note(MAX_MONEY);
    let note_b = wallet.random_note(MAX_MONEY);
    let (_, _, output_a) = build_output_plan(rng, note_a);
    let (_, _, output_b) = build_output_plan(rng, note_b);
    let bundle_plan = Plan::new(alloc::vec![], alloc::vec![output_a, output_b]);

    assert_eq!(bundle_plan.value_balance(), Err(value::OutOfRange));
    {
        let err = bundle_plan.commitment().unwrap_err();
        assert_eq!(err, value::OutOfRange);
    }
    let sighash = [0u8; 32];
    {
        let err = bundle_plan.sign(rng, &sighash, &ask).unwrap_err();
        assert_eq!(err, PlanError::BalanceOverflow);
    }
}

#[test]
fn read_accepts_value_balance_at_max_money_boundaries() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_money = i64::try_from(MAX_MONEY).unwrap();

    for value_balance in [max_money, -max_money] {
        let vb = value::Balance::try_from(value_balance).unwrap();
        let mut bundle = build_autonome(rng, &wallet, 1000, 700);
        bundle.value_balance = vb;

        let mut buf = Vec::new();
        bundle.write(&mut buf).expect("write");
        let decoded = Bundle::<ProofStamp>::read(&*buf).expect("read must accept boundary balance");
        assert_eq!(decoded.value_balance, vb);
    }
}

/// `value::Balance::try_from` cannot construct an out-of-range value at all, so
/// this forges the invalid shape directly on the wire: `valueBalanceTachyon` is
/// the 8 bytes right after the 1-byte state tag (see the module-level wire
/// format documentation), mirroring `read_rejects_zero_wtxid`'s approach of
/// overwriting valid-encoding bytes to build an otherwise-unconstructible
/// input.
#[test]
fn read_rejects_value_balance_out_of_range() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_money = i64::try_from(MAX_MONEY).unwrap();

    for value_balance in [max_money + 1, -max_money - 1] {
        let bundle = build_autonome(rng, &wallet, 1000, 700);

        let mut buf = Vec::new();
        bundle.write(&mut buf).expect("write");
        buf[1..9].copy_from_slice(&value_balance.to_le_bytes());

        let stamp_err = Bundle::<ProofStamp>::read(&*buf)
            .expect_err("Bundle::<ProofStamp>::read must reject out-of-range value balance");
        assert_eq!(stamp_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(stamp_err.to_string(), "value balance out of range");

        let enum_err = TachyonBundle::read(&*buf)
            .expect_err("TachyonBundle::read must reject out-of-range value balance");
        assert_eq!(enum_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(enum_err.to_string(), "value balance out of range");
    }
}

#[test]
fn read_rejects_zero_actions_with_nonzero_balance() {
    let rng = &mut StdRng::seed_from_u64(0);
    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let bundle = Bundle {
        actions: alloc::vec![],
        value_balance: value::Balance::try_from(1).unwrap(),
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        stamp: PointerStamp::try_from([0x42u8; 64]).expect("nonzero id"),
    };

    let mut buf = Vec::new();
    bundle.write(&mut buf).expect("write");

    let adjunct_err = Bundle::<PointerStamp>::read(&*buf)
        .expect_err("Adjunct::read must reject zero actions with nonzero balance");
    assert_eq!(adjunct_err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        adjunct_err.to_string(),
        "bundle with no actions must have zero value balance"
    );

    let enum_err = TachyonBundle::read(&*buf)
        .expect_err("TachyonBundle::read must reject zero actions with nonzero balance");
    assert_eq!(enum_err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        enum_err.to_string(),
        "bundle with no actions must have zero value balance"
    );
}

/// Every construction path guarantees "no actions implies zero value
/// balance", so a violation here can only come from a hand-constructed
/// `Bundle` that bypasses `Plan`/`read`. `verify_signatures` has no special
/// case for it: the binding signature was produced for the real (zero)
/// balance, so it simply fails to validate against the `bvk` recomputed from
/// the forged nonzero balance.
#[test]
fn zero_action_bundle_rejects_nonzero_balance() {
    let rng = &mut StdRng::seed_from_u64(0);
    let plan = Plan::new(alloc::vec![], alloc::vec![]);
    let sighash = mock_sighash(plan.commitment().unwrap());

    let bundle = Bundle {
        actions: alloc::vec![],
        value_balance: value::Balance::try_from(1).unwrap(),
        binding_sig: plan.derive_bsk_private().sign(rng, &sighash),
        stamp: PointerStamp::try_from([1u8; 64]).expect("nonzero id"),
    };

    let err = bundle.verify_signatures(&sighash).unwrap_err();
    let VerifySignaturesError::Binding(_) = err else {
        panic!("expected SignatureError::Binding, got {err:?}");
    };
}
