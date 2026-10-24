//! Bundles: planning and signing, `verify_signatures`, and the `verify`
//! composition over autonomes and aggregates, with its failure surfaces.

extern crate alloc;

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::iter;

use corez::io;
use ff::Field as _;
use pasta_curves::Fp;
use proptest::{collection::vec, option, prelude::*, sample::Index};
use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, ActionSetPoly, Anchor, BlockHeight, Bundle, SignatureError, Tachygram,
    TachygramSetCommit, TachygramSetPoly, VerificationError, VerifyCoverageError,
    VerifyPointersError, VerifyTachygramsError, action,
    bundle::{self, Signature},
    constants::MAX_MONEY,
    digest::blake2b,
    effect,
    entropy::ActionEntropy,
    fee,
    keys::private,
    note::Note,
    stamp::{
        self, PointerStamp, ProofStamp, StampState,
        proof::{
            PROOF_SYSTEM, output,
            stamp::{Actions, FeeFuse, OutputAction},
        },
    },
    value, witness,
};

use crate::{
    fixtures::{
        PoolSim, WalletSim, build_lift_span, build_output_plan, fee_digests,
        forge_overlapping_merge, mock_sighash, mock_wtxid, random_block, random_block_with,
        shared_sk, stamp_coverage,
    },
    strategies::check,
};

/// `amount` zatoshis.
fn zat(amount: u64) -> value::Positive {
    value::Positive::try_from(amount).expect("amount in range")
}

/// A maximum fee and a fee within it.
fn fees() -> impl Strategy<Value = (u64, u64)> {
    (0..=MAX_MONEY).prop_flat_map(|max_fee| (Just(max_fee), 0..=max_fee))
}

/// A spend of `note` whose `rk` derives from `ask`.
fn spend_of(
    rng: &mut StdRng,
    ask: &private::SpendAuthorizingKey,
    note: Note,
) -> action::Plan<effect::Spend> {
    action::Plan::spend(
        note,
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
        |alpha| ask.derive_action_private(&alpha).derive_action_public(),
    )
}

/// A signed bundle of `wallet`'s outputs of `amounts` and a max fee note of
/// `max_fee`, proved at `anchor` paying `fee`.
fn output_bundle(
    rng: &mut StdRng,
    wallet: &WalletSim,
    anchor: Anchor,
    amounts: &[u64],
    (max_fee, fee): (u64, u64),
) -> Bundle<ProofStamp> {
    let notes = amounts
        .iter()
        .map(|&amount| wallet.random_note(amount))
        .collect();
    let (plan, signed, pcds) = wallet.signed(rng, vec![], notes, wallet.random_note(max_fee));
    let proved = plan
        .stamp_plan(anchor, zat(fee))
        .prove(rng, &wallet.pak, pcds)
        .expect("prove the bundle's stamp");
    signed.stamp(proved)
}

/// The stamp of `bundle` with the descriptors and fees it covers together
/// with `adjuncts`, the form `ProofStamp::merge` takes.
fn merge_side(
    bundle: &Bundle<ProofStamp>,
    adjuncts: &[&Bundle<dyn StampState>],
) -> (
    ProofStamp,
    BTreeSet<action::Descriptor>,
    BTreeSet<fee::Descriptor>,
) {
    let members = || iter::once(bundle.as_dyn()).chain(adjuncts.iter().copied());
    (
        bundle.stamp.clone(),
        members().flat_map(Bundle::descriptors).collect(),
        members().map(Bundle::fee_descriptor).collect(),
    )
}

/// The coverage digest of `bundles`' descriptors and fees.
fn coverage_of(bundles: &[&Bundle<dyn StampState>]) -> [u8; 32] {
    let mut descriptors: Vec<[u8; 64]> = bundles
        .iter()
        .flat_map(|bundle| bundle.descriptors())
        .collect();
    descriptors.sort_unstable();
    let fees: Vec<fee::Descriptor> = bundles
        .iter()
        .map(|bundle| bundle.fee_descriptor())
        .collect();
    stamp_coverage(&descriptors, &fees)
}

/// `bundle` verified alone, against its own sighash and wtxid.
fn verify_alone(rng: &mut StdRng, bundle: &Bundle<ProofStamp>) -> Result<(), VerificationError> {
    bundle.verify(
        rng,
        &mock_sighash(bundle.commitment()),
        &mock_wtxid(bundle).into(),
        &[],
    )
}

/// The bytes `write` produces with the first one flipped, read back by
/// `read`.
fn flipped<T>(
    write: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
    read: impl FnOnce(&[u8]) -> io::Result<T>,
) -> T {
    let mut bytes = Vec::new();
    write(&mut bytes).expect("write");
    bytes[0] ^= 0xFF;
    read(&bytes).expect("read")
}

/// The planned value balance is the spends less the outputs and the maximum
/// fee, at the `±MAX_MONEY` boundaries too. `sign` signs any plan, one-sided
/// and empty ones and a note spent under two randomizations included, into a
/// bundle carrying the plan's commitment, balance, descriptors and memo, whose
/// signatures verify; `apply_signatures` given the same signatures builds the
/// same bundle.
#[test]
fn signing_produces_the_planned_bundle() {
    let amounts = || vec(0..=MAX_MONEY / 8, 0..=2);
    let strategy = (
        any::<u64>(),
        (amounts(), amounts(), 0..=MAX_MONEY / 8),
        option::of(any::<bool>()),
        any::<bool>(),
        vec(any::<u8>(), 0..=96),
    );
    check(32, strategy, |(seed, drawn, boundary, respend, memo)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let (spend_amounts, output_amounts, max_fee) = match boundary {
            Some(true) => (vec![MAX_MONEY], vec![], 0),
            Some(false) => (vec![], vec![MAX_MONEY], 0),
            None => drawn,
        };
        let wallet = WalletSim::random(rng);
        let ask = wallet.sk.derive_auth_private();
        let spent: Vec<Note> = spend_amounts
            .iter()
            .map(|&amount| wallet.random_note(amount))
            .collect();
        let mut spends: Vec<action::Plan<effect::Spend>> = spent
            .iter()
            .map(|&note| spend_of(rng, &ask, note))
            .collect();
        if respend && boundary.is_none() && !spent.is_empty() {
            spends.push(spend_of(rng, &ask, spent[0]));
        }
        let outputs: Vec<action::Plan<effect::Output>> = output_amounts
            .iter()
            .map(|&amount| build_output_plan(rng, wallet.random_note(amount)).2)
            .collect();
        let expected = value::Balance::try_from(
            spends
                .iter()
                .map(|plan| i128::from(plan.note.value))
                .sum::<i128>()
                - outputs
                    .iter()
                    .map(|plan| i128::from(plan.note.value))
                    .sum::<i128>()
                - i128::from(max_fee),
        )
        .expect("balance in range");

        let plan = bundle::Plan::new(spends.clone(), outputs.clone(), wallet.random_note(max_fee))
            .with_memo(memo.clone());
        prop_assert_eq!(plan.value_balance(), Ok(expected));
        let sighash = mock_sighash(plan.commitment().expect("commitment"));
        let signed = plan.sign(rng, &sighash, &ask).expect("sign");
        prop_assert_eq!(signed.commitment(), plan.commitment().expect("commitment"));
        prop_assert_eq!(signed.value_balance, expected);
        prop_assert_eq!(&signed.memo, &memo);
        prop_assert_eq!(signed.actions.len(), spends.len() + outputs.len());
        prop_assert_eq!(
            signed.descriptors().collect::<BTreeSet<_>>(),
            plan.descriptors()
        );
        prop_assert!(signed.verify_signatures(&sighash).is_ok());

        let authorized: BTreeMap<action::Descriptor, action::Signature> = signed
            .actions
            .iter()
            .map(|act| (act.descriptor(), act.sig))
            .collect();
        let applied = plan
            .apply_signatures(rng, &sighash, authorized)
            .expect("apply the signatures");
        prop_assert_eq!(applied.commitment(), signed.commitment());
        prop_assert!(applied.verify_signatures(&sighash).is_ok());
        Ok(())
    });
}

/// `verify_signatures` names the binding signature for a tampered value
/// balance, permuted actions, a corrupted binding signature and a
/// zero-action bundle claiming a balance; and names an action signature for
/// signatures shuffled among the actions, an output signed under a key other
/// than its `rk`, a spend signed by another wallet and a corrupted action
/// signature. Stripping the stamp keeps the signatures valid.
#[test]
fn signature_tampering_fails_verify_signatures() {
    let strategy = (any::<u64>(), 1usize..=2, any::<Index>());
    check(16, strategy, |(seed, output_count, at)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::random(rng);
        let ask = wallet.sk.derive_auth_private();
        let max_fee_note = wallet.random_note(100);
        let spend = spend_of(rng, &ask, wallet.random_note(1000));
        let outputs: Vec<action::Plan<effect::Output>> =
            iter::repeat_with(|| build_output_plan(rng, wallet.random_note(200)).2)
                .take(output_count)
                .collect();
        let plan = bundle::Plan::new(vec![spend], outputs.clone(), max_fee_note);
        let sighash = mock_sighash(plan.commitment().expect("commitment"));
        let signed = plan.sign(rng, &sighash, &ask).expect("sign");
        let own_sighash = |tampered: &Bundle<_>| mock_sighash(tampered.commitment());
        let binding_fails = |result: Result<(), SignatureError>| {
            let Err(SignatureError::Binding(_)) = result else {
                panic!("expected a binding signature failure, got {result:?}");
            };
        };
        let action_fails = |result: Result<(), SignatureError>| {
            let Err(SignatureError::Action(sig)) = result else {
                panic!("expected an action signature failure, got {result:?}");
            };
            sig
        };

        let mut rebalanced = signed.clone();
        rebalanced.value_balance =
            value::Balance::try_from(i64::from(signed.value_balance) + 1).expect("in range");
        binding_fails(rebalanced.verify_signatures(&own_sighash(&rebalanced)));
        binding_fails(rebalanced.verify_signatures(&sighash));

        let mut permuted = signed.clone();
        permuted.actions.swap(0, 1);
        binding_fails(permuted.verify_signatures(&own_sighash(&permuted)));

        let mut rebound = signed.clone();
        rebound.binding_sig = flipped(
            |bytes| signed.binding_sig.write(bytes),
            |mut bytes| Signature::read(&mut bytes),
        );
        binding_fails(rebound.verify_signatures(&sighash));

        let empty_plan = bundle::Plan::new(vec![], vec![], wallet.random_note(0));
        let empty_sighash = mock_sighash(empty_plan.commitment().expect("commitment"));
        let mut claiming = empty_plan.sign(rng, &empty_sighash, &ask).expect("sign");
        claiming.value_balance = value::Balance::try_from(1i64).expect("in range");
        binding_fails(claiming.verify_signatures(&empty_sighash));

        let mut sigs: Vec<action::Signature> = signed.actions.iter().map(|act| act.sig).collect();
        sigs.reverse();
        let shuffled = plan
            .apply_signatures(
                rng,
                &sighash,
                plan.descriptors().into_iter().zip(sigs).collect(),
            )
            .expect("assembly takes any pairing");
        action_fails(shuffled.verify_signatures(&sighash));

        let mut rekeyed = outputs;
        rekeyed[0].rk = build_output_plan(rng, wallet.random_note(50)).2.rk;
        let rekeyed_plan = bundle::Plan::new(vec![spend], rekeyed, max_fee_note);
        let rekeyed_sighash = mock_sighash(rekeyed_plan.commitment().expect("commitment"));
        let misdirected = rekeyed_plan
            .sign(rng, &rekeyed_sighash, &ask)
            .expect("sign");
        action_fails(misdirected.verify_signatures(&rekeyed_sighash));

        let stranger = WalletSim::random(rng).sk.derive_auth_private();
        let forged = plan.sign(rng, &sighash, &stranger).expect("sign");
        action_fails(forged.verify_signatures(&sighash));

        let mut corrupted = signed.clone();
        let index = at.index(corrupted.actions.len());
        let bad_sig = flipped(
            |bytes| signed.actions[index].sig.write(bytes),
            |mut bytes| action::Signature::read(&mut bytes),
        );
        corrupted.actions[index].sig = bad_sig;
        prop_assert_eq!(action_fails(corrupted.verify_signatures(&sighash)), bad_sig);

        let stamped = signed.stamp(ProofStamp {
            coverage: [0; 32],
            anchor: Anchor::default(),
            tachygram_set: TachygramSetCommit::default(),
            tachygrams: BTreeSet::new(),
            proof: Box::new(Proof::trivial()),
            fee: value::Positive::ZERO,
        });
        let covering = mock_wtxid(&stamped);
        prop_assert!(stamped.strip(covering).verify_signatures(&sighash).is_ok());
        Ok(())
    });
}

/// An autonome of any spends and outputs, none included, verifies alone and
/// covers exactly its actions and fee. The fee is chosen after signing, up to
/// the maximum: the commitment and the binding signature do not depend on
/// it, the stamp publishes two tachygrams per action and the fee change note,
/// and the auth digest differs between fees. The bundle round-trips through
/// the wire and still verifies.
#[test]
fn autonome_lifecycle() {
    let fee_pair =
        (0..=MAX_MONEY).prop_flat_map(|max_fee| (Just(max_fee), 0..=max_fee, 0..=max_fee));
    let strategy = (any::<u64>(), any::<bool>(), 0usize..=2, fee_pair);
    check(10, strategy, |(seed, spending, outputs, drawn_fees)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::new(shared_sk());
        let actions = usize::from(spending) + outputs;
        let (max_fee, first_fee, second_fee) = if actions == 0 { (0, 0, 0) } else { drawn_fees };
        let mut pool = PoolSim::genesis(rng);
        let spent = wallet.random_note(1000);
        let spends = if spending {
            pool.mine(random_block_with(rng, &[vec![spent.commitment()]], 1));
            vec![(spent, wallet.fresh_spend(rng, &pool, pool.height(), &spent))]
        } else {
            vec![]
        };
        let anchor = pool.anchor();
        let output_notes = iter::repeat_with(|| wallet.random_note(300))
            .take(outputs)
            .collect();
        let max_fee_note = wallet.random_note(max_fee);
        let (plan, signed, pcds) = wallet.signed(rng, spends, output_notes, max_fee_note);
        let prove = |prove_rng: &mut StdRng, fee| {
            signed.clone().stamp(
                plan.stamp_plan(anchor, zat(fee))
                    .prove(prove_rng, &wallet.pak, pcds.clone())
                    .expect("prove"),
            )
        };

        let first = prove(rng, first_fee);
        let second = prove(rng, second_fee);
        for (proved, fee) in [(&first, first_fee), (&second, second_fee)] {
            prop_assert_eq!(proved.commitment(), signed.commitment());
            prop_assert_eq!(proved.binding_sig, signed.binding_sig);
            prop_assert_eq!(proved.stamp.fee, zat(fee));
            prop_assert_eq!(proved.stamp.tachygrams.len(), 2 * actions + 1);
            prop_assert!(proved.is_autonome());
            let (covered, covered_fees) = proved.verify_coverage(&[], &[]).expect("coverage");
            prop_assert_eq!(covered, plan.descriptors());
            prop_assert_eq!(covered_fees, BTreeSet::from([proved.fee_descriptor()]));
            prop_assert!(verify_alone(rng, proved).is_ok());
        }
        prop_assert_eq!(
            first.auth_digest() == second.auth_digest(),
            first_fee == second_fee
        );

        let mut bytes = Vec::new();
        first.write(&mut bytes).expect("write");
        let decoded = Bundle::<ProofStamp>::read(&*bytes).expect("read");
        prop_assert_eq!(decoded.auth_digest(), first.auth_digest());
        prop_assert!(verify_alone(rng, &decoded).is_ok());
        Ok(())
    });
}

/// A wire-valid bundle repeating one action, its balance and binding key
/// doubled to match and its coverage forged over the repeat, passes the
/// signature check and `is_autonome`, and is rejected by `verify_coverage`
/// and by `verify` as `DuplicateActions`; the proof does not verify against
/// the repeated multiset either. The stamp is either an honest single-action
/// stamp or a forced merge of that stamp with itself.
#[test]
fn duplicated_actions_fail_coverage() {
    let strategy = (any::<u64>(), any::<bool>(), 1..=MAX_MONEY / 2);
    check(6, strategy, |(seed, spending, amount)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::new(shared_sk());
        let note = wallet.random_note(amount);
        let max_fee_note = wallet.random_note(0);
        let fee_max_commitment = max_fee_note.fee_blind().commit(-max_fee_note.value);
        let fee_desc = fee::Descriptor {
            max_commitment: fee_max_commitment,
            value: value::Positive::ZERO,
        };
        let (rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
        let ask = wallet.sk.derive_auth_private();
        let sighash_of = |descriptor: action::Descriptor, balance: i128| {
            mock_sighash(blake2b::bundle_commitment(
                &blake2b::action_descriptor_digest(&Vec::<[u8; 64]>::from_iter([
                    descriptor, descriptor,
                ])),
                i64::try_from(balance).expect("balance fits"),
                &fee_max_commitment.into(),
                &blake2b::memo_digest(&[]),
            ))
        };

        let (descriptor, sig, doubled_plan, honest_stamp, balance, fees) = if spending {
            let mut pool = PoolSim::genesis(rng);
            pool.mine(random_block_with(rng, &[vec![note.commitment()]], 1));
            let spendable = wallet.fresh_spend(rng, &pool, pool.height(), &note);
            let anchor = spendable.data().2;
            let plan = action::Plan::spend(note, theta, rcv, |alpha| {
                wallet.pak.ak.derive_action_public(&alpha)
            });
            let secret = wallet.secret_pcd(rng, note);
            let proved = bundle::Plan::new(vec![plan], vec![], max_fee_note)
                .stamp_plan(anchor, value::Positive::ZERO)
                .prove(rng, &wallet.pak, vec![(secret, spendable, vec![])])
                .expect("prove the single spend");
            let alpha = theta.randomizer::<effect::Spend>(note.commitment());
            let balance = 2 * i128::from(amount);
            let sighash = sighash_of(plan.descriptor(), balance);
            (
                plan.descriptor(),
                ask.derive_action_private(&alpha).sign(rng, &sighash),
                bundle::Plan::new(vec![plan, plan], vec![], max_fee_note),
                proved,
                balance,
                vec![fee_desc],
            )
        } else {
            let anchor = PoolSim::genesis(rng).anchor();
            let plan = action::Plan::output(note, theta, rcv);
            let single = stamp::Plan::new(
                vec![],
                vec![(plan.descriptor(), theta, note, rcv)],
                anchor,
                max_fee_note,
                value::Positive::ZERO,
            )
            .prove(rng, &wallet.pak, vec![])
            .expect("prove the single output");
            let doubled_pcd = forge_overlapping_merge(
                rng,
                (&single, &vec![plan.descriptor()], &[fee_desc]),
                (&single, &vec![plan.descriptor()], &[fee_desc]),
            );
            let alpha = theta.randomizer::<effect::Output>(note.commitment());
            let balance = -2 * i128::from(amount);
            let sighash = sighash_of(plan.descriptor(), balance);
            (
                plan.descriptor(),
                private::ActionSigningKey::new(&alpha).sign(rng, &sighash),
                bundle::Plan::new(vec![], vec![plan, plan], max_fee_note),
                ProofStamp {
                    anchor: doubled_pcd.data().2,
                    proof: Box::new(doubled_pcd.proof().clone()),
                    ..single
                },
                balance,
                vec![fee_desc, fee_desc],
            )
        };

        let sighash = sighash_of(descriptor, balance);
        let repeated = action::Action::from((descriptor, sig));
        let duplicated = Bundle {
            actions: vec![repeated, repeated],
            value_balance: value::Balance::try_from(balance).expect("in range"),
            fee_max_commitment,
            binding_sig: doubled_plan.derive_bsk_private().sign(rng, &sighash),
            memo: Vec::new(),
            stamp: ProofStamp {
                coverage: stamp_coverage(
                    &Vec::<[u8; 64]>::from_iter([descriptor, descriptor]),
                    &[fee_desc],
                ),
                ..honest_stamp
            },
        };
        let mut bytes = Vec::new();
        duplicated.write(&mut bytes).expect("write");
        let decoded = Bundle::<ProofStamp>::read(&*bytes).expect("a repeated action is wire-valid");

        prop_assert!(decoded.verify_signatures(&sighash).is_ok());
        prop_assert!(decoded.is_autonome());
        let Err(VerifyCoverageError::DuplicateActions) = decoded.verify_coverage(&[], &[]) else {
            panic!("verify_coverage accepted a repeated action");
        };
        let Err(VerificationError::Coverage(VerifyCoverageError::DuplicateActions)) =
            verify_alone(rng, &decoded)
        else {
            panic!("verify accepted a repeated action");
        };
        let digests: Vec<ActionDigest> = decoded
            .descriptors()
            .map(|desc| desc.digest().expect("action digest"))
            .chain(fee_digests(fees))
            .collect();
        prop_assert!(
            !decoded
                .verify_proof(rng, &digests)
                .expect("proof system verification")
        );
        Ok(())
    });
}

/// A stamp without its bundle's fee fails `verify` at coverage, then at
/// tachygram arity once the coverage is forged, then at the proof once the
/// fee change note is forged in. A fee applied twice fails at coverage, then
/// at arity once the coverage is forged, and its proof does not verify against
/// the one fee the bundle publishes.
#[test]
fn missing_fee_fails_verify() {
    let strategy = (
        any::<u64>(),
        (1..=MAX_MONEY / 2).prop_flat_map(|max_fee| (Just(max_fee), 1..=max_fee)),
    );
    check(6, strategy, |(seed, (max_fee, fee))| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::new(shared_sk());
        let max_fee_note = wallet.random_note(max_fee);
        let anchor = PoolSim::genesis(rng).anchor();

        let (rcv, theta, output_plan) = build_output_plan(rng, wallet.random_note(500));
        let (bind, ()) = PROOF_SYSTEM
            .seed(rng, output::OutputBind, (output_plan.note, rcv))
            .expect("OutputBind");
        let (cm, pad, _) = *bind.data();
        let (actions, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                OutputAction,
                witness::output_action((*bind.data(), ()), theta, anchor),
                bind,
                Proof::trivial().carry::<()>(()),
            )
            .expect("OutputAction");
        let plan = bundle::Plan::new(vec![], vec![output_plan], max_fee_note);
        let sighash = mock_sighash(plan.commitment().expect("commitment"));
        let mut fee_less = plan
            .sign(rng, &sighash, &wallet.sk.derive_auth_private())
            .expect("sign")
            .stamp(ProofStamp {
                coverage: stamp_coverage(
                    &Vec::<[u8; 64]>::from_iter([output_plan.descriptor()]),
                    &[],
                ),
                anchor,
                tachygram_set: actions.data().1,
                tachygrams: BTreeSet::from([cm, pad]),
                proof: Box::new(actions.proof().clone()),
                fee: value::Positive::ZERO,
            });
        let Err(VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch)) =
            verify_alone(rng, &fee_less)
        else {
            panic!("a stamp without its fee passed coverage");
        };
        fee_less.stamp.coverage = coverage_of(&[fee_less.as_dyn()]);
        let Err(VerificationError::Tachygrams(VerifyTachygramsError::WrongArity)) =
            verify_alone(rng, &fee_less)
        else {
            panic!("a stamp without its fee change note passed arity");
        };
        fee_less
            .stamp
            .tachygrams
            .insert(Tachygram::from(max_fee_note.commitment()));
        fee_less.stamp.tachygram_set =
            TachygramSetPoly::from_iter(fee_less.stamp.tachygrams.iter().copied()).commit();
        let Err(VerificationError::Disproved) = verify_alone(rng, &fee_less) else {
            panic!("a proof without the fee verified");
        };

        let (fee_plan, signed, pcds, fee_anchor, fee_note) =
            wallet.fee_bundle(rng, 1000, 700, max_fee);
        let once = signed.stamp(
            fee_plan
                .stamp_plan(fee_anchor, zat(fee))
                .prove(rng, &wallet.pak, pcds)
                .expect("prove with the fee"),
        );
        let digests: BTreeSet<ActionDigest> = once
            .descriptors()
            .map(|desc| desc.digest().expect("action digest"))
            .chain([once.fee_descriptor().digest().expect("fee digest")])
            .collect();
        let header = (
            ActionSetPoly::from_iter(digests.iter().copied()).commit(),
            once.stamp.tachygram_set,
            fee_anchor,
        );
        let (twice_pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                FeeFuse,
                witness::fee_fuse(
                    (header, ()),
                    fee_note,
                    value::Positive::ZERO,
                    &digests,
                    &once.stamp.tachygrams,
                ),
                once.stamp.proof.clone().carry::<Actions>(header),
                Proof::trivial().carry::<()>(()),
            )
            .expect("mock ragu permits a recarried child header");
        let mut twice = once;
        *twice.stamp.proof = twice_pcd.proof().clone();
        twice.stamp.tachygram_set = twice_pcd.data().1;
        twice
            .stamp
            .tachygrams
            .insert(Tachygram::from(fee_note.commitment()));
        twice.stamp.coverage = [0; 32];
        let Err(VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch)) =
            verify_alone(rng, &twice)
        else {
            panic!("a second fee passed coverage");
        };
        twice.stamp.coverage = coverage_of(&[twice.as_dyn()]);
        let Err(VerificationError::Tachygrams(VerifyTachygramsError::WrongArity)) =
            verify_alone(rng, &twice)
        else {
            panic!("a second fee change note passed arity");
        };
        let published: Vec<ActionDigest> = digests.into_iter().collect();
        prop_assert!(
            !twice
                .verify_proof(rng, &published)
                .expect("proof system verification")
        );
        Ok(())
    });
}

/// An innocent (zero-action) or based receiver merges two or three
/// fee-bearing adjuncts, one at a time or pre-merged, keeps its own fee, and
/// verifies against them stripped to its wtxid; a parent then absorbs the
/// whole aggregate, the receiver stripped like any adjunct. `verify` reports
/// adjuncts pointing elsewhere, a missing adjunct, a repeated one, one not
/// covered, the receiver itself as an adjunct and an adjunct sharing the
/// receiver's fee descriptor (even under forged coverage), and a published
/// tachygram dropped or substituted.
#[test]
fn aggregation_lifecycle() {
    let strategy = (
        any::<u64>(),
        any::<bool>(),
        2usize..=3,
        any::<bool>(),
        vec(fees(), 5),
        any::<Index>(),
    );
    check(
        6,
        strategy,
        |(seed, based, adjunct_count, premerged, bundle_fees, at)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let wallet = WalletSim::new(shared_sk());
            let anchor = Anchor::from(Fp::random(&mut *rng));
            let mut aggregate = if based {
                output_bundle(rng, &wallet, anchor, &[300], bundle_fees[0])
            } else {
                output_bundle(rng, &wallet, anchor, &[], (0, 0))
            };
            let receiver_fee = aggregate.stamp.fee;
            let adjuncts: Vec<Bundle<ProofStamp>> = (0..adjunct_count)
                .map(|index| output_bundle(rng, &wallet, anchor, &[200], bundle_fees[index + 1]))
                .collect();
            let adjunct_dyns: Vec<&Bundle<dyn StampState>> =
                adjuncts.iter().map(Bundle::as_dyn).collect();

            if premerged {
                let (first, rest) = adjuncts.split_first().expect("adjuncts");
                let mut combined = first.clone();
                for (index, next) in rest.iter().enumerate() {
                    let (stamp, desc, fees) = merge_side(&combined, &adjunct_dyns[1..=index]);
                    combined.stamp = stamp
                        .merge(rng, (desc, fees), merge_side(next, &[]))
                        .expect("merge the adjuncts");
                }
                let (stamp, desc, fees) = merge_side(&aggregate, &[]);
                aggregate.stamp = stamp
                    .merge(rng, (desc, fees), merge_side(&combined, &adjunct_dyns[1..]))
                    .expect("merge into the receiver");
            } else {
                for (index, next) in adjuncts.iter().enumerate() {
                    let (stamp, desc, fees) = merge_side(&aggregate, &adjunct_dyns[..index]);
                    aggregate.stamp = stamp
                        .merge(rng, (desc, fees), merge_side(next, &[]))
                        .expect("merge into the receiver");
                }
            }
            prop_assert_eq!(aggregate.stamp.fee, receiver_fee);
            prop_assert!(aggregate.is_aggregate());
            prop_assert!(aggregate.is_covering(&adjunct_dyns));

            let sighash = mock_sighash(aggregate.commitment());
            let id = mock_wtxid(&aggregate);
            let stripped: Vec<Bundle<PointerStamp>> = adjuncts
                .iter()
                .map(|adjunct| adjunct.clone().strip(id))
                .collect();
            let refs: Vec<&Bundle<PointerStamp>> = stripped.iter().collect();
            let verify = |verify_rng: &mut StdRng,
                          bundle: &Bundle<ProofStamp>,
                          wtxid: [u8; 64],
                          with: &[&Bundle<PointerStamp>]| {
                bundle.verify(verify_rng, &sighash, &wtxid, with)
            };
            prop_assert!(verify(rng, &aggregate, id.into(), &refs).is_ok());

            let Err(VerificationError::Pointers(VerifyPointersError::AdjunctPointerMismatch)) =
                verify(rng, &aggregate, [0x5a; 64], &refs)
            else {
                panic!("adjuncts pointing elsewhere verified");
            };
            prop_assert!(!aggregate.is_covering(&adjunct_dyns[1..]));
            let Err(VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch)) =
                verify(rng, &aggregate, id.into(), &refs[1..])
            else {
                panic!("a missing adjunct verified");
            };
            let repeated: Vec<&Bundle<PointerStamp>> =
                refs.iter().copied().chain([refs[0]]).collect();
            prop_assert!(
                !aggregate.is_covering(
                    &adjunct_dyns
                        .iter()
                        .copied()
                        .chain([adjunct_dyns[0]])
                        .collect::<Vec<_>>()
                )
            );
            let Err(VerificationError::Coverage(VerifyCoverageError::DuplicateActions)) =
                verify(rng, &aggregate, id.into(), &repeated)
            else {
                panic!("a repeated adjunct verified");
            };
            let uncovered = output_bundle(rng, &wallet, anchor, &[100], (0, 0)).strip(id);
            let with_uncovered: Vec<&Bundle<PointerStamp>> =
                refs.iter().copied().chain([&uncovered]).collect();
            let Err(VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch)) =
                verify(rng, &aggregate, id.into(), &with_uncovered)
            else {
                panic!("an uncovered adjunct verified");
            };
            let uncovered_digests: Vec<ActionDigest> = aggregate
                .descriptors()
                .chain(
                    with_uncovered
                        .iter()
                        .flat_map(|adjunct| adjunct.descriptors()),
                )
                .map(|desc| desc.digest().expect("action digest"))
                .chain(fee_digests(
                    iter::once(aggregate.fee_descriptor()).chain(
                        with_uncovered
                            .iter()
                            .map(|adjunct| adjunct.fee_descriptor()),
                    ),
                ))
                .collect();
            prop_assert!(
                !aggregate
                    .verify_proof(rng, &uncovered_digests)
                    .expect("proof system verification")
            );
            let itself = aggregate.clone().strip(id);
            let with_itself: Vec<&Bundle<PointerStamp>> =
                refs.iter().copied().chain([&itself]).collect();
            let Err(VerificationError::Coverage(shared)) =
                verify(rng, &aggregate, id.into(), &with_itself)
            else {
                panic!("the receiver verified as its own adjunct");
            };
            if based {
                let VerifyCoverageError::DuplicateActions = shared else {
                    panic!("expected DuplicateActions, got {shared:?}");
                };
            } else {
                let VerifyCoverageError::DuplicateFees = shared else {
                    panic!("expected DuplicateFees, got {shared:?}");
                };
            }

            let mut fee_sharing = aggregate.clone();
            let mut mimic = adjuncts[0].clone().strip(id);
            mimic.fee_max_commitment = aggregate.fee_max_commitment;
            mimic.stamp.fee = aggregate.stamp.fee;
            let with_mimic: Vec<&Bundle<PointerStamp>> = iter::once(&mimic)
                .chain(refs[1..].iter().copied())
                .collect();
            let Err(VerificationError::Coverage(VerifyCoverageError::DuplicateFees)) =
                verify(rng, &fee_sharing, id.into(), &with_mimic)
            else {
                panic!("a shared fee descriptor verified");
            };
            fee_sharing.stamp.coverage = coverage_of(
                &iter::once(fee_sharing.as_dyn())
                    .chain(with_mimic.iter().map(|adjunct| adjunct.as_dyn()))
                    .collect::<Vec<_>>(),
            );
            let forged_id = mock_wtxid(&fee_sharing);
            let restripped: Vec<Bundle<PointerStamp>> = with_mimic
                .iter()
                .map(|&adjunct| Bundle {
                    stamp: PointerStamp {
                        wtxid: forged_id,
                        fee: adjunct.stamp.fee,
                    },
                    ..adjunct.clone()
                })
                .collect();
            let Err(VerificationError::Coverage(VerifyCoverageError::DuplicateFees)) = verify(
                rng,
                &fee_sharing,
                forged_id.into(),
                &restripped.iter().collect::<Vec<_>>(),
            ) else {
                panic!("a shared fee descriptor verified under forged coverage");
            };

            let published: Vec<Tachygram> = aggregate.stamp.tachygrams.iter().copied().collect();
            let mut dropped = aggregate.clone();
            dropped
                .stamp
                .tachygrams
                .remove(&published[at.index(published.len())]);
            let Err(VerificationError::Tachygrams(VerifyTachygramsError::WrongArity)) =
                verify(rng, &dropped, id.into(), &refs)
            else {
                panic!("a dropped tachygram verified");
            };
            let mut substituted = dropped;
            substituted
                .stamp
                .tachygrams
                .insert(Tachygram::from(Fp::random(&mut *rng)));
            let Err(VerificationError::Tachygrams(VerifyTachygramsError::WrongSet)) =
                verify(rng, &substituted, id.into(), &refs)
            else {
                panic!("a substituted tachygram verified");
            };

            let mut parent = output_bundle(rng, &wallet, anchor, &[150], bundle_fees[4]);
            let covered: Vec<&Bundle<dyn StampState>> = iter::once(aggregate.as_dyn())
                .chain(adjunct_dyns.iter().copied())
                .collect();
            let (stamp, desc, fees) = merge_side(&parent, &[]);
            parent.stamp = stamp
                .merge(rng, (desc, fees), merge_side(&aggregate, &adjunct_dyns))
                .expect("merge the aggregate into a parent");
            prop_assert!(parent.is_covering(&covered));
            let parent_id = mock_wtxid(&parent);
            let parent_adjuncts: Vec<Bundle<PointerStamp>> = iter::once(aggregate.strip(parent_id))
                .chain(adjuncts.into_iter().map(|adjunct| adjunct.strip(parent_id)))
                .collect();
            prop_assert!(
                parent
                    .verify(
                        rng,
                        &mock_sighash(parent.commitment()),
                        &parent_id.into(),
                        &parent_adjuncts.iter().collect::<Vec<_>>(),
                    )
                    .is_ok()
            );
            Ok(())
        },
    );
}

/// A lift moves an autonome's or an aggregate's anchor to the end of the
/// blocks after it, keeps its coverage, and the lifted bundle verifies against
/// its adjuncts stripped to its new wtxid.
#[test]
fn bundle_lift_keeps_coverage_and_verifies() {
    let strategy = (any::<u64>(), 0usize..=2, 1u32..=3, vec(fees(), 3));
    check(6, strategy, |(seed, adjunct_count, blocks, bundle_fees)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::new(shared_sk());
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
        let anchor = pool.anchor();
        let mut lifting = output_bundle(rng, &wallet, anchor, &[300], bundle_fees[0]);
        let adjuncts: Vec<Bundle<ProofStamp>> = (0..adjunct_count)
            .map(|index| output_bundle(rng, &wallet, anchor, &[200], bundle_fees[index + 1]))
            .collect();
        let adjunct_dyns: Vec<&Bundle<dyn StampState>> =
            adjuncts.iter().map(Bundle::as_dyn).collect();
        for (index, next) in adjuncts.iter().enumerate() {
            let (stamp, desc, fees) = merge_side(&lifting, &adjunct_dyns[..index]);
            lifting.stamp = stamp
                .merge(rng, (desc, fees), merge_side(next, &[]))
                .expect("merge into the receiver");
        }
        let adjunct_descs: Vec<action::Descriptor> = adjunct_dyns
            .iter()
            .flat_map(|adjunct| adjunct.descriptors())
            .collect();
        let adjunct_fees: Vec<fee::Descriptor> = adjunct_dyns
            .iter()
            .map(|adjunct| adjunct.fee_descriptor())
            .collect();
        let coverage = lifting
            .verify_coverage(&adjunct_descs, &adjunct_fees)
            .expect("coverage");

        for _ in 0..blocks {
            pool.mine(random_block(rng, 1, 2));
        }
        let span = build_lift_span(rng, &pool, BlockHeight(1)..=pool.height());
        let lifted = lifting.lift(rng, &adjunct_dyns, vec![span]).expect("lift");
        prop_assert_eq!(lifted.stamp.anchor, pool.anchor());
        prop_assert_eq!(
            lifted
                .verify_coverage(&adjunct_descs, &adjunct_fees)
                .expect("coverage survives a lift"),
            coverage
        );
        let id = mock_wtxid(&lifted);
        let stripped: Vec<Bundle<PointerStamp>> = adjuncts
            .into_iter()
            .map(|adjunct| adjunct.strip(id))
            .collect();
        prop_assert!(
            lifted
                .verify(
                    rng,
                    &mock_sighash(lifted.commitment()),
                    &id.into(),
                    &stripped.iter().collect::<Vec<_>>(),
                )
                .is_ok()
        );
        Ok(())
    });
}
