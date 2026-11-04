extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use core::iter;

use corez::io;
use ragu::Pcd;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, Anchor, Bundle, EpochIndex, SignatureError, Tachygram, VerificationError,
    VerifyCoverageError, VerifyPointersError, VerifyTachygramsError, action,
    bundle::{self, Signature},
    constants::MAX_MONEY,
    effect,
    entropy::ActionEntropy,
    fee,
    keys::private,
    note::Note,
    stamp::{PointerStamp, ProofStamp, StampState, proof::spendable},
    value,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_lift_span, build_output_plan, fee_digests, mine_sparse, mock_sighash,
    mock_wtxid, random_block, random_block_with, stamp_coverage,
};

/// Leaves up to 1000 zatoshis of outputs with a balance in range.
const FUNDED_MAX_FEE: u64 = MAX_MONEY - 1000;

const RECEIVER_FEES: (u64, u64) = (FUNDED_MAX_FEE, FUNDED_MAX_FEE / 2);

const ADJUNCT_FEES: [(u64, u64); 3] = [
    (0, 0),
    (FUNDED_MAX_FEE, FUNDED_MAX_FEE),
    (FUNDED_MAX_FEE, 1),
];

fn zat(amount: u64) -> value::Positive {
    value::Positive::try_from(amount).expect("amount in range")
}

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

fn proved_bundle(
    rng: &mut StdRng,
    wallet: &WalletSim,
    anchor: Anchor,
    spends: Vec<(Note, Pcd<spendable::NoteSpendable>)>,
    amounts: &[u64],
    (max_fee, fee): (u64, u64),
) -> Bundle<ProofStamp> {
    let notes = amounts
        .iter()
        .map(|&amount| wallet.random_note(amount))
        .collect();
    let (plan, signed, pcds) = wallet.signed(rng, spends, notes, wallet.random_note(max_fee));
    let proved = plan
        .stamp_plan(anchor, zat(fee))
        .prove(rng, &wallet.pak, pcds)
        .expect("prove the bundle's stamp");
    signed.stamp(proved)
}

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

fn build_aggregate(
    rng: &mut StdRng,
    wallet: &WalletSim,
    pool: &mut PoolSim,
    (based, adjunct_count, premerged): (bool, usize, bool),
    spending: bool,
) -> (Bundle<ProofStamp>, Vec<Bundle<ProofStamp>>) {
    assert!(adjunct_count <= ADJUNCT_FEES.len(), "one fee per adjunct");
    let spenders = if spending {
        usize::from(based) + adjunct_count
    } else {
        0
    };
    let spent: Vec<Note> = iter::repeat_with(|| wallet.random_note(1000))
        .take(spenders)
        .collect();
    if spending {
        pool.mine(random_block_with(
            rng,
            &[spent.iter().map(Note::commitment).collect()],
            1,
        ));
    }
    let height = pool.height();
    let anchor = pool.anchor();
    let mut spends: Vec<(Note, Pcd<spendable::NoteSpendable>)> = spent
        .into_iter()
        .map(|note| (note, wallet.fresh_spend(rng, pool, height, &note)))
        .collect();

    let mut receiver = if based {
        proved_bundle(
            rng,
            wallet,
            anchor,
            spends.pop().into_iter().collect(),
            &[300],
            RECEIVER_FEES,
        )
    } else {
        proved_bundle(rng, wallet, anchor, vec![], &[], (0, 0))
    };
    let adjuncts: Vec<Bundle<ProofStamp>> = ADJUNCT_FEES[..adjunct_count]
        .iter()
        .map(|&fees| {
            proved_bundle(
                rng,
                wallet,
                anchor,
                spends.pop().into_iter().collect(),
                &[200],
                fees,
            )
        })
        .collect();
    let adjunct_dyns: Vec<&Bundle<dyn StampState>> = adjuncts.iter().map(Bundle::as_dyn).collect();

    if premerged {
        let (first, rest) = adjuncts.split_first().expect("adjuncts");
        let mut combined = first.clone();
        for (index, next) in rest.iter().enumerate() {
            let (stamp, desc, fees) = merge_side(&combined, &adjunct_dyns[1..=index]);
            combined.stamp = stamp
                .merge(rng, (desc, fees), merge_side(next, &[]))
                .expect("merge the adjuncts");
        }
        let (stamp, desc, fees) = merge_side(&receiver, &[]);
        receiver.stamp = stamp
            .merge(rng, (desc, fees), merge_side(&combined, &adjunct_dyns[1..]))
            .expect("merge into the receiver");
    } else {
        for (index, next) in adjuncts.iter().enumerate() {
            let (stamp, desc, fees) = merge_side(&receiver, &adjunct_dyns[..index]);
            receiver.stamp = stamp
                .merge(rng, (desc, fees), merge_side(next, &[]))
                .expect("merge into the receiver");
        }
    }
    (receiver, adjuncts)
}

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

fn verify_alone(rng: &mut StdRng, bundle: &Bundle<ProofStamp>) -> Result<(), VerificationError> {
    bundle.verify(
        rng,
        &mock_sighash(bundle.commitment()),
        &mock_wtxid(bundle).into(),
        &[],
    )
}

fn flipped<T>(
    write: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
    read: impl FnOnce(&[u8]) -> io::Result<T>,
) -> T {
    let mut bytes = Vec::new();
    write(&mut bytes).expect("write");
    bytes[0] ^= 0xFF;
    read(&bytes).expect("read")
}

#[test]
fn signing_produces_the_planned_bundle() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (label, spend_amounts, output_amounts, max_fee, respend, memo) in [
        ("the empty plan", vec![], vec![], 0, false, vec![]),
        (
            "spends alone",
            vec![300, MAX_MONEY / 8],
            vec![],
            0,
            false,
            vec![],
        ),
        (
            "outputs alone",
            vec![],
            vec![200, MAX_MONEY / 8],
            MAX_MONEY / 8,
            false,
            vec![0x5au8; 96],
        ),
        (
            "spends and outputs",
            vec![1000],
            vec![300, 200],
            100,
            false,
            vec![1],
        ),
        (
            "a note spent under two randomizations",
            vec![500, 700],
            vec![100],
            0,
            true,
            vec![],
        ),
        (
            "a balance of MAX_MONEY",
            vec![MAX_MONEY],
            vec![],
            0,
            false,
            vec![],
        ),
        (
            "a balance of -MAX_MONEY",
            vec![],
            vec![MAX_MONEY],
            0,
            false,
            vec![],
        ),
    ] {
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
        if respend {
            let again = spend_of(rng, &ask, spent[0]);
            assert_ne!(again.cv(), spends[0].cv(), "{label}");
            assert_ne!(again.rk, spends[0].rk, "{label}");
            spends.push(again);
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
        assert_eq!(plan.value_balance(), Ok(expected), "{label}");
        let sighash = mock_sighash(plan.commitment().expect("commitment"));
        let signed = plan.sign(rng, &sighash, &ask).expect("sign");
        assert_eq!(
            signed.commitment(),
            plan.commitment().expect("commitment"),
            "{label}"
        );
        assert_eq!(signed.value_balance, expected, "{label}");
        assert_eq!(&signed.memo, &memo, "{label}");
        assert_eq!(
            signed.actions.len(),
            spends.len() + outputs.len(),
            "{label}"
        );
        assert_eq!(
            signed.descriptors().collect::<BTreeSet<_>>(),
            plan.descriptors(),
            "{label}"
        );
        assert!(
            signed.verify_signatures(&sighash).is_ok(),
            "{label}: the signed bundle's signatures verify"
        );

        let authorized: BTreeMap<action::Descriptor, action::Signature> = signed
            .actions
            .iter()
            .map(|act| (act.descriptor(), act.sig))
            .collect();
        let applied = plan
            .apply_signatures(rng, &sighash, authorized)
            .expect("apply the signatures");
        assert_eq!(applied.commitment(), signed.commitment(), "{label}");
        assert!(
            applied.verify_signatures(&sighash).is_ok(),
            "{label}: the applied bundle's signatures verify"
        );
    }
}

#[test]
fn signature_tampering_fails_verify_signatures() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let max_fee_note = wallet.random_note(100);
    let spend = spend_of(rng, &ask, wallet.random_note(1000));
    let output = build_output_plan(rng, wallet.random_note(200)).2;
    let plan = bundle::Plan::new(vec![spend], vec![output], max_fee_note);
    let sighash = mock_sighash(plan.commitment().expect("commitment"));
    let signed = plan.sign(rng, &sighash, &ask).expect("sign");
    let own_sighash = |tampered: &Bundle<_>| mock_sighash(tampered.commitment());

    let mut rebalanced = signed.clone();
    rebalanced.value_balance =
        value::Balance::try_from(i64::from(signed.value_balance) + 1).expect("in range");
    let mut permuted = signed.clone();
    permuted.actions.swap(0, 1);
    let mut rebound = signed.clone();
    rebound.binding_sig = flipped(
        |bytes| signed.binding_sig.write(bytes),
        |mut bytes| Signature::read(&mut bytes),
    );
    let empty_plan = bundle::Plan::new(vec![], vec![], wallet.random_note(0));
    let empty_sighash = mock_sighash(empty_plan.commitment().expect("commitment"));
    let mut claiming = empty_plan.sign(rng, &empty_sighash, &ask).expect("sign");
    claiming.value_balance = value::Balance::try_from(1i64).expect("in range");
    for (label, result) in [
        (
            "a tampered balance under its own sighash",
            rebalanced.verify_signatures(&own_sighash(&rebalanced)),
        ),
        (
            "a tampered balance under the signed sighash",
            rebalanced.verify_signatures(&sighash),
        ),
        (
            "permuted actions",
            permuted.verify_signatures(&own_sighash(&permuted)),
        ),
        (
            "a corrupted binding signature",
            rebound.verify_signatures(&sighash),
        ),
        (
            "a zero-action bundle claiming a balance",
            claiming.verify_signatures(&empty_sighash),
        ),
    ] {
        let Err(SignatureError::Binding(_)) = result else {
            panic!("{label}: expected a binding signature failure, got {result:?}");
        };
    }

    let mut sigs: Vec<action::Signature> = signed.actions.iter().map(|act| act.sig).collect();
    sigs.reverse();
    let shuffled = plan
        .apply_signatures(
            rng,
            &sighash,
            plan.descriptors().into_iter().zip(sigs).collect(),
        )
        .expect("assembly takes any pairing");
    let mut rekeyed = output;
    rekeyed.rk = build_output_plan(rng, wallet.random_note(50)).2.rk;
    let rekeyed_plan = bundle::Plan::new(vec![spend], vec![rekeyed], max_fee_note);
    let rekeyed_sighash = mock_sighash(rekeyed_plan.commitment().expect("commitment"));
    let misdirected = rekeyed_plan
        .sign(rng, &rekeyed_sighash, &ask)
        .expect("sign");
    let stranger = WalletSim::random(rng).sk.derive_auth_private();
    let forged = plan.sign(rng, &sighash, &stranger).expect("sign");
    for (label, result) in [
        (
            "signatures shuffled among the actions",
            shuffled.verify_signatures(&sighash),
        ),
        (
            "an output signed under a key other than its rk",
            misdirected.verify_signatures(&rekeyed_sighash),
        ),
        (
            "a spend signed by another wallet",
            forged.verify_signatures(&sighash),
        ),
    ] {
        let Err(SignatureError::Action(_)) = result else {
            panic!("{label}: expected an action signature failure, got {result:?}");
        };
    }

    for index in 0..signed.actions.len() {
        let mut corrupted = signed.clone();
        let bad_sig = flipped(
            |bytes| signed.actions[index].sig.write(bytes),
            |mut bytes| action::Signature::read(&mut bytes),
        );
        corrupted.actions[index].sig = bad_sig;
        let result = corrupted.verify_signatures(&sighash);
        let Err(SignatureError::Action(sig)) = result else {
            panic!(
                "action {index} corrupted: expected an action signature failure, got {result:?}"
            );
        };
        assert_eq!(sig, bad_sig, "action {index}'s signature is named");
    }
}

#[test]
fn autonome_lifecycle() {
    let rng = &mut StdRng::seed_from_u64(0);
    for spending in [false, true] {
        for outputs in 0..=2 {
            let spends_count = usize::from(spending);
            let shape = format!("{spends_count} spends and {outputs} outputs");
            let wallet = WalletSim::random(rng);
            let actions = spends_count + outputs;
            let max_fee = if actions == 0 { 0 } else { FUNDED_MAX_FEE };
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

            let mut fee_amounts = vec![0, max_fee / 2, max_fee];
            fee_amounts.dedup();
            let proved: Vec<Bundle<ProofStamp>> =
                fee_amounts.iter().map(|&fee| prove(rng, fee)).collect();
            for (bundle, &fee) in proved.iter().zip(&fee_amounts) {
                let case = format!("{shape}, fee {fee}");
                assert_eq!(bundle.commitment(), signed.commitment(), "{case}");
                assert_eq!(bundle.binding_sig, signed.binding_sig, "{case}");
                assert_eq!(bundle.actions.len(), actions, "{case}");
                assert_eq!(bundle.stamp.fee, zat(fee), "{case}");
                assert_eq!(bundle.stamp.tachygrams.len(), 2 * actions + 1, "{case}");
                assert!(bundle.is_autonome(), "{case}: an autonome");
                let fee_desc = fee::Descriptor {
                    max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
                    value: zat(fee),
                };
                assert_eq!(bundle.fee_descriptor(), fee_desc, "{case}");
                assert!(
                    bundle.stamp.is_covering(plan.descriptors(), [fee_desc]),
                    "{case}: the stamp covers its actions and fee"
                );
                let (covered, covered_fees) = bundle
                    .verify_coverage(&[], &[])
                    .unwrap_or_else(|err| panic!("{case}: coverage fails: {err:?}"));
                assert_eq!(covered.len(), actions, "{case}");
                assert_eq!(covered_fees.len(), 1, "{case}");
                verify_alone(rng, bundle)
                    .unwrap_or_else(|err| panic!("{case}: the autonome does not verify: {err:?}"));
            }
            for (left, left_fee) in proved.iter().zip(&fee_amounts) {
                for (right, right_fee) in proved.iter().zip(&fee_amounts) {
                    assert_eq!(
                        left.auth_digest() == right.auth_digest(),
                        left_fee == right_fee,
                        "{shape}: auth digests at fees {left_fee} and {right_fee}"
                    );
                }
            }

            let middle = &proved[proved.len() / 2];
            let mut bytes = Vec::new();
            middle.write(&mut bytes).expect("write");
            let decoded = Bundle::<ProofStamp>::read(&*bytes).expect("read");
            assert_eq!(decoded.auth_digest(), middle.auth_digest(), "{shape}");
            verify_alone(rng, &decoded).unwrap_or_else(|err| {
                panic!("{shape}: the decoded bundle does not verify: {err:?}")
            });
        }
    }
}

#[test]
fn duplicated_actions_fail_coverage() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let anchor = PoolSim::genesis(rng).anchor();
    let mut repeating = proved_bundle(rng, &wallet, anchor, vec![], &[500], (0, 0));
    repeating.actions.push(repeating.actions[0]);
    let Err(VerifyCoverageError::DuplicateActions) = repeating.verify_coverage(&[], &[]) else {
        panic!("verify_coverage accepted a repeated action");
    };
}

#[test]
fn misapplied_fee_fails_verify() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let anchor = PoolSim::genesis(rng).anchor();
    let (max_fee, fee) = (MAX_MONEY / 2, MAX_MONEY / 4);
    let output_plan = build_output_plan(rng, wallet.random_note(500)).2;
    let plan = bundle::Plan::new(vec![], vec![output_plan], wallet.random_note(max_fee));
    let sighash = mock_sighash(plan.commitment().expect("commitment"));
    let mut foreign_fee = plan
        .sign(rng, &sighash, &wallet.sk.derive_auth_private())
        .expect("sign")
        .stamp(
            bundle::Plan::new(vec![], vec![output_plan], wallet.random_note(max_fee))
                .stamp_plan(anchor, zat(fee))
                .prove(rng, &wallet.pak, vec![])
                .expect("prove under another max fee note"),
        );
    let Err(VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch)) =
        verify_alone(rng, &foreign_fee)
    else {
        panic!("a stamp with another fee passed coverage");
    };
    foreign_fee.stamp.coverage = coverage_of(&[foreign_fee.as_dyn()]);
    let Err(VerificationError::Disproved) = verify_alone(rng, &foreign_fee) else {
        panic!("a proof with another fee verified");
    };
}

#[test]
fn aggregates_merge_and_verify() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (label, based, adjunct_count, premerged, spending) in [
        (
            "an innocent receiver merging two adjuncts one at a time",
            false,
            2,
            false,
            false,
        ),
        (
            "a based receiver merging three spending adjuncts premerged",
            true,
            3,
            true,
            true,
        ),
    ] {
        let wallet = WalletSim::random(rng);
        let mut pool = PoolSim::genesis(rng);
        let (aggregate, adjuncts) = build_aggregate(
            rng,
            &wallet,
            &mut pool,
            (based, adjunct_count, premerged),
            spending,
        );
        let adjunct_dyns: Vec<&Bundle<dyn StampState>> =
            adjuncts.iter().map(Bundle::as_dyn).collect();
        let receiver_fee = if based { RECEIVER_FEES.1 } else { 0 };
        assert_eq!(aggregate.stamp.fee, zat(receiver_fee), "{label}");
        assert!(aggregate.is_aggregate(), "{label}: an aggregate");
        assert!(
            aggregate.is_covering(&adjunct_dyns),
            "{label}: the aggregate covers its adjuncts"
        );

        let id = mock_wtxid(&aggregate);
        let stripped: Vec<Bundle<PointerStamp>> = adjuncts
            .iter()
            .map(|adjunct| adjunct.clone().strip(id))
            .collect();
        for (index, (adjunct, signed)) in stripped.iter().zip(&adjuncts).enumerate() {
            assert!(
                adjunct
                    .verify_signatures(&mock_sighash(signed.commitment()))
                    .is_ok(),
                "{label}: stripped adjunct {index}'s signatures verify"
            );
        }
        aggregate
            .verify(
                rng,
                &mock_sighash(aggregate.commitment()),
                &id.into(),
                &stripped.iter().collect::<Vec<_>>(),
            )
            .unwrap_or_else(|err| panic!("{label}: the aggregate does not verify: {err:?}"));
    }
}

fn stripped_aggregate(
    rng: &mut StdRng,
    wallet: &WalletSim,
) -> (
    Bundle<ProofStamp>,
    Vec<Bundle<ProofStamp>>,
    Vec<Bundle<PointerStamp>>,
) {
    let mut pool = PoolSim::genesis(rng);
    let (aggregate, adjuncts) = build_aggregate(rng, wallet, &mut pool, (true, 2, false), false);
    let id = mock_wtxid(&aggregate);
    let stripped = adjuncts
        .iter()
        .map(|adjunct| adjunct.clone().strip(id))
        .collect();
    (aggregate, adjuncts, stripped)
}

#[test]
fn aggregate_verify_rejects_foreign_sighashes_and_pointers() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let (aggregate, adjuncts, stripped) = stripped_aggregate(rng, &wallet);
    let id = mock_wtxid(&aggregate);
    let refs: Vec<&Bundle<PointerStamp>> = stripped.iter().collect();

    let Err(VerificationError::Signatures(SignatureError::Binding(_))) = aggregate.verify(
        rng,
        &mock_sighash(adjuncts[0].commitment()),
        &id.into(),
        &refs,
    ) else {
        panic!("the aggregate verified under another bundle's sighash");
    };
    let mut rememoed = aggregate.clone();
    rememoed.memo.push(0x5a);
    let Err(VerificationError::Signatures(SignatureError::Binding(_))) =
        rememoed.verify(rng, &mock_sighash(rememoed.commitment()), &id.into(), &refs)
    else {
        panic!("an altered memo verified under its own sighash");
    };

    let Err(VerificationError::Pointers(VerifyPointersError::AdjunctPointerMismatch)) = aggregate
        .verify(
            rng,
            &mock_sighash(aggregate.commitment()),
            &[0x5a; 64],
            &refs,
        )
    else {
        panic!("adjuncts pointing elsewhere verified");
    };
}

#[test]
fn aggregate_verify_rejects_adjunct_sets_it_does_not_cover() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let (aggregate, adjuncts, stripped) = stripped_aggregate(rng, &wallet);
    let anchor = aggregate.stamp.anchor;
    let adjunct_dyns: Vec<&Bundle<dyn StampState>> = adjuncts.iter().map(Bundle::as_dyn).collect();
    let sighash = mock_sighash(aggregate.commitment());
    let id = mock_wtxid(&aggregate);
    let refs: Vec<&Bundle<PointerStamp>> = stripped.iter().collect();
    let verify = |verify_rng: &mut StdRng, with: &[&Bundle<PointerStamp>]| {
        aggregate.verify(verify_rng, &sighash, &id.into(), with)
    };

    assert!(
        !aggregate.is_covering(&adjunct_dyns[1..]),
        "the aggregate covers a missing adjunct"
    );
    let Err(VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch)) =
        verify(rng, &refs[1..])
    else {
        panic!("a missing adjunct verified");
    };

    let repeated: Vec<&Bundle<PointerStamp>> = refs.iter().copied().chain([refs[0]]).collect();
    assert!(
        !aggregate.is_covering(
            &adjunct_dyns
                .iter()
                .copied()
                .chain([adjunct_dyns[0]])
                .collect::<Vec<_>>()
        ),
        "the aggregate covers a repeated adjunct"
    );
    let Err(VerificationError::Coverage(VerifyCoverageError::DuplicateActions)) =
        verify(rng, &repeated)
    else {
        panic!("a repeated adjunct verified");
    };

    let uncovered = proved_bundle(rng, &wallet, anchor, vec![], &[100], (0, 0)).strip(id);
    let with_uncovered: Vec<&Bundle<PointerStamp>> =
        refs.iter().copied().chain([&uncovered]).collect();
    let Err(VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch)) =
        verify(rng, &with_uncovered)
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
    assert!(
        !aggregate
            .verify_proof(rng, &uncovered_digests)
            .expect("proof system verification"),
        "the proof verified with an uncovered adjunct"
    );
}

/// An innocent receiver has no actions to repeat, so its fee repeats instead.
#[test]
fn aggregate_verify_rejects_the_receiver_as_its_own_adjunct() {
    let rng = &mut StdRng::seed_from_u64(0);
    for based in [true, false] {
        let wallet = WalletSim::random(rng);
        let mut pool = PoolSim::genesis(rng);
        let (aggregate, adjuncts) =
            build_aggregate(rng, &wallet, &mut pool, (based, 2, false), false);
        let id = mock_wtxid(&aggregate);
        let with_itself: Vec<Bundle<PointerStamp>> = adjuncts
            .into_iter()
            .chain([aggregate.clone()])
            .map(|adjunct| adjunct.strip(id))
            .collect();
        let result = aggregate.verify(
            rng,
            &mock_sighash(aggregate.commitment()),
            &id.into(),
            &with_itself.iter().collect::<Vec<_>>(),
        );
        if based {
            let Err(VerificationError::Coverage(VerifyCoverageError::DuplicateActions)) = result
            else {
                panic!("a based receiver: expected DuplicateActions, got {result:?}");
            };
        } else {
            let Err(VerificationError::Coverage(VerifyCoverageError::DuplicateFees)) = result
            else {
                panic!("an innocent receiver: expected DuplicateFees, got {result:?}");
            };
        }
    }
}

#[test]
fn aggregate_verify_rejects_a_shared_fee_descriptor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let (aggregate, adjuncts, stripped) = stripped_aggregate(rng, &wallet);
    let sighash = mock_sighash(aggregate.commitment());
    let id = mock_wtxid(&aggregate);

    let mut fee_sharing = aggregate.clone();
    let mut mimic = adjuncts[0].clone().strip(id);
    mimic.fee_max_commitment = aggregate.fee_max_commitment;
    mimic.stamp.fee = aggregate.stamp.fee;
    let with_mimic: Vec<&Bundle<PointerStamp>> =
        iter::once(&mimic).chain(stripped[1..].iter()).collect();
    let Err(VerificationError::Coverage(VerifyCoverageError::DuplicateFees)) =
        fee_sharing.verify(rng, &sighash, &id.into(), &with_mimic)
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
    let Err(VerificationError::Coverage(VerifyCoverageError::DuplicateFees)) = fee_sharing.verify(
        rng,
        &sighash,
        &forged_id.into(),
        &restripped.iter().collect::<Vec<_>>(),
    ) else {
        panic!("a shared fee descriptor verified under forged coverage");
    };
}

#[test]
fn aggregate_verify_rejects_edited_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let (aggregate, _, stripped) = stripped_aggregate(rng, &wallet);
    let sighash = mock_sighash(aggregate.commitment());
    let id = mock_wtxid(&aggregate);
    let refs: Vec<&Bundle<PointerStamp>> = stripped.iter().collect();

    let published: Vec<Tachygram> = aggregate.stamp.tachygrams.iter().copied().collect();
    for (end, removed) in [
        ("first", published[0]),
        ("last", published[published.len() - 1]),
    ] {
        let mut dropped = aggregate.clone();
        dropped.stamp.tachygrams.remove(&removed);
        let Err(VerificationError::Tachygrams(VerifyTachygramsError::WrongArity)) =
            dropped.verify(rng, &sighash, &id.into(), &refs)
        else {
            panic!("the {end} tachygram dropped verified");
        };
        let mut substituted = dropped;
        substituted.stamp.tachygrams.insert(Tachygram::random(rng));
        let Err(VerificationError::Tachygrams(VerifyTachygramsError::WrongSet)) =
            substituted.verify(rng, &sighash, &id.into(), &refs)
        else {
            panic!("the {end} tachygram substituted verified");
        };
    }
}

#[test]
fn aggregates_reaggregate_into_a_parent() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let (aggregate, adjuncts, stripped) = stripped_aggregate(rng, &wallet);
    let anchor = aggregate.stamp.anchor;
    let adjunct_dyns: Vec<&Bundle<dyn StampState>> = adjuncts.iter().map(Bundle::as_dyn).collect();
    let itself = aggregate.clone().strip(mock_wtxid(&aggregate));

    let mut parent = proved_bundle(rng, &wallet, anchor, vec![], &[150], (FUNDED_MAX_FEE, 0));
    let covered: Vec<&Bundle<dyn StampState>> = iter::once(aggregate.as_dyn())
        .chain(adjunct_dyns.iter().copied())
        .collect();
    let (stamp, desc, fees) = merge_side(&parent, &[]);
    parent.stamp = stamp
        .merge(rng, (desc, fees), merge_side(&aggregate, &adjunct_dyns))
        .expect("merge the aggregate into a parent");
    assert!(
        parent.is_covering(&covered),
        "the parent covers the aggregate and its adjuncts"
    );
    let parent_id = mock_wtxid(&parent);
    let parent_sighash = mock_sighash(parent.commitment());
    let stale: Vec<&Bundle<PointerStamp>> = iter::once(&itself).chain(&stripped).collect();
    let Err(VerificationError::Pointers(VerifyPointersError::AdjunctPointerMismatch)) =
        parent.verify(rng, &parent_sighash, &parent_id.into(), &stale)
    else {
        panic!("adjuncts stripped to the absorbed aggregate verified against the parent");
    };
    let parent_adjuncts: Vec<Bundle<PointerStamp>> = iter::once(aggregate.strip(parent_id))
        .chain(adjuncts.into_iter().map(|adjunct| adjunct.strip(parent_id)))
        .collect();
    parent
        .verify(
            rng,
            &parent_sighash,
            &parent_id.into(),
            &parent_adjuncts.iter().collect::<Vec<_>>(),
        )
        .unwrap_or_else(|err| panic!("the parent does not verify: {err:?}"));
}

#[test]
fn verify_rejects_each_edit_at_its_stage() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let anchor = Anchor::random(rng);
    let mut aggregate = proved_bundle(rng, &wallet, anchor, vec![], &[300], RECEIVER_FEES);
    let adjunct = proved_bundle(
        rng,
        &wallet,
        anchor,
        vec![],
        &[200],
        (FUNDED_MAX_FEE, FUNDED_MAX_FEE),
    );
    let elsewhere = Anchor::random(rng);
    let other = proved_bundle(rng, &wallet, elsewhere, vec![], &[100], (0, 0));
    let (stamp, desc, fees) = merge_side(&aggregate, &[]);
    aggregate.stamp = stamp
        .merge(rng, (desc, fees), merge_side(&adjunct, &[]))
        .expect("merge the adjunct");
    let sighash = mock_sighash(aggregate.commitment());
    let id = mock_wtxid(&aggregate);
    let stripped = adjunct.clone().strip(id);
    let verify = |verify_rng: &mut StdRng,
                  bundle: &Bundle<ProofStamp>,
                  wtxid: [u8; 64],
                  with: &Bundle<PointerStamp>| {
        bundle.verify(verify_rng, &sighash, &wtxid, &[with])
    };
    verify(rng, &aggregate, id.into(), &stripped)
        .unwrap_or_else(|err| panic!("the aggregate does not verify: {err:?}"));

    let mut resigned = aggregate.clone();
    resigned.actions[0].sig = other.actions[0].sig;
    assert_ne!(resigned.actions[0].sig, aggregate.actions[0].sig);
    let Err(VerificationError::Signatures(SignatureError::Action(_))) =
        verify(rng, &resigned, id.into(), &stripped)
    else {
        panic!("another action's signature verified");
    };
    let mut rekeyed = aggregate.clone();
    rekeyed.actions[0].rk = other.actions[0].rk;
    assert_ne!(rekeyed.actions[0].rk, aggregate.actions[0].rk);
    let Err(VerificationError::Signatures(SignatureError::Action(_))) =
        verify(rng, &rekeyed, id.into(), &stripped)
    else {
        panic!("another action's rk verified");
    };
    let mut recommitted = aggregate.clone();
    recommitted.actions[0].cv = other.actions[0].cv;
    assert_ne!(recommitted.actions[0].cv, aggregate.actions[0].cv);
    let Err(VerificationError::Signatures(SignatureError::Binding(_))) =
        verify(rng, &recommitted, id.into(), &stripped)
    else {
        panic!("another action's cv verified");
    };

    let Err(VerificationError::Pointers(VerifyPointersError::AdjunctPointerInvalid(_))) =
        verify(rng, &aggregate, [0; 64], &stripped)
    else {
        panic!("an invalid wtxid verified");
    };

    let claims = |bundle: &Bundle<PointerStamp>| {
        (
            bundle.descriptors().collect::<Vec<action::Descriptor>>(),
            bundle.fee_descriptor(),
        )
    };
    let mut adjunct_cv = stripped.clone();
    adjunct_cv.actions[0].cv = other.actions[0].cv;
    let mut adjunct_rk = stripped.clone();
    adjunct_rk.actions[0].rk = other.actions[0].rk;
    let mut adjunct_fee = stripped.clone();
    adjunct_fee.stamp.fee = zat(u64::from(stripped.stamp.fee) ^ 1);
    for (label, edited) in [("cv", adjunct_cv), ("rk", adjunct_rk), ("fee", adjunct_fee)] {
        assert_ne!(claims(&edited), claims(&stripped), "{label}");
        let Err(VerificationError::Coverage(VerifyCoverageError::StampActionsMismatch)) =
            verify(rng, &aggregate, id.into(), &edited)
        else {
            panic!("an adjunct with another {label} verified");
        };
    }

    let mut forged = aggregate.clone();
    let mut digestless = adjunct;
    digestless.actions[0].cv = value::Trapdoor::ZERO.commit(value::Positive::ZERO);
    digestless.actions[0].descriptor().digest().unwrap_err();
    let coverage = coverage_of(&[forged.as_dyn(), digestless.as_dyn()]);
    forged.stamp.coverage = coverage;
    let forged_id = mock_wtxid(&forged);
    let Err(VerificationError::Actions(_)) =
        verify(rng, &forged, forged_id.into(), &digestless.strip(forged_id))
    else {
        panic!("an action without a digest verified");
    };

    let mut foreign_set = aggregate.clone();
    foreign_set.stamp.tachygram_set = other.stamp.tachygram_set;
    assert_ne!(
        foreign_set.stamp.tachygram_set,
        aggregate.stamp.tachygram_set
    );
    let Err(VerificationError::Tachygrams(VerifyTachygramsError::WrongSet)) =
        verify(rng, &foreign_set, id.into(), &stripped)
    else {
        panic!("another tachygram set verified");
    };
    let mut reanchored = aggregate.clone();
    reanchored.stamp.anchor = other.stamp.anchor;
    let mut reproved = aggregate.clone();
    reproved.stamp.proof = other.stamp.proof;
    for (label, edited) in [("anchor", reanchored), ("proof", reproved)] {
        assert_ne!(edited.auth_digest(), aggregate.auth_digest(), "{label}");
        let Err(VerificationError::Disproved) = verify(rng, &edited, id.into(), &stripped) else {
            panic!("another {label} verified");
        };
    }
}

#[test]
fn bundle_lift_keeps_coverage_and_verifies() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (label, based, adjunct_count, spending, next_epoch, blocks) in [
        ("an autonome over a block", true, 0, false, false, 1),
        (
            "an aggregate of one adjunct over two blocks",
            true,
            1,
            false,
            false,
            2,
        ),
        (
            "an aggregate of two adjuncts over three blocks",
            true,
            2,
            false,
            false,
            3,
        ),
        (
            "an innocent aggregate of two adjuncts over a block",
            false,
            2,
            false,
            false,
            1,
        ),
        (
            "an innocent aggregate at the next epoch's entry anchor over a block",
            false,
            2,
            false,
            true,
            1,
        ),
        (
            "a spending aggregate of two adjuncts over two blocks",
            true,
            2,
            true,
            false,
            2,
        ),
    ] {
        let wallet = WalletSim::random(rng);
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
        if next_epoch {
            mine_sparse(rng, &mut pool, EpochIndex::new(1), None);
        }
        let (lifting, adjuncts) = build_aggregate(
            rng,
            &wallet,
            &mut pool,
            (based, adjunct_count, false),
            spending,
        );
        if next_epoch {
            assert_eq!(
                lifting.stamp.anchor,
                pool.block(EpochIndex::new(1).first_block()).prev,
                "{label}: stamped at the entry anchor"
            );
        }
        let stamped_at = pool.height();
        let adjunct_dyns: Vec<&Bundle<dyn StampState>> =
            adjuncts.iter().map(Bundle::as_dyn).collect();
        for _ in 0..blocks {
            pool.mine(random_block(rng, 1, 2));
        }
        let coverage = lifting.stamp.coverage;
        let span = build_lift_span(rng, &pool, stamped_at.next().unwrap()..=pool.height());
        let lifted = lifting.lift(rng, &adjunct_dyns, vec![span]).expect("lift");
        assert_eq!(lifted.stamp.anchor, pool.anchor(), "{label}");
        assert_eq!(lifted.stamp.coverage, coverage, "{label}");
        let id = mock_wtxid(&lifted);
        let stripped: Vec<Bundle<PointerStamp>> = adjuncts
            .into_iter()
            .map(|adjunct| adjunct.strip(id))
            .collect();
        lifted
            .verify(
                rng,
                &mock_sighash(lifted.commitment()),
                &id.into(),
                &stripped.iter().collect::<Vec<_>>(),
            )
            .unwrap_or_else(|err| panic!("{label}: the lifted bundle does not verify: {err:?}"));
    }
}

#[test]
fn aggregates_merge_with_aggregates_and_lift() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    let (mut receiver, receiver_adjuncts) =
        build_aggregate(rng, &wallet, &mut pool, (true, 2, false), false);
    let (other, other_adjuncts) =
        build_aggregate(rng, &wallet, &mut pool, (false, 1, false), false);
    let receiver_fee = receiver.stamp.fee;
    let receiver_dyns: Vec<&Bundle<dyn StampState>> =
        receiver_adjuncts.iter().map(Bundle::as_dyn).collect();
    let other_dyns: Vec<&Bundle<dyn StampState>> =
        other_adjuncts.iter().map(Bundle::as_dyn).collect();
    let (stamp, desc, fees) = merge_side(&receiver, &receiver_dyns);
    receiver.stamp = stamp
        .merge(rng, (desc, fees), merge_side(&other, &other_dyns))
        .expect("merge an aggregate into an aggregate");
    assert_eq!(receiver.stamp.fee, receiver_fee);
    let covered: Vec<Bundle<ProofStamp>> = receiver_adjuncts
        .into_iter()
        .chain([other])
        .chain(other_adjuncts)
        .collect();
    let covered_dyns: Vec<&Bundle<dyn StampState>> = covered.iter().map(Bundle::as_dyn).collect();
    assert!(receiver.is_covering(&covered_dyns));

    let stamped_at = pool.height();
    pool.mine(random_block(rng, 1, 2));
    let span = build_lift_span(rng, &pool, stamped_at.next().unwrap()..=pool.height());
    let lifted = receiver.lift(rng, &covered_dyns, vec![span]).expect("lift");
    assert_eq!(lifted.stamp.anchor, pool.anchor());
    let id = mock_wtxid(&lifted);
    let stripped: Vec<Bundle<PointerStamp>> =
        covered.into_iter().map(|bundle| bundle.strip(id)).collect();
    lifted
        .verify(
            rng,
            &mock_sighash(lifted.commitment()),
            &id.into(),
            &stripped.iter().collect::<Vec<_>>(),
        )
        .expect("the lifted aggregate of aggregates verifies");
}
