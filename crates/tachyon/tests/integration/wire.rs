//! The bundle wire format and the bundle digests, over generated wire-valid
//! bundles stamped with a trivial proof.

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeSet, string::ToString as _, vec, vec::Vec};
use std::{fs, path::Path};

use corez::io;
use ff::Field as _;
use pasta_curves::Fp;
use proptest::{collection, prelude::*, sample::Index, test_runner::TestCaseError};
use ragu::Proof;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionSetPoly, Anchor, Bundle, CompactSize, Tachygram, TachygramSetPoly, TachyonBundle, action,
    bundle::{self, StateByte},
    constants::MAX_MONEY,
    digest::blake2b,
    entropy::ActionEntropy,
    stamp::{
        AggregateId, PointerStamp, ProofStamp, StampState,
        proof::{PROOF_SYSTEM, stamp::FeeSeed},
    },
    value, witness,
};

use crate::{
    fixtures::{
        PoolSim, WalletSim, build_autonome, mock_sighash, mock_wtxid, random_action, shared_sk,
    },
    strategies::{check, tachygrams},
};

/// The structure of a generated bundle. The seed draws its keys, notes, memo
/// bytes and stamp content.
#[derive(Clone, Debug)]
struct Shape {
    seed: u64,
    /// Whether each action is a spend. The first action carries the balance
    /// net of the max fee, and takes its kind from that amount's sign.
    spends: Vec<bool>,
    /// The canonical position of the action at each wire position.
    order: Vec<usize>,
    balance: i64,
    max_fee: u64,
    fee: u64,
    memo_len: usize,
    tachygram_count: usize,
}

/// Any value balance, weighted towards zero and `±MAX_MONEY`.
fn balance() -> impl Strategy<Value = i64> {
    let max = MAX_MONEY.cast_signed();
    prop_oneof![-max..=max, Just(0), Just(max), Just(-max)]
}

/// Any fee, weighted towards zero and `MAX_MONEY`.
fn fee() -> impl Strategy<Value = u64> {
    prop_oneof![0..=MAX_MONEY, Just(0), Just(MAX_MONEY)]
}

/// A memo length: absent, short or large.
fn memo_len() -> impl Strategy<Value = usize> {
    prop_oneof![Just(0usize), 1..=256usize, 4096..=20_000usize]
}

/// Up to four actions in any wire order, a balance the actions and the max
/// fee note realize (zero without actions), and any fee, memo and tachygram
/// count.
fn shape() -> impl Strategy<Value = Shape> {
    let actions = prop_oneof![1 => Just(0usize), 3 => 1..=4usize]
        .prop_flat_map(|count| {
            (
                collection::vec(any::<bool>(), count),
                Just((0..count).collect::<Vec<usize>>()).prop_shuffle(),
                balance().prop_map(move |amount| if count == 0 { 0 } else { amount }),
            )
        })
        .prop_flat_map(|(spends, order, balance)| {
            let headroom = if spends.is_empty() {
                0
            } else {
                MAX_MONEY - balance.unsigned_abs()
            };
            (
                Just(spends),
                Just(order),
                Just(balance),
                prop_oneof![0..=headroom, Just(0)],
            )
        });
    (any::<u64>(), actions, fee(), memo_len(), 1..=8usize).prop_map(
        |(seed, (spends, order, balance, max_fee), fee, memo_len, tachygram_count)| Shape {
            seed,
            spends,
            order,
            balance,
            max_fee,
            fee,
            memo_len,
            tachygram_count,
        },
    )
}

fn random_bytes<const N: usize>(rng: &mut StdRng) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn memo(rng: &mut StdRng, len: usize) -> Vec<u8> {
    let mut memo = vec![0u8; len];
    rng.fill_bytes(&mut memo);
    memo
}

/// A random wtxid, nonzero by construction.
fn wtxid(rng: &mut StdRng) -> AggregateId {
    AggregateId::try_from(random_bytes::<64>(rng)).expect("a random wtxid is nonzero")
}

/// A binding signature under a fresh key.
fn other_binding_sig(rng: &mut StdRng) -> bundle::Signature {
    let sighash = random_bytes(rng);
    bundle::Plan::new(vec![], vec![], WalletSim::random(rng).random_note(0))
        .derive_bsk_private()
        .sign(rng, &sighash)
}

/// A proof other than the trivial one: `FeeSeed` at a random anchor.
fn other_proof(rng: &mut StdRng) -> Box<Proof> {
    let note = WalletSim::random(rng).random_note(0);
    let anchor = Anchor::from(Fp::random(&mut *rng));
    let (pcd, ()) = PROOF_SYSTEM
        .seed(rng, FeeSeed, witness::fee_seed(((), ()), note, anchor))
        .expect("FeeSeed");
    Box::new(pcd.proof().clone())
}

/// A proof-stamped bundle of `shape`, signed over its commitment in wire
/// order and stamped with a trivial proof.
fn bundle(rng: &mut StdRng, shape: &Shape) -> Bundle<ProofStamp> {
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let max_fee_note = wallet.random_note(shape.max_fee);
    let carried = shape.balance + shape.max_fee.cast_signed();

    let mut spends = Vec::new();
    let mut outputs = Vec::new();
    for (index, &spend) in shape.spends.iter().enumerate() {
        let amount = if index == 0 {
            carried.unsigned_abs()
        } else {
            0
        };
        let is_spend = if index == 0 && carried != 0 {
            carried > 0
        } else {
            spend
        };
        let note = wallet.random_note(amount);
        let (theta, rcv) = (ActionEntropy::random(rng), value::Trapdoor::random(rng));
        if is_spend {
            spends.push(action::Plan::spend(note, theta, rcv, |alpha| {
                wallet.pak.ak.derive_action_public(&alpha)
            }));
        } else {
            outputs.push(action::Plan::output(note, theta, rcv));
        }
    }
    let memo = memo(rng, shape.memo_len);
    let plan = bundle::Plan::new(spends, outputs, max_fee_note).with_memo(memo.clone());
    assert_eq!(
        plan.value_balance(),
        Ok(value::Balance::try_from(shape.balance).unwrap()),
        "the plan realizes the balance"
    );

    let canonical: Vec<action::Descriptor> = plan.descriptors().into_iter().collect();
    let wire: Vec<[u8; 64]> = shape.order.iter().map(|&at| canonical[at]).collect();
    let sighash = mock_sighash(blake2b::bundle_commitment(
        &blake2b::action_descriptor_digest(&wire),
        shape.balance,
        &max_fee_note.fee_blind().commit(-max_fee_note.value).into(),
        &blake2b::memo_digest(&memo),
    ));
    let signed = plan.sign(rng, &sighash, &ask).expect("sign the plan");
    let actions = shape.order.iter().map(|&at| signed.actions[at]).collect();

    let published: BTreeSet<Tachygram> =
        tachygrams(rng, shape.tachygram_count).into_iter().collect();
    Bundle { actions, ..signed }.stamp(ProofStamp {
        coverage: random_bytes(rng),
        anchor: Anchor::from(Fp::random(&mut *rng)),
        tachygram_set: published
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit(),
        tachygrams: published,
        proof: Box::new(Proof::trivial()),
        fee: value::Positive::try_from(shape.fee).unwrap(),
    })
}

/// Write `original`, read it back through its typed reader and through the
/// dispatching reader, and check both against it.
fn round_trip<S>(original: &Bundle<S>) -> Result<Bundle<S>, TestCaseError>
where
    S: StampState + Clone + 'static,
    Bundle<S>: TryFrom<TachyonBundle>,
    TachyonBundle: From<Bundle<S>>,
{
    let failed = |err: io::Error| TestCaseError::fail(err.to_string());
    let mut wire = Vec::new();
    original.write(&mut wire).map_err(failed)?;
    let decoded = Bundle::<S>::read(&*wire).map_err(failed)?;
    prop_assert_eq!(&decoded.actions, &original.actions);
    prop_assert_eq!(decoded.value_balance, original.value_balance);
    prop_assert_eq!(decoded.fee_max_commitment, original.fee_max_commitment);
    prop_assert_eq!(decoded.binding_sig, original.binding_sig);
    prop_assert!(decoded.memo == original.memo);
    prop_assert_eq!(decoded.stamp.fee(), original.stamp.fee());
    prop_assert_eq!(decoded.commitment(), original.commitment());
    prop_assert_eq!(decoded.auth_digest(), original.auth_digest());
    prop_assert!(
        decoded
            .verify_signatures(&mock_sighash(decoded.commitment()))
            .is_ok()
    );
    let mut rewritten = Vec::new();
    decoded.write(&mut rewritten).map_err(failed)?;
    prop_assert!(rewritten == wire, "the decoded bundle re-encodes the wire");

    let erased = TachyonBundle::from(original.clone());
    prop_assert_eq!(erased.commitment(), original.commitment());
    prop_assert_eq!(erased.auth_digest(), original.auth_digest());
    let mut erased_wire = Vec::new();
    erased.write(&mut erased_wire).map_err(failed)?;
    prop_assert!(erased_wire == wire, "both writers emit the same wire");
    let dispatched = TachyonBundle::read(&*wire).map_err(failed)?;
    prop_assert!(dispatched == erased);
    let typed = Bundle::<S>::try_from(dispatched)
        .map_err(|_err| TestCaseError::fail("the dispatching reader decoded the other state"))?;
    prop_assert!(typed == *original);
    Ok(decoded)
}

/// Bundles in both states, with any number of actions up to four in any wire
/// order, any memo, balance, fee and tachygram set, read back equal through
/// the typed and the dispatching reader and re-encode their wire. The
/// `TachyonBundle` variants convert from and back to their bundles, refuse
/// the other state, and dispatch the digests. Proof and pointer stamps
/// round-trip alone.
#[test]
fn bundles_round_trip() {
    check(64, shape(), |shape| {
        let rng = &mut StdRng::seed_from_u64(shape.seed);
        let stamped = bundle(rng, &shape);
        let stripped = stamped.clone().strip(wtxid(rng));

        let decoded = round_trip(&stamped)?;
        let adjunct = round_trip(&stripped)?;
        prop_assert_eq!(adjunct.stamp, stripped.stamp);
        prop_assert!(
            Bundle::<PointerStamp>::try_from(TachyonBundle::from(stamped.clone())).is_err()
        );
        prop_assert!(
            Bundle::<ProofStamp>::try_from(TachyonBundle::from(stripped.clone())).is_err()
        );

        let mut stamp_wire = Vec::new();
        stamped.stamp.write(&mut stamp_wire).expect("write stamp");
        let alone = ProofStamp::read(&*stamp_wire).expect("read stamp");
        for read in [&decoded.stamp, &alone] {
            prop_assert_eq!(read.fee, stamped.stamp.fee);
            prop_assert_eq!(read.coverage, stamped.stamp.coverage);
            prop_assert_eq!(read.anchor, stamped.stamp.anchor);
            prop_assert_eq!(read.tachygram_set, stamped.stamp.tachygram_set);
            prop_assert_eq!(&read.tachygrams, &stamped.stamp.tachygrams);
            prop_assert!(read.proof.serialize() == stamped.stamp.proof.serialize());
        }

        let mut pointer_wire = Vec::new();
        stripped
            .stamp
            .write(&mut pointer_wire)
            .expect("write pointer");
        prop_assert_eq!(
            PointerStamp::read(&*pointer_wire).expect("read pointer"),
            stripped.stamp
        );
        Ok(())
    });
}

/// The commitment moves with the wire order of the actions, any action's
/// value commitment or key, the value balance, the max fee commitment and the
/// memo. The stamp's state, wtxid, fee, coverage, anchor, tachygrams and
/// proof leave it, as do the signatures, and stripping keeps the memo.
#[test]
fn commitment_binds_effecting_data_only() {
    let strategy = (shape(), any::<Index>(), balance(), memo_len(), fee());
    check(
        64,
        strategy,
        |(shape, at, other_balance, other_memo_len, other_fee)| {
            let rng = &mut StdRng::seed_from_u64(shape.seed);
            let stamped = bundle(rng, &shape);
            let commitment = stamped.commitment();
            let edit = |change: &dyn Fn(&mut Bundle<ProofStamp>)| {
                let mut edited = stamped.clone();
                change(&mut edited);
                edited.commitment()
            };

            let count = stamped.actions.len();
            let foreign = random_action(rng);
            if count > 0 {
                let index = at.index(count);
                prop_assert_ne!(
                    edit(&|edited| edited.actions[index].cv = foreign.cv),
                    commitment
                );
                prop_assert_ne!(
                    edit(&|edited| edited.actions[index].rk = foreign.rk),
                    commitment
                );
                prop_assert_eq!(
                    edit(&|edited| edited.actions[index].sig = foreign.sig),
                    commitment
                );
                if count > 1 {
                    prop_assert_ne!(
                        edit(&|edited| edited.actions.swap(index, (index + 1) % count)),
                        commitment
                    );
                }
            }
            let balance = value::Balance::try_from(other_balance).unwrap();
            prop_assert_eq!(
                edit(&|edited| edited.value_balance = balance) == commitment,
                other_balance == shape.balance
            );
            let max_commitment = value::Trapdoor::random(rng).commit(value::Balance::ZERO);
            prop_assert_ne!(
                edit(&|edited| edited.fee_max_commitment = max_commitment),
                commitment
            );
            let other_memo = memo(rng, other_memo_len);
            prop_assert_eq!(
                edit(&|edited| edited.memo.clone_from(&other_memo)) == commitment,
                other_memo == stamped.memo
            );

            let fee = value::Positive::try_from(other_fee).unwrap();
            let coverage = random_bytes(rng);
            let anchor = Anchor::from(Fp::random(&mut *rng));
            let extra = tachygrams(rng, 1)[0];
            let proof = other_proof(rng);
            let binding_sig = other_binding_sig(rng);
            for edited in [
                edit(&|edited| edited.stamp.fee = fee),
                edit(&|edited| edited.stamp.coverage = coverage),
                edit(&|edited| edited.stamp.anchor = anchor),
                edit(&|edited| {
                    edited.stamp.tachygrams.insert(extra);
                }),
                edit(&|edited| edited.stamp.proof.clone_from(&proof)),
                edit(&|edited| edited.binding_sig = binding_sig),
            ] {
                prop_assert_eq!(edited, commitment);
            }

            let stripped = stamped.clone().strip(wtxid(rng));
            prop_assert_eq!(stripped.commitment(), commitment);
            prop_assert!(stripped.memo == stamped.memo, "stripping keeps the memo");
            let mut restripped = stamped.clone().strip(wtxid(rng));
            restripped.stamp.fee = fee;
            prop_assert_eq!(restripped.commitment(), commitment);
            Ok(())
        },
    );
}

/// The auth digest moves with the state, the pointer's wtxid and fee, the
/// proof stamp's fee, coverage, anchor, tachygrams and proof, and the binding
/// and action signatures in either state. The memo and the value balance
/// leave it.
#[test]
fn auth_digest_binds_authorizing_data_only() {
    let strategy = (shape(), any::<Index>(), fee(), balance(), memo_len());
    check(
        64,
        strategy,
        |(shape, at, other_fee, other_balance, other_memo_len)| {
            let rng = &mut StdRng::seed_from_u64(shape.seed);
            let stamped = bundle(rng, &shape);
            let stripped = stamped.clone().strip(wtxid(rng));
            let (stamped_digest, stripped_digest) = (stamped.auth_digest(), stripped.auth_digest());
            prop_assert_ne!(stamped_digest, stripped_digest);

            let edit_stamped = |change: &dyn Fn(&mut Bundle<ProofStamp>)| {
                let mut edited = stamped.clone();
                change(&mut edited);
                edited.auth_digest()
            };
            let edit_stripped = |change: &dyn Fn(&mut Bundle<PointerStamp>)| {
                let mut edited = stripped.clone();
                change(&mut edited);
                edited.auth_digest()
            };

            let fee = value::Positive::try_from(other_fee).unwrap();
            let same_fee = other_fee == shape.fee;
            prop_assert_eq!(
                edit_stamped(&|edited| edited.stamp.fee = fee) == stamped_digest,
                same_fee
            );
            prop_assert_eq!(
                edit_stripped(&|edited| edited.stamp.fee = fee) == stripped_digest,
                same_fee
            );
            let other_wtxid = wtxid(rng);
            prop_assert_ne!(
                edit_stripped(&|edited| edited.stamp.wtxid = other_wtxid),
                stripped_digest
            );

            let flipped = at.index(32);
            let anchor = Anchor::from(Fp::random(&mut *rng));
            let extra = tachygrams(rng, 1)[0];
            let proof = other_proof(rng);
            for edited in [
                edit_stamped(&|edited| edited.stamp.coverage[flipped] ^= 1),
                edit_stamped(&|edited| edited.stamp.anchor = anchor),
                edit_stamped(&|edited| {
                    edited.stamp.tachygrams.insert(extra);
                }),
                edit_stamped(&|edited| edited.stamp.proof.clone_from(&proof)),
            ] {
                prop_assert_ne!(edited, stamped_digest);
            }

            let binding_sig = other_binding_sig(rng);
            prop_assert_ne!(
                edit_stamped(&|edited| edited.binding_sig = binding_sig),
                stamped_digest
            );
            prop_assert_ne!(
                edit_stripped(&|edited| edited.binding_sig = binding_sig),
                stripped_digest
            );
            let count = stamped.actions.len();
            let foreign = random_action(rng);
            if count > 0 {
                let index = at.index(count);
                prop_assert_ne!(
                    edit_stamped(&|edited| edited.actions[index].sig = foreign.sig),
                    stamped_digest
                );
                prop_assert_ne!(
                    edit_stripped(&|edited| edited.actions[index].sig = foreign.sig),
                    stripped_digest
                );
            }

            let other_memo = memo(rng, other_memo_len);
            let balance = value::Balance::try_from(other_balance).unwrap();
            prop_assert_eq!(
                edit_stamped(&|edited| edited.memo.clone_from(&other_memo)),
                stamped_digest
            );
            prop_assert_eq!(
                edit_stripped(&|edited| edited.memo.clone_from(&other_memo)),
                stripped_digest
            );
            prop_assert_eq!(
                edit_stamped(&|edited| edited.value_balance = balance),
                stamped_digest
            );
            prop_assert_eq!(
                edit_stripped(&|edited| edited.value_balance = balance),
                stripped_digest
            );
            Ok(())
        },
    );
}

/// The no-bundle byte reads as `NoBundle` and writes back, and its
/// commitment and auth digest are the no-bundle constants, distinct from
/// those of any bundle in either state, the empty bundle included.
#[test]
fn no_bundle_digests_are_distinct() {
    check(64, shape(), |shape| {
        let rng = &mut StdRng::seed_from_u64(shape.seed);
        let stamped = bundle(rng, &shape);
        let stripped = stamped.clone().strip(wtxid(rng));

        let no_bundle_wire = [u8::from(StateByte::NoBundle)];
        let no_bundle = TachyonBundle::read(no_bundle_wire.as_slice()).expect("read");
        prop_assert!(no_bundle.is_no_bundle());
        let mut rewritten = Vec::new();
        no_bundle.write(&mut rewritten).expect("write");
        prop_assert_eq!(rewritten.as_slice(), no_bundle_wire.as_slice());
        prop_assert_eq!(no_bundle.commitment(), *blake2b::COMMIT_NO_BUNDLE);
        prop_assert_eq!(no_bundle.auth_digest(), *blake2b::AUTH_DIGEST_NO_BUNDLE);

        for erased in [TachyonBundle::from(stamped), TachyonBundle::from(stripped)] {
            prop_assert_ne!(erased.commitment(), *blake2b::COMMIT_NO_BUNDLE);
            prop_assert_ne!(erased.auth_digest(), *blake2b::AUTH_DIGEST_NO_BUNDLE);
        }
        Ok(())
    });
}

/// Regenerate the serializer-generated fuzz seeds in `fuzz/corpus`.
#[test]
#[ignore = "writes fuzz corpus seeds"]
fn write_fuzz_seeds() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let stamped = build_autonome(rng, &wallet, 1000, 700);
    let adjunct = build_autonome(rng, &wallet, 1000, 700).strip(mock_wtxid(&stamped));

    // An aggregate covering one adjunct, so the verifier target has a seed
    // that passes the pointer and coverage checks with an adjunct present.
    let anchor = PoolSim::genesis(rng).anchor();
    let mut aggregate = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(200)]);
    let to_cover = wallet.autonome(rng, anchor, vec![], vec![wallet.random_note(300)]);
    aggregate.stamp = aggregate
        .stamp
        .clone()
        .merge(
            rng,
            (
                aggregate.descriptors().collect(),
                BTreeSet::from([aggregate.fee_descriptor()]),
            ),
            (
                to_cover.stamp.clone(),
                to_cover.descriptors().collect(),
                BTreeSet::from([to_cover.fee_descriptor()]),
            ),
        )
        .expect("merge the covered bundle");
    let covered = to_cover.strip(mock_wtxid(&aggregate));

    let encode = |write: &dyn Fn(&mut Vec<u8>) -> io::Result<()>| {
        let mut buf = Vec::new();
        write(&mut buf).expect("write seed");
        buf
    };
    let component = |selector: u8, write: &dyn Fn(&mut Vec<u8>) -> io::Result<()>| {
        let mut buf = vec![selector];
        write(&mut buf).expect("write seed");
        buf
    };
    let stamped_buf = encode(&|buf| stamped.write(buf));
    let adjunct_buf = encode(&|buf| adjunct.write(buf));
    let action = stamped.actions[0];
    let action_set = ActionSetPoly::from_iter([action.digest().expect("action digest")]).commit();

    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    for (target, name, bytes) in [
        ("bundle_read", "valid_proof_stamped", stamped_buf.clone()),
        ("bundle_read", "valid_pointer_stamped", adjunct_buf.clone()),
        (
            "stamped_bundle_read",
            "valid_proof_stamped",
            stamped_buf.clone(),
        ),
        ("stripped_bundle_read", "valid_pointer_stamped", adjunct_buf),
        (
            "proof_stamp_read",
            "valid_proof_stamp",
            encode(&|buf| stamped.stamp.write(buf)),
        ),
        (
            "pointer_stamp_read",
            "valid_pointer_stamp",
            encode(&|buf| adjunct.stamp.write(buf)),
        ),
        (
            "compact_size_read",
            "one_byte",
            encode(&|buf| CompactSize::from(0xFCu64).write(buf)),
        ),
        (
            "compact_size_read",
            "two_bytes",
            encode(&|buf| CompactSize::from(0xFDu64).write(buf)),
        ),
        (
            "compact_size_read",
            "four_bytes",
            encode(&|buf| CompactSize::from(0x0200_0000u64).write(buf)),
        ),
        (
            "compact_size_read",
            "eight_bytes",
            encode(&|buf| CompactSize::from(u64::MAX).write(buf)),
        ),
        (
            "component_read",
            "action_descriptor",
            component(0, &|buf| action.descriptor().write(buf)),
        ),
        (
            "component_read",
            "action_signature",
            component(1, &|buf| action.sig.write(buf)),
        ),
        (
            "component_read",
            "binding_signature",
            component(2, &|buf| stamped.binding_sig.write(buf)),
        ),
        (
            "component_read",
            "anchor",
            component(3, &|buf| stamped.stamp.anchor.write(buf)),
        ),
        (
            "component_read",
            "tachygram",
            component(4, &|buf| {
                stamped
                    .stamp
                    .tachygrams
                    .first()
                    .expect("a published tachygram")
                    .write(buf)
            }),
        ),
        (
            "component_read",
            "tachygram_set",
            component(5, &|buf| stamped.stamp.tachygram_set.write(buf)),
        ),
        (
            "component_read",
            "action_set",
            component(6, &|buf| action_set.write(buf)),
        ),
        ("verify_pipeline", "autonome", stamped_buf),
        (
            "verify_pipeline",
            "aggregate_with_adjunct",
            encode(&|buf| {
                aggregate.write(&mut *buf)?;
                covered.write(buf)
            }),
        ),
    ] {
        let dir = corpus.join(target);
        fs::create_dir_all(&dir).expect("create corpus directory");
        fs::write(dir.join(name), bytes).expect("write seed");
    }
}
