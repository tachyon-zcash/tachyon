extern crate alloc;

use alloc::{boxed::Box, collections::BTreeSet, format, string::ToString as _, vec, vec::Vec};
use core::iter;

use corez::io;
use ragu::{PROOF_SIZE_COMPRESSED, Proof};
use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, Bundle, Tachygram, TachygramSetPoly, TachyonBundle, action,
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

use crate::fixtures::{WalletSim, mock_sighash};

const TACHYGRAM_COUNT: usize = 3;

fn signed_bundle(
    rng: &mut StdRng,
    (spends, outputs): (&[u64], &[u64]),
    order: &[usize],
    (max_fee, fee): (u64, u64),
    memo_len: usize,
) -> Bundle<ProofStamp> {
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let max_fee_note = wallet.random_note(max_fee);
    let spend_plans = spends
        .iter()
        .map(|&amount| {
            action::Plan::spend(
                wallet.random_note(amount),
                ActionEntropy::random(rng),
                value::Trapdoor::random(rng),
                |alpha| wallet.pak.ak.derive_action_public(&alpha),
            )
        })
        .collect();
    let output_plans = outputs
        .iter()
        .map(|&amount| {
            action::Plan::output(
                wallet.random_note(amount),
                ActionEntropy::random(rng),
                value::Trapdoor::random(rng),
            )
        })
        .collect();
    let mut memo = vec![0u8; memo_len];
    rng.fill_bytes(&mut memo);
    let plan = bundle::Plan::new(spend_plans, output_plans, max_fee_note).with_memo(memo.clone());

    let canonical: Vec<action::Descriptor> = plan.descriptors().into_iter().collect();
    let wire: Vec<[u8; 64]> = order.iter().map(|&at| canonical[at]).collect();
    let sighash = mock_sighash(blake2b::bundle_commitment(
        &blake2b::action_descriptor_digest(&wire),
        i64::from(plan.value_balance().unwrap()),
        &max_fee_note.fee_blind().commit(-max_fee_note.value).into(),
        &blake2b::memo_digest(&memo),
    ));
    let signed = plan.sign(rng, &sighash, &ask).unwrap();
    let wire_actions = order.iter().map(|&at| signed.actions[at]).collect();

    let published: BTreeSet<Tachygram> = iter::repeat_with(|| Tachygram::random(rng))
        .take(TACHYGRAM_COUNT)
        .collect();
    let mut coverage = [0u8; 32];
    rng.fill_bytes(&mut coverage);
    Bundle {
        actions: wire_actions,
        ..signed
    }
    .stamp(ProofStamp {
        coverage,
        anchor: Anchor::random(rng),
        tachygram_set: published
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit(),
        tachygrams: published,
        proof: Box::new(Proof::bootstrap()),
        fee: value::Positive::try_from(fee).unwrap(),
    })
}

fn round_trip<S>(name: &str, original: &Bundle<S>) -> Bundle<S>
where
    S: StampState + Clone + 'static,
    Bundle<S>: TryFrom<TachyonBundle>,
    TachyonBundle: From<Bundle<S>>,
{
    let mut wire = Vec::new();
    original
        .write(&mut wire)
        .unwrap_or_else(|err| panic!("{name}: write: {err}"));
    let decoded = Bundle::<S>::read(&*wire).unwrap_or_else(|err| panic!("{name}: read: {err}"));
    assert_eq!(&decoded.actions, &original.actions, "{name}");
    assert_eq!(decoded.value_balance, original.value_balance, "{name}");
    assert_eq!(
        decoded.fee_max_commitment, original.fee_max_commitment,
        "{name}"
    );
    assert_eq!(decoded.binding_sig, original.binding_sig, "{name}");
    assert!(decoded.memo == original.memo, "{name}: the memo");
    assert_eq!(decoded.stamp.fee(), original.stamp.fee(), "{name}");
    assert_eq!(decoded.commitment(), original.commitment(), "{name}");
    assert_eq!(decoded.auth_digest(), original.auth_digest(), "{name}");
    assert!(
        decoded
            .verify_signatures(&mock_sighash(decoded.commitment()))
            .is_ok(),
        "{name}: the decoded signatures verify"
    );
    let mut rewritten = Vec::new();
    decoded
        .write(&mut rewritten)
        .unwrap_or_else(|err| panic!("{name}: rewrite: {err}"));
    assert!(
        rewritten == wire,
        "{name}: the decoded bundle re-encodes the wire"
    );

    let erased = TachyonBundle::from(original.clone());
    assert_eq!(erased.commitment(), original.commitment(), "{name}");
    assert_eq!(erased.auth_digest(), original.auth_digest(), "{name}");
    let mut erased_wire = Vec::new();
    erased
        .write(&mut erased_wire)
        .unwrap_or_else(|err| panic!("{name}: erased write: {err}"));
    assert!(
        erased_wire == wire,
        "{name}: both writers emit the same wire"
    );
    let dispatched =
        TachyonBundle::read(&*wire).unwrap_or_else(|err| panic!("{name}: dispatch: {err}"));
    assert!(dispatched == erased, "{name}: the dispatched bundle");
    let Ok(typed) = Bundle::<S>::try_from(dispatched) else {
        panic!("{name}: the dispatching reader decoded the other state");
    };
    assert!(
        typed == *original,
        "{name}: the dispatched bundle converts back"
    );
    decoded
}

#[test]
fn bundles_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (name, stamped) in [
        ("no actions", signed_bundle(rng, (&[], &[]), &[], (0, 0), 0)),
        (
            "a spend and two outputs",
            signed_bundle(rng, (&[1_000], &[300, 200]), &[0, 1, 2], (100, 40), 20),
        ),
        (
            "two outputs out of order",
            signed_bundle(rng, (&[], &[300, 200]), &[1, 0], (100, 40), 0),
        ),
    ] {
        let mut wtxid = [0u8; 64];
        rng.fill_bytes(&mut wtxid);
        let stripped = stamped.clone().strip(AggregateId::try_from(wtxid).unwrap());

        let decoded = round_trip(name, &stamped);
        let adjunct = round_trip(name, &stripped);
        assert_eq!(adjunct.stamp, stripped.stamp, "{name}");
        assert!(
            Bundle::<PointerStamp>::try_from(TachyonBundle::from(stamped.clone())).is_err(),
            "{name}: a proof-stamped bundle converts to a pointer-stamped one"
        );
        assert!(
            Bundle::<ProofStamp>::try_from(TachyonBundle::from(stripped.clone())).is_err(),
            "{name}: a pointer-stamped bundle converts to a proof-stamped one"
        );

        let mut stamp_wire = Vec::new();
        stamped.stamp.write(&mut stamp_wire).unwrap();
        let alone = ProofStamp::read(&*stamp_wire).unwrap();
        for read in [&decoded.stamp, &alone] {
            assert_eq!(read.fee, stamped.stamp.fee, "{name}");
            assert_eq!(read.coverage, stamped.stamp.coverage, "{name}");
            assert_eq!(read.anchor, stamped.stamp.anchor, "{name}");
            assert_eq!(read.tachygram_set, stamped.stamp.tachygram_set, "{name}");
            assert_eq!(&read.tachygrams, &stamped.stamp.tachygrams, "{name}");
            assert!(
                read.proof.serialize() == stamped.stamp.proof.serialize(),
                "{name}: the proof"
            );
        }

        let mut pointer_wire = Vec::new();
        stripped.stamp.write(&mut pointer_wire).unwrap();
        assert_eq!(
            PointerStamp::read(&*pointer_wire).unwrap(),
            stripped.stamp,
            "{name}"
        );
    }
}

#[test]
fn bundles_round_trip_at_their_bounds() {
    let rng = &mut StdRng::seed_from_u64(0);
    for memo_len in [252, 253, 0xFFFF, 0x0001_0000] {
        let bundle = signed_bundle(rng, (&[], &[300]), &[0], (0, 0), memo_len);
        round_trip(&format!("a {memo_len}-byte memo"), &bundle);
    }
    for (name, actions, fees) in [
        (
            "a balance of MAX_MONEY",
            (&[MAX_MONEY][..], &[][..]),
            (0, 0),
        ),
        (
            "a balance of -MAX_MONEY",
            (&[][..], &[MAX_MONEY][..]),
            (0, 0),
        ),
        (
            "a fee of MAX_MONEY",
            (&[MAX_MONEY][..], &[][..]),
            (MAX_MONEY, MAX_MONEY),
        ),
    ] {
        round_trip(name, &signed_bundle(rng, actions, &[0], fees, 0));
    }
}

#[test]
fn commitment_binds_effecting_data_only() {
    let rng = &mut StdRng::seed_from_u64(0);
    let stamped = signed_bundle(rng, (&[1_000], &[300, 200]), &[0, 1, 2], (100, 40), 20);
    let commitment = stamped.commitment();
    let edit = |change: &dyn Fn(&mut Bundle<ProofStamp>)| {
        let mut edited = stamped.clone();
        change(&mut edited);
        edited.commitment()
    };

    let foreign_wallet = WalletSim::random(rng);
    let foreign_note = foreign_wallet.random_note(400);
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let foreign_output = action::Plan::output(foreign_note, theta, rcv);
    let foreign_plan =
        bundle::Plan::new(vec![], vec![foreign_output], foreign_wallet.random_note(0));
    let foreign_sighash = mock_sighash(foreign_plan.commitment().unwrap());
    let foreign = foreign_plan
        .sign(
            rng,
            &foreign_sighash,
            &foreign_wallet.sk.derive_auth_private(),
        )
        .unwrap()
        .actions[0];
    let balance = value::Balance::try_from(i64::from(stamped.value_balance) + 1).unwrap();
    let max_commitment = value::Trapdoor::random(rng).commit(value::Balance::ZERO);
    let mut other_memo = vec![0u8; stamped.memo.len()];
    rng.fill_bytes(&mut other_memo);
    for (label, edited) in [
        (
            "the first cv",
            edit(&|edited| edited.actions[0].cv = foreign.cv),
        ),
        (
            "the first rk",
            edit(&|edited| edited.actions[0].rk = foreign.rk),
        ),
        ("the wire order", edit(&|edited| edited.actions.swap(0, 1))),
        (
            "the balance",
            edit(&|edited| edited.value_balance = balance),
        ),
        (
            "the max fee commitment",
            edit(&|edited| edited.fee_max_commitment = max_commitment),
        ),
        (
            "the memo",
            edit(&|edited| edited.memo.clone_from(&other_memo)),
        ),
    ] {
        assert_ne!(edited, commitment, "{label}");
    }

    let fee = value::Positive::try_from(1).unwrap();
    let mut coverage = [0u8; 32];
    rng.fill_bytes(&mut coverage);
    let anchor = Anchor::random(rng);
    let extra = Tachygram::random(rng);
    let tachygram_set = iter::once(extra).collect::<TachygramSetPoly>().commit();
    let proof_note = WalletSim::random(rng).random_note(0);
    let proof_anchor = Anchor::random(rng);
    let (proof_pcd, ()) = PROOF_SYSTEM
        .seed(
            rng,
            FeeSeed,
            witness::fee_seed(((), ()), proof_note, proof_anchor),
        )
        .unwrap();
    let proof = Box::new(proof_pcd.proof().clone());
    let mut sighash = [0u8; 32];
    rng.fill_bytes(&mut sighash);
    let binding_sig = bundle::Plan::new(vec![], vec![], WalletSim::random(rng).random_note(0))
        .derive_bsk_private()
        .sign(rng, &sighash);
    let mut repointed_wtxid = [0u8; 64];
    rng.fill_bytes(&mut repointed_wtxid);
    let mut repointed = stamped
        .clone()
        .strip(AggregateId::try_from(repointed_wtxid).unwrap());
    repointed.stamp.fee = fee;
    for (label, edited) in [
        (
            "the first signature",
            edit(&|edited| edited.actions[0].sig = foreign.sig),
        ),
        ("the fee", edit(&|edited| edited.stamp.fee = fee)),
        ("a pointer and its fee", repointed.commitment()),
        (
            "the coverage",
            edit(&|edited| edited.stamp.coverage = coverage),
        ),
        ("the anchor", edit(&|edited| edited.stamp.anchor = anchor)),
        (
            "the tachygram set",
            edit(&|edited| edited.stamp.tachygram_set = tachygram_set),
        ),
        (
            "the tachygrams",
            edit(&|edited| {
                edited.stamp.tachygrams.insert(extra);
            }),
        ),
        (
            "the proof",
            edit(&|edited| edited.stamp.proof.clone_from(&proof)),
        ),
        (
            "the binding signature",
            edit(&|edited| edited.binding_sig = binding_sig),
        ),
    ] {
        assert_eq!(edited, commitment, "{label}");
    }

    let mut wtxid = [0u8; 64];
    rng.fill_bytes(&mut wtxid);
    let stripped = stamped.clone().strip(AggregateId::try_from(wtxid).unwrap());
    assert_eq!(stripped.commitment(), commitment);
    assert_eq!(stripped.memo, stamped.memo);
}

#[test]
fn auth_digest_binds_authorizing_data_only() {
    let rng = &mut StdRng::seed_from_u64(0);
    let stamped = signed_bundle(rng, (&[1_000], &[300, 200]), &[0, 1, 2], (100, 40), 20);
    let mut wtxid = [0u8; 64];
    rng.fill_bytes(&mut wtxid);
    let stripped = stamped.clone().strip(AggregateId::try_from(wtxid).unwrap());
    let (stamped_digest, stripped_digest) = (stamped.auth_digest(), stripped.auth_digest());

    // A pointer repeating the proof stamp's digest isolates the state byte.
    let stamp_digest = stamped.stamp.stamp_digest();
    let mirror = AggregateId::try_from(<[u8; 64]>::try_from(&stamp_digest[8..]).unwrap()).unwrap();
    let mirrored = stamped.clone().strip(mirror);
    assert_eq!(mirrored.stamp.stamp_digest(), stamp_digest);
    assert_ne!(mirrored.auth_digest(), stamped_digest);

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

    let fee = value::Positive::try_from(1).unwrap();
    let mut other_wtxid_bytes = [0u8; 64];
    rng.fill_bytes(&mut other_wtxid_bytes);
    let other_wtxid = AggregateId::try_from(other_wtxid_bytes).unwrap();
    let anchor = Anchor::random(rng);
    let extra = Tachygram::random(rng);
    let tachygram_set = iter::once(extra).collect::<TachygramSetPoly>().commit();
    let proof_note = WalletSim::random(rng).random_note(0);
    let proof_anchor = Anchor::random(rng);
    let (proof_pcd, ()) = PROOF_SYSTEM
        .seed(
            rng,
            FeeSeed,
            witness::fee_seed(((), ()), proof_note, proof_anchor),
        )
        .unwrap();
    let proof = Box::new(proof_pcd.proof().clone());
    let mut sighash = [0u8; 32];
    rng.fill_bytes(&mut sighash);
    let binding_sig = bundle::Plan::new(vec![], vec![], WalletSim::random(rng).random_note(0))
        .derive_bsk_private()
        .sign(rng, &sighash);
    let foreign_wallet = WalletSim::random(rng);
    let foreign_note = foreign_wallet.random_note(400);
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let foreign_output = action::Plan::output(foreign_note, theta, rcv);
    let foreign_plan =
        bundle::Plan::new(vec![], vec![foreign_output], foreign_wallet.random_note(0));
    let foreign_sighash = mock_sighash(foreign_plan.commitment().unwrap());
    let foreign = foreign_plan
        .sign(
            rng,
            &foreign_sighash,
            &foreign_wallet.sk.derive_auth_private(),
        )
        .unwrap()
        .actions[0];
    for (label, edited, digest) in [
        (
            "the fee",
            edit_stamped(&|edited| edited.stamp.fee = fee),
            stamped_digest,
        ),
        (
            "a pointer's fee",
            edit_stripped(&|edited| edited.stamp.fee = fee),
            stripped_digest,
        ),
        (
            "the wtxid",
            edit_stripped(&|edited| edited.stamp.wtxid = other_wtxid),
            stripped_digest,
        ),
        (
            "the coverage",
            edit_stamped(&|edited| edited.stamp.coverage[0] ^= 1),
            stamped_digest,
        ),
        (
            "the anchor",
            edit_stamped(&|edited| edited.stamp.anchor = anchor),
            stamped_digest,
        ),
        (
            "the tachygram set",
            edit_stamped(&|edited| edited.stamp.tachygram_set = tachygram_set),
            stamped_digest,
        ),
        (
            "the tachygrams",
            edit_stamped(&|edited| {
                edited.stamp.tachygrams.insert(extra);
            }),
            stamped_digest,
        ),
        (
            "the proof",
            edit_stamped(&|edited| edited.stamp.proof.clone_from(&proof)),
            stamped_digest,
        ),
        (
            "the binding signature",
            edit_stamped(&|edited| edited.binding_sig = binding_sig),
            stamped_digest,
        ),
        (
            "a pointer's binding signature",
            edit_stripped(&|edited| edited.binding_sig = binding_sig),
            stripped_digest,
        ),
        (
            "the first action's signature",
            edit_stamped(&|edited| edited.actions[0].sig = foreign.sig),
            stamped_digest,
        ),
        (
            "a pointer's first action's signature",
            edit_stripped(&|edited| edited.actions[0].sig = foreign.sig),
            stripped_digest,
        ),
    ] {
        assert_ne!(edited, digest, "{label}");
    }

    let mut other_memo = vec![0u8; stamped.memo.len()];
    rng.fill_bytes(&mut other_memo);
    let balance = value::Balance::try_from(i64::from(stamped.value_balance) + 1).unwrap();
    for (label, edited, digest) in [
        (
            "the memo",
            edit_stamped(&|edited| edited.memo.clone_from(&other_memo)),
            stamped_digest,
        ),
        (
            "a pointer's memo",
            edit_stripped(&|edited| edited.memo.clone_from(&other_memo)),
            stripped_digest,
        ),
        (
            "the balance",
            edit_stamped(&|edited| edited.value_balance = balance),
            stamped_digest,
        ),
        (
            "a pointer's balance",
            edit_stripped(&|edited| edited.value_balance = balance),
            stripped_digest,
        ),
    ] {
        assert_eq!(edited, digest, "{label}");
    }
}

#[test]
fn no_bundle_round_trips_and_digests_apart() {
    let no_bundle_wire = [u8::from(StateByte::NoBundle)];
    let no_bundle = TachyonBundle::read(no_bundle_wire.as_slice()).unwrap();
    assert!(no_bundle.is_no_bundle());
    let mut rewritten = Vec::new();
    no_bundle.write(&mut rewritten).unwrap();
    assert_eq!(rewritten.as_slice(), no_bundle_wire.as_slice());

    let rng = &mut StdRng::seed_from_u64(0);
    for (name, stamped) in [
        ("no actions", signed_bundle(rng, (&[], &[]), &[], (0, 0), 0)),
        (
            "a spend and two outputs",
            signed_bundle(rng, (&[1_000], &[300, 200]), &[0, 1, 2], (100, 40), 20),
        ),
        (
            "two outputs out of order",
            signed_bundle(rng, (&[], &[300, 200]), &[1, 0], (100, 40), 0),
        ),
    ] {
        let mut wtxid = [0u8; 64];
        rng.fill_bytes(&mut wtxid);
        let stripped = stamped.clone().strip(AggregateId::try_from(wtxid).unwrap());
        for erased in [TachyonBundle::from(stamped), TachyonBundle::from(stripped)] {
            assert_ne!(erased.commitment(), no_bundle.commitment(), "{name}");
            assert_ne!(erased.auth_digest(), no_bundle.auth_digest(), "{name}");
        }
    }
}

#[test]
fn readers_reject_malformed_wire() {
    let proof_stamped: fn(&[u8]) -> io::Result<()> =
        |wire| Bundle::<ProofStamp>::read(wire).map(drop);
    let pointer_stamped: fn(&[u8]) -> io::Result<()> =
        |wire| Bundle::<PointerStamp>::read(wire).map(drop);
    let dispatching: fn(&[u8]) -> io::Result<()> = |wire| TachyonBundle::read(wire).map(drop);
    let stamped_readers = [proof_stamped, dispatching];
    let stripped_readers = [pointer_stamped, dispatching];
    let rejects =
        |label: &str, wire: &[u8], readers: &[fn(&[u8]) -> io::Result<()>], expected: &str| {
            for read in readers {
                let Err(err) = read(wire) else {
                    panic!("{label}: a reader accepted the forgery");
                };
                assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{label}");
                assert_eq!(err.to_string(), expected, "{label}");
            }
        };
    let splice = |wire: &[u8], offset: usize, len: usize, bytes: &[u8]| {
        [&wire[..offset], bytes, &wire[offset + len..]].concat()
    };
    let non_canonical = [0xFFu8; 32];
    // `MAX_COMPACT_SIZE + 1` in the five-byte form.
    let over_maximum = [&[0xFE][..], &0x0200_0001u32.to_le_bytes()].concat();
    let rank_coeffs = u16::try_from(ProductionRank::num_coeffs()).unwrap();
    let over_rank = [&[0xFD][..], &rank_coeffs.to_le_bytes()].concat();

    let rng = &mut StdRng::seed_from_u64(0);
    let stamped = signed_bundle(rng, (&[1_000], &[300, 200]), &[0, 1, 2], (100, 40), 20);
    let mut wtxid = [0u8; 64];
    rng.fill_bytes(&mut wtxid);
    let stripped = stamped.clone().strip(AggregateId::try_from(wtxid).unwrap());
    let mut stamped_wire = Vec::new();
    stamped.write(&mut stamped_wire).unwrap();
    let mut stripped_wire = Vec::new();
    stripped.write(&mut stripped_wire).unwrap();

    // Three actions and a 20-byte memo keep both counts to one byte.
    let actions = stamped.actions.len();
    let balance_at = 1;
    let action_count_at = balance_at + 8;
    let descriptors_at = action_count_at + 1;
    let fee_max_at = descriptors_at + 64 * actions;
    let action_sigs_at = fee_max_at + 32;
    let binding_sig_at = action_sigs_at + 64 * actions;
    let memo_count_at = binding_sig_at + 64;
    let stamp_at = memo_count_at + 1 + stamped.memo.len();
    // After the fee: the pointer's wtxid, or the proof stamp's coverage.
    let fee_at = stamp_at;
    let wtxid_at = fee_at + 8;
    let anchor_at = fee_at + 8 + 32;
    let tachygram_set_at = anchor_at + 32;
    let tachygram_count_at = tachygram_set_at + 32;
    let first_at = tachygram_count_at + 1;
    let last_at = first_at + 32 * (TACHYGRAM_COUNT - 1);
    let proof_at = first_at + 32 * TACHYGRAM_COUNT;
    assert_eq!(wtxid_at + 64, stripped_wire.len());
    assert_eq!(proof_at + PROOF_SIZE_COMPRESSED, stamped_wire.len());
    let first = &stamped_wire[first_at..first_at + 32];

    rejects(
        "a proof-stamped wire under the pointer reader",
        &stamped_wire,
        &stripped_readers[..1],
        "unexpected tachyonBundleState",
    );
    rejects(
        "a pointer-stamped wire under the proof reader",
        &stripped_wire,
        &stamped_readers[..1],
        "unexpected tachyonBundleState",
    );
    rejects(
        "an all-zero wtxid",
        &splice(&stripped_wire, wtxid_at, 64, &[0u8; 64]),
        &stripped_readers,
        "aggregate id is zero and refers to no aggregate",
    );
    rejects(
        "a pointer's fee beyond MAX_MONEY",
        &splice(&stripped_wire, fee_at, 8, &(MAX_MONEY + 1).to_le_bytes()),
        &stripped_readers,
        "fee out of range",
    );

    rejects(
        "a state byte of 3",
        &splice(&stamped_wire, 0, 1, &[3]),
        &stamped_readers,
        "invalid bundle state",
    );
    for balance in [MAX_MONEY.cast_signed() + 1, -MAX_MONEY.cast_signed() - 1] {
        rejects(
            &format!("a balance of {balance}"),
            &splice(&stamped_wire, balance_at, 8, &balance.to_le_bytes()),
            &stamped_readers,
            "value balance out of range",
        );
    }
    rejects(
        "a balance without actions",
        &[
            &stamped_wire[..balance_at],
            &1i64.to_le_bytes()[..],
            &[0],
            &stamped_wire[fee_max_at..action_sigs_at],
            &stamped_wire[binding_sig_at..],
        ]
        .concat(),
        &stamped_readers,
        "bundle with no actions must have zero value balance",
    );
    rejects(
        "an action count in the two-byte form",
        &splice(&stamped_wire, action_count_at, 1, &[0xFD, 3, 0]),
        &stamped_readers,
        "non-canonical compact size",
    );
    rejects(
        "an action count beyond the consensus maximum",
        &splice(&stamped_wire, action_count_at, 1, &over_maximum),
        &stamped_readers,
        "compact size exceeds consensus maximum",
    );
    rejects(
        "a non-canonical cv",
        &splice(&stamped_wire, descriptors_at, 32, &non_canonical),
        &stamped_readers,
        "invalid curve point encoding",
    );
    rejects(
        "a non-canonical rk",
        &splice(&stamped_wire, descriptors_at + 32, 32, &non_canonical),
        &stamped_readers,
        "invalid action verification key",
    );
    rejects(
        "a non-canonical max fee commitment",
        &splice(&stamped_wire, fee_max_at, 32, &non_canonical),
        &stamped_readers,
        "invalid curve point encoding",
    );
    rejects(
        "a max fee commitment at the identity",
        &splice(&stamped_wire, fee_max_at, 32, &[0u8; 32]),
        &stamped_readers,
        "fee commitment is the identity",
    );
    rejects(
        "a memo length in the two-byte form",
        &splice(&stamped_wire, memo_count_at, 1, &[0xFD, 20, 0]),
        &stamped_readers,
        "non-canonical compact size",
    );
    rejects(
        "a memo length beyond the consensus maximum",
        &splice(&stamped_wire, memo_count_at, 1, &over_maximum),
        &stamped_readers,
        "compact size exceeds consensus maximum",
    );
    rejects(
        "a fee beyond MAX_MONEY",
        &splice(&stamped_wire, fee_at, 8, &(MAX_MONEY + 1).to_le_bytes()),
        &stamped_readers,
        "fee out of range",
    );

    rejects(
        "a non-canonical anchor",
        &splice(&stamped_wire, anchor_at, 32, &non_canonical),
        &stamped_readers,
        "invalid Fp encoding",
    );
    rejects(
        "a non-canonical tachygram set",
        &splice(&stamped_wire, tachygram_set_at, 32, &non_canonical),
        &stamped_readers,
        "invalid curve point encoding",
    );
    rejects(
        "no tachygrams",
        &splice(
            &stamped_wire,
            tachygram_count_at,
            1 + 32 * TACHYGRAM_COUNT,
            &[0],
        ),
        &stamped_readers,
        "no tachygrams",
    );
    rejects(
        "a tachygram count in the two-byte form",
        &splice(&stamped_wire, tachygram_count_at, 1, &[0xFD, 3, 0]),
        &stamped_readers,
        "non-canonical compact size",
    );
    rejects(
        "a tachygram count beyond the consensus maximum",
        &splice(&stamped_wire, tachygram_count_at, 1, &over_maximum),
        &stamped_readers,
        "compact size exceeds consensus maximum",
    );
    rejects(
        "more tachygrams than the rank holds",
        &splice(&stamped_wire, tachygram_count_at, 1, &over_rank),
        &stamped_readers,
        "too many tachygrams",
    );
    rejects(
        "a non-canonical tachygram",
        &splice(&stamped_wire, first_at, 32, &non_canonical),
        &stamped_readers,
        "invalid Fp encoding",
    );
    rejects(
        "a repeated tachygram",
        &splice(
            &stamped_wire,
            tachygram_count_at,
            1,
            &[&[4], first].concat(),
        ),
        &stamped_readers,
        "tachygrams are not unique",
    );
    let mut unsorted = stamped_wire.clone();
    unsorted.copy_within(last_at..last_at + 32, first_at);
    unsorted[last_at..last_at + 32].copy_from_slice(first);
    rejects(
        "the first and last tachygrams swapped",
        &unsorted,
        &stamped_readers,
        "tachygrams are not canonically sorted",
    );
    let mut wrong_proof = stamped_wire.clone();
    wrong_proof[proof_at] ^= 1;
    rejects(
        "a proof byte flipped against the binding",
        &wrong_proof,
        &stamped_readers,
        "invalid proof encoding",
    );
}

#[test]
fn readers_reject_truncated_wire() {
    let proof_stamped: fn(&[u8]) -> io::Result<()> =
        |wire| Bundle::<ProofStamp>::read(wire).map(drop);
    let pointer_stamped: fn(&[u8]) -> io::Result<()> =
        |wire| Bundle::<PointerStamp>::read(wire).map(drop);
    let dispatching: fn(&[u8]) -> io::Result<()> = |wire| TachyonBundle::read(wire).map(drop);

    let rng = &mut StdRng::seed_from_u64(0);
    let stamped = signed_bundle(rng, (&[1_000], &[300, 200]), &[0, 1, 2], (100, 40), 20);
    let mut wtxid = [0u8; 64];
    rng.fill_bytes(&mut wtxid);
    let stripped = stamped.clone().strip(AggregateId::try_from(wtxid).unwrap());
    let mut stamped_wire = Vec::new();
    stamped.write(&mut stamped_wire).unwrap();
    let mut stripped_wire = Vec::new();
    stripped.write(&mut stripped_wire).unwrap();

    let actions = stamped.actions.len();
    let body = [
        1,
        8,
        1,
        64 * actions,
        32,
        64 * actions,
        64,
        1,
        stamped.memo.len(),
        8,
    ];
    let proof_stamp = [32, 32, 32, 1, 32 * TACHYGRAM_COUNT, PROOF_SIZE_COMPRESSED];
    for (wire, readers, fields) in [
        (
            &stamped_wire,
            [proof_stamped, dispatching],
            [&body[..], &proof_stamp[..]].concat(),
        ),
        (
            &stripped_wire,
            [pointer_stamped, dispatching],
            [&body[..], &[64]].concat(),
        ),
    ] {
        let mut at = 0;
        for len in fields {
            for cut in [at, at + len / 2] {
                for read in readers {
                    let Err(err) = read(&wire[..cut]) else {
                        panic!("a reader accepted a {cut}-byte prefix");
                    };
                    assert_eq!(
                        err.kind(),
                        io::ErrorKind::UnexpectedEof,
                        "a {cut}-byte prefix"
                    );
                }
            }
            at += len;
        }
        assert_eq!(at, wire.len());
    }
}
