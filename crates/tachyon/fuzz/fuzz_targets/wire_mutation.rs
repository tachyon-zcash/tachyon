#![no_main]

//! Fuzz the bundle reader and [`Bundle::verify`] with edits to a consistent
//! wire.
//!
//! The input draws a proof-stamped aggregate and zero to four pointer-stamped
//! adjuncts it covers, then up to four edits to their concatenated encoding: a
//! byte flipped, inserted or deleted outside the memos and the proof blob, or
//! the encoding truncated anywhere. Every bundle that decodes passes
//! [`check_bundle_wire`], and the decoded aggregate is verified against the
//! decoded adjuncts. The aggregate carries the proof of another stamp, so no
//! wire verifies. Without an edit, every bundle decodes completely to the one
//! built, each adjunct signs its own commitment, and `verify` rejects only at
//! the proof.
//!
//! The proof is of one action-free stamp, proved at initialization, so the
//! input never pays for proving.

use std::{cmp, collections::BTreeSet, iter, sync::LazyLock};

use libfuzzer_sys::{arbitrary::Unstructured, fuzz_target};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Action, Anchor, Tachygram, TachygramSetPoly, action,
    bundle::{self, Bundle, TachyonBundle, VerificationError},
    constants::MAX_MONEY,
    digest::blake2b,
    entropy::ActionEntropy,
    fee,
    keys::private,
    note::{self, Note},
    nullifier,
    stamp::{self, AggregateId, PointerStamp, ProofStamp},
    value,
};
use zcash_tachyon_fuzz::check_bundle_wire;

/// The most edits one input applies.
const MAX_EDITS: u8 = 4;

/// The largest note value, max fee and fee the builder draws, small enough
/// that five of them keep a value balance within `MAX_MONEY`.
const VALUE_BOUND: u64 = MAX_MONEY / 8;

/// The memo lengths the builder draws besides an arbitrary short one.
///
/// They are empty, either side of the three-byte compact size, and either side
/// of the five-byte one.
const MEMO_LENGTHS: [usize; 5] = [0, 252, 253, 0xFFFF, 0x1_0000];

/// A stamp of no actions and a zero fee, whose proof every built aggregate
/// carries.
static PROOF: LazyLock<ProofStamp> = LazyLock::new(|| {
    let rng = &mut StdRng::seed_from_u64(0);
    let sk = private::SpendingKey::random(rng);
    let max_fee_note = Note {
        pk: sk.derive_payment_key(),
        value: value::Positive::ZERO,
        psi: nullifier::Trapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    };
    stamp::Plan::new(
        vec![],
        vec![],
        Anchor::random(rng),
        max_fee_note,
        value::Positive::ZERO,
    )
    .prove(rng, &sk.derive_proof_private(), vec![])
    .expect("an action-free stamp proves")
});

/// The length of `PROOF`'s proof blob, the tail of every built aggregate.
static PROOF_LEN: LazyLock<usize> = LazyLock::new(|| PROOF.proof.serialize().len());

/// A signed bundle of `actions.0` to `actions.1` actions drawn from `input`.
///
/// Each action is a spend or an output of a note `sk` owns, and the actions
/// are in an input-chosen wire order. The bundle signs its own commitment,
/// computed in that order before the bundle exists. Returns the unproven
/// bundle and the fee it pays. A bundle without actions has a zero max fee
/// and fee.
fn signed_bundle(
    input: &mut Unstructured<'_>,
    rng: &mut StdRng,
    sk: private::SpendingKey,
    actions: (usize, usize),
) -> (Bundle<stamp::Unproven>, value::Positive) {
    let pk = sk.derive_payment_key();
    let pak = sk.derive_proof_private();
    let note = |entropy: &mut StdRng, amount: u64| Note {
        pk,
        value: value::Positive::try_from(amount).unwrap(),
        psi: nullifier::Trapdoor::random(entropy),
        rcm: note::CommitmentTrapdoor::random(entropy),
    };
    let count = input.int_in_range(actions.0..=actions.1).unwrap();
    let mut spends = Vec::new();
    let mut outputs = Vec::new();
    for _ in 0..count {
        let spending = input.arbitrary::<bool>().unwrap();
        let action_note = note(rng, input.int_in_range(0..=VALUE_BOUND).unwrap());
        let (theta, rcv) = (ActionEntropy::random(rng), value::Trapdoor::random(rng));
        if spending {
            spends.push(action::Plan::spend(action_note, theta, rcv, |alpha| {
                pak.ak.derive_action_public(&alpha)
            }));
        } else {
            outputs.push(action::Plan::output(action_note, theta, rcv));
        }
    }
    let max_fee = if count == 0 {
        0
    } else {
        input.int_in_range(0..=VALUE_BOUND).unwrap()
    };
    let fee = input.int_in_range(0..=max_fee).unwrap();
    let memo_len = if input.arbitrary::<bool>().unwrap() {
        MEMO_LENGTHS[input.choose_index(MEMO_LENGTHS.len()).unwrap()]
    } else {
        input.int_in_range(0..=300).unwrap()
    };
    let mut memo = vec![0u8; memo_len];
    rng.fill_bytes(&mut memo);
    let max_fee_note = note(rng, max_fee);
    let plan = bundle::Plan::new(spends, outputs, max_fee_note).with_memo(memo);

    let mut order: Vec<usize> = (0..count).collect();
    for at in (1..order.len()).rev() {
        order.swap(at, input.int_in_range(0..=at).unwrap());
    }
    let ask = sk.derive_auth_private();
    let in_wire_order = |signed: Bundle<stamp::Unproven>| Bundle {
        actions: order.iter().map(|&at| signed.actions[at]).collect(),
        ..signed
    };
    // The commitment leaves out the signatures, so a bundle signed over any
    // sighash yields the commitment it must sign.
    let sighash = in_wire_order(plan.sign(rng, &[0; 32], &ask).unwrap()).commitment();
    let signed = in_wire_order(plan.sign(rng, &sighash, &ask).unwrap());
    assert_eq!(
        signed.commitment(),
        sighash,
        "the bundle signs its own commitment"
    );
    (signed, value::Positive::try_from(fee).unwrap())
}

fuzz_target!(
    init: {
        LazyLock::force(&PROOF_LEN);
    },
    |data: &[u8]| {
        let mut input = Unstructured::new(data);

        // A proof-stamped aggregate covering zero to four adjuncts: its
        // coverage digests all their descriptors and fees, it publishes two
        // tachygrams per covered action and one per covered fee, and the
        // adjuncts point at its wtxid.
        let rng = &mut StdRng::seed_from_u64(input.arbitrary().unwrap());
        let sk = private::SpendingKey::random(rng);
        let (host, host_fee) = signed_bundle(&mut input, rng, sk, (0, 4));
        let adjunct_count = input.int_in_range(0..=4).unwrap();
        let unstripped: Vec<(Bundle<stamp::Unproven>, value::Positive)> =
            iter::repeat_with(|| signed_bundle(&mut input, rng, sk, (1, 2)))
                .take(adjunct_count)
                .collect();
        let fee_of = |bundle: &Bundle<stamp::Unproven>, fee| fee::Descriptor {
            max_commitment: bundle.fee_max_commitment,
            value: fee,
        };
        let mut descriptors: Vec<[u8; 64]> = iter::once(&host)
            .chain(unstripped.iter().map(|(adjunct, _)| adjunct))
            .flat_map(|bundle| bundle.actions.iter().map(Action::descriptor))
            .collect();
        descriptors.sort_unstable();
        let mut fees: Vec<[u8; 40]> = iter::once(fee_of(&host, host_fee))
            .chain(
                unstripped
                    .iter()
                    .map(|(adjunct, fee)| fee_of(adjunct, *fee)),
            )
            .map(Into::into)
            .collect();
        fees.sort_unstable();
        let published: BTreeSet<Tachygram> = iter::repeat_with(|| Tachygram::random(rng))
            .take(2 * descriptors.len() + fees.len())
            .collect();
        let aggregate = host.stamp(ProofStamp {
            coverage: blake2b::stamp_coverage_digest(
                &blake2b::action_descriptor_digest(&descriptors),
                &blake2b::stamp_fees_digest(&fees),
            ),
            anchor: Anchor::random(rng),
            tachygram_set: published
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit(),
            tachygrams: published,
            proof: PROOF.proof.clone(),
            fee: host_fee,
        });
        let aggregate_id =
            AggregateId::try_from((&aggregate.commitment(), &aggregate.auth_digest())).unwrap();
        let adjuncts: Vec<Bundle<PointerStamp>> = unstripped
            .into_iter()
            .map(|(adjunct, fee)| {
                adjunct
                    .stamp(ProofStamp {
                        fee,
                        ..PROOF.clone()
                    })
                    .strip(aggregate_id)
            })
            .collect();

        // Flips, deletions and insertions land outside the memos and the proof
        // blob: a memo byte only moves the commitment, and the proof blob is
        // ragu's encoding. An insertion may also follow the last byte, and a
        // truncation may cut anywhere.
        let mut built = Vec::new();
        let mut editable = Vec::new();
        let mut mark = |base: usize, end: usize, memo: usize, trailer: usize, proof: usize| {
            let memo_end = end - trailer;
            editable.extend((base..memo_end - memo).chain(memo_end..end - proof));
        };
        let mut trailer = Vec::new();
        aggregate.write(&mut built).unwrap();
        aggregate.stamp.write(&mut trailer).unwrap();
        mark(0, built.len(), aggregate.memo.len(), trailer.len(), *PROOF_LEN);
        for adjunct in &adjuncts {
            let base = built.len();
            trailer.clear();
            adjunct.write(&mut built).unwrap();
            adjunct.stamp.write(&mut trailer).unwrap();
            mark(base, built.len(), adjunct.memo.len(), trailer.len(), 0);
        }

        // Applied from the highest offset down, so each edit lands where it
        // was drawn.
        let mut edits: Vec<(usize, u8, u8)> = (0..input.int_in_range(0..=MAX_EDITS).unwrap())
            .map(|_| {
                let kind = input.int_in_range(0u8..=3).unwrap();
                let at = match kind {
                    1 => {
                        let index = input.int_in_range(0..=editable.len()).unwrap();
                        if index == editable.len() {
                            built.len()
                        } else {
                            editable[index]
                        }
                    },
                    3 => input.int_in_range(0..=built.len()).unwrap(),
                    _ => editable[input.choose_index(editable.len()).unwrap()],
                };
                (at, kind, input.arbitrary::<u8>().unwrap())
            })
            .collect();
        edits.sort_unstable_by_key(|&(at, ..)| cmp::Reverse(at));
        let mut wire = built.clone();
        for (at, kind, byte) in edits {
            match kind {
                0 if at < wire.len() => wire[at] ^= byte.max(1),
                1 => wire.insert(at, byte),
                2 if at < wire.len() => {
                    wire.remove(at);
                },
                3 => wire.truncate(at),
                // A flip or deletion past an earlier truncation.
                _ => {},
            }
        }
        let edited = wire != built;

        let mut rest = wire.as_slice();
        let mut decoded = Vec::new();
        while decoded.len() <= adjuncts.len() {
            let Some((bundle, tail)) = check_bundle_wire(rest) else {
                break;
            };
            decoded.push(bundle);
            rest = tail;
        }

        let mut bundles = decoded.into_iter();
        let Some(TachyonBundle::Proven(head)) = bundles.next() else {
            assert!(edited, "the built aggregate decodes as proof-stamped");
            return;
        };
        let tail: Vec<Bundle<PointerStamp>> = bundles
            .map_while(|bundle| match bundle {
                TachyonBundle::Adjunct(adjunct) => Some(adjunct),
                TachyonBundle::NoBundle | TachyonBundle::Proven(_) => None,
            })
            .collect();

        let wtxid: [u8; 64] = AggregateId::try_from((&head.commitment(), &head.auth_digest()))
            .expect("a digest pair is not all zero")
            .into();
        let verified = head.verify(
            &mut StdRng::seed_from_u64(0),
            &head.commitment(),
            &wtxid,
            &tail.iter().collect::<Vec<_>>(),
        );
        match verified {
            Ok(()) => panic!("a proof of another stamp verifies"),
            Err(VerificationError::Disproved) => {},
            Err(err) => assert!(
                edited,
                "the built aggregate passes every check before the proof, not: {err}"
            ),
        }

        if !edited {
            assert!(rest.is_empty(), "the built wire decodes completely");
            assert_eq!(
                (head.commitment(), head.auth_digest()),
                (aggregate.commitment(), aggregate.auth_digest()),
                "the aggregate decodes to the one built"
            );
            assert_eq!(
                tail.iter()
                    .map(|adjunct| (adjunct.commitment(), adjunct.auth_digest()))
                    .collect::<Vec<_>>(),
                adjuncts
                    .iter()
                    .map(|adjunct| (adjunct.commitment(), adjunct.auth_digest()))
                    .collect::<Vec<_>>(),
                "the adjuncts decode to the ones built"
            );
            for adjunct in &tail {
                assert!(
                    adjunct.verify_signatures(&adjunct.commitment()).is_ok(),
                    "an adjunct signs its own commitment"
                );
            }
        }
    }
);
