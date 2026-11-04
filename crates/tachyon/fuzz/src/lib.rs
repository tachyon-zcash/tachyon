//! Oracles and the wire builder the fuzz targets share.
//!
//! Every reader under fuzz consumes untrusted bytes. Liveness is the floor: an
//! input decodes or returns an `io::Error`, never panics. On top of that, an
//! accepted input must be the canonical encoding of the value it decodes to,
//! so writing the value back reproduces exactly the bytes the reader consumed.
//! A reader that accepted an over-long count, an unsorted or repeated
//! tachygram, or any other alternative spelling fails that comparison.
//!
//! The one exception is a proof stamp's proof, an opaque blob that ragu's own
//! codec decodes. Mock ragu reads the proof's fields and ignores the padding
//! after them, so a blob is accepted with any padding and written back with
//! zeros. The comparison stops short of the proof and leaves its canonicality
//! to ragu.

use std::{collections::BTreeSet, hint, io, iter};

use libfuzzer_sys::arbitrary::{self, Unstructured};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Action, Anchor, Bundle, Tachygram, TachygramSetPoly, action,
    bundle::{self, TachyonBundle},
    constants::MAX_MONEY,
    digest::blake2b,
    entropy::ActionEntropy,
    fee,
    keys::private,
    note::{self, Note},
    nullifier,
    stamp::{self, AggregateId, PointerStamp, ProofStamp, StampState},
    value,
};

/// The bytes `write` produces.
///
/// # Panics
///
/// Panics if `write` fails.
pub fn encode(write: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> Vec<u8> {
    let mut buf = Vec::new();
    write(&mut buf).expect("an in-memory write succeeds");
    buf
}

/// The value of a draw from an [`Unstructured`]. A draw from a nonempty range
/// or choice cannot fail: an exhausted input pads with zeros.
///
/// # Panics
///
/// Panics if the draw failed.
pub fn draw<T>(drawn: arbitrary::Result<T>) -> T {
    drawn.expect("a draw from a nonempty range or choice succeeds")
}

/// Read a value off the front of `data`. When it decodes, assert `write`
/// reproduces the consumed bytes, all but the last `opaque_tail(&value)` of
/// them, and return the value with the unread tail of `data`.
///
/// # Panics
///
/// Panics if an accepted value fails to re-encode, or re-encodes to bytes
/// other than the ones consumed.
pub fn read_canonical<'data, T>(
    data: &'data [u8],
    read: impl FnOnce(&mut &'data [u8]) -> io::Result<T>,
    write: impl FnOnce(&T, &mut Vec<u8>) -> io::Result<()>,
    opaque_tail: impl FnOnce(&T) -> usize,
) -> Option<(T, &'data [u8])> {
    let mut rest = data;
    let decoded = read(&mut rest).ok()?;
    let consumed = &data[..data.len() - rest.len()];

    let mut encoded = Vec::new();
    write(&decoded, &mut encoded).expect("an accepted value re-encodes");
    assert_eq!(
        encoded.len(),
        consumed.len(),
        "an accepted value re-encodes to the length consumed"
    );
    let compared = consumed.len() - opaque_tail(&decoded);
    if let Some(offset) = encoded[..compared]
        .iter()
        .zip(&consumed[..compared])
        .position(|(re, orig)| re != orig)
    {
        panic!(
            "an accepted encoding is not canonical: {} bytes consumed, first difference at byte {offset}",
            consumed.len(),
        );
    }

    Some((decoded, rest))
}

/// The length of a proof stamp's proof blob, the tail of its encoding.
#[must_use]
pub fn proof_len(stamp: &ProofStamp) -> usize {
    stamp.proof.serialize().len()
}

/// Assert the bundle-body invariants a canonical encoding does not imply, and
/// take both digests over the decoded bundle.
///
/// # Panics
///
/// Panics if a bundle without actions carries a nonzero value balance, or if
/// its max fee commitment is the identity.
pub fn assert_bundle_invariants<S: StampState + 'static>(bundle: &Bundle<S>) {
    if bundle.actions.is_empty() {
        assert_eq!(
            bundle.value_balance,
            value::Balance::ZERO,
            "a bundle without actions has a zero value balance"
        );
    }
    assert_ne!(
        bundle.fee_max_commitment,
        value::Commitment::default(),
        "the max fee commitment is not the identity"
    );

    hint::black_box(bundle.commitment());
    hint::black_box(bundle.auth_digest());
}

/// Read a bundle off the front of `data` through [`TachyonBundle::read`].
///
/// Returns the bundle with the unread tail if it decodes. An accepted bundle
/// is canonical, with the proof blob as an opaque tail, and holds the bundle
/// invariants. An accepted proof stamp publishes a tachygram.
///
/// # Panics
///
/// Panics if an accepted bundle is not canonical or breaks an invariant.
#[must_use]
pub fn check_bundle_wire(data: &[u8]) -> Option<(TachyonBundle, &[u8])> {
    let (bundle, rest) = read_canonical(
        data,
        |reader| TachyonBundle::read(reader),
        |bundle, writer| bundle.write(writer),
        |bundle| match bundle {
            TachyonBundle::Proven(proven) => proof_len(&proven.stamp),
            TachyonBundle::NoBundle | TachyonBundle::Adjunct(_) => 0,
        },
    )?;
    match &bundle {
        TachyonBundle::NoBundle => {},
        TachyonBundle::Proven(proven) => {
            assert_bundle_invariants(proven);
            assert!(
                !proven.stamp.tachygrams.is_empty(),
                "a proof stamp publishes at least one tachygram"
            );
        },
        TachyonBundle::Adjunct(adjunct) => assert_bundle_invariants(adjunct),
    }
    Some((bundle, rest))
}

/// The largest note value, max fee and fee the builder draws, small enough
/// that five of them keep a value balance within `MAX_MONEY`.
const VALUE_BOUND: u64 = MAX_MONEY / 8;

/// The memo lengths the builder draws besides an arbitrary short one.
///
/// They are empty, either side of the three-byte compact size, and either side
/// of the five-byte one.
const MEMO_LENGTHS: [usize; 5] = [0, 252, 253, 0xFFFF, 0x1_0000];

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
        value: value::Positive::try_from(amount).expect("a value within MAX_MONEY"),
        psi: nullifier::Trapdoor::random(entropy),
        rcm: note::CommitmentTrapdoor::random(entropy),
    };
    let count = draw(input.int_in_range(actions.0..=actions.1));
    let mut spends = Vec::new();
    let mut outputs = Vec::new();
    for _ in 0..count {
        let spending = draw(input.arbitrary::<bool>());
        let action_note = note(rng, draw(input.int_in_range(0..=VALUE_BOUND)));
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
        draw(input.int_in_range(0..=VALUE_BOUND))
    };
    let fee = draw(input.int_in_range(0..=max_fee));
    let memo_len = if draw(input.arbitrary::<bool>()) {
        MEMO_LENGTHS[draw(input.choose_index(MEMO_LENGTHS.len()))]
    } else {
        draw(input.int_in_range(0..=300))
    };
    let mut memo = vec![0u8; memo_len];
    rng.fill_bytes(&mut memo);
    let max_fee_note = note(rng, max_fee);
    let plan = bundle::Plan::new(spends, outputs, max_fee_note).with_memo(memo);

    let mut order: Vec<usize> = (0..count).collect();
    for at in (1..order.len()).rev() {
        order.swap(at, draw(input.int_in_range(0..=at)));
    }
    let ask = sk.derive_auth_private();
    let in_wire_order = |signed: Bundle<stamp::Unproven>| Bundle {
        actions: order.iter().map(|&at| signed.actions[at]).collect(),
        ..signed
    };
    // The commitment leaves out the signatures, so a bundle signed over any
    // sighash yields the commitment it must sign.
    let sighash =
        in_wire_order(plan.sign(rng, &[0; 32], &ask).expect("sign the plan")).commitment();
    let signed = in_wire_order(plan.sign(rng, &sighash, &ask).expect("sign the plan"));
    assert_eq!(
        signed.commitment(),
        sighash,
        "the bundle signs its own commitment"
    );
    (
        signed,
        value::Positive::try_from(fee).expect("a fee within MAX_MONEY"),
    )
}

/// A proof-stamped aggregate and zero to four pointer-stamped adjuncts it
/// covers, drawn from `input`.
///
/// Every bundle signs its own commitment. The aggregate's coverage is the
/// digest of all their descriptors and fees, it publishes two tachygrams per
/// covered action and one per covered fee under a commitment to them, and it
/// carries `proof`. The adjuncts point at the aggregate's wtxid, its
/// commitment followed by its auth digest.
///
/// # Panics
///
/// Panics if a drawn shape cannot be signed, which is a builder bug.
pub fn build_wire(
    input: &mut Unstructured<'_>,
    proof: &ProofStamp,
) -> (Bundle<ProofStamp>, Vec<Bundle<PointerStamp>>) {
    let rng = &mut StdRng::seed_from_u64(draw(input.arbitrary()));
    let sk = private::SpendingKey::random(rng);
    let (host, host_fee) = signed_bundle(input, rng, sk, (0, 4));
    let adjunct_count = draw(input.int_in_range(0..=4));
    let unstripped: Vec<(Bundle<stamp::Unproven>, value::Positive)> =
        iter::repeat_with(|| signed_bundle(input, rng, sk, (1, 2)))
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
        proof: proof.proof.clone(),
        fee: host_fee,
    });

    let wtxid = AggregateId::try_from((&aggregate.commitment(), &aggregate.auth_digest()))
        .expect("a digest pair is not all zero");
    let adjuncts = unstripped
        .into_iter()
        .map(|(adjunct, fee)| {
            adjunct
                .stamp(ProofStamp {
                    fee,
                    ..proof.clone()
                })
                .strip(wtxid)
        })
        .collect();
    (aggregate, adjuncts)
}
