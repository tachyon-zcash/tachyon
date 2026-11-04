#![no_main]

//! Fuzz the bundle reader and [`Bundle::verify`] with edits to a consistent
//! wire.
//!
//! The input draws a proof-stamped aggregate and zero to four pointer-stamped
//! adjuncts it covers ([`build_wire`]), then up to four edits to their
//! concatenated encoding outside the memos and the proof blob: a byte flipped,
//! inserted or deleted, or the encoding truncated. Every bundle that decodes
//! passes [`check_bundle_wire`], and the decoded aggregate is verified against
//! the decoded adjuncts. The aggregate carries the proof of another stamp, so
//! no wire verifies. Without an edit, every bundle decodes completely to the
//! one built, each adjunct signs its own commitment, and `verify` rejects only
//! at the proof.
//!
//! The proof is of one action-free stamp, proved at initialization, so the
//! input never pays for proving.

use std::{cmp, sync::LazyLock};

use libfuzzer_sys::{arbitrary::Unstructured, fuzz_target};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor,
    bundle::{Bundle, TachyonBundle, VerificationError},
    keys::private,
    note::{self, Note},
    nullifier,
    stamp::{self, AggregateId, PointerStamp, ProofStamp},
    value,
};
use zcash_tachyon_fuzz::{build_wire, check_bundle_wire, draw, encode, proof_len};

/// The most edits one input applies.
const MAX_EDITS: u8 = 4;

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

fuzz_target!(
    init: {
        LazyLock::force(&PROOF);
    },
    |data: &[u8]| {
        let mut input = Unstructured::new(data);
        let (aggregate, adjuncts) = build_wire(&mut input, &PROOF);

        // Edits land outside the memos and the proof blob: a memo byte only
        // moves the commitment, and the proof blob is ragu's encoding.
        let mut built = Vec::new();
        let mut editable = Vec::new();
        let mut append = |encoding: Vec<u8>, memo: usize, trailer: usize, proof: usize| {
            let memo_end = encoding.len() - trailer;
            let base = built.len();
            editable.extend(
                (0..memo_end - memo)
                    .chain(memo_end..encoding.len() - proof)
                    .map(|at| base + at),
            );
            built.extend(encoding);
        };
        append(
            encode(|writer| aggregate.write(writer)),
            aggregate.memo.len(),
            encode(|writer| aggregate.stamp.write(writer)).len(),
            proof_len(&aggregate.stamp),
        );
        for adjunct in &adjuncts {
            append(
                encode(|writer| adjunct.write(writer)),
                adjunct.memo.len(),
                encode(|writer| adjunct.stamp.write(writer)).len(),
                0,
            );
        }

        // Applied from the highest offset down, so each edit lands where it
        // was drawn.
        let mut edits: Vec<(usize, u8, u8)> = (0..draw(input.int_in_range(0..=MAX_EDITS)))
            .map(|_| {
                (
                    editable[draw(input.choose_index(editable.len()))],
                    draw(input.int_in_range(0u8..=3)),
                    draw(input.arbitrary::<u8>()),
                )
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
                _ => wire.truncate(at),
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
