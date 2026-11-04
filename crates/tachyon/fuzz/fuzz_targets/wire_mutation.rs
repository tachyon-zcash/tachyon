#![no_main]

//! Fuzz the bundle reader and [`Bundle::verify`] with edits to a consistent
//! wire.
//!
//! The input draws a proof-stamped aggregate and zero to four pointer-stamped
//! adjuncts it covers ([`build_wire`]), then up to four edits to their
//! concatenated encoding: a byte flipped, inserted or deleted, or the encoding
//! truncated. Every bundle that decodes passes [`check_bundle_wire`], and the
//! decoded aggregate is verified against the decoded adjuncts. The aggregate
//! carries the proof of another stamp, so no wire verifies. Without an edit,
//! every bundle decodes completely to the one built, each adjunct signs its
//! own commitment, and `verify` rejects only at the proof.
//!
//! The proof is of one action-free stamp, proved at initialization, so the
//! input never pays for proving.

use std::sync::LazyLock;

use libfuzzer_sys::{arbitrary::Unstructured, fuzz_target};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor,
    bundle::{Bundle, TachyonBundle, VerificationError},
    keys::private,
    note::{self, Note},
    nullifier,
    stamp::{self, PointerStamp, ProofStamp},
    value,
};
use zcash_tachyon_fuzz::{build_wire, check_bundle_wire, draw, encode};

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
        let mut built = encode(|writer| aggregate.write(writer));
        for adjunct in &adjuncts {
            built.extend(encode(|writer| adjunct.write(writer)));
        }

        let mut wire = built.clone();
        for _ in 0..draw(input.int_in_range(0..=MAX_EDITS)) {
            let byte = draw(input.arbitrary::<u8>());
            match draw(input.int_in_range(0u8..=3)) {
                0 if !wire.is_empty() => {
                    let at = draw(input.choose_index(wire.len()));
                    wire[at] ^= byte.max(1);
                },
                1 => {
                    let at = draw(input.int_in_range(0..=wire.len()));
                    wire.insert(at, byte);
                },
                2 if !wire.is_empty() => {
                    let at = draw(input.choose_index(wire.len()));
                    wire.remove(at);
                },
                _ => {
                    let at = draw(input.int_in_range(0..=wire.len()));
                    wire.truncate(at);
                },
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

        let mut wtxid = [0u8; 64];
        wtxid[..32].copy_from_slice(&head.commitment());
        wtxid[32..].copy_from_slice(&head.auth_digest());
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
