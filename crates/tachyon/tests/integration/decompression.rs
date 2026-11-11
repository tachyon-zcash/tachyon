extern crate alloc;

use alloc::{collections::BTreeSet, vec, vec::Vec};

use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, ProofStamp, TachygramSetPoly, action, fee,
    stamp::{self, Compressed},
    value,
};

use crate::fixtures::{WalletSim, build_output_plan, stamp_coverage};

type CoveredStamp = (
    ProofStamp<Compressed>,
    BTreeSet<action::Descriptor>,
    BTreeSet<fee::Descriptor>,
);

fn transport(stamp: &ProofStamp<Compressed>) -> ProofStamp<Compressed> {
    let mut bytes = Vec::new();
    stamp.write(&mut bytes).unwrap();
    ProofStamp::<Compressed>::read(&*bytes).unwrap()
}

fn payment(rng: &mut StdRng, anchor: Anchor, amount: u64, fee_zat: u64) -> CoveredStamp {
    let wallet = WalletSim::random(rng);
    let note = wallet.random_note(amount);
    let (trapdoor, entropy, plan) = build_output_plan(rng, note);
    let fee_note = wallet.random_note(100);
    let selected_fee = value::Positive::try_from(fee_zat).unwrap();
    let descriptors = BTreeSet::from([plan.descriptor()]);
    let fees = BTreeSet::from([fee::Descriptor {
        cv_feemax: fee_note.cv_feemax(),
        v_fee: selected_fee,
    }]);
    let uncompressed = stamp::Plan::new(
        vec![],
        vec![(plan.descriptor(), entropy, note, trapdoor)],
        anchor,
        fee_note,
        selected_fee,
    )
    .prove(rng, &wallet.pak, vec![])
    .unwrap();
    (
        transport(&uncompressed.compress(rng).unwrap()),
        descriptors,
        fees,
    )
}

#[test]
fn compressed_aggregates_roundtrip_and_merge_again() {
    let rng = &mut StdRng::seed_from_u64(947);
    let anchor = Anchor::random(rng);
    let (left, left_desc, left_fees) = payment(rng, anchor, 200, 10);
    let (right, right_desc, right_fees) = payment(rng, anchor, 300, 20);
    let (third, third_desc, third_fees) = payment(rng, anchor, 400, 30);
    let restored = left
        .clone()
        .decompress(rng, &left_desc, &left_fees)
        .unwrap();
    assert_eq!(restored.coverage, left.coverage);
    assert_eq!(restored.anchor, left.anchor);
    assert_eq!(restored.tachygram_set, left.tachygram_set);
    assert_eq!(restored.tachygrams, left.tachygrams);
    assert_eq!(restored.fee, left.fee);

    let mut all_desc = left_desc
        .union(&right_desc)
        .copied()
        .collect::<BTreeSet<_>>();
    let mut all_fees = left_fees
        .union(&right_fees)
        .copied()
        .collect::<BTreeSet<_>>();
    let mut all_tachygrams = left
        .tachygrams
        .union(&right.tachygrams)
        .copied()
        .collect::<BTreeSet<_>>();
    let merged = left
        .clone()
        .merge(rng, (left_desc, left_fees), (right, right_desc, right_fees))
        .unwrap();
    let received = transport(&merged);
    assert!(received.is_covering(all_desc.iter().copied(), all_fees.iter().copied()));
    assert!(
        received
            .verify_proof(
                rng,
                all_desc
                    .iter()
                    .map(|descriptor| descriptor.digest().unwrap())
                    .chain(
                        all_fees
                            .iter()
                            .map(|descriptor| descriptor.digest().unwrap())
                    )
            )
            .unwrap()
    );
    assert_eq!(received.tachygrams, all_tachygrams);
    assert_eq!(received.fee, left.fee);

    let aggregate = received
        .merge(
            rng,
            (all_desc.clone(), all_fees.clone()),
            (third.clone(), third_desc.clone(), third_fees.clone()),
        )
        .unwrap();
    all_desc.extend(third_desc);
    all_fees.extend(third_fees);
    all_tachygrams.extend(third.tachygrams);
    let final_stamp = transport(&aggregate);
    assert!(final_stamp.is_covering(all_desc.iter().copied(), all_fees.iter().copied()));
    assert!(
        final_stamp
            .verify_proof(
                rng,
                all_desc
                    .iter()
                    .map(|descriptor| descriptor.digest().unwrap())
                    .chain(
                        all_fees
                            .iter()
                            .map(|descriptor| descriptor.digest().unwrap())
                    )
            )
            .unwrap()
    );
    assert_eq!(final_stamp.tachygrams, all_tachygrams);
    assert_eq!(final_stamp.fee, left.fee);
}

#[test]
fn decompression_rejects_mismatched_public_data() {
    let rng = &mut StdRng::seed_from_u64(894);
    let anchor = Anchor::random(rng);
    let (stamp, descriptors, fees) = payment(rng, anchor, 200, 10);
    let (other, other_desc, other_fees) = payment(rng, anchor, 300, 20);
    let mut wrong_coverage = stamp.clone();
    wrong_coverage.coverage[0] ^= 1;
    let mut wrong_anchor = stamp.clone();
    wrong_anchor.anchor = Anchor::random(rng);
    let mut wrong_tachygrams = stamp.clone();
    wrong_tachygrams.tachygrams.pop_first();
    let mut wrong_commitment = wrong_tachygrams.clone();
    wrong_commitment.tachygram_set = wrong_commitment
        .tachygrams
        .iter()
        .copied()
        .collect::<TachygramSetPoly>()
        .commit();
    let mut substituted_proof = stamp.clone();
    substituted_proof.proof = other.proof;
    for altered in [
        wrong_coverage,
        wrong_anchor,
        wrong_tachygrams,
        wrong_commitment,
        substituted_proof,
    ] {
        altered.decompress(rng, &descriptors, &fees).unwrap_err();
    }
    // Matching a forged coverage digest must not bypass the proof's online
    // commitments.
    let mut wrong_actions = stamp.clone();
    wrong_actions.coverage = stamp_coverage(
        other_desc.iter().copied(),
        &fees.iter().copied().collect::<Vec<_>>(),
    );
    wrong_actions
        .decompress(rng, &other_desc, &fees)
        .unwrap_err();
    let mut wrong_fees = stamp.clone();
    wrong_fees.coverage = stamp_coverage(
        descriptors.iter().copied(),
        &other_fees.iter().copied().collect::<Vec<_>>(),
    );
    wrong_fees
        .decompress(rng, &descriptors, &other_fees)
        .unwrap_err();
    stamp.decompress(rng, &descriptors, &fees).unwrap();
}

#[test]
fn compressed_merge_rejects_overlap_and_different_anchors() {
    let rng = &mut StdRng::seed_from_u64(948);
    let anchor = Anchor::random(rng);
    let (left, descriptors, fees) = payment(rng, anchor, 200, 10);
    left.clone()
        .merge(
            rng,
            (descriptors.clone(), fees.clone()),
            (left.clone(), descriptors.clone(), fees.clone()),
        )
        .unwrap_err();
    let other_anchor = Anchor::random(rng);
    let right = payment(rng, other_anchor, 300, 20);
    left.merge(rng, (descriptors, fees), right).unwrap_err();
}

#[test]
fn oversized_descriptor_sets_are_rejected_before_polynomial_construction() {
    let rng = &mut StdRng::seed_from_u64(949);
    let anchor = Anchor::random(rng);
    let (stamp, descriptors, fees) = payment(rng, anchor, 200, 10);
    let fee_template = *fees.first().unwrap();
    let oversized = (1..=ProductionRank::num_coeffs())
        .map(|index| fee::Descriptor {
            v_fee: value::Positive::try_from(u64::try_from(index).unwrap()).unwrap(),
            ..fee_template
        })
        .collect::<BTreeSet<_>>();
    let decompression_error = stamp
        .clone()
        .decompress(rng, &descriptors, &oversized)
        .unwrap_err();
    assert!(decompression_error.to_string().contains("rank capacity"));
    // Each half fits separately, but the merged polynomial does not.
    let left_fees = oversized
        .iter()
        .take(oversized.len() / 2)
        .copied()
        .collect();
    let right_fees = oversized
        .iter()
        .skip(oversized.len() / 2)
        .copied()
        .collect();
    let merge_error = stamp
        .clone()
        .merge(
            rng,
            (descriptors.clone(), left_fees),
            (stamp, descriptors, right_fees),
        )
        .unwrap_err();
    assert!(merge_error.to_string().contains("rank capacity"));
}
