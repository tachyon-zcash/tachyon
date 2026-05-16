//! Proptest generators for Tachyon types.
//!
//! Generators live here for reuse across test modules.
//! Property tests are colocated with the types they exercise.

#![allow(
    dead_code,
    reason = "generators are provided for reuse by other test modules"
)]

use proptest::prelude::*;

use crate::{
    constants::NOTE_VALUE_MAX,
    entropy::ActionEntropy,
    keys::private,
    note::{self, Note},
    value,
};

/// Half of `NOTE_VALUE_MAX`, for generating pairs that don't overflow when summed.
pub(crate) const HALF_MAX: u64 = 1_050_000_000_000_000;

/// Arbitrary spending key: any 32-byte array is valid.
pub(crate) fn arb_spending_key() -> impl Strategy<Value = private::SpendingKey> {
    any::<[u8; 32]>().prop_map(private::SpendingKey::from)
}

/// Arbitrary note value: non-zero, bounded by `NOTE_VALUE_MAX`.
pub(crate) fn arb_value() -> impl Strategy<Value = note::Value> {
    (1u64..=NOTE_VALUE_MAX).prop_map(note::Value::from)
}

/// Arbitrary value commitment trapdoor from a random 32-byte seed.
pub(crate) fn arb_commitment_trapdoor() -> impl Strategy<Value = value::CommitmentTrapdoor> {
    any::<u64>().prop_map(|seed| {
        use rand::{SeedableRng as _, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(seed);
        value::CommitmentTrapdoor::random(&mut rng)
    })
}

/// Arbitrary nullifier trapdoor from a random seed.
pub(crate) fn arb_nullifier_trapdoor() -> impl Strategy<Value = note::NullifierTrapdoor> {
    any::<u64>().prop_map(|seed| {
        use ff::Field as _;
        use pasta_curves::Fp;
        use rand::{SeedableRng as _, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(seed);
        note::NullifierTrapdoor::from(Fp::random(&mut rng))
    })
}

/// Arbitrary note commitment trapdoor from a random seed.
pub(crate) fn arb_note_commitment_trapdoor() -> impl Strategy<Value = note::CommitmentTrapdoor> {
    any::<u64>().prop_map(|seed| {
        use ff::Field as _;
        use pasta_curves::Fp;
        use rand::{SeedableRng as _, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(seed);
        note::CommitmentTrapdoor::from(Fp::random(&mut rng))
    })
}

/// Arbitrary note with a valid (pk, value, psi, rcm) combination.
///
/// Derives `pk` from an actual spending key to ensure semantic validity.
pub(crate) fn arb_note() -> impl Strategy<Value = Note> {
    (
        arb_spending_key(),
        arb_value(),
        arb_nullifier_trapdoor(),
        arb_note_commitment_trapdoor(),
    )
        .prop_map(|(sk, val, psi, rcm)| Note {
            pk: sk.derive_payment_key(),
            value: val,
            psi,
            rcm,
        })
}

/// Arbitrary action entropy from a random seed.
pub(crate) fn arb_action_entropy() -> impl Strategy<Value = ActionEntropy> {
    any::<[u8; 32]>().prop_map(ActionEntropy::from_bytes)
}
