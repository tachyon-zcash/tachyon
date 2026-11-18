use alloc::vec::Vec;

use ragu::ProductionRank;
use rand::SeedableRng as _;
use rand::rngs::StdRng;

use super::*;
use crate::constants::EPOCH_MAX;
use crate::keys::private;
use crate::nullifier::Nullifier;
use crate::stamp::proof::{App, new_application};
use crate::witness;

/// # Panics
///
/// Panics if seeding the fixed note fails.
fn note_secret(app: &App<'_>, rng: &mut StdRng) -> ragu::Pcd<Pasta, ProductionRank, NoteSecret> {
    let pak = private::SpendingKey::from([0xab; 32]).derive_proof_private();
    let note = Note {
        pk: pak.derive_payment_key(),
        value: value::Positive::try_from(500u64).unwrap(),
        psi: nullifier::Trapdoor::from(Fp::from(13)),
        rcm: note::CommitmentTrapdoor::from(Fp::from(17)),
    };
    app.seed(rng, NoteSeed, witness::note_seed(((), ()), note, pak))
        .unwrap()
        .0
}

/// # Panics
///
/// Panics if the starting epoch is out of range or proving the window fails.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "the fixture widens the epoch to u64 and only supplies four fixed group offsets"
)]
fn derive_window(
    app: &App<'_>,
    rng: &mut StdRng,
    start: u32,
) -> ragu::Pcd<Pasta, ProductionRank, NoteNullifiers> {
    let secret = note_secret(app, rng);
    let (_, _, mk) = *secret.data();
    let epoch_start = EpochIndex::new(start);
    let nullifiers: Vec<Nullifier> = (0..4u64)
        .flat_map(|group| poseidon::nullifier_group(mk.0, Fp::from(u64::from(start) + 4 * group)))
        .map(Nullifier::from)
        .collect();
    app.fuse(
        rng,
        NullifierDerive,
        (epoch_start, NfSeqPoly::new(epoch_start, &nullifiers)),
        secret,
        app.bootstrap_proof().clone().carry::<()>(()),
    )
    .unwrap()
    .0
}

/// # Panics
///
/// Panics if the application cannot be built or the final valid window cannot
/// be proved and verified.
#[test]
fn nullifier_derive_proves_a_window_ending_at_the_final_epoch() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let pcd = derive_window(&app, rng, EPOCH_MAX - 15);
    assert!(app.verify_uncompressed(&pcd, &mut *rng).unwrap());
}

/// # Panics
///
/// Panics if the end of the window exceeds `EPOCH_MAX`.
#[test]
#[should_panic(expected = "epoch index above EPOCH_MAX")]
fn nullifier_derive_refuses_to_prove_a_window_past_the_final_epoch() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let _pcd = derive_window(&app, rng, EPOCH_MAX - 11);
}

/// # Panics
///
/// Panics if the requested witness would extend past `EPOCH_MAX`.
#[test]
#[should_panic(expected = "epoch index above EPOCH_MAX")]
fn nullifier_derive_witness_refuses_a_window_past_the_final_epoch() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let secret = note_secret(&app, rng);
    let _witness = witness::nullifier_derive((*secret.data(), ()), EpochIndex::new(EPOCH_MAX - 3));
}
