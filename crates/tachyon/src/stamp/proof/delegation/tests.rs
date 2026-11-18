use alloc::vec::Vec;
use core::panic::AssertUnwindSafe;
use std::panic::catch_unwind;

use ragu::ProductionRank;
use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    constants::EPOCH_MAX,
    keys::private,
    nullifier::Nullifier,
    stamp::proof::{App, new_application},
    witness,
};

fn note_secret(app: &App<'_>, rng: &mut StdRng) -> ragu::Pcd<Pasta, ProductionRank, NoteSecret> {
    let pak = private::SpendingKey::from([0xAB; 32]).derive_proof_private();
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

/// The last group-aligned window start that fits, and the next. The sequence
/// holds the nullifiers the circuit derives. The window ending at `EPOCH_MAX`
/// verifies; the next one panics proving its end.
#[test]
fn nullifier_derive_proves_only_windows_inside_the_epoch_range() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let secret = note_secret(&app, rng);
    let (_, _, mk) = *secret.data();
    for start in [EPOCH_MAX - 15, EPOCH_MAX - 11] {
        let epoch_start = EpochIndex::new(start);
        let nullifiers: Vec<Nullifier> = (0..4u64)
            .flat_map(|group| {
                poseidon::nullifier_group(mk.0, Fp::from(u64::from(start) + 4 * group))
            })
            .map(Nullifier::from)
            .collect();
        let fused = catch_unwind(AssertUnwindSafe(|| {
            app.fuse(
                &mut *rng,
                NullifierDerive,
                (epoch_start, NfSeqPoly::new(epoch_start, &nullifiers)),
                secret.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
        }));
        if start == EPOCH_MAX - 15 {
            let (pcd, ()) = fused.unwrap().unwrap();
            assert!(app.verify_uncompressed(&pcd, &mut *rng).unwrap());
        } else {
            let payload = fused.err().unwrap();
            assert_eq!(
                payload.downcast_ref::<&str>(),
                Some(&"epoch index above EPOCH_MAX")
            );
        }
    }
}

#[test]
#[should_panic(expected = "epoch index above EPOCH_MAX")]
fn nullifier_derive_witness_refuses_a_window_past_the_final_epoch() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let secret = note_secret(&app, rng);
    let _witness = witness::nullifier_derive((*secret.data(), ()), EpochIndex::new(EPOCH_MAX - 3));
}
