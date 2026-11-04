use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{constants::MAX_MONEY, value};

#[test]
fn the_commitment_binds_every_field() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (amount, other_amount) in [(0, MAX_MONEY), (MAX_MONEY, 0), (1000, 1000)] {
        let note = Note {
            pk: PaymentKey::random(rng),
            value: value::Positive::try_from(amount).unwrap(),
            psi: nullifier::Trapdoor::random(rng),
            rcm: CommitmentTrapdoor::random(rng),
        };
        let cm = note.commitment();
        let other_value = value::Positive::try_from(other_amount).unwrap();
        for (field, changed, other) in [
            (
                "rcm",
                true,
                Note {
                    rcm: CommitmentTrapdoor::random(rng),
                    ..note
                },
            ),
            (
                "pk",
                true,
                Note {
                    pk: PaymentKey::random(rng),
                    ..note
                },
            ),
            (
                "psi",
                true,
                Note {
                    psi: nullifier::Trapdoor::random(rng),
                    ..note
                },
            ),
            (
                "value",
                amount != other_amount,
                Note {
                    value: other_value,
                    ..note
                },
            ),
        ] {
            assert_eq!(
                other.commitment() != cm,
                changed,
                "value {amount} against {other_amount}: {field}"
            );
        }
        let pad = poseidon::pad_tachygram(note.rcm.0, note.pk.into(), amount, note.psi.into());
        assert_ne!(Fp::from(cm), pad, "value {amount}: the pad");
    }
}
