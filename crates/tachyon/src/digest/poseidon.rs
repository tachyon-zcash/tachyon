//! Tachyon Poseidon digests.
//!
//! Each named function provides one protocol-defined hash.

use core::array;

use ff::PrimeField as _;
use group::{CurveAffine as _, GroupEncoding as _};
use pasta_curves::{EpAffine, EqAffine, Fp, arithmetic::Coordinates};
use ragu_arithmetic::{Cycle as _, PoseidonPermutation as _};
use ragu_core::{
    drivers::emulator::{Emulator, Wireless},
    maybe::{Always, Maybe as _},
};
use ragu_pasta::{Pasta, PoseidonFp};
use ragu_primitives::{Element, poseidon::Sponge};

/// The wireless emulator that evaluates the real in-circuit sponge natively:
/// witness values are always present and no wires are tracked, so absorb and
/// squeeze compute field values without building constraints.
type Emu = Emulator<Wireless<Always<()>, Fp>>;

fn sponge() -> (Emu, Sponge<'static, Emu, PoseidonFp>) {
    let mut emulator = Emu::execute();
    let sponge = Sponge::new(&mut emulator, Pasta::circuit_poseidon(Pasta::baked()));
    (emulator, sponge)
}

#[expect(
    clippy::expect_used,
    reason = "sponge absorb/squeeze cannot fail in wireless `Always` mode"
)]
fn hash<const L: usize>(input: [Fp; L]) -> Fp {
    let (mut emulator, mut sponge) = sponge();
    for value in input {
        let element = Element::constant(&mut emulator, value);
        sponge.absorb(&mut emulator, &element).expect("infallible");
    }
    let squeezed = sponge.squeeze(&mut emulator).expect("infallible");
    *squeezed.value().take()
}

const ACTION_DIGEST_DOMAIN: &[u8; 16] = b"Tachyon-ActionDg";

/// Derives an action digest from action fields.
#[must_use]
pub fn action_digest(cv: Coordinates<EpAffine>, rk: Coordinates<EpAffine>) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*ACTION_DIGEST_DOMAIN)),
        *cv.x(),
        *cv.y(),
        *rk.x(),
        *rk.y(),
    ])
}

const PAYMENT_KEY_DOMAIN: &[u8; 16] = b"Tachyon-PkDerive";

/// Derives a payment key from a spend validating key and nullifier key.
#[must_use]
pub fn payment_key(ak: Coordinates<EpAffine>, nk: Fp) -> Fp {
    hash::<4>([
        Fp::from_u128(u128::from_le_bytes(*PAYMENT_KEY_DOMAIN)),
        *ak.x(),
        *ak.y(),
        nk,
    ])
}

const NOTE_COMMITMENT_DOMAIN: &[u8; 16] = b"Tachyon-CmDerive";

/// Derives a note commitment from note fields.
#[must_use]
pub fn note_commitment(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*NOTE_COMMITMENT_DOMAIN)),
        rcm,
        pk,
        Fp::from(value),
        psi,
    ])
}

const PAD_COMMITMENT_DOMAIN: &[u8; 16] = b"Tachyon-CmOutPad";

/// Derives an output's padding tachygram from the same note fields
/// [`note_commitment`] commits to.
///
/// The preimage is the note opening rather than the commitment: both values are
/// published in one multiset, so a pad derived from $\mathsf{cm}$ would let an
/// observer pair them off and recover the output count.
#[must_use]
pub fn pad_tachygram(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*PAD_COMMITMENT_DOMAIN)),
        rcm,
        pk,
        Fp::from(value),
        psi,
    ])
}

const NULLIFIER_MASTER_DOMAIN: &[u8; 16] = b"Tachyon-NfMaster";

/// Derives a note's master key from its trapdoor and the wallet nullifier key.
///
/// $\mathsf{mk} = \mathsf{Poseidon}(\mathtt{NF\_MASTER\_DOMAIN}, \psi,
/// \mathsf{nk})$
#[must_use]
pub fn nf_master(psi: Fp, nk: Fp) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*NULLIFIER_MASTER_DOMAIN)),
        psi,
        nk,
    ])
}

const NULLIFIER_DOMAIN: &[u8; 16] = b"Tachyon-NfDerive";

/// Derives the group of consecutive epoch nullifiers starting at the
/// group-aligned epoch `epoch_start` from the note's master key.
#[expect(
    clippy::expect_used,
    reason = "sponge absorb/squeeze cannot fail in wireless `Always` mode"
)]
#[must_use]
pub fn nullifier_group(mk: Fp, epoch_start: Fp) -> [Fp; PoseidonFp::RATE] {
    let (mut emulator, mut sponge) = sponge();
    for value in [
        Fp::from_u128(u128::from_le_bytes(*NULLIFIER_DOMAIN)),
        mk,
        epoch_start,
    ] {
        let element = Element::constant(&mut emulator, value);
        sponge.absorb(&mut emulator, &element).expect("infallible");
    }
    array::from_fn(|_| {
        let squeezed = sponge.squeeze(&mut emulator).expect("infallible");
        *squeezed.value().take()
    })
}

/// A Vesta point's compressed encoding as two 128-bit $\mathbb{F}_p$ limbs.
///
/// The 32-byte encoding carries $x$ with the sign of $y$ in its high bit, so
/// the limb pair determines the point. Each limb reads 16 bytes little-endian,
/// far below the $\mathbb{F}_p$ modulus.
///
/// # Panics
///
/// Panics if `point` is the identity.
#[expect(clippy::expect_used, reason = "constant-size decomposition")]
fn point_limbs(point: EqAffine) -> (Fp, Fp) {
    assert!(
        !bool::from(point.is_identity()),
        "commitment must not be the identity point"
    );

    let encoding = point.to_bytes();
    let (lo, hi) = encoding.split_at(16);
    (
        Fp::from_u128(u128::from_le_bytes(lo.try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(hi.try_into().expect("16 bytes"))),
    )
}

const ANCHOR_STAMP_DOMAIN: &[u8; 16] = b"Tachyon-AnchorSt";

/// Advances the anchor by absorbing one stamp's epoch and tachygram-set
/// commitment.
///
/// # Panics
///
/// Panics if `tgs` is the identity point.
#[must_use]
pub fn anchor_next_stamp(anchor_prev: Fp, epoch: Fp, tgs: EqAffine) -> Fp {
    let (tgs_lo, tgs_hi) = point_limbs(tgs);
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_STAMP_DOMAIN)),
        anchor_prev,
        epoch,
        tgs_lo,
        tgs_hi,
    ])
}

const ANCHOR_EPOCH_DOMAIN: &[u8; 16] = b"Tachyon-AnchorEp";

/// Advances the terminal anchor of an epoch into a new epoch's initial state.
#[must_use]
pub fn anchor_next_epoch(anchor_prev: Fp, new_epoch: Fp) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_EPOCH_DOMAIN)),
        anchor_prev,
        new_epoch,
    ])
}
