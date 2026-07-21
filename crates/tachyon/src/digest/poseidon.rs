//! Tachyon Poseidon digests.
//!
//! Each named function provides one protocol-defined hash.

use ff::PrimeField as _;
use group::Curve as _;
use pasta_curves::{
    EpAffine, Eq, EqAffine, Fp,
    arithmetic::{Coordinates, CurveAffine as _},
};
use ragu::Sponge;

use crate::EpochIndex;

#[expect(
    clippy::expect_used,
    reason = "mock sponge absorb/squeeze cannot fail in wireless `Always` mode"
)]
fn hash<const L: usize>(input: [Fp; L]) -> Fp {
    let mut sponge = Sponge::new();
    for value in input {
        sponge.absorb(value).expect("infallible");
    }
    sponge.squeeze().expect("infallible")
}

const ACTION_DIGEST_DOMAIN: &[u8; 16] = b"Tachyon-ActionDg";

/// Derives an action digest from action fields.
pub(crate) fn action_digest(cv: Coordinates<EpAffine>, rk: Coordinates<EpAffine>) -> Fp {
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
pub(crate) fn payment_key(ak: Fp, nk: Fp) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*PAYMENT_KEY_DOMAIN)),
        ak,
        nk,
    ])
}

const NOTE_COMMITMENT_DOMAIN: &[u8; 16] = b"Tachyon-CmDerive";

/// Derives a note commitment from note fields.
#[must_use]
pub(crate) fn note_commitment(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*NOTE_COMMITMENT_DOMAIN)),
        rcm,
        pk,
        Fp::from(value),
        psi,
    ])
}

const NULLIFIER_MASTER_DOMAIN: &[u8; 16] = b"Tachyon-NfMaster";

/// Derive a note's master key `mk = [k, w]` from the note trapdoor `psi` and
/// the nullifier key `nk`.
///
/// This is the nullifier PRF's round key `k` and whitening key `w`.
#[expect(
    clippy::expect_used,
    reason = "mock sponge absorb/squeeze is infallible"
)]
#[must_use]
pub(crate) fn nf_master_key(psi: Fp, nk: Fp) -> (Fp, Fp) {
    let mut sponge = Sponge::new();
    sponge
        .absorb(Fp::from_u128(u128::from_le_bytes(*NULLIFIER_MASTER_DOMAIN)))
        .expect("infallible");
    sponge.absorb(psi).expect("infallible");
    sponge.absorb(nk).expect("infallible");
    (
        sponge.squeeze().expect("infallible"),
        sponge.squeeze().expect("infallible"),
    )
}

const DERIVATION_BIND_DOMAIN: &[u8; 16] = b"Tachyon-NfLeafSq";

/// The `x`-coordinate of a commitment as two 128-bit `Fp` limbs.
#[expect(
    clippy::expect_used,
    reason = "constant-size coordinate decomposition; committed derivation polynomials are never the identity point"
)]
fn x_limbs(commit: Eq) -> (Fp, Fp) {
    let x = commit
        .to_affine()
        .coordinates()
        .expect("commitment must not be identity")
        .x()
        .to_repr();
    let (lo, hi) = x.split_at(16);
    (
        Fp::from_u128(u128::from_le_bytes(lo.try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(hi.try_into().expect("16 bytes"))),
    )
}

/// Derive the combination challenge $\chi_A$ over the commitments of the
/// three polynomials the S-box identities relate: the trace $T$ and the
/// intermediates `(square, quartic)`.
///
/// The scalar operands $k$ and $\mathsf{base}$ are not absorbed (a third
/// permutation); the wrap-step `mk` pin completes the combination argument
/// instead, per `SboxStep`'s soundness section. The combined quotient
/// depends on $\chi_A$, so the challenge is a Poseidon digest the native
/// witness builder replicates, not a transcript challenge.
#[must_use]
pub(crate) fn derivation_challenge(trace: Eq, square: Eq, quartic: Eq) -> Fp {
    let (trace_lo, trace_hi) = x_limbs(trace);
    let (square_lo, square_hi) = x_limbs(square);
    let (quartic_lo, quartic_hi) = x_limbs(quartic);
    hash::<7>([
        Fp::from_u128(u128::from_le_bytes(*DERIVATION_BIND_DOMAIN)),
        trace_lo,
        trace_hi,
        square_lo,
        square_hi,
        quartic_lo,
        quartic_hi,
    ])
}

const NF_FOLD_DOMAIN: &[u8; 16] = b"Tachyon-NfLeafFd";

/// Derive the nullifier-fold weight $\chi$ over the commitments of the two
/// polynomials the fold relates: the whitened trace $W$ and the sentinel
/// sequence `elapsed`.
///
/// Both operands are pinned before $\chi$ exists, so the single-point
/// discharge forces every coefficient of `elapsed` to the genuine leaves
/// (Schwartz-Zippel). The fold accumulator `A` depends on $\chi$, so the
/// weight is a Poseidon digest the native witness builder replicates, not a
/// transcript challenge.
#[must_use]
pub(crate) fn fold_challenge(trace: Eq, seq: Eq) -> Fp {
    let (trace_lo, trace_hi) = x_limbs(trace);
    let (seq_lo, seq_hi) = x_limbs(seq);
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*NF_FOLD_DOMAIN)),
        trace_lo,
        trace_hi,
        seq_lo,
        seq_hi,
    ])
}

const ANCHOR_STAMP_DOMAIN: &[u8; 16] = b"Tachyon-StampFld";

/// Advances the anchor by absorbing one stamp's tachygram-set commitment.
#[must_use]
pub(crate) fn anchor_stamp_step(anchor_prev: Fp, tgs: Coordinates<EqAffine>) -> Fp {
    let (x, y) = (tgs.x().to_repr(), tgs.y().to_repr());

    #[expect(clippy::expect_used, reason = "constant size decomposition")]
    let (x_lo, x_hi, y_lo, y_hi) = (
        Fp::from_u128(u128::from_le_bytes(x[..16].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(x[16..].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(y[..16].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(y[16..].try_into().expect("16 bytes"))),
    );

    hash::<6>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_STAMP_DOMAIN)),
        anchor_prev,
        x_lo,
        x_hi,
        y_lo,
        y_hi,
    ])
}

const ANCHOR_EMPTY_DOMAIN: &[u8; 16] = b"Tachyon-EmptyBlk";

/// Advances the anchor through one block that contains zero stamps.
#[must_use]
pub(crate) fn anchor_empty_step(anchor_prev: Fp) -> Fp {
    hash::<2>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_EMPTY_DOMAIN)),
        anchor_prev,
    ])
}

const ANCHOR_EPOCH_DOMAIN: &[u8; 16] = b"Tachyon-EpochStp";

/// Advances the terminal anchor of an epoch into a new epoch's initial state.
#[must_use]
pub(crate) fn anchor_epoch_step(anchor_prev: Fp, new_epoch: EpochIndex) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_EPOCH_DOMAIN)),
        anchor_prev,
        Fp::from(new_epoch),
    ])
}
