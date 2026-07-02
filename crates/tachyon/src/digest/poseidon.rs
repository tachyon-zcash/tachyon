//! Tachyon Poseidon digests.
//!
//! Each named function provides one protocol-defined hash.

use ff::{Field as _, PrimeField as _};
use pasta_curves::{EpAffine, EqAffine, Fp, arithmetic::Coordinates};
use ragu::Sponge;

use crate::{
    EpochIndex,
    constants::{MK_PART_LEN, NF_EMITTERS, NF_QUERY_MK_PREFIX},
    keys::NoteMasterKey,
};

#[expect(
    clippy::expect_used,
    reason = "mock sponge absorb/squeeze is infallible"
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

/// Derive one `mk` part: `MK_PART_LEN` round keys from the note trapdoor `psi`,
/// the nullifier key `nk`, and the part index. One sponge absorbs
/// `(domain, part, psi, nk)` and squeezes `MK_PART_LEN` elements; the squeeze
/// position is the key index within the part. The two parts concatenate into
/// the full master key.
#[expect(
    clippy::expect_used,
    reason = "mock sponge absorb/squeeze is infallible"
)]
#[must_use]
pub(crate) fn nf_master_part(psi: Fp, nk: Fp, part: u64) -> [Fp; MK_PART_LEN] {
    let mut sponge = Sponge::new();
    sponge
        .absorb(Fp::from_u128(u128::from_le_bytes(*NULLIFIER_MASTER_DOMAIN)))
        .expect("infallible");
    sponge.absorb(Fp::from(part)).expect("infallible");
    sponge.absorb(psi).expect("infallible");
    sponge.absorb(nk).expect("infallible");
    [Fp::ZERO; MK_PART_LEN].map(|_| sponge.squeeze().expect("infallible"))
}

const NF_QUERY_SALT_DOMAIN: &[u8; 16] = b"Tachyon-NfSalt__";
const NF_QUERY_WEIGHT_DOMAIN: &[u8; 16] = b"Tachyon-NfWeight";

/// Derive the note's per-emitter nullifier-query salts from its master key
/// `mk`. Each salt seeds one derivation poly's 8192-round cipher. Domain-
/// separated from the weight/shift derivation below so the two outputs are
/// cryptographically independent.
#[expect(
    clippy::expect_used,
    reason = "mock sponge absorb/squeeze is infallible"
)]
#[must_use]
pub(crate) fn nf_query_salts(mk: &[Fp; NoteMasterKey::MK_LENGTH]) -> [Fp; NF_EMITTERS] {
    let mut sponge = Sponge::new();
    sponge
        .absorb(Fp::from_u128(u128::from_le_bytes(*NF_QUERY_SALT_DOMAIN)))
        .expect("infallible");
    for &part in mk.iter().take(NF_QUERY_MK_PREFIX) {
        sponge.absorb(part).expect("infallible");
    }
    [Fp::ZERO; NF_EMITTERS].map(|_| sponge.squeeze().expect("infallible"))
}

/// Derive the note's nullifier-query weight parameters from its master key
/// `mk`: the per-poly geometric weight bases `ρ_j` and the secret query-coset
/// origin `c` (the `shift`). Domain-separated from the salt derivation above.
#[expect(
    clippy::expect_used,
    reason = "mock sponge absorb/squeeze is infallible"
)]
#[must_use]
pub(crate) fn nf_query_weights(mk: &[Fp; NoteMasterKey::MK_LENGTH]) -> ([Fp; NF_EMITTERS], Fp) {
    let mut sponge = Sponge::new();
    sponge
        .absorb(Fp::from_u128(u128::from_le_bytes(*NF_QUERY_WEIGHT_DOMAIN)))
        .expect("infallible");
    for &part in mk.iter().take(NF_QUERY_MK_PREFIX) {
        sponge.absorb(part).expect("infallible");
    }
    let ratios = [Fp::ZERO; NF_EMITTERS].map(|_| sponge.squeeze().expect("infallible"));
    let shift = sponge.squeeze().expect("infallible");
    (ratios, shift)
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

const ARC_CHALLENGE_DOMAIN: &[u8; 16] = b"Tachyon-NfArcCh_";

/// Derive the arc challenge `β`, binding the certified derivation (through the
/// `derivation_digest` scalar, a transcript challenge over all `N` commitments
/// so one element stands for the set), the sync-tested value polynomial `q` (by
/// its commitment's affine coordinates, split into 128-bit halves), and the
/// absolute range `[start, end)`. The prover can compute `β` from these before
/// committing the weight and accumulator polynomials, so it builds them for
/// this `β`.
#[expect(
    clippy::expect_used,
    reason = "constant-size coordinate decomposition into fixed input"
)]
#[must_use]
pub(crate) fn arc_challenge(
    derivation_digest: Fp,
    range_commit: Coordinates<EqAffine>,
    start: EpochIndex,
    end: EpochIndex,
) -> Fp {
    let x = range_commit.x().to_repr();
    let y = range_commit.y().to_repr();
    hash::<8>([
        Fp::from_u128(u128::from_le_bytes(*ARC_CHALLENGE_DOMAIN)),
        derivation_digest,
        Fp::from_u128(u128::from_le_bytes(x[..16].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(x[16..].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(y[..16].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(y[16..].try_into().expect("16 bytes"))),
        Fp::from(start),
        Fp::from(end),
    ])
}
