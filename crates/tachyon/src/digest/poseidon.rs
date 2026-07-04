//! Tachyon Poseidon digests.
//!
//! Each named function provides one protocol-defined hash.

use ff::{Field as _, PrimeField as _};
use group::Curve as _;
use pasta_curves::{
    EpAffine, Eq, EqAffine, Fp,
    arithmetic::{Coordinates, CurveAffine as _},
};
use ragu::Sponge;

use crate::{
    EpochIndex,
    constants::{MK_PART_LEN, NF_EXPANSION_KEY_PREFIX},
};

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

const NF_EXPANSION_DOMAIN: &[u8; 16] = b"Tachyon-NfExpand";
const NF_LEAF_DOMAIN: &[u8; 16] = b"Tachyon-NfLeaf__";

/// Derives a GGM node's child-cipher input parameters from its key schedule:
/// the secret input salt `s`, the input stride `δ`, and the whitening key
/// `w`. Domain-separated from the master-key derivation above so a node's
/// parameters are cryptographically independent of the tree's keys, and from
/// the leaf variant below so a leaf can never read as a child
/// schedule.
///
/// The sponge absorbs the domain tag plus an `NF_EXPANSION_KEY_PREFIX`-element
/// prefix of the node's schedule (exactly `RATE` elements) and squeezes
/// three, so the whole derivation is one Poseidon permutation; the expansion
/// steps run it in-step.
#[must_use]
pub(crate) fn nf_expansion_params(prefix: [Fp; NF_EXPANSION_KEY_PREFIX]) -> (Fp, Fp, Fp) {
    nf_params(NF_EXPANSION_DOMAIN, prefix)
}

/// Derives a depth-2 node's leaf cipher parameters: the leaf-level
/// counterpart of [`nf_expansion_params`], under its own domain.
#[must_use]
pub(crate) fn nf_leaf_params(prefix: [Fp; NF_EXPANSION_KEY_PREFIX]) -> (Fp, Fp, Fp) {
    nf_params(NF_LEAF_DOMAIN, prefix)
}

#[expect(
    clippy::expect_used,
    reason = "mock sponge absorb/squeeze is infallible"
)]
fn nf_params(domain: &[u8; 16], prefix: [Fp; NF_EXPANSION_KEY_PREFIX]) -> (Fp, Fp, Fp) {
    let mut sponge = Sponge::new();
    sponge
        .absorb(Fp::from_u128(u128::from_le_bytes(*domain)))
        .expect("infallible");
    for key in prefix {
        sponge.absorb(key).expect("infallible");
    }
    let salt = sponge.squeeze().expect("infallible");
    let stride = sponge.squeeze().expect("infallible");
    let whitening = sponge.squeeze().expect("infallible");
    (salt, stride, whitening)
}

const LEAF_SEQUENCE_DOMAIN: &[u8; 16] = b"Tachyon-NfLeafSq";

/// Derive the leaf-sequence challenge `β`, binding the eval-form leaf
/// commitment `B` and the coeff-form sentinel sequence commitment `q` (each by
/// its affine coordinates, split into 128-bit halves). The prover computes `β`
/// from the two commitments before building the running-sum accumulator, so
/// the native witness builder and the in-step homomorphic bind agree on it.
#[expect(
    clippy::expect_used,
    reason = "constant-size coordinate decomposition; committed leaf/sequence polynomials are never the identity point"
)]
#[must_use]
pub(crate) fn leaf_sequence_challenge(leaf_commit: Eq, seq_commit: Eq) -> Fp {
    let leaf = leaf_commit
        .to_affine()
        .coordinates()
        .expect("leaf commitment must not be identity");
    let seq = seq_commit
        .to_affine()
        .coordinates()
        .expect("sequence commitment must not be identity");
    let (leaf_x, leaf_y) = (leaf.x().to_repr(), leaf.y().to_repr());
    let (seq_x, seq_y) = (seq.x().to_repr(), seq.y().to_repr());
    hash::<9>([
        Fp::from_u128(u128::from_le_bytes(*LEAF_SEQUENCE_DOMAIN)),
        Fp::from_u128(u128::from_le_bytes(
            leaf_x[..16].try_into().expect("16 bytes"),
        )),
        Fp::from_u128(u128::from_le_bytes(
            leaf_x[16..].try_into().expect("16 bytes"),
        )),
        Fp::from_u128(u128::from_le_bytes(
            leaf_y[..16].try_into().expect("16 bytes"),
        )),
        Fp::from_u128(u128::from_le_bytes(
            leaf_y[16..].try_into().expect("16 bytes"),
        )),
        Fp::from_u128(u128::from_le_bytes(
            seq_x[..16].try_into().expect("16 bytes"),
        )),
        Fp::from_u128(u128::from_le_bytes(
            seq_x[16..].try_into().expect("16 bytes"),
        )),
        Fp::from_u128(u128::from_le_bytes(
            seq_y[..16].try_into().expect("16 bytes"),
        )),
        Fp::from_u128(u128::from_le_bytes(
            seq_y[16..].try_into().expect("16 bytes"),
        )),
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
