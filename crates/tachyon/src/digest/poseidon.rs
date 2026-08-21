//! Tachyon Poseidon digests.
//!
//! Each named function provides one protocol-defined hash.

use ff::PrimeField as _;
use group::{GroupEncoding as _, prime::PrimeCurveAffine as _};
use pasta_curves::{EpAffine, EqAffine, Fp, arithmetic::Coordinates};
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
pub(crate) fn payment_key(ak: Coordinates<EpAffine>, nk: Fp) -> Fp {
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
pub(crate) fn note_commitment(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*NOTE_COMMITMENT_DOMAIN)),
        rcm,
        pk,
        Fp::from(value),
        psi,
    ])
}

const PAD_TACHYGRAM_DOMAIN: &[u8; 16] = b"Tachyon-PadDeriv";

/// Derives an output's padding tachygram from the same note fields
/// [`note_commitment`] commits to.
///
/// The preimage is the note opening rather than the commitment: both values are
/// published in one multiset, so a pad derived from $\mathsf{cm}$ would let an
/// observer pair them off and recover the output count.
#[must_use]
pub(crate) fn pad_tachygram(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*PAD_TACHYGRAM_DOMAIN)),
        rcm,
        pk,
        Fp::from(value),
        psi,
    ])
}

const NULLIFIER_PREFIX_DOMAIN: &[u8; 16] = b"Tachyon-NfPrefix";

/// Derives a GGM root (master key) from note trapdoor and wallet nullifier key.
#[must_use]
pub(crate) fn nf_master(psi: Fp, nk: Fp) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*NULLIFIER_PREFIX_DOMAIN)),
        psi,
        nk,
    ])
}

/// Derives a nullifier prefix from a previous prefix and a walk direction.
#[must_use]
pub(crate) fn nf_prefix(prefix_prev: Fp, step: u8) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*NULLIFIER_PREFIX_DOMAIN)),
        prefix_prev,
        Fp::from(u64::from(step)), // TODO: chunk some booleans by arity?
    ])
}

const NULLIFIER_DOMAIN: &[u8; 16] = b"Tachyon-NfDerive";

/// Derives a nullifier from a leaf of the prefix tree.
#[must_use]
pub(crate) fn nullifier(leaf: Fp) -> Fp {
    hash::<2>([Fp::from_u128(u128::from_le_bytes(*NULLIFIER_DOMAIN)), leaf])
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

const ANCHOR_STAMP_DOMAIN: &[u8; 16] = b"Tachyon-StampFld";

/// Advances the anchor by absorbing one stamp's epoch and tachygram-set
/// commitment.
///
/// # Panics
///
/// Panics if `tgs` is the identity point.
#[must_use]
pub(crate) fn anchor_stamp_step(anchor_prev: Fp, epoch: EpochIndex, tgs: EqAffine) -> Fp {
    let (tgs_lo, tgs_hi) = point_limbs(tgs);
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_STAMP_DOMAIN)),
        anchor_prev,
        Fp::from(epoch),
        tgs_lo,
        tgs_hi,
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

#[cfg(test)]
mod domain_separation {
    //! Registry of every Poseidon hash context and a check that they are
    //! mutually domain-separated.
    //!
    //! Each [`hash`] call absorbs a 16-byte domain tag first, so two contexts
    //! are separated whenever their `(tag, arity)` pair differs. The single
    //! unseparated reuse is legacy GGM (`nf_master`/`nf_prefix`, see
    //! `KNOWN_SHARED`); the flat-MiMC nullifier rework (#171) removes that path.
    //! New code must not introduce another shared `(tag, arity)` without an
    //! in-preimage discriminator.

    use super::{
        ACTION_DIGEST_DOMAIN, ANCHOR_EMPTY_DOMAIN, ANCHOR_EPOCH_DOMAIN, ANCHOR_STAMP_DOMAIN,
        NOTE_COMMITMENT_DOMAIN, NULLIFIER_DOMAIN, NULLIFIER_PREFIX_DOMAIN, PAYMENT_KEY_DOMAIN,
    };

    /// A Poseidon hash context: the domain tag it absorbs first and its total
    /// arity (tag element included). `(tag, arity)` is the separation key.
    struct Context {
        name: &'static str,
        tag: &'static [u8; 16],
        arity: usize,
    }

    const REGISTRY: &[Context] = &[
        Context {
            name: "action_digest",
            tag: ACTION_DIGEST_DOMAIN,
            arity: 5,
        },
        Context {
            name: "payment_key",
            tag: PAYMENT_KEY_DOMAIN,
            arity: 3,
        },
        Context {
            name: "note_commitment",
            tag: NOTE_COMMITMENT_DOMAIN,
            arity: 5,
        },
        Context {
            name: "nf_master",
            tag: NULLIFIER_PREFIX_DOMAIN,
            arity: 3,
        },
        Context {
            name: "nf_prefix",
            tag: NULLIFIER_PREFIX_DOMAIN,
            arity: 3,
        },
        Context {
            name: "nullifier",
            tag: NULLIFIER_DOMAIN,
            arity: 2,
        },
        Context {
            name: "anchor_stamp_step",
            tag: ANCHOR_STAMP_DOMAIN,
            arity: 6,
        },
        Context {
            name: "anchor_empty_step",
            tag: ANCHOR_EMPTY_DOMAIN,
            arity: 2,
        },
        Context {
            name: "anchor_epoch_step",
            tag: ANCHOR_EPOCH_DOMAIN,
            arity: 3,
        },
    ];

    /// Context pairs that intentionally share `(tag, arity)` with no in-preimage
    /// discriminator. Legacy GGM: `nf_master(psi, nk)` and
    /// `nf_prefix(prefix_prev, step)` both absorb `Tachyon-NfPrefix` at arity 3,
    /// separated only by the meaning of their second field. The flat-MiMC
    /// nullifier rework (#171) deletes this path; until it lands the reuse is
    /// documented here rather than treated as a fresh collision.
    const KNOWN_SHARED: &[[&str; 2]] = &[["nf_master", "nf_prefix"]];

    fn is_known_shared(a: &str, b: &str) -> bool {
        KNOWN_SHARED
            .iter()
            .any(|pair| *pair == [a, b] || *pair == [b, a])
    }

    #[test]
    fn every_poseidon_context_is_domain_separated() {
        for (index, a) in REGISTRY.iter().enumerate() {
            for b in REGISTRY.iter().skip(index + 1) {
                let collides = a.tag == b.tag && a.arity == b.arity;
                assert!(
                    !collides || is_known_shared(a.name, b.name),
                    "Poseidon contexts `{}` and `{}` share a domain tag at arity {} \
                     with no discriminator — add a discriminator or a justified \
                     KNOWN_SHARED entry",
                    a.name,
                    b.name,
                    a.arity,
                );
            }
        }
    }
}
