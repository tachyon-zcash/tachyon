//! Tachyon Poseidon digests.
//!
//! Each named function provides one protocol-defined hash.
//!
//! A tagged hash starts from a zero rate and the capacity element
//! $\mathsf{tag}$, the 16-byte domain read as a little-endian integer. It
//! absorbs only its data. Every Tachyon Poseidon hash is tagged this way.

use core::array;

use ff::{Field as _, PrimeField as _};
use group::{CurveAffine as _, GroupEncoding as _};
use pasta_curves::{EpAffine, EqAffine, Fp, arithmetic::Coordinates};
use ragu_arithmetic::{Cycle as _, PoseidonPermutation as _};
use ragu_core::{
    drivers::emulator::{Emulator, Wireless},
    maybe::{Always, Maybe as _},
};
use ragu_pasta::{Pasta, PoseidonFp};
use ragu_primitives::{
    Element,
    poseidon::{Sponge, SpongeState},
    vec::FixedVec,
};

use crate::constants::EVIDENCE_TREE_ARITY;

/// The wireless emulator that evaluates the real in-circuit sponge natively:
/// witness values are always present and no wires are tracked, so absorb and
/// squeeze compute field values without building constraints.
type Emu = Emulator<Wireless<Always<()>, Fp>>;

#[expect(
    clippy::expect_used,
    reason = "sponge squeeze cannot fail in wireless `Always` mode"
)]
fn squeeze(emulator: &mut Emu, sponge: &mut Sponge<'static, Emu, PoseidonFp>) -> Fp {
    let squeezed = sponge.squeeze(emulator).expect("infallible");
    *squeezed.value().take()
}

/// Opens the sponge of `domain` with capacity element $\mathsf{tag}$ over a
/// zero rate, then absorbs `input`.
fn tagged_sponge<const L: usize>(
    domain: &[u8; 16],
    input: [Fp; L],
) -> (Emu, Sponge<'static, Emu, PoseidonFp>) {
    const { assert!(L > 0, "a tagged hash must absorb at least one element") };
    let capacity = Fp::from_u128(u128::from_le_bytes(*domain));

    let mut emulator = Emu::execute();
    let state = SpongeState::from_elements(FixedVec::from_fn(|index| {
        let value = if index == PoseidonFp::RATE {
            capacity
        } else {
            Fp::ZERO
        };
        Element::constant(&mut emulator, value)
    }));
    let mut sponge = Sponge::resume(state, Pasta::circuit_poseidon(Pasta::baked()));
    #[expect(
        clippy::expect_used,
        reason = "sponge absorb cannot fail in wireless `Always` mode"
    )]
    for value in input {
        let element = Element::constant(&mut emulator, value);
        sponge.absorb(&mut emulator, &element).expect("infallible");
    }
    (emulator, sponge)
}

fn hash<const L: usize>(domain: &[u8; 16], input: [Fp; L]) -> Fp {
    let (mut emulator, mut sponge) = tagged_sponge(domain, input);
    squeeze(&mut emulator, &mut sponge)
}

const FEE_BLIND_DOMAIN: &[u8; 16] = b"Tachyon-FeeBlind";

/// A max fee note's value commitment blind,
/// $r = \mathsf{Poseidon}_\texttt{Tachyon-FeeBlind}(\mathsf{pk}, \psi,
/// \mathsf{rcm})$.
#[must_use]
pub fn fee_blind(pk: Fp, psi: Fp, rcm: Fp) -> Fp {
    hash::<3>(FEE_BLIND_DOMAIN, [pk, psi, rcm])
}

const FEE_DIGEST_DOMAIN: &[u8; 16] = b"Tachyon-FeeDg\0\0\0";

/// A fee digest, $d_\mathsf{fee} = \mathsf{Poseidon}_\texttt{Tachyon-FeeDg}(
/// x(\mathsf{cv}_\mathsf{maxfee}), y(\mathsf{cv}_\mathsf{maxfee}),
/// \mathsf{fee})$.
#[must_use]
pub fn fee_digest(cv_max_fee: Coordinates<EpAffine>, fee: u64) -> Fp {
    hash::<3>(
        FEE_DIGEST_DOMAIN,
        [*cv_max_fee.x(), *cv_max_fee.y(), Fp::from(fee)],
    )
}

const ACTION_DIGEST_DOMAIN: &[u8; 16] = b"Tachyon-ActionDg";

/// Derives an action digest from action fields.
#[must_use]
pub fn action_digest(cv: Coordinates<EpAffine>, rk: Coordinates<EpAffine>) -> Fp {
    hash::<4>(ACTION_DIGEST_DOMAIN, [*cv.x(), *cv.y(), *rk.x(), *rk.y()])
}

const PAYMENT_KEY_DOMAIN: &[u8; 16] = b"Tachyon-PkDerive";

/// Derives a payment key from a spend validating key and nullifier key.
#[must_use]
pub fn payment_key(ak: Coordinates<EpAffine>, nk: Fp) -> Fp {
    hash::<3>(PAYMENT_KEY_DOMAIN, [*ak.x(), *ak.y(), nk])
}

const NOTE_COMMITMENT_DOMAIN: &[u8; 16] = b"Tachyon-CmDerive";

/// Derives a note commitment from note fields.
#[must_use]
pub fn note_commitment(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> Fp {
    hash::<4>(NOTE_COMMITMENT_DOMAIN, [rcm, pk, Fp::from(value), psi])
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
    hash::<4>(PAD_COMMITMENT_DOMAIN, [rcm, pk, Fp::from(value), psi])
}

const NULLIFIER_MASTER_DOMAIN: &[u8; 16] = b"Tachyon-NfMaster";

/// Derives a note's master key from its trapdoor and the wallet nullifier key.
///
/// $$
///   \mathsf{mk} = \mathsf{Poseidon}_\texttt{Tachyon-NfMaster}(
///     \psi,\ \mathsf{nk}
///   )
/// $$
#[must_use]
pub fn nf_master(psi: Fp, nk: Fp) -> Fp {
    hash::<2>(NULLIFIER_MASTER_DOMAIN, [psi, nk])
}

const SPEND_ALPHA_DOMAIN: &[u8; 16] = b"Tachyon-Spend\0\0\0";

/// Derives a spend's $\alpha$ preimage from its entropy and note commitment.
///
/// $$
///   \mathsf{Poseidon}_\texttt{Tachyon-Spend}(\theta,\ \mathsf{cm})
/// $$
#[must_use]
pub fn alpha_spend(theta: Fp, cm: Fp) -> Fp {
    hash::<2>(SPEND_ALPHA_DOMAIN, [theta, cm])
}

const OUTPUT_ALPHA_DOMAIN: &[u8; 16] = b"Tachyon-Output\0\0";

/// Derives an output's $\alpha$ preimage from its entropy and note commitment.
///
/// $$
///   \mathsf{Poseidon}_\texttt{Tachyon-Output}(\theta,\ \mathsf{cm})
/// $$
#[must_use]
pub fn alpha_output(theta: Fp, cm: Fp) -> Fp {
    hash::<2>(OUTPUT_ALPHA_DOMAIN, [theta, cm])
}

const NULLIFIER_DOMAIN: &[u8; 16] = b"Tachyon-NfDerive";

/// Derives the group of consecutive epoch nullifiers starting at the
/// group-aligned epoch `epoch_start` from the note's master key.
///
/// # Panics
///
/// Panics if the sponge rejects an absorb or a squeeze. The emulator is
/// native and the element count is fixed at `RATE`, so this is unreachable.
#[must_use]
pub fn nullifier_group(mk: Fp, epoch_start: Fp) -> [Fp; PoseidonFp::RATE] {
    let (mut emulator, mut sponge) = tagged_sponge(NULLIFIER_DOMAIN, [mk, epoch_start]);
    array::from_fn(|_| squeeze(&mut emulator, &mut sponge))
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
    hash::<4>(ANCHOR_STAMP_DOMAIN, [anchor_prev, epoch, tgs_lo, tgs_hi])
}

const QR_BUCKET_DOMAIN: &[u8; 16] = b"Tachyon-QrBucket";
const EVIDENCE_NODE_DOMAIN: &[u8; 16] = b"Tachyon-EvidNode";

/// Digests a sealed bucket into the leaf of a evidence tree.
///
/// # Panics
///
/// Panics if `contents` is the identity point.
#[must_use]
pub fn evidence_tree_leaf(
    epoch: Fp,
    anchor_start: Fp,
    anchor_next: Fp,
    discriminant: Fp,
    depth: Fp,
    bits: Fp,
    contents: EqAffine,
) -> Fp {
    let (contents_lo, contents_hi) = point_limbs(contents);
    hash::<8>(
        QR_BUCKET_DOMAIN,
        [
            epoch,
            anchor_start,
            anchor_next,
            discriminant,
            depth,
            bits,
            contents_lo,
            contents_hi,
        ],
    )
}

/// Folds four subtree roots into their parent node of a evidence tree.
///
/// $$
///   \mathsf{node} = \mathsf{Poseidon}_\texttt{Tachyon-EvidNode}(
///     c_0,\ c_1,\ c_2,\ c_3
///   )
/// $$
#[must_use]
pub fn evidence_tree_node(children: [Fp; EVIDENCE_TREE_ARITY]) -> Fp {
    hash::<EVIDENCE_TREE_ARITY>(EVIDENCE_NODE_DOMAIN, children)
}

const ANCHOR_EPOCH_DOMAIN: &[u8; 16] = b"Tachyon-AnchorEp";

/// Computes the boundary digest of `anchor_prev` into `epoch`.
///
/// Produces the entry anchor of `epoch` when `anchor_prev` is the final
/// anchor of the epoch before.
#[must_use]
pub fn anchor_next_epoch(anchor_prev: Fp, epoch: Fp) -> Fp {
    hash::<2>(ANCHOR_EPOCH_DOMAIN, [anchor_prev, epoch])
}
