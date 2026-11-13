//! Tachyon Poseidon digests.
//!
//! Each named function provides one protocol-defined hash.
//!
//! A tagged hash starts from a zero rate and the capacity element
//! $\mathsf{tag}$, the 16-byte domain read as a little-endian integer. It
//! absorbs only its data. Every Tachyon Poseidon hash is tagged this way.

use core::array;

use ragu_core::{
    PoseidonPermutation as _,
    drivers::emulator::{Emulator, Wireless},
    maybe::{Always, Maybe as _},
    pasta::PoseidonFp,
};
use ragu_primitives::Element;
use udon::curve::Affine as _;

use crate::{
    constants::EVIDENCE_TREE_ARITY,
    pasta::{EpAffine, Fp},
};

fn emulated<const L: usize, const N: usize>(domain: &[u8; 16], preimage: [Fp; L]) -> [Fp; N] {
    type Emu = Emulator<Wireless<Always<()>, Fp>>;
    let mut emu = Emu::execute();

    let input = preimage.map(|item| Element::constant(&mut emu, item));

    let mut sponge = circuit::init(&mut emu, domain);

    #[expect(clippy::expect_used, reason = "emulator is infallible")]
    let output = {
        sponge = circuit::absorb(&mut emu, sponge, input.each_ref()).expect("infallible");
        array::from_fn(|_| sponge.squeeze(&mut emu).expect("infallible"))
    };

    output.map(|item| *item.value().take())
}

const FEE_BLIND_DOMAIN: &[u8; 16] = b"Tachyon-FeeBlind";

/// The feemax blind, the trapdoor of $\mathsf{cv}_\mathsf{feemax}$,
/// $r = \mathsf{Poseidon}_\texttt{Tachyon-FeeBlind}(\mathsf{pk}, \psi,
/// \mathsf{rcm})$.
#[must_use]
pub fn feemax_blind(pk: Fp, psi: Fp, rcm: Fp) -> Fp {
    let [hash] = emulated(FEE_BLIND_DOMAIN, [pk, psi, rcm]);
    hash
}

const FEE_DIGEST_DOMAIN: &[u8; 16] = b"Tachyon-FeeDg\0\0\0";

/// A fee digest, $d_\mathsf{fee} = \mathsf{Poseidon}_\texttt{Tachyon-FeeDg}(
/// x(\mathsf{cv}_\mathsf{feemax}), y(\mathsf{cv}_\mathsf{feemax}),
/// \mathsf{fee})$.
///
/// # Panics
///
/// Panics if `cv_feemax` is the identity.
#[must_use]
pub fn fee_digest(cv_feemax: EpAffine, fee: u64) -> Fp {
    #[expect(clippy::expect_used, reason = "callers reject the identity")]
    let (x, y) = cv_feemax
        .coordinates()
        .expect("cv_feemax must not be the identity");

    let [hash] = emulated(FEE_DIGEST_DOMAIN, [x, y, Fp::from(fee)]);
    hash
}

const ACTION_DIGEST_DOMAIN: &[u8; 16] = b"Tachyon-ActionDg";

/// Derives an action digest from action fields.
///
/// # Panics
///
/// Panics if `cv` or `rk` is the identity.
#[must_use]
pub fn action_digest(cv: EpAffine, rk: EpAffine) -> Fp {
    #[expect(clippy::expect_used, reason = "callers reject the identity")]
    let (cv_x, cv_y) = cv.coordinates().expect("cv must not be the identity");
    #[expect(clippy::expect_used, reason = "callers reject the identity")]
    let (rk_x, rk_y) = rk.coordinates().expect("rk must not be the identity");

    let [hash] = emulated(ACTION_DIGEST_DOMAIN, [cv_x, cv_y, rk_x, rk_y]);
    hash
}

const PAYMENT_KEY_DOMAIN: &[u8; 16] = b"Tachyon-PkDerive";

/// Derives a payment key from a spend validating key and nullifier key.
///
/// # Panics
///
/// Panics if `ak` is the identity.
#[must_use]
pub fn payment_key(ak: EpAffine, nk: Fp) -> Fp {
    #[expect(
        clippy::expect_used,
        reason = "ak = [ask]G for a PRF-derived ask is not the identity"
    )]
    let (x, y) = ak.coordinates().expect("ak must not be the identity");

    let [hash] = emulated(PAYMENT_KEY_DOMAIN, [x, y, nk]);
    hash
}

const NOTE_COMMITMENT_DOMAIN: &[u8; 16] = b"Tachyon-CmDerive";

/// Derives a note commitment from note fields.
#[must_use]
pub fn note_commitment(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> Fp {
    let [hash] = emulated(NOTE_COMMITMENT_DOMAIN, [rcm, pk, Fp::from(value), psi]);
    hash
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
    let [hash] = emulated(PAD_COMMITMENT_DOMAIN, [rcm, pk, Fp::from(value), psi]);
    hash
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
    let [hash] = emulated(NULLIFIER_MASTER_DOMAIN, [psi, nk]);
    hash
}

const SPEND_ALPHA_DOMAIN: &[u8; 16] = b"Tachyon-Spend\0\0\0";

/// Derives a spend's $\alpha$ preimage from its entropy and note commitment.
///
/// $$
///   \mathsf{Poseidon}_\texttt{Tachyon-Spend}(\theta,\ \mathsf{cm})
/// $$
#[must_use]
pub fn alpha_spend(theta: Fp, cm: Fp) -> Fp {
    let [hash] = emulated(SPEND_ALPHA_DOMAIN, [theta, cm]);
    hash
}

const OUTPUT_ALPHA_DOMAIN: &[u8; 16] = b"Tachyon-Output\0\0";

/// Derives an output's $\alpha$ preimage from its entropy and note commitment.
///
/// $$
///   \mathsf{Poseidon}_\texttt{Tachyon-Output}(\theta,\ \mathsf{cm})
/// $$
#[must_use]
pub fn alpha_output(theta: Fp, cm: Fp) -> Fp {
    let [hash] = emulated(OUTPUT_ALPHA_DOMAIN, [theta, cm]);
    hash
}

const NULLIFIER_DOMAIN: &[u8; 16] = b"Tachyon-NfDerive";

/// Derives the group of consecutive epoch nullifiers starting at the
/// group-aligned epoch `epoch_start` from the note's master key.
#[must_use]
pub fn nullifier_group(mk: Fp, epoch_start: Fp) -> [Fp; PoseidonFp::RATE] {
    emulated(NULLIFIER_DOMAIN, [mk, epoch_start])
}

const ANCHOR_STAMP_DOMAIN: &[u8; 16] = b"Tachyon-AnchorSt";

/// Advances the anchor with the stamp's epoch and tachygram-set bridge hash,
/// absorbing the point's affine coordinates.
///
/// # Panics
///
/// Panics if `stamp_hash` is the identity.
#[must_use]
#[expect(clippy::expect_used, reason = "a bridge hash is never the identity")]
pub fn anchor_next_stamp(anchor_prev: Fp, epoch: Fp, stamp_hash: EpAffine) -> Fp {
    let (x, y) = stamp_hash
        .coordinates()
        .expect("bridge hash must not be the identity point");

    let [hash] = emulated(ANCHOR_STAMP_DOMAIN, [anchor_prev, epoch, x, y]);
    hash
}

const QR_BUCKET_DOMAIN: &[u8; 16] = b"Tachyon-QrBucket";
const EVIDENCE_NODE_DOMAIN: &[u8; 16] = b"Tachyon-EvidNode";

/// Digests a sealed bucket's metadata and contents bridge hash into a leaf,
/// absorbing the point's affine coordinates.
///
/// # Panics
///
/// Panics if `contents` is the identity.
#[must_use]
#[expect(clippy::expect_used, reason = "a bridge hash is never the identity")]
pub fn evidence_tree_leaf(
    epoch: Fp,
    anchor_start: Fp,
    anchor_next: Fp,
    discriminant: Fp,
    depth: Fp,
    bits: Fp,
    contents: EpAffine,
) -> Fp {
    let (contents_x, contents_y) = contents
        .coordinates()
        .expect("bridge hash must not be the identity point");

    let [hash] = emulated(
        QR_BUCKET_DOMAIN,
        [
            epoch,
            anchor_start,
            anchor_next,
            discriminant,
            depth,
            bits,
            contents_x,
            contents_y,
        ],
    );
    hash
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
    let [hash] = emulated(EVIDENCE_NODE_DOMAIN, children);
    hash
}

const ANCHOR_EPOCH_DOMAIN: &[u8; 16] = b"Tachyon-AnchorEp";

/// Computes the boundary digest of `anchor_prev` into `epoch`.
///
/// Produces the entry anchor of `epoch` when `anchor_prev` is the final
/// anchor of the epoch before.
#[must_use]
pub fn anchor_next_epoch(anchor_prev: Fp, epoch: Fp) -> Fp {
    let [hash] = emulated(ANCHOR_EPOCH_DOMAIN, [anchor_prev, epoch]);
    hash
}

pub(crate) mod circuit {
    use alloc::vec::Vec;

    use ragu_core::{
        Cycle as _, PoseidonPermutation as _, Result,
        drivers::Driver,
        pasta::{Pasta, PoseidonFp},
    };
    use ragu_primitives::{
        Element, GadgetExt as _, Point,
        poseidon::{Sponge, SpongeState},
        vec::FixedVec,
    };
    use udon::field::Field as _;

    use super::{
        ACTION_DIGEST_DOMAIN, ANCHOR_EPOCH_DOMAIN, ANCHOR_STAMP_DOMAIN, EVIDENCE_NODE_DOMAIN,
        FEE_BLIND_DOMAIN, FEE_DIGEST_DOMAIN, NOTE_COMMITMENT_DOMAIN, NULLIFIER_DOMAIN,
        NULLIFIER_MASTER_DOMAIN, OUTPUT_ALPHA_DOMAIN, PAD_COMMITMENT_DOMAIN, PAYMENT_KEY_DOMAIN,
        QR_BUCKET_DOMAIN, SPEND_ALPHA_DOMAIN,
    };
    use crate::{
        constants::EVIDENCE_TREE_ARITY,
        pasta,
        pasta::{EpAffine, Fp},
    };

    pub(super) fn init<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        domain: &[u8; 16],
    ) -> Sponge<'dr, D, PoseidonFp> {
        let capacity = Fp::from_u128(u128::from_le_bytes(*domain));
        Sponge::resume(
            SpongeState::from_elements(FixedVec::from_fn(|idx| match idx {
                PoseidonFp::RATE => Element::constant(dr, capacity),
                _ => Element::zero(dr),
            })),
            Pasta::circuit_poseidon(pasta::baked()),
        )
    }

    pub(super) fn absorb<'element, 'dr: 'element, D: Driver<'dr, F = Fp> + 'element>(
        dr: &mut D,
        mut sponge: Sponge<'dr, D, PoseidonFp>,
        input: impl IntoIterator<Item = &'element Element<'dr, D>>,
    ) -> Result<Sponge<'dr, D, PoseidonFp>> {
        for value in input {
            sponge.absorb(dr, value)?;
        }
        Ok(sponge)
    }

    pub(crate) fn feemax_blind<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        pk: &Element<'dr, D>,
        psi: &Element<'dr, D>,
        rcm: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let sponge = init(dr, FEE_BLIND_DOMAIN);
        absorb(dr, sponge, [pk, psi, rcm])?.squeeze(dr)
    }

    pub(crate) fn fee_digest<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        cv: &Point<'dr, D, EpAffine>,
        fee: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let mut cv_coordinates = Vec::new();
        cv.write(dr, &mut cv_coordinates)?;
        let sponge = init(dr, FEE_DIGEST_DOMAIN);
        absorb(dr, sponge, cv_coordinates.iter().chain([fee]))?.squeeze(dr)
    }

    pub(crate) fn action_digest<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        cv: &Point<'dr, D, EpAffine>,
        rk: &Point<'dr, D, EpAffine>,
    ) -> Result<Element<'dr, D>> {
        let mut coordinates = Vec::new();
        cv.write(dr, &mut coordinates)?;
        rk.write(dr, &mut coordinates)?;
        let sponge = init(dr, ACTION_DIGEST_DOMAIN);
        absorb(dr, sponge, &coordinates)?.squeeze(dr)
    }

    pub(crate) fn payment_key<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        ak: &Point<'dr, D, EpAffine>,
        nk: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let mut ak_coordinates = Vec::new();
        ak.write(dr, &mut ak_coordinates)?;
        let sponge = init(dr, PAYMENT_KEY_DOMAIN);
        absorb(dr, sponge, ak_coordinates.iter().chain([nk]))?.squeeze(dr)
    }

    pub(crate) fn note_commitment<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        rcm: &Element<'dr, D>,
        pk: &Element<'dr, D>,
        value: &Element<'dr, D>,
        psi: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let sponge = init(dr, NOTE_COMMITMENT_DOMAIN);
        absorb(dr, sponge, [rcm, pk, value, psi])?.squeeze(dr)
    }

    pub(crate) fn pad_tachygram<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        rcm: &Element<'dr, D>,
        pk: &Element<'dr, D>,
        value: &Element<'dr, D>,
        psi: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let sponge = init(dr, PAD_COMMITMENT_DOMAIN);
        absorb(dr, sponge, [rcm, pk, value, psi])?.squeeze(dr)
    }

    pub(crate) fn nf_master<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        psi: &Element<'dr, D>,
        nk: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let sponge = init(dr, NULLIFIER_MASTER_DOMAIN);
        absorb(dr, sponge, [psi, nk])?.squeeze(dr)
    }

    pub(crate) fn alpha_spend<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        theta: &Element<'dr, D>,
        cm: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let sponge = init(dr, SPEND_ALPHA_DOMAIN);
        absorb(dr, sponge, [theta, cm])?.squeeze(dr)
    }

    pub(crate) fn alpha_output<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        theta: &Element<'dr, D>,
        cm: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let sponge = init(dr, OUTPUT_ALPHA_DOMAIN);
        absorb(dr, sponge, [theta, cm])?.squeeze(dr)
    }

    pub(crate) fn nullifier_group<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        master: &Element<'dr, D>,
        epoch_start: &Element<'dr, D>,
    ) -> Result<[Element<'dr, D>; PoseidonFp::RATE]> {
        let mut sponge = init(dr, NULLIFIER_DOMAIN);
        sponge = absorb(dr, sponge, [master, epoch_start])?;
        Ok([
            sponge.squeeze(dr)?,
            sponge.squeeze(dr)?,
            sponge.squeeze(dr)?,
            sponge.squeeze(dr)?,
        ])
    }

    pub(crate) fn anchor_next_stamp<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        anchor_prev: &Element<'dr, D>,
        epoch: &Element<'dr, D>,
        bridge_hash: &[Element<'dr, D>; 2],
    ) -> Result<Element<'dr, D>> {
        let sponge = init(dr, ANCHOR_STAMP_DOMAIN);
        absorb(
            dr,
            sponge,
            [anchor_prev, epoch, &bridge_hash[0], &bridge_hash[1]],
        )?
        .squeeze(dr)
    }

    pub(crate) fn anchor_next_epoch<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        anchor_prev: &Element<'dr, D>,
        epoch: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let sponge = init(dr, ANCHOR_EPOCH_DOMAIN);
        absorb(dr, sponge, [anchor_prev, epoch])?.squeeze(dr)
    }

    pub(crate) fn evidence_tree_leaf<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        epoch: &Element<'dr, D>,
        anchor_start: &Element<'dr, D>,
        anchor_next: &Element<'dr, D>,
        discriminant: &Element<'dr, D>,
        profile: (&Element<'dr, D>, &Element<'dr, D>),
        bridge_hash: &[Element<'dr, D>; 2],
    ) -> Result<Element<'dr, D>> {
        let sponge = init(dr, QR_BUCKET_DOMAIN);
        absorb(
            dr,
            sponge,
            [
                epoch,
                anchor_start,
                anchor_next,
                discriminant,
                profile.0,
                profile.1,
                &bridge_hash[0],
                &bridge_hash[1],
            ],
        )?
        .squeeze(dr)
    }

    pub(crate) fn evidence_tree_node<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        children: &[Element<'dr, D>; EVIDENCE_TREE_ARITY],
    ) -> Result<Element<'dr, D>> {
        let sponge = init(dr, EVIDENCE_NODE_DOMAIN);
        absorb(dr, sponge, children.each_ref())?.squeeze(dr)
    }
}
