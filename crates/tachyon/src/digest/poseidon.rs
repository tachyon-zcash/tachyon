//! Tachyon Poseidon digests.
//!
//! Each named function provides one protocol-defined hash.
//!
//! A tagged hash starts from a zero rate and the capacity element
//! $\mathsf{tag}$, the 16-byte domain read as a little-endian integer. It
//! absorbs only its data. Every Tachyon Poseidon hash is tagged this way.

use core::array;

use ragu::{
    Cycle as _, PoseidonPermutation as _,
    pasta::{EqAffine, Fp, Pasta, PoseidonFp},
};
use ragu_core::{
    drivers::emulator::{Emulator, Wireless},
    maybe::{Always, Maybe as _},
};
use ragu_pcd::pasta::baked;
use ragu_primitives::{
    Element,
    poseidon::{Sponge, SpongeState},
    vec::FixedVec,
};
use udon::{curve::Affine as _, field::Field as _};

use crate::constants::EVIDENCE_TREE_ARITY;

#[expect(
    clippy::expect_used,
    reason = "sponge squeeze cannot fail in wireless `Always` mode"
)]
fn squeeze(
    emulator: &mut Emulator<Wireless<Always<()>, Fp>>,
    sponge: &mut Sponge<'static, Emulator<Wireless<Always<()>, Fp>>, PoseidonFp>,
) -> Fp {
    let squeezed = sponge.squeeze(emulator).expect("infallible");
    *squeezed.value().take()
}

/// Opens the sponge of `domain` with capacity element $\mathsf{tag}$ over a
/// zero rate, then absorbs `input`.
#[expect(
    clippy::type_complexity,
    reason = "keep the real sponge driver type explicit"
)]
fn tagged_sponge<const L: usize>(
    domain: &[u8; 16],
    input: [Fp; L],
) -> (
    Emulator<Wireless<Always<()>, Fp>>,
    Sponge<'static, Emulator<Wireless<Always<()>, Fp>>, PoseidonFp>,
) {
    const { assert!(L > 0, "a tagged hash must absorb at least one element") };
    let capacity = Fp::from_u128(u128::from_le_bytes(*domain));

    let mut emulator = Emulator::<Wireless<Always<()>, Fp>>::execute();
    let state = SpongeState::from_elements(FixedVec::from_fn(|index| {
        let value = if index == PoseidonFp::RATE {
            capacity
        } else {
            Fp::ZERO
        };
        Element::constant(&mut emulator, value)
    }));
    let mut sponge = Sponge::resume(state, Pasta::circuit_poseidon(baked()));
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
pub fn fee_digest(cv_max_fee: (Fp, Fp), fee: u64) -> Fp {
    hash::<3>(
        FEE_DIGEST_DOMAIN,
        [cv_max_fee.0, cv_max_fee.1, Fp::from(fee)],
    )
}

const ACTION_DIGEST_DOMAIN: &[u8; 16] = b"Tachyon-ActionDg";

/// Derives an action digest from action fields.
#[must_use]
pub fn action_digest(cv: (Fp, Fp), rk: (Fp, Fp)) -> Fp {
    hash::<4>(ACTION_DIGEST_DOMAIN, [cv.0, cv.1, rk.0, rk.1])
}

const PAYMENT_KEY_DOMAIN: &[u8; 16] = b"Tachyon-PkDerive";

/// Derives a payment key from a spend validating key and nullifier key.
#[must_use]
pub fn payment_key(ak: (Fp, Fp), nk: Fp) -> Fp {
    hash::<3>(PAYMENT_KEY_DOMAIN, [ak.0, ak.1, nk])
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
        !point.is_identity(),
        "commitment must not be the identity point"
    );

    let encoding = point.to_bytes();
    let (lo, hi) = encoding.as_ref().split_at(16);
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

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::{array, mem};

    use ff::{Field as _, PrimeField as _};
    use ragu_arithmetic::{Cycle as _, PoseidonPermutation as _};
    use ragu_pasta::Pasta as LegacyPasta;

    use super::*;

    fn legacy_permute(
        mut state: [pasta_curves::Fp; ragu_pasta::PoseidonFp::T],
    ) -> [pasta_curves::Fp; ragu_pasta::PoseidonFp::T] {
        let parameters = LegacyPasta::circuit_poseidon(LegacyPasta::baked());
        let first_full_rounds = ragu_pasta::PoseidonFp::FULL_ROUNDS >> 1;
        let partial_round_end = first_full_rounds + ragu_pasta::PoseidonFp::PARTIAL_ROUNDS;
        let total_rounds = partial_round_end + first_full_rounds;
        let mut round_constants = parameters.round_constants();

        for round in 0..total_rounds {
            let constants = round_constants
                .next()
                .expect("legacy Poseidon has one constant row per round");
            for (value, constant) in state.iter_mut().zip(constants) {
                *value += *constant;
            }
            let active = if round < first_full_rounds || round >= partial_round_end {
                ragu_pasta::PoseidonFp::T
            } else {
                1
            };
            for value in state.iter_mut().take(active) {
                let square = value.square();
                *value = square.square() * *value;
            }

            let mut next_state = [pasta_curves::Fp::ZERO; ragu_pasta::PoseidonFp::T];
            for (next, row) in next_state.iter_mut().zip(parameters.mds_matrix()) {
                *next = state
                    .iter()
                    .zip(row)
                    .fold(pasta_curves::Fp::ZERO, |sum, (value, coefficient)| {
                        sum + (*value * *coefficient)
                    });
            }
            state = next_state;
        }
        state
    }

    fn legacy_sponge_state<const L: usize>(
        domain: &[u8; 16],
        input: [Fp; L],
    ) -> [pasta_curves::Fp; ragu_pasta::PoseidonFp::T] {
        let capacity = domain
            .iter()
            .rev()
            .fold(pasta_curves::Fp::ZERO, |acc, byte| {
                acc * pasta_curves::Fp::from(256) + pasta_curves::Fp::from(u64::from(*byte))
            });
        let mut state = array::from_fn(|index| {
            if index == ragu_pasta::PoseidonFp::RATE {
                capacity
            } else {
                pasta_curves::Fp::ZERO
            }
        });
        let mut pending = Vec::new();
        for input_value in input {
            if pending.len() == ragu_pasta::PoseidonFp::RATE {
                let absorbed_values = mem::take(&mut pending);
                for (lane, value) in state
                    .iter_mut()
                    .take(ragu_pasta::PoseidonFp::RATE)
                    .zip(absorbed_values)
                {
                    *lane += value;
                }
                state = legacy_permute(state);
            }
            pending.push(
                pasta_curves::Fp::from_repr(input_value.to_bytes())
                    .into_option()
                    .expect("canonical Udon field bytes decode in the legacy field"),
            );
        }
        for (lane, pending_value) in state
            .iter_mut()
            .take(ragu_pasta::PoseidonFp::RATE)
            .zip(pending)
        {
            *lane += pending_value;
        }
        legacy_permute(state)
    }

    #[test]
    fn tagged_hash_matches_legacy_parameters_at_and_past_the_absorb_rate() {
        let domain = *b"Tachyon-ActionDg";
        let at_rate = [Fp::from(2), Fp::from(3), Fp::from(5), Fp::from(7)];
        let past_rate = [
            Fp::from(2),
            Fp::from(3),
            Fp::from(5),
            Fp::from(7),
            Fp::from(11),
        ];
        let [legacy_at_rate, ..] = legacy_sponge_state(&domain, at_rate);
        let [legacy_past_rate, ..] = legacy_sponge_state(&domain, past_rate);

        assert_eq!(
            hash::<4>(&domain, at_rate).to_bytes(),
            legacy_at_rate.to_repr()
        );
        assert_eq!(
            hash::<5>(&domain, past_rate).to_bytes(),
            legacy_past_rate.to_repr()
        );
    }

    #[test]
    fn nullifier_group_matches_legacy_parameters_across_successive_squeezes() {
        let master = Fp::from(19);
        let epoch_start = Fp::from(32);
        let [legacy_0, legacy_1, legacy_2, legacy_3, _capacity] =
            legacy_sponge_state(NULLIFIER_DOMAIN, [master, epoch_start]);
        let current = nullifier_group(master, epoch_start);

        assert_eq!(current[0].to_bytes(), legacy_0.to_repr());
        assert_eq!(current[1].to_bytes(), legacy_1.to_repr());
        assert_eq!(current[2].to_bytes(), legacy_2.to_repr());
        assert_eq!(current[3].to_bytes(), legacy_3.to_repr());
    }
}
