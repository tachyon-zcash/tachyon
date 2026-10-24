//! `NoteSeed`, `NullifierDerive` and `NullifierFuse`: a note's certified
//! opening and its nullifier windows.

extern crate alloc;

use alloc::vec::Vec;

use pasta_curves::Fp;
use proptest::prelude::*;
use ragu::{Pcd, Proof};
use ragu_arithmetic::PoseidonPermutation as _;
use ragu_pasta::PoseidonFp;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    EpochIndex, NfSeqPoly, Note,
    constants::{EPOCH_MAX, MAX_MONEY},
    nullifier::{NF_DERIVATION_WIDTH, Nullifier},
    stamp::proof::{PROOF_SYSTEM, delegation},
    value, witness,
};

use crate::{
    fixtures::{WalletSim, shared_sk},
    strategies::{assert_rejections, check, tachygrams},
};

/// The window width as an epoch count.
fn width() -> u32 {
    u32::try_from(NF_DERIVATION_WIDTH).expect("the window width fits u32")
}

/// The sponge group width as an epoch count.
fn group() -> u32 {
    u32::try_from(PoseidonFp::RATE).expect("the sponge rate fits u32")
}

/// The group-aligned start nearest `index` that leaves room for `windows`
/// consecutive windows up to the final epoch.
fn window_start(index: u32, windows: u32) -> EpochIndex {
    let room = EPOCH_MAX + 1 - (windows * width());
    EpochIndex::new(index.min(room) & !(group() - 1))
}

/// A note's certified secret, witnessed under `wallet`'s key.
fn secret(rng: &mut StdRng, wallet: &WalletSim, note: Note) -> Pcd<delegation::NoteSecret> {
    PROOF_SYSTEM
        .seed(
            rng,
            delegation::NoteSeed,
            witness::note_seed(((), ()), note, wallet.pak),
        )
        .expect("NoteSeed")
        .0
}

/// One derived window of `secret`'s note from `start`.
fn window(
    rng: &mut StdRng,
    secret: &Pcd<delegation::NoteSecret>,
    start: EpochIndex,
) -> Pcd<delegation::NoteNullifiers> {
    PROOF_SYSTEM
        .fuse(
            rng,
            delegation::NullifierDerive,
            witness::nullifier_derive((*secret.data(), ()), start),
            secret.clone(),
            Proof::trivial().carry::<()>(()),
        )
        .expect("NullifierDerive")
        .0
}

/// The note's nullifiers over `count` epochs from `start`.
fn nullifiers(wallet: &WalletSim, note: &Note, start: EpochIndex, count: u32) -> Vec<Nullifier> {
    (u32::from(start)..u32::from(start) + count)
        .map(|epoch| wallet.nf_at(note, EpochIndex::new(epoch)))
        .collect()
}

/// The seed certifies the opening the witnessed key derives, with its
/// commitment and master key; a note addressed to another key comes out as
/// the secret of a different note. Windows derived at any aligned start and
/// fused in order export one member per epoch over their whole range.
#[test]
fn derivation_chain_exports_its_windows() {
    let strategy = (
        any::<u64>(),
        0..=MAX_MONEY,
        0..=EPOCH_MAX,
        1u32..=3,
        any::<bool>(),
    );
    check(
        12,
        strategy,
        |(seed, amount, start, windows, foreign_pak)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let wallet = WalletSim::new(shared_sk());
            let note = Note {
                value: value::Positive::try_from(amount).unwrap(),
                ..wallet.random_note(0)
            };

            let signer = if foreign_pak {
                WalletSim::random(rng)
            } else {
                WalletSim::new(shared_sk())
            };
            let (cm, opening, mk) = *secret(rng, &signer, note).data();
            prop_assert_eq!(
                Fp::from(opening.pk),
                Fp::from(signer.pak.derive_payment_key())
            );
            prop_assert_eq!(
                (Fp::from(opening.rcm), opening.value, Fp::from(opening.psi)),
                (Fp::from(note.rcm), note.value, Fp::from(note.psi))
            );
            prop_assert_eq!(mk, signer.mk(&opening));
            prop_assert_eq!(cm, opening.commitment());
            prop_assert_eq!(cm == note.commitment(), !foreign_pak);

            let secret_pcd = secret(rng, &wallet, note);
            let first = window_start(start, windows);
            let mut chain = window(rng, &secret_pcd, first);
            for index in 1..windows {
                let next_start = EpochIndex::new(u32::from(first) + index * width());
                let next = window(rng, &secret_pcd, next_start);
                let fuse_witness = witness::nullifier_fuse(
                    (*chain.data(), *next.data()),
                    &nullifiers(&wallet, &note, first, index * width()),
                    &nullifiers(&wallet, &note, next_start, width()),
                );
                chain = PROOF_SYSTEM
                    .fuse(rng, delegation::NullifierFuse, fuse_witness, chain, next)
                    .expect("NullifierFuse")
                    .0;
            }

            let last = EpochIndex::new(u32::from(first) + windows * width() - 1);
            let members = nullifiers(&wallet, &note, first, windows * width());
            let commit = NfSeqPoly::new(first, &members).commit();
            prop_assert_eq!(*chain.data(), (note.commitment(), first, commit, last));
            Ok(())
        },
    );
}

/// A derivation refuses a sequence of another note's nullifiers, an
/// unaligned start, and a window past the final epoch; a fuse refuses ranges
/// that do not meet, windows of two notes, halves other than the headers',
/// and a merged sequence other than their concatenation.
#[test]
fn delegation_steps_reject_corruptions() {
    let strategy = (
        any::<u64>(),
        0..=EPOCH_MAX,
        1..PoseidonFp::RATE,
        1u32..=3,
        1u32..=2,
    );
    check(
        12,
        strategy,
        |(seed, start, misalignment, short_by, gap)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let wallet = WalletSim::new(shared_sk());
            let (note, other) = (wallet.random_note(500), wallet.random_note(700));
            let secret_pcd = secret(rng, &wallet, note);
            let other_secret = secret(rng, &wallet, other);

            let left_start = window_start(start, 2 + gap);
            let right_start = EpochIndex::new(u32::from(left_start) + width());
            let gapped_start = EpochIndex::new(u32::from(right_start) + gap * width());
            let left = window(rng, &secret_pcd, left_start);
            let right = window(rng, &secret_pcd, right_start);
            let gapped = window(rng, &secret_pcd, gapped_start);
            let foreign_right = window(rng, &other_secret, right_start);

            let left_nfs = nullifiers(&wallet, &note, left_start, width());
            let right_nfs = nullifiers(&wallet, &note, right_start, width());
            let (left_seq, merged_seq, right_seq) =
                witness::nullifier_fuse((*left.data(), *right.data()), &left_nfs, &right_nfs);
            let reversed: Vec<Nullifier> = right_nfs.iter().rev().copied().collect();
            let junk: Vec<Nullifier> = tachygrams(rng, 2 * NF_DERIVATION_WIDTH)
                .into_iter()
                .map(Nullifier::from)
                .collect();
            let past_the_end = EpochIndex::new(EPOCH_MAX + 1 - short_by * group());
            let misaligned =
                EpochIndex::new(u32::from(left_start) + u32::try_from(misalignment).unwrap());
            let foreign_seq = NfSeqPoly::new(
                left_start,
                &nullifiers(&wallet, &other, left_start, width()),
            );
            let (_, honest_seq) = witness::nullifier_derive((*secret_pcd.data(), ()), left_start);
            let gapped_witness = witness::nullifier_fuse(
                (*left.data(), *gapped.data()),
                &left_nfs,
                &nullifiers(&wallet, &note, gapped_start, width()),
            );
            let foreign_witness = witness::nullifier_fuse(
                (*left.data(), *foreign_right.data()),
                &left_nfs,
                &nullifiers(&wallet, &other, right_start, width()),
            );

            let derive = |derive_rng: &mut StdRng, at: EpochIndex, seq: NfSeqPoly| {
                PROOF_SYSTEM
                    .fuse(
                        derive_rng,
                        delegation::NullifierDerive,
                        (at, seq),
                        secret_pcd.clone(),
                        Proof::trivial().carry::<()>(()),
                    )
                    .map(drop)
            };
            let fuse =
                |fuse_rng: &mut StdRng, fuse_witness, with: &Pcd<delegation::NoteNullifiers>| {
                    PROOF_SYSTEM
                        .fuse(
                            fuse_rng,
                            delegation::NullifierFuse,
                            fuse_witness,
                            left.clone(),
                            with.clone(),
                        )
                        .map(drop)
                };

            assert_rejections([
                (
                    "a sequence of another note's nullifiers",
                    derive(rng, left_start, foreign_seq),
                    "NullifierDerive: sequence does not match the derived window",
                ),
                (
                    "an unaligned start",
                    derive(rng, misaligned, honest_seq),
                    "NullifierDerive: epoch_start is not group-aligned",
                ),
                (
                    "a window past the final epoch",
                    derive(rng, past_the_end, NfSeqPoly::new(past_the_end, &[])),
                    "NullifierDerive: window exceeds the epoch range",
                ),
                (
                    "ranges with a gap",
                    fuse(rng, gapped_witness, &gapped),
                    "NullifierFuse: ranges not contiguous",
                ),
                (
                    "windows of two notes",
                    fuse(rng, foreign_witness, &foreign_right),
                    "NullifierFuse: note commitments differ",
                ),
                (
                    "a left half other than the header's",
                    fuse(
                        rng,
                        (
                            NfSeqPoly::new(left_start, &right_nfs),
                            merged_seq.clone(),
                            right_seq.clone(),
                        ),
                        &right,
                    ),
                    "NullifierFuse: left polynomial does not match header",
                ),
                (
                    "a right half other than the header's",
                    fuse(
                        rng,
                        (
                            left_seq.clone(),
                            merged_seq,
                            NfSeqPoly::new(right_start, &reversed),
                        ),
                        &right,
                    ),
                    "NullifierFuse: right polynomial does not match header",
                ),
                (
                    "a merged sequence other than the concatenation",
                    fuse(
                        rng,
                        (left_seq, NfSeqPoly::new(left_start, &junk), right_seq),
                        &right,
                    ),
                    "NullifierFuse: merged is not the concat of the halves",
                ),
            ]);
            Ok(())
        },
    );
}
