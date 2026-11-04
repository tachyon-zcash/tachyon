extern crate alloc;

use alloc::vec::Vec;

use ragu::{Pcd, Proof};
use ragu_core::{PoseidonPermutation as _, pasta::PoseidonFp};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    EpochIndex, NfSeqPoly, Note,
    constants::EPOCH_MAX,
    nullifier::{NF_DERIVATION_WIDTH, Nullifier},
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, delegation},
    witness,
};

use crate::fixtures::{WalletSim, assert_rejected, tachygrams};

fn width() -> u32 {
    u32::try_from(NF_DERIVATION_WIDTH).unwrap()
}

fn group() -> u32 {
    u32::try_from(PoseidonFp::RATE).unwrap()
}

fn window_start(index: u32, windows: u32) -> EpochIndex {
    let room = EPOCH_MAX + 1 - (windows * width());
    EpochIndex::new(index.min(room) & !(group() - 1))
}

fn secret(rng: &mut StdRng, wallet: &WalletSim, note: Note) -> Pcd<delegation::NoteSecret> {
    PROOF_SYSTEM
        .seed(
            rng,
            delegation::NoteSeed,
            witness::note_seed(((), ()), note, wallet.pak),
        )
        .unwrap()
        .0
}

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
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap()
        .0
}

fn nullifiers(wallet: &WalletSim, note: &Note, start: EpochIndex, count: u32) -> Vec<Nullifier> {
    (u32::from(start)..u32::from(start) + count)
        .map(|epoch| wallet.nf_at(note, EpochIndex::new(epoch)))
        .collect()
}

#[test]
fn derivation_chain_exports_its_windows() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (start, windows) in [(0, 1), (EPOCH_MAX / 2, 2), (EPOCH_MAX, 3)] {
        let case = format!("{windows} windows from epoch {start}");
        let wallet = WalletSim::random(rng);
        let note = wallet.random_note(500);
        let stranger = WalletSim::random(rng);
        let stranger_pk = stranger.random_note(0).pk;

        for (signer, pk) in [(&wallet, note.pk), (&stranger, stranger_pk)] {
            let (cm, opening, mk) = *secret(rng, signer, note).data();
            assert_eq!(
                (
                    Fp::from(opening.pk),
                    Fp::from(opening.rcm),
                    opening.value,
                    Fp::from(opening.psi)
                ),
                (
                    Fp::from(pk),
                    Fp::from(note.rcm),
                    note.value,
                    Fp::from(note.psi)
                ),
                "{case}: opening"
            );
            assert_eq!(mk, signer.mk(&note), "{case}: master key");
            assert_eq!(cm, Note { pk, ..note }.commitment(), "{case}: commitment");
        }

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
                .unwrap()
                .0;
        }

        let last = EpochIndex::new(u32::from(first) + windows * width() - 1);
        let members = nullifiers(&wallet, &note, first, windows * width());
        let commit = NfSeqPoly::new(first, &members).commit();
        assert_eq!(
            *chain.data(),
            (note.commitment(), first, commit, last),
            "{case}: chain"
        );
    }
}

#[test]
fn delegation_steps_reject_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let (note, other) = (wallet.random_note(500), wallet.random_note(700));
    let secret_pcd = secret(rng, &wallet, note);
    let other_secret = secret(rng, &wallet, other);

    let left_start = window_start(EPOCH_MAX / 2, 3);
    let right_start = EpochIndex::new(u32::from(left_start) + width());
    let gapped_start = EpochIndex::new(u32::from(right_start) + width());
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
    let past_the_end = EpochIndex::new(EPOCH_MAX + 1 - group());
    let misaligned = EpochIndex::new(u32::from(left_start) + 1);
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
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
    };
    let fuse = |fuse_rng: &mut StdRng, fuse_witness, with: &Pcd<delegation::NoteNullifiers>| {
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

    assert_rejected(
        derive(rng, left_start, foreign_seq),
        "NullifierDerive: sequence does not match the derived window",
    );
    assert_rejected(
        derive(rng, misaligned, honest_seq),
        "NullifierDerive: epoch_start is not group-aligned",
    );
    assert_rejected(
        derive(rng, past_the_end, NfSeqPoly::new(past_the_end, &[])),
        "NullifierDerive: window exceeds the epoch range",
    );
    assert_rejected(
        fuse(rng, gapped_witness, &gapped),
        "NullifierFuse: ranges not contiguous",
    );
    assert_rejected(
        fuse(rng, foreign_witness, &foreign_right),
        "NullifierFuse: note commitments differ",
    );
    assert_rejected(
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
    );
    assert_rejected(
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
    );
    assert_rejected(
        fuse(
            rng,
            (left_seq, NfSeqPoly::new(left_start, &junk), right_seq),
            &right,
        ),
        "NullifierFuse: merged is not the concat of the halves",
    );
}
