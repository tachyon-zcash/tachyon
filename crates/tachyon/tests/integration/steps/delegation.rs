extern crate alloc;

use alloc::vec::Vec;
use core::iter;

use ragu::{Pcd, Proof};
use ragu_core::{PoseidonPermutation as _, pasta::PoseidonFp};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    EpochIndex, NfSeqPoly, Note, Tachygram,
    constants::EPOCH_MAX,
    nullifier::{NF_DERIVATION_WIDTH, Nullifier},
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, delegation},
    witness,
};

use crate::fixtures::WalletSim;

#[test]
fn derivation_chain_exports_its_windows() {
    let rng = &mut StdRng::seed_from_u64(0);
    let width = u32::try_from(NF_DERIVATION_WIDTH).unwrap();
    let group = u32::try_from(PoseidonFp::RATE).unwrap();
    for (start, windows) in [(0, 1), (EPOCH_MAX / 2, 2), (EPOCH_MAX, 3)] {
        let case = format!("{windows} windows from epoch {start}");
        let wallet = WalletSim::random(rng);
        let note = wallet.random_note(500);
        let stranger = WalletSim::random(rng);
        let stranger_pk = stranger.random_note(0).pk;

        for (signer, pk) in [(&wallet, note.pk), (&stranger, stranger_pk)] {
            let (signer_secret, ()) = PROOF_SYSTEM
                .seed(
                    rng,
                    delegation::NoteSeed,
                    witness::note_seed(((), ()), note, signer.pak),
                )
                .unwrap();
            let (cm, opening, mk) = *signer_secret.data();
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
            assert_eq!(
                mk,
                signer.pak.nk.derive_note_private(note.psi),
                "{case}: master key"
            );
            assert_eq!(cm, Note { pk, ..note }.commitment(), "{case}: commitment");
        }

        let (secret_pcd, ()) = PROOF_SYSTEM
            .seed(
                rng,
                delegation::NoteSeed,
                witness::note_seed(((), ()), note, wallet.pak),
            )
            .unwrap();
        let mk = wallet.pak.nk.derive_note_private(note.psi);
        let first = EpochIndex::new(start.min(EPOCH_MAX + 1 - windows * width) & !(group - 1));
        let (mut chain, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                delegation::NullifierDerive,
                witness::nullifier_derive((*secret_pcd.data(), ()), first),
                secret_pcd.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        for index in 1..windows {
            let next_start = EpochIndex::new(u32::from(first) + index * width);
            let (next, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    delegation::NullifierDerive,
                    witness::nullifier_derive((*secret_pcd.data(), ()), next_start),
                    secret_pcd.clone(),
                    Proof::bootstrap().carry::<()>(()),
                )
                .unwrap();
            let chain_nfs: Vec<Nullifier> = (u32::from(first)..u32::from(next_start))
                .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
                .collect();
            let next_nfs: Vec<Nullifier> = (u32::from(next_start)..u32::from(next_start) + width)
                .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
                .collect();
            let fuse_witness =
                witness::nullifier_fuse((*chain.data(), *next.data()), &chain_nfs, &next_nfs);
            chain = PROOF_SYSTEM
                .fuse(rng, delegation::NullifierFuse, fuse_witness, chain, next)
                .unwrap()
                .0;
        }

        let last = EpochIndex::new(u32::from(first) + windows * width - 1);
        let members: Vec<Nullifier> = (u32::from(first)..=u32::from(last))
            .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
            .collect();
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
    let width = u32::try_from(NF_DERIVATION_WIDTH).unwrap();
    let group = u32::try_from(PoseidonFp::RATE).unwrap();
    let wallet = WalletSim::random(rng);
    let (note, other) = (wallet.random_note(500), wallet.random_note(700));
    let (secret_pcd, ()) = PROOF_SYSTEM
        .seed(
            rng,
            delegation::NoteSeed,
            witness::note_seed(((), ()), note, wallet.pak),
        )
        .unwrap();
    let (other_secret, ()) = PROOF_SYSTEM
        .seed(
            rng,
            delegation::NoteSeed,
            witness::note_seed(((), ()), other, wallet.pak),
        )
        .unwrap();
    let mk = wallet.pak.nk.derive_note_private(note.psi);
    let other_mk = wallet.pak.nk.derive_note_private(other.psi);

    let left_start = EpochIndex::new((EPOCH_MAX / 2).min(EPOCH_MAX + 1 - 3 * width) & !(group - 1));
    let right_start = EpochIndex::new(u32::from(left_start) + width);
    let gapped_start = EpochIndex::new(u32::from(right_start) + width);
    let [left, right, gapped, foreign_right] = [
        (&secret_pcd, left_start),
        (&secret_pcd, right_start),
        (&secret_pcd, gapped_start),
        (&other_secret, right_start),
    ]
    .map(|(secret, start)| {
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
    });

    let left_nfs: Vec<Nullifier> = (u32::from(left_start)..u32::from(right_start))
        .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
        .collect();
    let right_nfs: Vec<Nullifier> = (u32::from(right_start)..u32::from(gapped_start))
        .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
        .collect();
    let (left_seq, merged_seq, right_seq) =
        witness::nullifier_fuse((*left.data(), *right.data()), &left_nfs, &right_nfs);
    let reversed: Vec<Nullifier> = right_nfs.iter().rev().copied().collect();
    let junk: Vec<Nullifier> = iter::repeat_with(|| Tachygram::random(rng))
        .take(2 * NF_DERIVATION_WIDTH)
        .map(Nullifier::from)
        .collect();
    let past_the_end = EpochIndex::new(EPOCH_MAX + 1 - group);
    let misaligned = EpochIndex::new(u32::from(left_start) + 1);
    let foreign_nfs: Vec<Nullifier> = (u32::from(left_start)..u32::from(right_start))
        .map(|epoch| other_mk.derive_nullifier(EpochIndex::new(epoch)))
        .collect();
    let foreign_seq = NfSeqPoly::new(left_start, &foreign_nfs);
    let (_, honest_seq) = witness::nullifier_derive((*secret_pcd.data(), ()), left_start);
    let gapped_nfs: Vec<Nullifier> = (u32::from(gapped_start)..u32::from(gapped_start) + width)
        .map(|epoch| mk.derive_nullifier(EpochIndex::new(epoch)))
        .collect();
    let gapped_witness =
        witness::nullifier_fuse((*left.data(), *gapped.data()), &left_nfs, &gapped_nfs);
    let foreign_right_nfs: Vec<Nullifier> = (u32::from(right_start)..u32::from(gapped_start))
        .map(|epoch| other_mk.derive_nullifier(EpochIndex::new(epoch)))
        .collect();
    let foreign_witness = witness::nullifier_fuse(
        (*left.data(), *foreign_right.data()),
        &left_nfs,
        &foreign_right_nfs,
    );

    let derive = |derive_rng: &mut StdRng, at: EpochIndex, seq: NfSeqPoly| {
        PROOF_SYSTEM.fuse(
            derive_rng,
            delegation::NullifierDerive,
            (at, seq),
            secret_pcd.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
    };
    let fuse = |fuse_rng: &mut StdRng, fuse_witness, with: &Pcd<delegation::NoteNullifiers>| {
        PROOF_SYSTEM.fuse(
            fuse_rng,
            delegation::NullifierFuse,
            fuse_witness,
            left.clone(),
            with.clone(),
        )
    };

    {
        let Err(ragu_core::Error::InvalidWitness(err)) = derive(rng, left_start, foreign_seq)
        else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "NullifierDerive: sequence does not match the derived window"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = derive(rng, misaligned, honest_seq) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "NullifierDerive: epoch_start is not group-aligned"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) =
            derive(rng, past_the_end, NfSeqPoly::new(past_the_end, &[]))
        else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "NullifierDerive: window exceeds the epoch range"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fuse(rng, gapped_witness, &gapped) else {
            panic!();
        };
        assert_eq!(err.to_string(), "NullifierFuse: ranges not contiguous");
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fuse(rng, foreign_witness, &foreign_right)
        else {
            panic!();
        };
        assert_eq!(err.to_string(), "NullifierFuse: note commitments differ");
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fuse(
            rng,
            (
                NfSeqPoly::new(left_start, &right_nfs),
                merged_seq.clone(),
                right_seq.clone(),
            ),
            &right,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "NullifierFuse: left polynomial does not match header"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fuse(
            rng,
            (
                left_seq.clone(),
                merged_seq,
                NfSeqPoly::new(right_start, &reversed),
            ),
            &right,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "NullifierFuse: right polynomial does not match header"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fuse(
            rng,
            (left_seq, NfSeqPoly::new(left_start, &junk), right_seq),
            &right,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "NullifierFuse: merged is not the concat of the halves"
        );
    }
}
