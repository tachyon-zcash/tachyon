use alloc::vec;

use ragu::circuits::polynomials;
use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    Anchor, Bundle, Note, TachyonBundle, VerificationError, bundle,
    entropy::ActionEntropy,
    keys::private::SpendingKey,
    pasta::Fp,
    stamp::{Compressed, proof},
    value,
};

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "exercise the complete publication and mining workflow with one paired setup"
)]
fn wallet_publications_merge_and_divide_before_block_compression() {
    let rng = &mut StdRng::seed_from_u64(58);
    let app = proof::new_aggregator_application(rng).unwrap();
    let wallet = proof::new_application().unwrap();
    let sk = SpendingKey::random(rng);
    let start = Anchor::random(rng);
    let mut issue = |tag: u64| {
        let note = Note {
            pk: Fp::from(tag).into(),
            value: value::Positive::ZERO,
            psi: Fp::from(tag).into(),
            rcm: Fp::from(tag).into(),
        };
        // The right host has one output; the left has only its zero fee.
        let outputs = if tag == 2 {
            vec![crate::ActionPlan::output(
                Note {
                    value: value::Positive::try_from(5).unwrap(),
                    rcm: Fp::from(7).into(),
                    ..note
                },
                ActionEntropy::random(rng),
                value::Trapdoor::random(rng),
            )]
        } else {
            vec![]
        };
        let plan = bundle::Plan::new(vec![], outputs, note);
        let sighash = plan.commitment().unwrap();
        let sigs = plan.sign(rng, &sighash, &sk.derive_auth_private()).unwrap();
        let proved = plan
            .stamp_plan(start, value::Positive::ZERO)
            .prove(rng, &wallet, &sk.derive_proof_private(), vec![])
            .unwrap();
        let signed = plan.assemble(sigs, proved);
        let fees = BTreeMap::from([(signed.fee, signed.fee_auth)]);
        let public = signed.stamp.clone().finalize(rng, &wallet).unwrap();
        let mut bytes = Vec::new();
        public.write(&mut bytes).unwrap();
        let stamp = ProofStamp::<Compressed>::read(bytes.as_slice()).unwrap();
        let body = Bundle {
            actions: signed.actions,
            action_auth: signed.action_auth,
            value_balance: signed.value_balance,
            memo: signed.memo,
            fee: signed.fee,
            fee_auth: signed.fee_auth,
            binding_sig: signed.binding_sig,
            stamp,
        };
        let work = body.rehydrate(rng, &app, &sighash, &[]).unwrap();
        (body, fees, work, signed.stamp)
    };
    let (left, left_fee, left_work, initial_left) = issue(1);
    let (right, right_fee, right_work, initial_right) = issue(2);
    let empty = BTreeMap::new();
    let right_id = right.commitment();
    let right_actions = BTreeMap::from([(right.actions[0], right.action_auth[0].1)]);
    let reversed = BTreeMap::from([(
        right.actions[0],
        (right.action_auth[0].1.1, right.action_auth[0].1.0),
    )]);
    let stripped = right.clone().strip();
    let wallet_union = initial_left
        .merge(
            rng,
            &wallet,
            (&empty, &left_fee),
            (initial_right, right_id, &right_actions, &right_fee),
        )
        .unwrap()
        .finalize(rng, &wallet)
        .unwrap();
    let wallet_host = Bundle {
        stamp: wallet_union,
        ..left.clone()
    };
    let sighash = wallet_host.commitment();
    let block = TachyonBundle::from(wallet_host.clone());
    let encoded_hash = block.auth_digest();
    let mut wire = Vec::new();
    block.write(&mut wire).unwrap();
    let mixed = Bundle::<ProofStamp<PublicationProof>>::read(wire.as_slice()).unwrap();
    assert_eq!(mixed.auth_digest(), encoded_hash);
    assert_eq!(mixed.commitment(), sighash);
    check_publication_frame(&mixed, 1, 7296, 3, 14432);
    check_trailer(
        &mixed.stamp,
        bundle::StateByte::ProofStamp,
        bundle::StateByte::AggregatorProofStamp,
        7296,
    );
    mixed.verify(&app, &sighash, &[&stripped]).unwrap();
    check_wallet_admission(rng, &app, mixed.clone(), &stripped);
    let extracted = Bundle::<ProofStamp<Compressed>>::try_from(TachyonBundle::from(mixed)).unwrap();
    assert_eq!(extracted, wallet_host);
    let combined = extracted
        .rehydrate(rng, &app, &sighash, &[&stripped])
        .unwrap();
    // Proof multiplication counts repeated roots. Admission of the same
    // covered body twice is a separate coverage check.
    let product = left_work
        .clone()
        .merge(
            rng,
            &app,
            (&empty, &left_fee),
            (left_work.clone(), sighash, &empty, &left_fee),
        )
        .unwrap();
    let digest = left.fee.digest(left.fee_auth);
    product
        .clone()
        .unmerge(
            rng,
            &app,
            (&empty, &left_fee),
            (left_work.clone(), sighash, &empty, &left_fee),
        )
        .unwrap_err();
    let (one_copy, ()) = app
        .fuse(
            rng,
            TransactionUnmerge,
            (ActionSetPoly::from_iter([digest]),),
            (*product.proof).clone(),
            (*left_work.proof).clone(),
        )
        .unwrap();
    let result = ProofStamp {
        anchor: start,
        tachygram_set: left_work.tachygram_set,
        adjuncts: BTreeSet::new(),
        proof: Box::new(one_copy),
    }
    .finalize(rng, &app)
    .unwrap();
    assert!(result.verify_proof(&app, &[digest]).unwrap());
    let doubled = product.finalize(rng, &app).unwrap();
    assert!(doubled.verify_proof(&app, &[digest, digest]).unwrap());
    assert!(!doubled.verify_proof(&app, &[digest]).unwrap());
    let missing_divisor = left_work
        .clone()
        .unmerge(
            rng,
            &app,
            (&empty, &left_fee),
            (right_work.clone(), right_id, &right_actions, &right_fee),
        )
        .unwrap()
        .finalize(rng, &app)
        .unwrap();
    assert!(!missing_divisor.verify_proof(&app, &[digest]).unwrap());
    let merged = left_work
        .clone()
        .merge(
            rng,
            &app,
            (&empty, &left_fee),
            (right_work.clone(), right_id, &right_actions, &right_fee),
        )
        .unwrap();
    assert_eq!(combined.proof.data(), merged.proof.data());
    assert_eq!(combined.proof.commitments(), merged.proof.commitments());
    // A private worker receives the bare full frame and independently verifies
    // it before resuming. No transaction CompactSize encloses this frame.
    let checkpoint = merged.proof.proof().to_bytes().unwrap();
    assert_eq!(checkpoint.len(), 174_072_896);
    let (checkpoint_digests, _) = extracted.verify_covered(&[&stripped]).unwrap();
    let expected = ActionSetPoly::from_iter(checkpoint_digests).commit();
    assert!(receive_work(&app, rng, &checkpoint[1..], expected, start).is_none());
    assert!(receive_work(&app, rng, &checkpoint, expected, Anchor::from(Fp::from(99))).is_none());
    let resumed = receive_work(&app, rng, &checkpoint, expected, start).unwrap();
    drop(checkpoint);
    let all_fees = left_fee
        .iter()
        .chain(&right_fee)
        .map(|(&desc, &change)| (desc, change))
        .collect();
    let hostless = merged
        .clone()
        .unmerge(
            rng,
            &app,
            (&right_actions, &all_fees),
            (left_work, left.commitment(), &empty, &left_fee),
        )
        .unwrap()
        .finalize(rng, &app)
        .unwrap();
    assert!(
        hostless
            .verify_proof(&app, &right.verify_covered(&[]).unwrap().0)
            .unwrap()
    );
    let mut invalid_host =
        Bundle::<ProofStamp<PublicationProof>>::try_from(TachyonBundle::from(left.clone()))
            .unwrap();
    invalid_host.stamp = hostless;
    assert!(matches!(
        invalid_host.verify(&app, &sighash, &[&stripped]),
        Err(VerificationError::Coverage(_))
    ));
    let restored = ProofStamp {
        proof: Box::new(resumed),
        ..merged
    };
    let quotient = restored
        .clone()
        .unmerge(
            rng,
            &app,
            (&right_actions, &all_fees),
            (right_work, right_id, &reversed, &right_fee),
        )
        .unwrap();
    for (working, adjuncts) in [(restored, vec![&stripped]), (quotient, vec![])] {
        assert_eq!(working.anchor, start);
        assert_eq!(working.adjuncts.contains(&right_id), !adjuncts.is_empty());
        let stamp = working.finalize(rng, &app).unwrap();
        let body = Bundle {
            actions: left.actions.clone(),
            action_auth: left.action_auth.clone(),
            fee: left.fee,
            fee_auth: left.fee_auth,
            binding_sig: left.binding_sig,
            value_balance: left.value_balance,
            memo: left.memo.clone(),
            stamp,
        };
        check_block(
            &app,
            &body,
            &left,
            &adjuncts,
            Anchor::from(Fp::from(99)),
            start,
        );
    }
}

fn check_wallet_admission(
    rng: &mut StdRng,
    app: &aggregator::App<'static>,
    mut host: Bundle<ProofStamp<PublicationProof>>,
    stripped: &Bundle<crate::StrippedStamp>,
) {
    let sighash = host.commitment();
    let wallet_host =
        Bundle::<ProofStamp<Compressed>>::try_from(TachyonBundle::from(host.clone())).unwrap();
    assert!(matches!(
        wallet_host.rehydrate(rng, app, &[0; 32], &[stripped]),
        Err(VerificationError::Signatures(_))
    ));
    assert!(matches!(
        wallet_host.rehydrate(rng, app, &sighash, &[]),
        Err(VerificationError::Coverage(_))
    ));
    let old = proof::historical::new_application().unwrap();
    for registry in [app.context().wallet(), &*old] {
        let unit = registry.bootstrap_proof().clone().carry::<()>(());
        *host.stamp.proof =
            PublicationProof::Wallet(registry.compress(&unit, &mut *rng).unwrap().into_parts().0);
        assert!(matches!(
            host.verify(app, &sighash, &[stripped]),
            Err(VerificationError::Disproved)
        ));
    }
}

fn check_block(
    app: &aggregator::App<'_>,
    body: &Bundle<ProofStamp<PublicationProof>>,
    left: &Bundle<ProofStamp<Compressed>>,
    adjuncts: &[&Bundle<crate::StrippedStamp>],
    start: Anchor,
    end: Anchor,
) {
    let mut bytes = Vec::new();
    body.write(&mut bytes).unwrap();
    assert_eq!(bytes[0], 3);
    bytes.push(0x7b);
    let mut reader = bytes.as_slice();
    let TachyonBundle::Proven(read) = TachyonBundle::read(&mut reader).unwrap() else {
        panic!("expected stamped block item")
    };
    assert_eq!(reader, [0x7b]);
    assert_eq!(read.auth_digest(), body.auth_digest());
    assert_eq!(read.commitment(), left.commitment());
    assert_eq!(read.binding_sig, left.binding_sig);
    assert_eq!(read.action_auth, left.action_auth);
    check_publication_frame(&read, 3, 14432, 1, 7296);
    check_trailer(
        &read.stamp,
        bundle::StateByte::AggregatorProofStamp,
        bundle::StateByte::ProofStamp,
        14432,
    );
    Bundle::<ProofStamp<Compressed>>::read(bytes.as_slice()).unwrap_err();
    let wallet_error: derive_more::TryIntoError<TachyonBundle> =
        Bundle::<ProofStamp<Compressed>>::try_from(TachyonBundle::from(read.clone())).unwrap_err();
    assert_eq!(wallet_error.input, TachyonBundle::from(read.clone()));
    let absent: derive_more::TryIntoError<TachyonBundle> =
        Bundle::<ProofStamp<Compressed>>::try_from(TachyonBundle::NoBundle).unwrap_err();
    assert_eq!(absent.input, TachyonBundle::NoBundle);
    read.verify(app, &left.commitment(), adjuncts).unwrap();
    let digests = read.verify_covered(adjuncts).unwrap().0;
    let repeated: Vec<_> = digests.iter().copied().chain([digests[0]]).collect();
    assert!(!read.stamp.verify_proof(app, &repeated).unwrap());
    let commit = ActionSetPoly::from_iter(digests).commit();
    let PublicationProof::Aggregator(compressed) = *read.stamp.proof else {
        panic!("expected aggregator frame")
    };
    assert!(aggregator::verify(app, &compressed, (commit, end)).unwrap());
    assert!(!aggregator::verify(app, &compressed, (commit, start)).unwrap());
}

fn check_publication_frame(
    host: &Bundle<ProofStamp<PublicationProof>>,
    tag: u8,
    size: usize,
    other_tag: u8,
    other: usize,
) {
    use corez::io::ErrorKind;
    use ragu::udon::{curve::Affine as _, field::Field as _};

    use crate::{CompactSize, digest::blake2b, stamp::StampState as _};
    let mut bytes = Vec::new();
    host.write(&mut bytes).unwrap();
    assert_eq!(bytes[0], tag);
    bytes.push(0x7b);
    let mut reader = bytes.as_slice();
    let mut round_trip = Vec::new();
    TachyonBundle::read(&mut reader)
        .unwrap()
        .write(&mut round_trip)
        .unwrap();
    assert_eq!(reader, [0x7b]);
    reader = bytes.as_slice();
    let submission = Bundle::<ProofStamp<PublicationProof>>::read(&mut reader).unwrap();
    assert_eq!(reader, [0x7b]);
    assert_eq!(submission, *host);
    bytes.pop();
    assert_eq!(round_trip, bytes);
    let offset = bytes.len() - size;
    let frame_hash = blake2b::stamp_proof_digest(
        Fp::from(host.stamp.anchor).to_bytes(),
        host.stamp.tachygram_set.as_ref().to_bytes(),
        &bytes[offset..],
    );
    let stamp_hash = blake2b::stamp_digest(
        &host.stamp.adjuncts.iter().copied().collect::<Vec<_>>(),
        &frame_hash,
    );
    assert_eq!(host.actions.len(), 0);
    let auth = |state| {
        blake2b::bundle_auth_digest(
            state,
            &[],
            host.fee.v_fee.into(),
            &Fp::from(host.fee_auth).to_bytes(),
            &host.binding_sig.0.into(),
            &stamp_hash,
        )
    };
    assert_eq!(host.stamp.stamp_digest(), stamp_hash);
    assert_eq!(host.auth_digest(), auth(tag));
    if tag == 3 {
        // Hold the frame, stamp digest and signed body fixed. Only the auth
        // half of this fixture's (txid, auth_digest) identifier changes.
        let txid = host.commitment();
        assert_ne!((txid, auth(1)), (txid, host.auth_digest()));
    }
    let mut truncated = bytes.clone();
    truncated.pop();
    assert_eq!(
        TachyonBundle::read(truncated.as_slice())
            .unwrap_err()
            .kind(),
        ErrorKind::UnexpectedEof
    );
    let mut bad = bytes.clone();
    bad[0] = other_tag;
    let mut block_reader = bad.as_slice();
    assert_eq!(
        TachyonBundle::read(&mut block_reader).unwrap_err().kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(block_reader, &bad[offset..]);
    let mut mixed_reader = bad.as_slice();
    assert_eq!(
        Bundle::<ProofStamp<PublicationProof>>::read(&mut mixed_reader)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(mixed_reader, &bad[offset..]);
    for index in [8, 10, 12] {
        // Ragu envelope version, kind, schema
        let mut changed = bytes.clone();
        changed[offset + index] ^= 1;
        TachyonBundle::read(changed.as_slice()).unwrap_err();
    }
    let mut swapped = bytes[..offset - 3].to_vec();
    CompactSize::try_from(other)
        .unwrap()
        .write(&mut swapped)
        .unwrap();
    swapped.extend_from_slice(&bytes[offset..]);
    swapped.resize(offset + other, 0);
    TachyonBundle::read(swapped.as_slice()).unwrap_err();
}

fn check_trailer(
    stamp: &ProofStamp<PublicationProof>,
    tag: bundle::StateByte,
    other: bundle::StateByte,
    frame_len: usize,
) {
    use corez::io::{self, ErrorKind};

    use crate::stamp::StampState;

    fn read_tagged<S: StampState>(tag: bundle::StateByte, reader: &mut &[u8]) -> io::Result<S> {
        S::read(tag, reader)
    }

    let saved = StampState::state_byte(stamp);
    assert_eq!(saved, tag);
    let mut bytes = Vec::new();
    stamp.write(&mut bytes).unwrap();
    bytes.push(0x7b);
    for trait_read in [false, true] {
        let read = |state, reader: &mut &[u8]| {
            if trait_read {
                read_tagged(state, reader)
            } else {
                ProofStamp::<PublicationProof>::read(state, reader)
            }
        };
        let mut reader = bytes.as_slice();
        let decoded = read(saved, &mut reader).unwrap();
        assert_eq!(reader, [0x7b]);
        assert_eq!(decoded.state_byte(), tag);
        let mut encoded = Vec::new();
        decoded.write(&mut encoded).unwrap();
        assert_eq!(encoded, &bytes[..bytes.len() - 1]);
        for invalid in [
            other,
            bundle::StateByte::NoBundle,
            bundle::StateByte::StrippedStamp,
        ] {
            reader = bytes.as_slice();
            assert_eq!(
                read(invalid, &mut reader).unwrap_err().kind(),
                ErrorKind::InvalidData
            );
            assert_eq!(
                reader.len(),
                if invalid == other {
                    frame_len + 1
                } else {
                    bytes.len()
                }
            );
        }
    }
}

fn receive_work(
    app: &aggregator::App<'_>,
    rng: &mut StdRng,
    frame: &[u8],
    expected: crate::ActionSetCommit,
    anchor: Anchor,
) -> Option<aggregator::Transaction> {
    type Frame = ragu::Proof<aggregator::Cycle, polynomials::AggregatorRank>;
    if frame.len() != Frame::encoded_len() {
        return None;
    }
    let bridge = app.bridge_hash(expected.into()).ok()?.into();
    let pcd = Frame::from_bytes(frame)
        .ok()?
        .carry::<proof::transaction::Transaction>((bridge, anchor));
    if pcd.commitments()[1] != expected.into() {
        return None;
    }
    let checked = app.compress(&pcd, rng).ok()?;
    app.verify_compressed(&checked).ok()?.then_some(pcd)
}
