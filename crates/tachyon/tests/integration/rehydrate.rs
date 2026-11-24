use std::time::Instant;

use ragu::{
    Cycle as _, FixedGenerators as _, WalletRank,
    circuits::polynomials,
    pasta::{EpAffine, Fp, Pasta},
    pcd::{
        ipa::IpaCycle as _,
        profile::{Aggregator, Profiled, ProfiledCycle},
    },
    udon::{curve::Affine as _, field::Field as _},
};
use ragu_pcd::pasta::{baked as baked_wallet, baked_aggregator};
use rand::{SeedableRng as _, rngs::StdRng};
use transaction::{PublicTransaction, Transaction, TransactionDehydrate, TransactionRehydrate};
use zcash_tachyon::{
    ActionSetBridge, ActionSetPoly, Anchor, AnchorSetBridge, AnchorSetPoly, BlockHeight,
    EpochIndex, Note,
    keys::ProofAuthorizingKey,
    stamp::proof::{
        HEADER_SIZE, delegation, new_aggregator_application, new_application, pool, spend,
        spendable, transaction,
    },
    value, witness,
};

use super::{
    dehydrate::funded_output,
    fixtures::{
        pool::{PoolSim, random_block},
        wallet::{WalletSim, shared_sk},
    },
};

#[path = "../../src/stamp/proof/tests/registered_cost.rs"]
mod registered_cost;

// This fixture transports prefix roots; an empty sidecar encodes the unit
// prefix, whereas an absent sidecar supplies no witness. Bound before
// allocation.
fn prefix_roots(sidecar: Option<&[u8]>) -> Option<AnchorSetPoly> {
    use ragu::Rank as _;
    let bytes = sidecar?;
    if bytes.len() > (WalletRank::num_coeffs() - 2) * 32 || !bytes.len().is_multiple_of(32) {
        return None;
    }
    bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(|chunk| Anchor::read(chunk.as_slice()).ok())
        .collect()
}

#[test]
fn span_prefix_admission_bounds_the_full_members_degree() {
    assert!(prefix_roots(None).is_none());
    assert!(prefix_roots(Some(&[])).is_some());
    assert!(prefix_roots(Some(&[0; 31])).is_none());
    assert!(prefix_roots(Some(&[255; 32])).is_none());
    assert!(prefix_roots(Some(&vec![0; 8191 * 32])).is_none());
}

#[test]
fn aggregator_lifts_transactions_with_one_imported_span() {
    use pool::{AnchorSpan, AnchorSpanDehydrate, AnchorSpanRehydrate, PublicAnchorSpan};
    let rng = &mut StdRng::seed_from_u64(42);
    let start_config = Instant::now();
    let transaction = TransactionRehydrate::new().unwrap();
    let transaction_micros = start_config.elapsed().as_micros();
    let span_config = Instant::now();
    let step = AnchorSpanRehydrate::new().unwrap();
    eprintln!(
        "configuration: transaction {transaction_micros} us, span {} us",
        span_config.elapsed().as_micros()
    );
    let app = new_aggregator_application(rng).unwrap();
    let circuits = app.native_registry();
    let first = circuits.num_circuits() - 43;
    assert_eq!(
        [31, 32, 41, 42].map(|index| registered_cost::cost(circuits, first + index)),
        [(330, 675), (23, 50), (17, 47), (1407, 2830)]
    );
    let issuer = new_application().unwrap();
    let wallet = issuer.as_ref();
    let wallet_unit = wallet.bootstrap_proof().clone().carry::<()>(());
    let unit = app.bootstrap_proof().clone().carry::<()>(());
    let mut chain = PoolSim::genesis_with(random_block(rng, 1, 1));
    chain.advance(3, |_| random_block(rng, 2, 1));
    // One stamp per block, so each of the tested anchors is a block end.
    let [start, interior, end, next]: [Anchor; 4] = chain
        .anchors_in(BlockHeight(0)..=BlockHeight(3))
        .try_into()
        .unwrap();
    let outside = Anchor::from(Fp::from(42));
    let mut restored = Vec::new();
    for (range, predecessor, endpoint, roots) in [
        (BlockHeight(1)..=BlockHeight(2), start, end, vec![interior]),
        (BlockHeight(3)..=BlockHeight(3), end, next, vec![]),
    ] {
        let full = chain.anchor_span(wallet, range);
        let bytes: Vec<_> = roots
            .iter()
            .flat_map(|root| Fp::from(*root).to_bytes())
            .collect();
        let prefix = prefix_roots(Some(&bytes)).unwrap();
        let commitment = prefix.commit();
        let portable = AnchorSetBridge::from(wallet.bridge_hash(commitment.into()).unwrap());
        let local = AnchorSetBridge::from(app.bridge_hash(commitment.into()).unwrap());
        assert_ne!(portable, local);
        let fields = (predecessor, endpoint, portable);
        assert_eq!(full.data(), &fields);
        let started = Instant::now();
        let (public, ()) = wallet
            .fuse(rng, AnchorSpanDehydrate, (), full, wallet_unit.clone())
            .unwrap();
        let padding = wallet.commit(&[Fp::ONE]).unwrap();
        assert_eq!(public.commitments(), [padding; 2]);
        let refreshed = wallet.rerandomize(public.clone(), &mut *rng).unwrap();
        let publication = wallet.compress(&refreshed, &mut *rng).unwrap();
        assert_eq!(publication.proof().online_commitments(), [padding; 2]);
        assert!(wallet.verify_compressed(&publication).unwrap());
        let import_start = Instant::now();
        let input = app.decompress(rng, &publication).unwrap();
        let (span, ()) = app
            .fuse(
                rng,
                step.clone(),
                (prefix.clone(), commitment),
                input.clone(),
                unit.clone(),
            )
            .unwrap();
        eprintln!(
            "decompress + span rehydrate: {} ms",
            import_start.elapsed().as_millis()
        );
        eprintln!(
            "span crossing, {} links: {} ms",
            roots.len() + 1,
            started.elapsed().as_millis()
        );
        let members = AnchorSetPoly::from_iter(roots.iter().copied().chain([endpoint]));
        assert_eq!(
            span.commitments(),
            [members.commit().into(), commitment.into()]
        );
        assert_eq!(span.data(), &(predecessor, endpoint, local));
        assert!(
            app.verify_compressed(&app.compress(&span, &mut *rng).unwrap())
                .unwrap()
        );

        if !roots.is_empty() {
            let (same_rank, ()) = wallet
                .fuse(
                    rng,
                    step.clone(),
                    (prefix.clone(), commitment),
                    public,
                    wallet_unit.clone(),
                )
                .unwrap();
            assert!(!wallet.verify_uncompressed(&same_rank, &mut *rng).unwrap());
            let (wrong_issuer, ()) = app
                .fuse(rng, AnchorSpanDehydrate, (), span.clone(), unit.clone())
                .unwrap();
            assert!(
                !app.verify_compressed(&app.compress(&wrong_issuer, &mut *rng).unwrap())
                    .unwrap()
            );
            let frame = publication.into_parts().0;
            let (x, y) = EpAffine::from(portable).coordinates().unwrap();
            for other in [
                (outside, endpoint, portable),
                (predecessor, outside, portable),
                (
                    predecessor,
                    endpoint,
                    EpAffine::from_xy(x, -y).unwrap().into(),
                ),
                (
                    predecessor,
                    endpoint,
                    EpAffine::from_xy(x * Fp::ZETA, y).unwrap().into(),
                ),
            ] {
                assert!(
                    app.decompress(rng, &frame.clone().carry::<PublicAnchorSpan>(other))
                        .is_err()
                );
            }
            assert!(
                app.decompress(rng, &frame.carry::<AnchorSpan>(fields))
                    .is_err()
            );
            let replacement = AnchorSetPoly::from_iter([interior, interior]);
            let other_commit = replacement.commit();
            for witness in [
                (replacement.clone(), commitment),
                (replacement, other_commit),
                (prefix, other_commit),
            ] {
                let (wrong, ()) = app
                    .fuse(rng, step.clone(), witness, input.clone(), unit.clone())
                    .unwrap();
                assert!(
                    !app.verify_compressed(&app.compress(&wrong, &mut *rng).unwrap())
                        .unwrap()
                );
            }
        }
        restored.push(span);
    }

    let full_members = AnchorSetPoly::from_iter([interior, end, next]);
    let (joined, ()) = app
        .fuse(
            rng,
            pool::AnchorSpanFuse,
            (full_members.clone(),),
            restored[0].clone(),
            restored[1].clone(),
        )
        .unwrap();
    assert_eq!(joined.commitments()[0], full_members.commit().into());
    assert_eq!((joined.data().0, joined.data().1), (start, next));
    assert!(
        app.verify_compressed(&app.compress(&joined, &mut *rng).unwrap())
            .unwrap()
    );
    check_lifts(
        rng,
        &app,
        &transaction,
        &restored[0],
        &joined,
        [start, interior, end, next, outside],
    );
}

type AggregatorCycle = Profiled<Pasta, Aggregator<HEADER_SIZE>>;
type LocalSpan = ragu::Pcd<AggregatorCycle, polynomials::AggregatorRank, pool::AnchorSpan>;

fn spend_header<C: ProfiledCycle<Base = Pasta, CircuitField = Fp>, R: ragu::Rank>(
    app: &ragu::Application<'_, C, R, HEADER_SIZE, ragu::AcceleratedProver>,
    rng: &mut StdRng,
    note: Note,
    pak: ProofAuthorizingKey,
) -> ragu::Pcd<C, R, spend::SpendHeader> {
    let unit = app.bootstrap_proof().clone().carry::<()>(());
    let secret = app
        .seed(
            rng,
            delegation::NoteSeed,
            witness::note_seed(((), ()), note, pak),
        )
        .unwrap()
        .0;
    let epoch = EpochIndex::new(0);
    let window = app
        .fuse(
            rng,
            delegation::NullifierDerive,
            witness::nullifier_derive((*secret.data(), ()), epoch),
            secret.clone(),
            unit.clone(),
        )
        .unwrap()
        .0;
    let anchor = Anchor::from(Fp::from(11));
    let init = witness::spendable_init(
        (*window.data(), ()),
        anchor,
        &[note.commitment().into()],
        epoch,
    );
    let lineage = app
        .fuse(rng, spendable::SpendableInit, init, window, unit)
        .unwrap()
        .0;
    let blind = value::Trapdoor::random(rng);
    app.fuse(rng, spend::SpendBind, (blind,), lineage, secret)
        .unwrap()
        .0
}

#[test]
fn paired_app_imports_wallet_spend_headers_but_cannot_issue_them() {
    let rng = &mut StdRng::seed_from_u64(711);
    let app = new_aggregator_application(rng).unwrap();
    let wallet = new_application().unwrap();
    let owner = WalletSim::new(shared_sk());
    let note = owner.random_note(37);
    let issued = spend_header(&wallet, rng, note, owner.pak);
    let public = wallet.compress(&issued, &mut *rng).unwrap();
    let imported = app.decompress(rng, &public).unwrap();
    assert_eq!(imported.data().0, issued.data().0);
    assert_eq!(imported.data().3, issued.data().3);
    assert!(
        app.verify_compressed(&app.compress(&imported, &mut *rng).unwrap())
            .unwrap()
    );
    let foreign = spend_header(&app, rng, note, owner.pak);
    assert!(
        !app.verify_compressed(&app.compress(&foreign, &mut *rng).unwrap())
            .unwrap()
    );
}

fn check_lifts(
    rng: &mut StdRng,
    app: &ragu::Application<
        '_,
        AggregatorCycle,
        polynomials::AggregatorRank,
        HEADER_SIZE,
        ragu::AcceleratedProver,
    >,
    transaction: &TransactionRehydrate,
    span: &LocalSpan,
    joined: &LocalSpan,
    [start, interior, end, next, outside]: [Anchor; 5],
) {
    let owner = WalletSim::new(shared_sk());
    let wallet = app.context().wallet();
    let unit = app.bootstrap_proof().clone().carry::<()>(());
    for old in [start, interior, end, outside] {
        let bundle = funded_output(wallet, &owner, old);
        let (digests, _) = bundle.verify_covered(&[]).unwrap();
        let actions = ActionSetPoly::from_iter(digests);
        let commitment = actions.commit();
        let portable = wallet.bridge_hash(commitment.into()).unwrap().into();
        let finalized = bundle.stamp.finalize(rng, wallet).unwrap();
        let import_start = Instant::now();
        let imported = app
            .decompress(
                rng,
                &finalized.proof.carry::<PublicTransaction>((portable, old)),
            )
            .unwrap();
        let (working, ()) = app
            .fuse(
                rng,
                transaction.clone(),
                (actions.clone(), commitment),
                imported,
                unit.clone(),
            )
            .unwrap();
        eprintln!(
            "decompress + transaction rehydrate: {} ms",
            import_start.elapsed().as_millis()
        );
        let polys = working.polynomials();
        let (lifted, ()) = app
            .fuse(
                rng,
                transaction::TransactionLift,
                (actions.clone(),),
                working,
                span.clone(),
            )
            .unwrap();
        assert_eq!(
            app.verify_compressed(&app.compress(&lifted, &mut *rng).unwrap())
                .unwrap(),
            old != outside
        );
        assert_eq!(lifted.data().1, end);
        assert_eq!(lifted.polynomials(), polys);
        if old == interior {
            let (later, ()) = app
                .fuse(
                    rng,
                    transaction::TransactionLift,
                    (actions,),
                    lifted,
                    joined.clone(),
                )
                .unwrap();
            assert_eq!(later.data().1, next);
            assert!(
                app.verify_compressed(&app.compress(&later, &mut *rng).unwrap())
                    .unwrap()
            );
        }
    }
}

#[test]
fn aggregator_rehydrates_only_the_finalized_wallet_action_set() {
    let rng = &mut StdRng::seed_from_u64(40);
    let params = baked_aggregator();
    let baked = baked_wallet();
    let prefix = Pasta::host_generators(baked).g();
    assert_eq!(prefix, &Pasta::host_generators(params).g()[..prefix.len()]);
    for i in [3975, 8071, 16263, 32647] {
        assert_eq!(
            Pasta::nested_generator(baked, i),
            Some(Pasta::nested_generators(params).g()[i])
        );
    }
    let step = TransactionRehydrate::new().unwrap();
    let app = new_aggregator_application(rng).unwrap();
    // Issue on the ordinary baked wallet, independently of the wallet verifier
    // constructed with the aggregator's larger parameter object above.
    let issuer = new_application().unwrap();
    let wallet = issuer.as_ref();
    let anchor = Anchor::from(Fp::from(42));
    let bundle = funded_output(wallet, &WalletSim::new(shared_sk()), anchor);
    let (digests, _) = bundle.verify_covered(&[]).unwrap();
    let actions = ActionSetPoly::from_iter(digests.iter().copied());
    let coefficients: Vec<_> = actions
        .as_ref()
        .iter_coeffs()
        .take(digests.len() + 1)
        .collect();
    let commitment = actions.commit();
    assert_eq!(app.commit(&coefficients).unwrap(), commitment.into());
    let portable = ActionSetBridge::from(wallet.bridge_hash(commitment.into()).unwrap());
    let local = ActionSetBridge::from(app.bridge_hash(commitment.into()).unwrap());
    assert_ne!(portable, local);

    // An honestly compressed working proof is valid in W, but its online
    // action slot cannot substitute for the padding required at import.
    let working = bundle
        .stamp
        .proof
        .clone()
        .carry::<Transaction>((portable, anchor));
    let ordinary = wallet.compress(&working, &mut *rng).unwrap();
    assert!(wallet.verify_compressed(&ordinary).unwrap());
    assert!(app.decompress(rng, &ordinary).is_err());
    let disguised = ordinary
        .into_parts()
        .0
        .carry::<PublicTransaction>((portable, anchor));
    assert!(app.decompress(rng, &disguised).is_err());

    let finalized = bundle.stamp.finalize(rng, wallet).unwrap();
    let fields = (portable, finalized.anchor);
    let publication = finalized.proof.clone().carry::<PublicTransaction>(fields);
    assert!(
        app.context()
            .wallet()
            .verify_compressed(&publication)
            .unwrap()
    );
    let input = app.decompress(rng, &publication).unwrap();
    assert_eq!(input.data(), &fields);
    // Import verifies the padded source header, not merely the proof bytes.
    let other_anchor = Anchor::from(Fp::from(43));
    let (x, y) = EpAffine::from(portable).coordinates().unwrap();
    let other_bridge = ActionSetBridge::from(EpAffine::from_xy(x, -y).unwrap());
    for other in [(portable, other_anchor), (other_bridge, anchor)] {
        assert!(
            app.decompress(
                rng,
                &finalized.proof.clone().carry::<PublicTransaction>(other)
            )
            .is_err()
        );
    }
    assert!(
        app.decompress(rng, &finalized.proof.carry::<Transaction>(fields))
            .is_err()
    );

    let unit = app.bootstrap_proof().clone().carry::<()>(());
    let (restored, ()) = app
        .fuse(
            rng,
            step.clone(),
            (actions.clone(), commitment),
            input.clone(),
            unit.clone(),
        )
        .unwrap();
    assert_eq!(restored.polynomials(), [vec![Fp::ONE], coefficients]);
    assert_eq!(restored.commitments()[1], commitment.into());
    assert_eq!(restored.data(), &(local, anchor));
    let candidate = app.compress(&restored, &mut *rng).unwrap().into_parts().0;
    let claimed = |data| candidate.clone().carry::<Transaction>(data);
    assert!(app.verify_compressed(&claimed((local, anchor))).unwrap());
    assert!(
        !app.verify_compressed(&claimed((local, other_anchor)))
            .unwrap()
    );
    assert!(!app.verify_compressed(&claimed((portable, anchor))).unwrap());

    // Step 39's wallet padding check also excludes local aggregator issuance.
    let (reissued, ()) = app
        .fuse(rng, TransactionDehydrate, (), restored, unit.clone())
        .unwrap();
    assert!(
        !app.verify_compressed(&app.compress(&reissued, &mut *rng).unwrap())
            .unwrap()
    );

    // Keep the roots but repeat one: root membership cannot detect this change.
    let replacement = ActionSetPoly::from_iter(digests.iter().copied().chain([digests[0]]));
    let other = replacement.commit();
    assert_ne!(other, commitment);
    for witness in [
        (replacement.clone(), commitment),
        (replacement, other),
        (actions, other),
    ] {
        let (wrong, ()) = app
            .fuse(rng, step.clone(), witness, input.clone(), unit.clone())
            .unwrap();
        let compressed = app.compress(&wrong, &mut *rng).unwrap();
        assert!(!app.verify_compressed(&compressed).unwrap());
    }
}
