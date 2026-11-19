use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, BlockHeight, fee,
    stamp::{ActionsPlan, AutonomeParts, proof::stamp::Actions},
    value,
};

use super::fixtures::{
    application,
    pool::PoolSim,
    wallet::{WalletSim, output_plan, shared_sk},
};

#[test]
fn pre_fee_proofs_lift_and_merge_at_a_common_anchor() {
    let rng = &mut StdRng::seed_from_u64(13);
    let app = &application();
    let pool = PoolSim::shared();
    let span = pool.anchor_span(app, BlockHeight(1)..=BlockHeight(2));
    let from = pool.block(BlockHeight(1)).anchor();
    let to = pool.block(BlockHeight(2)).anchor();
    let wallet = WalletSim::new(shared_sk());
    let first = output_plan(rng, wallet.random_note(101));
    let second = output_plan(rng, wallet.random_note(102));
    let proof = ActionsPlan::new(
        vec![],
        vec![(first.descriptor(), first.theta, first.note, first.rcv)],
        from,
    )
    .prove(rng, app, vec![])
    .unwrap();
    let proved_pcd = proof.proof.clone().carry::<Actions>(from);
    assert!(app.verify_uncompressed(&proved_pcd, &mut *rng).unwrap());
    let lifted = proof.lift(rng, app, vec![span]).unwrap();
    assert_eq!(lifted.anchor, to);
    let lifted_pcd = lifted.proof.clone().carry::<Actions>(to);
    assert!(app.verify_uncompressed(&lifted_pcd, &mut *rng).unwrap());
    let max_fee = wallet.random_note(10);
    let lifted_parts = lifted
        .clone()
        .fee(rng, app, max_fee, value::Positive::ZERO)
        .unwrap();
    let other = ActionsPlan::new(
        vec![],
        vec![(second.descriptor(), second.theta, second.note, second.rcv)],
        to,
    )
    .prove(rng, app, vec![])
    .unwrap();
    let merged = lifted.merge(rng, app, other).unwrap();
    assert_eq!(merged.pairs.len(), 2);
    let before = merged
        .clone()
        .fee(rng, app, max_fee, value::Positive::ZERO)
        .unwrap();
    let chosen_fee = value::Positive::try_from(2u64).unwrap();
    let after = merged.clone().fee(rng, app, max_fee, chosen_fee).unwrap();
    assert_eq!(before.pairs, after.pairs);
    assert_eq!(after.fee, chosen_fee);
    for parts in [lifted_parts, before, after] {
        let descriptor = fee::Descriptor {
            cv_feemax: max_fee.cv_feemax(),
            v_fee: parts.fee,
        };
        let digests = parts
            .pairs
            .iter()
            .map(|(desc, pair)| desc.digest(*pair))
            .chain([descriptor.digest(parts.cm_change)]);
        assert!(parts.stamp.verify_proof(rng, app, digests).unwrap());
    }
    let pcd = merged.proof.carry::<Actions>(to);
    assert!(app.verify_uncompressed(&pcd, rng).unwrap());
}

#[test]
fn fee_seed_proves_an_actionless_stamp() {
    let rng = &mut StdRng::seed_from_u64(14);
    let app = &application();
    let wallet = WalletSim::new(shared_sk());
    let max_fee = wallet.random_note(0);
    let anchor = Anchor::random(rng);
    let parts = AutonomeParts::seed(rng, app, max_fee, anchor).unwrap();
    assert!(parts.pairs.is_empty());
    assert_eq!(parts.fee, value::Positive::ZERO);
    let descriptor = fee::Descriptor {
        cv_feemax: max_fee.cv_feemax(),
        v_fee: parts.fee,
    };
    assert!(
        parts
            .stamp
            .verify_proof(rng, app, [descriptor.digest(parts.cm_change)])
            .unwrap()
    );
}
