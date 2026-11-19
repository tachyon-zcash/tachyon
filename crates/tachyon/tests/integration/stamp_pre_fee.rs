use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    BlockHeight,
    stamp::{ActionsPlan, proof::stamp::Actions},
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
    let other = ActionsPlan::new(
        vec![],
        vec![(second.descriptor(), second.theta, second.note, second.rcv)],
        to,
    )
    .prove(rng, app, vec![])
    .unwrap();
    let merged = lifted.merge(rng, app, other).unwrap();
    assert_eq!(merged.pairs.len(), 2);
    let pcd = merged.proof.carry::<Actions>(to);
    assert!(app.verify_uncompressed(&pcd, rng).unwrap());
}
