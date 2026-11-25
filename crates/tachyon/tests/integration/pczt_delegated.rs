use core::{convert::Infallible, error::Error};

use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{Anchor, BlockHeight, entropy::ActionEntropy, pasta::Fp, pczt, value};

use super::fixtures::{
    application, mock_sighash,
    pool::PoolSim,
    wallet::{WalletSim, other_sk, shared_sk},
};

#[test]
fn pczt_delegated_provers_merge_spends_from_two_owners() {
    let rng = &mut StdRng::seed_from_u64(42);
    let app = &application();
    let alice = WalletSim::new(shared_sk());
    let bob = WalletSim::new(other_sk());
    let alice_note = alice.random_note(700);
    let bob_note = bob.random_note(800);
    let mut pool = PoolSim::genesis_with(vec![]);
    pool.mine(vec![vec![
        alice_note.commitment().into(),
        bob_note.commitment().into(),
    ]]);
    pool.mine(vec![vec![alice.random_note(1).commitment().into()]]);
    let span = pool.anchor_span(app, BlockHeight(2)..=BlockHeight(2));
    let later = span.data().1;
    let opening = |note, ak, entropy: &mut StdRng| {
        (
            note,
            ActionEntropy::random(entropy),
            value::Trapdoor::random(entropy),
            ak,
        )
    };
    let plan = pczt::Plan::new(
        vec![
            opening(alice_note, alice.pak.ak, rng),
            opening(bob_note, bob.pak.ak, rng),
        ],
        vec![],
        alice.random_note(10),
        vec![],
    )
    .unwrap();
    let mut section = pczt::Bundle::from_plan(&plan);
    let sighash = mock_sighash(plan.effects().commitment());
    section.finalize_io(sighash, rng).unwrap();
    let mut contributions = Vec::new();
    for (wallet, note) in [(&alice, alice_note), (&bob, bob_note)] {
        let pk = Fp::from(note.pk);
        let index = section
            .actions()
            .iter()
            .position(|action| action.note().pk().is_some_and(|key| Fp::from(key) == pk))
            .unwrap();
        let ask = wallet.sk.derive_auth_private();
        section.sign_at(index, sighash, &ask, rng).unwrap();
        let mut delegate = pczt::Bundle::from_plan(&plan);
        let spendable = wallet.spendable_init(app, &pool, &note, BlockHeight(1));
        delegate
            .update_with(|mut updater| -> Result<(), Box<dyn Error>> {
                updater.set_anchor(spendable.data().2);
                updater.set_pak(index, wallet.pak)?;
                updater.set_lineage(
                    index,
                    pczt::SpendLineage::new(wallet.note_secret(app, note), spendable, vec![]),
                )?;
                Ok(())
            })
            .unwrap();
        delegate.prove_actions(rng, app, &[index]).unwrap();
        assert_eq!(delegate.actions_proofs()[0].pairs.len(), 1);
        delegate
            .lift_actions_proof(0, rng, app, vec![span.clone()])
            .unwrap();
        assert_eq!(delegate.actions_proofs()[0].anchor, later);
        contributions.push(delegate);
    }
    for contribution in contributions {
        section = section.combine(contribution).unwrap();
    }
    assert_eq!(section.actions_proofs().len(), 2);
    section
        .apply_fee(rng, app, value::Positive::try_from(2u64).unwrap())
        .unwrap();
    assert_eq!(section.actions_proofs().len(), 1);
    let pairs = section.actions_proofs()[0].pairs.clone();
    assert_eq!(pairs.len(), 2);
    let new_fee = value::Positive::try_from(3u64).unwrap();
    section.apply_fee(rng, app, new_fee).unwrap();
    assert_eq!(section.actions_proofs()[0].pairs, pairs);
    assert_eq!(section.autonome_parts().unwrap().fee, new_fee);
    section
        .extract()
        .unwrap()
        .apply_binding_signature(sighash, rng)
        .verify(rng, app, &sighash, &[])
        .unwrap();
}

#[test]
fn pczt_present_actionless_section_needs_stamp() {
    let rng = &mut StdRng::seed_from_u64(37);
    let app = &application();
    let wallet = WalletSim::new(shared_sk());
    let plan = pczt::Plan::new(vec![], vec![], wallet.random_note(0), vec![]).unwrap();
    let mut section = pczt::Bundle::from_plan(&plan);
    let sighash = mock_sighash(section.effects().commitment());
    section.finalize_io(sighash, rng).unwrap();
    assert_eq!(
        section.clone().extract().unwrap_err(),
        pczt::TxExtractorError::Missing(pczt::ExtractionField::AutonomeParts),
    );
    section
        .update_with(|mut updater| {
            updater.set_anchor(Anchor::random(rng));
            Ok::<_, Infallible>(())
        })
        .unwrap();
    section.apply_fee(rng, app, value::Positive::ZERO).unwrap();
    let encoded = section.to_mirror();
    let parsed = pczt::Bundle::parse(encoded.clone()).unwrap();
    assert_eq!(parsed.to_mirror(), encoded);
    parsed
        .extract()
        .unwrap()
        .apply_binding_signature(sighash, rng)
        .verify(rng, app, &sighash, &[])
        .unwrap();
}
