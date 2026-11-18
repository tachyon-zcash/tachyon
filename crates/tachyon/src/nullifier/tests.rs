use super::*;

#[test]
fn debug_nullifier_trapdoor_redacts_value() {
    let psi = Trapdoor::from(Fp::from(0xcafeu64));
    assert_eq!(alloc::format!("{psi:?}"), "Trapdoor(..)");
}
