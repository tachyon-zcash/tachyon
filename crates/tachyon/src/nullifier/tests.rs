use super::*;

#[test]
fn debug_nullifier_trapdoor_redacts_value() {
    let psi = Trapdoor::from(Fp::from(0xCAFEu64));
    let dbg = alloc::format!("{psi:?}");
    assert!(dbg.contains("Trapdoor"));
    assert!(!dbg.contains("CAFE"));
    assert!(!dbg.contains("51966"));
}
