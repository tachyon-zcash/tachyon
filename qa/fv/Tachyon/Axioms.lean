import Tachyon

/-!
# Axiom census

The headline theorems depend only on Lean's standard axioms, and in particular on no `sorryAx`.
-/

/--
info: 'Tachyon.Derivable.leafGenerated' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Derivable.leafGenerated

/--
info: 'Tachyon.Derivable.published' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Derivable.published

/--
info: 'Tachyon.unmerge_needs_pairing' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.unmerge_needs_pairing

/--
info: 'Tachyon.BundleVerified.tachygrams_eq' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.BundleVerified.tachygrams_eq

/--
info: 'Tachyon.BundleVerified.leaves_disjoint' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.BundleVerified.leaves_disjoint
