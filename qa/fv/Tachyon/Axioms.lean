import Tachyon

/-!
# Axiom census

The headline theorems depend only on Lean's standard axioms, and in particular on no `sorryAx`.
-/

/--
info: 'Tachyon.ActionsDerivable.leafGenerated' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.ActionsDerivable.leafGenerated

/--
info: 'Tachyon.ActionsDerivable.feeFuse_leaves' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.ActionsDerivable.feeFuse_leaves

/--
info: 'Tachyon.StampDerivable.leafGenerated' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.StampDerivable.leafGenerated

/--
info: 'Tachyon.StampDerivable.published' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.StampDerivable.published

/--
info: 'Tachyon.unmerge_strips_fee' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.unmerge_strips_fee

/--
info: 'Tachyon.BundleVerified.fee_published' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.BundleVerified.fee_published

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

/--
info: 'Tachyon.no_double_spend' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.no_double_spend

/--
info: 'Tachyon.no_double_spend_of_valid' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.no_double_spend_of_valid

/--
info: 'Tachyon.Chain.Node.epoch_unique' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Chain.Node.epoch_unique

/--
info: 'Tachyon.Chain.StampLiftStep.epoch_eq' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Chain.StampLiftStep.epoch_eq

/--
info: 'Tachyon.Chain.Valid.disjoint_of_window' depends on axioms: [propext, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Chain.Valid.disjoint_of_window

/--
info: 'Tachyon.Chain.Valid.nodup_two_epochs' depends on axioms: [propext, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Chain.Valid.nodup_two_epochs
