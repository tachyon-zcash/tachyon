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
info: 'Tachyon.StampTrace.spec' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.StampTrace.spec

/--
info: 'Tachyon.StampTrace.findLeaf' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.StampTrace.findLeaf

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
info: 'Tachyon.BundleVerified.no_double_spend' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.BundleVerified.no_double_spend

/--
info: 'Tachyon.no_double_spend_of_bundles' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.no_double_spend_of_bundles

/--
info: 'Tachyon.no_double_spend_of_spendable' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.no_double_spend_of_spendable

/--
info: 'Tachyon.SpendableDerivable.lineage' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SpendableDerivable.lineage

/--
info: 'Tachyon.spendableInit_cannot_lift' depends on axioms: [propext, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.spendableInit_cannot_lift

/--
info: 'Tachyon.ActionsDerivable.liftStep' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.ActionsDerivable.liftStep

/--
info: 'Tachyon.StampDerivable.liftStep' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.StampDerivable.liftStep

/--
info: 'Tachyon.card_product_check_le' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.card_product_check_le

/--
info: 'Tachyon.card_roots_check_le' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.card_roots_check_le

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

/--
info: 'Tachyon.SpendableDerivable.anchor_epoch' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SpendableDerivable.anchor_epoch

/--
info: 'Tachyon.SpendableDerivable.spend_pair' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SpendableDerivable.spend_pair

/--
info: 'Tachyon.no_double_spend_of_spend_binding' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.no_double_spend_of_spend_binding

/--
info: 'Tachyon.no_double_spend_of_routed_spend_binding' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.no_double_spend_of_routed_spend_binding
