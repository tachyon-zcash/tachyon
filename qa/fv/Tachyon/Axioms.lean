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
info: 'Tachyon.ActionsDerivable.liftOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.ActionsDerivable.liftOrBreak

/--
info: 'Tachyon.StampDerivable.liftOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.StampDerivable.liftOrBreak

/--
info: 'Tachyon.StampDerivable.lift_of_no_collisions' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.StampDerivable.lift_of_no_collisions

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
info: 'Tachyon.SpendableTrace.anchorEpochOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SpendableTrace.anchorEpochOrBreak

/--
info: 'Tachyon.SpendableTrace.spendPairOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SpendableTrace.spendPairOrBreak

/--
info: 'Tachyon.SpendableTrace.lineageOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SpendableTrace.lineageOrBreak

/--
info: 'Tachyon.StampTrace.positiveNodes_fst' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.StampTrace.positiveNodes_fst

/--
info: 'Tachyon.doubleSpendBreakOfTraces' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.doubleSpendBreakOfTraces

/--
info: 'Tachyon.noteAccountingOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.noteAccountingOrBreak

/--
info: 'Tachyon.doubleSpendBreakOrLaterStart' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.doubleSpendBreakOrLaterStart

/--
info: 'Tachyon.sameStartBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.sameStartBreak

/--
info: 'Tachyon.later_start_of_no_collisions' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.later_start_of_no_collisions

/--
info: 'Tachyon.publishedNoteOrCollision' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.publishedNoteOrCollision

/--
info: 'Tachyon.creationOrCollision' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.creationOrCollision

/--
info: 'Tachyon.sharedCreationBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.sharedCreationBreak

/--
info: 'Tachyon.Creation.debitOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Creation.debitOrBreak

/--
info: 'Tachyon.SpendableTrace.startPublishedOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SpendableTrace.startPublishedOrBreak

/--
info: 'Tachyon.distinctCreationsOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.distinctCreationsOrBreak

/--
info: 'Tachyon.sameBundleDistinctCreationsOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.sameBundleDistinctCreationsOrBreak

/--
info: 'Tachyon.TracedBundle.accountingOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.TracedBundle.accountingOrBreak

/--
info: 'Tachyon.TracedBundle.balanceOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.TracedBundle.balanceOrBreak

/--
info: 'Tachyon.spendsUnsharedOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.spendsUnsharedOrBreak

/--
info: 'Tachyon.ChainSpend.creditOrCollision' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.ChainSpend.creditOrCollision

/--
info: 'Tachyon.doubleSpendBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.doubleSpendBreak

/--
info: 'Tachyon.no_double_spend_of_no_collisions' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.no_double_spend_of_no_collisions

/--
info: 'Tachyon.balanceOrRelation' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.balanceOrRelation

/--
info: 'Tachyon.intBalanceOrRelation' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.intBalanceOrRelation

/--
info: 'Tachyon.feeAccountingOrRelation' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.feeAccountingOrRelation

/--
info: 'Tachyon.NontrivialDLRelation.ofPolyCollision' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.NontrivialDLRelation.ofPolyCollision

/--
info: 'Tachyon.StampDerivable.unmerge_generated' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.StampDerivable.unmerge_generated

/--
info: 'Tachyon.unmerge_through_hidden' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.unmerge_through_hidden
