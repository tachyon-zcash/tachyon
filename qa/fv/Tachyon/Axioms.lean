import Tachyon
import Tachyon.Meta.AxiomBudget

/-!
# Axiom census

Every declaration of every `Tachyon` module depends only on Lean's standard axioms, and in
particular on no `sorryAx` (`#check_axiom_budget`, which also checks that every module under
`Tachyon/` is imported). The headline theorems below are pinned to their exact axiom sets.
-/

#check_axiom_budget Tachyon.ActionsDerivable.leafGenerated Tachyon.ActionsDerivable.feeFuse_leaves
  Tachyon.StampDerivable.leafGenerated Tachyon.StampDerivable.published Tachyon.unmerge_strips_fee
  Tachyon.StampTrace.spec Tachyon.StampTrace.findLeaf Tachyon.BundleVerified.fee_published
  Tachyon.BundleVerified.fee_change_published Tachyon.unmerge_needs_pairing
  Tachyon.BundleVerified.tachygrams_eq Tachyon.BundleVerified.leaves_disjoint Tachyon.no_double_spend
  Tachyon.no_double_spend_of_valid Tachyon.SpendDerivable.pair Tachyon.StampTree.leaves_node
  Tachyon.StampTree.derivable Tachyon.no_double_spend_of_covered_spends
  Tachyon.no_double_spend_in_stamp Tachyon.QrBucketDerivable.covers Tachyon.QrBucket.Covers.onChain
  Tachyon.NoteUnspentDerivable.lineage Tachyon.SpendDerivable.lineage Tachyon.Chain.Node.epoch_unique
  Tachyon.Chain.StampLiftStep.epoch_eq Tachyon.Chain.Valid.disjoint_of_window
  Tachyon.Chain.Valid.nodup_two_epochs Tachyon.StampTree.fee_leaf Tachyon.CoveredSpend.fee_leaf
  Tachyon.cubicMember_law Tachyon.Instances.rust_memberLaw

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
info: 'Tachyon.BundleVerified.fee_change_published' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.BundleVerified.fee_change_published

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
info: 'Tachyon.SpendDerivable.pair' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SpendDerivable.pair

/--
info: 'Tachyon.StampTree.leaves_node' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.StampTree.leaves_node

/--
info: 'Tachyon.StampTree.derivable' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.StampTree.derivable

/--
info: 'Tachyon.no_double_spend_of_covered_spends' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.no_double_spend_of_covered_spends

/--
info: 'Tachyon.no_double_spend_in_stamp' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.no_double_spend_in_stamp

/--
info: 'Tachyon.QrBucketDerivable.covers' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.QrBucketDerivable.covers

/--
info: 'Tachyon.QrBucket.Covers.onChain' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.QrBucket.Covers.onChain

/--
info: 'Tachyon.NoteUnspentDerivable.lineage' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.NoteUnspentDerivable.lineage

/--
info: 'Tachyon.SpendDerivable.lineage' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SpendDerivable.lineage

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
info: 'Tachyon.StampTree.fee_leaf' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.StampTree.fee_leaf

/--
info: 'Tachyon.CoveredSpend.fee_leaf' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.CoveredSpend.fee_leaf

/--
info: 'Tachyon.cubicMember_law' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.cubicMember_law

/--
info: 'Tachyon.Instances.rust_memberLaw' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Instances.rust_memberLaw
