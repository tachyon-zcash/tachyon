import Tachyon.StepBudget

/-! Guard the complete accepted-path and bundle refinements against new axioms. -/

/-- info: 'Tachyon.StepBudget.accepted_refinement' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.StepBudget.accepted_refinement

/-- info: 'Tachyon.StepBudget.stamp_refinement' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.StepBudget.stamp_refinement

/-- info: 'Tachyon.StepBudget.bundle_through_refinement' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.StepBudget.bundle_through_refinement
