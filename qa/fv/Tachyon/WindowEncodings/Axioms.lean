import Tachyon.WindowEncodings

/-! Census for canonical field-limb matching and the accounting adapters. -/

/-- info: 'Tachyon.WindowEncodings.hash_match' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.WindowEncodings.hash_match

/-- info: 'Tachyon.StepBudget.outputDigestOpening' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.StepBudget.outputDigestOpening

/-- info: 'Tachyon.StepBudget.spendDigestOpening' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.StepBudget.spendDigestOpening

/-- info: 'Tachyon.StepBudget.feeDigestOpening' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.StepBudget.feeDigestOpening
