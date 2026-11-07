import Tachyon.FixedBase

/-! Axiom census for the fixed-base graph. No certificate or multiplication axiom. -/

/-- info: 'Tachyon.FixedBase.Accepted.invariant' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.FixedBase.Accepted.invariant

/-- info: 'Tachyon.FixedBase.Accepted.product' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.FixedBase.Accepted.product

/-- info: 'Tachyon.FixedBase.Accepted.complete' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.FixedBase.Accepted.complete

/-- info: 'Tachyon.FixedBase.consumer_refinement' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.FixedBase.consumer_refinement

/-- info: 'Tachyon.FixedBase.amount_product' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Tachyon.FixedBase.amount_product
