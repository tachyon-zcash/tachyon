import Tachyon.AnchorBreaks

/-! Computed collision reductions use no `Classical.choice` or `sorryAx`. -/

/-- info: 'Tachyon.AnchorBreaks.hashEqOrBreak' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.hashEqOrBreak

/-- info: 'Tachyon.AnchorBreaks.stampEqOrBreak' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.stampEqOrBreak

/-- info: 'Tachyon.AnchorBreaks.epochEqOrBreak' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.epochEqOrBreak

/-- info: 'Tachyon.AnchorBreaks.stamp_eq_of_no_collisions' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.stamp_eq_of_no_collisions
