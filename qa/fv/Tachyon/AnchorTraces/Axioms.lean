import Tachyon.AnchorTraces

/-! Computed chain reductions retain the no-classical-choice guarantee. -/

/-- info: 'Tachyon.AnchorBreaks.nodeEpochOrBreak' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.nodeEpochOrBreak

/-- info: 'Tachyon.AnchorBreaks.stampPredecessorOrBreak' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.stampPredecessorOrBreak

/-- info: 'Tachyon.AnchorBreaks.node_epoch_eq_of_no_collisions' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.node_epoch_eq_of_no_collisions
