import Tachyon.SpanTraces

/-!
The scope/predecessor decoder uses only `propext`. Span certificates additionally
carry the existing Mathlib polynomial specification proofs, whose axiom set
includes choice and quotient soundness. No reducer selects trace/break data
classically, and every reducer compiles as a computable definition.
-/

/-- info: 'Tachyon.AnchorBreaks.scopedPredecessorOrBreak' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.scopedPredecessorOrBreak

/--
info: 'Tachyon.AnchorBreaks.spanBoundOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.spanBoundOrBreak

/--
info: 'Tachyon.AnchorBreaks.liftNodeOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.liftNodeOrBreak

/--
info: 'Tachyon.AnchorBreaks.liftNodeOfNoCollisions' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.liftNodeOfNoCollisions
