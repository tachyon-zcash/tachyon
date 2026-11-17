import Tachyon.AnchorBreakComposition

/-! Core classification is axiom-free; query and polynomial specializations
inherit only the existing mathematical infrastructure's standard axioms. -/

/-- info: 'Tachyon.AnchorBreaks.ScopedBreak.refineComposition' does not depend on any axioms -/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.ScopedBreak.refineComposition

/-- info: 'Tachyon.AnchorBreaks.ScopedBreak.forget_refineComposition' does not depend on any axioms -/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.ScopedBreak.forget_refineComposition

/-- info: 'Tachyon.SourceQueryBreaks.ObservedBreak.refineComposition' does not depend on any axioms -/
#guard_msgs in
#print axioms Tachyon.SourceQueryBreaks.ObservedBreak.refineComposition

/-- info: 'Tachyon.SourceQueryBreaks.ObservedBreak.forget_refineComposition' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Tachyon.SourceQueryBreaks.ObservedBreak.forget_refineComposition

/-- info: 'Tachyon.SourceQueryBreaks.Certificate.primitiveOutcome' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.SourceQueryBreaks.Certificate.primitiveOutcome

/-- info: 'Tachyon.SourceQueryBreaks.Certificate.forget_primitiveOutcome' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms Tachyon.SourceQueryBreaks.Certificate.forget_primitiveOutcome

/-- info: 'Tachyon.AnchorBreaks.ScopedPrimitiveBreak.toPolyBreak' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.AnchorBreaks.ScopedPrimitiveBreak.toPolyBreak

/-- info: 'Tachyon.AnchorBreaks.ScopedPrimitiveBreak.forget_toPolyBreak' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms Tachyon.AnchorBreaks.ScopedPrimitiveBreak.forget_toPolyBreak

/-- info: 'Tachyon.SourceQueryBreaks.ObservedBreak.polyRefine' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.SourceQueryBreaks.ObservedBreak.polyRefine

/-- info: 'Tachyon.SourceQueryBreaks.ObservedBreak.forget_polyRefine' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.SourceQueryBreaks.ObservedBreak.forget_polyRefine

/-- info: 'Tachyon.SourceQueryBreaks.Certificate.polyOutcome' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.SourceQueryBreaks.Certificate.polyOutcome

/-- info: 'Tachyon.SourceQueryBreaks.Certificate.forget_polyOutcome' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Tachyon.SourceQueryBreaks.Certificate.forget_polyOutcome
