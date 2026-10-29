import Tachyon.SourceSealing

/-! Axiom census for source chain sealing. -/

/--
info: 'Tachyon.SourceSealing.Run.unique_from_boundaries' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SourceSealing.Run.unique_from_boundaries

/--
info: 'Tachyon.SourceSealing.Run.sealed_source_eq' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SourceSealing.Run.sealed_source_eq

/--
info: 'Tachyon.SourceSealing.sealed_empty_no_publication' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SourceSealing.sealed_empty_no_publication

/--
info: 'Tachyon.SourceSealing.RootIntakeDerivable.routedQuery' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SourceSealing.RootIntakeDerivable.routedQuery
