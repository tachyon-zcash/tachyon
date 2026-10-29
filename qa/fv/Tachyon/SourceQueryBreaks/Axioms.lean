import Tachyon.SourceQueryBreaks

/-!
The publication/source polynomial specifications use standard Mathlib axioms.
The reductions do not select trace or collision data from classical existence.
Both `PublicationTrace.run` and `queryCompleteOrBreak` compile as ordinary defs.
-/

/--
info: 'Tachyon.SourceQueryBreaks.PublicationTrace.source_spec' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SourceQueryBreaks.PublicationTrace.source_spec

/--
info: 'Tachyon.SourceQueryBreaks.queryCompleteOrBreak' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SourceQueryBreaks.queryCompleteOrBreak

/--
info: 'Tachyon.SourceQueryBreaks.query_complete_of_no_collisions' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.SourceQueryBreaks.query_complete_of_no_collisions
