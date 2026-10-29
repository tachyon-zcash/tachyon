import Tachyon.RoutedIntakes

/-! Axiom census for routing/merge composition. -/

/--
info: 'Tachyon.RoutedIntakes.Derivable.retains' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.RoutedIntakes.Derivable.retains

/--
info: 'Tachyon.RoutedIntakes.CheckedIntake.complete' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.RoutedIntakes.CheckedIntake.complete

/--
info: 'Tachyon.RoutedIntakes.lineage_of_checked_intakes' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.RoutedIntakes.lineage_of_checked_intakes
