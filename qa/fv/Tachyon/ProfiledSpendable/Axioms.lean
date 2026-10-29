import Tachyon.ProfiledSpendable

/-! Axiom census for the profile-aware spendable phase. -/

/--
info: 'Tachyon.Profiled.RoutedQuery.complete' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Profiled.RoutedQuery.complete

/--
info: 'Tachyon.Profiled.SpendableDerivable.forget' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Profiled.SpendableDerivable.forget

/--
info: 'Tachyon.Profiled.SpendableDerivable.routed_lineage' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Profiled.SpendableDerivable.routed_lineage

/--
info: 'Tachyon.Profiled.no_double_spend_of_routed' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Profiled.no_double_spend_of_routed

/--
info: 'Tachyon.Profiled.routed_query_without_global_completeness' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Profiled.routed_query_without_global_completeness
