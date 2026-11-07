import Tachyon.Qr

/-! Axiom census for the independently reviewable QR routing phase. -/

/--
info: 'Tachyon.Qr.SideCheck.retains' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Qr.SideCheck.retains

/--
info: 'Tachyon.Qr.Route.retains' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Qr.Route.retains

/--
info: 'Tachyon.Qr.Route.not_published' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Qr.Route.not_published

/--
info: 'Tachyon.Qr.exceptional_guard_needed' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Qr.exceptional_guard_needed

/--
info: 'Tachyon.Qr.split_without_selection' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Qr.split_without_selection
