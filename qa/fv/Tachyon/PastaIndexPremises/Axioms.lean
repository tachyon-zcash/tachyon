import Tachyon.PastaIndexPremises

/-! The concrete modular exponent is kernel-checked, not a native-decide axiom.
Primality remains an explicit theorem argument for the two field statements. -/

/--
info: 'Tachyon.PastaIndexPremises.two_power_witness' depends on axioms: [propext, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.PastaIndexPremises.two_power_witness

/--
info: 'Tachyon.PastaIndexPremises.two_noncube' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.PastaIndexPremises.two_noncube

/--
info: 'Tachyon.PastaIndexPremises.indexed_division' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.PastaIndexPremises.indexed_division
