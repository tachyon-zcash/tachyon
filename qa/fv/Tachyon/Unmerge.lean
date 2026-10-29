import Tachyon.Stamp

/-!
# Unmerge soundness

`StampUnmerge` checks each column independently. Per column, exact division of set polynomials
places the divisor's roots inside the dividend's and pins the quotient to their difference
(`Unmerge.columns`). The quotient is leaf-generated only because both columns come from one leaf
multiset under a single pairing `R` (`Unmerge.generatedBy`). Without that pairing, division can
assemble a leaf no proof derived (`unmerge_needs_pairing`).
-/

namespace Tachyon

variable {F A : Type*} [Field F] [DecidableEq F]

theorem Unmerge.columns {R : F → Multiset F} {dividend divisor quotient : Stamp F A}
    {D D' : Multiset F} (h : Unmerge dividend divisor quotient)
    (hdividend : GeneratedBy R D dividend) (hdivisor : GeneratedBy R D' divisor) :
    D' ≤ D ∧ quotient.actions = setPoly (D - D') ∧
      D'.bind R ≤ D.bind R ∧ quotient.tachygrams = setPoly (D.bind R - D'.bind R) := by
  obtain ⟨hda, hdt⟩ := hdividend
  obtain ⟨hra, hrt⟩ := hdivisor
  obtain ⟨hle, ha⟩ := setPoly_mul_eq (hra ▸ hda ▸ h.actions)
  obtain ⟨hlet, ht⟩ := setPoly_mul_eq (hrt ▸ hdt ▸ h.tachygrams)
  exact ⟨hle, ha, hlet, ht⟩

theorem Unmerge.generatedBy {R : F → Multiset F} {dividend divisor quotient : Stamp F A}
    {D D' : Multiset F} (h : Unmerge dividend divisor quotient)
    (hdividend : GeneratedBy R D dividend) (hdivisor : GeneratedBy R D' divisor) :
    GeneratedBy R (D - D') quotient := by
  obtain ⟨hle, ha, -, ht⟩ := h.columns hdividend hdivisor
  have hbind : D.bind R = D'.bind R + (D - D').bind R := by
    rw [← Multiset.add_bind, add_tsub_cancel_of_le hle]
  exact ⟨ha, by rw [ht, hbind, add_tsub_cancel_left]⟩

/-- Unmerge is unsound when two leaves share a digest but derive different tachygrams. The leaves
`(0, {2})`, `(1, {3})` and `(0, {3})` are each derived by some proof. Dividing the merge of the first
two by the third passes both column checks, and the quotient is the leaf `(1, {2})`, which is not a
combination of derived leaves. -/
theorem unmerge_needs_pairing :
    let derived : Multiset (ℚ × Multiset ℚ) := {(0, {2}), (1, {3}), (0, {3})}
    ∃ dividend divisor quotient : Stamp ℚ Unit,
      Unmerge dividend divisor quotient ∧
      dividend.actions = setPoly {0, 1} ∧ dividend.tachygrams = setPoly ({2} + {3}) ∧
      divisor.actions = setPoly {0} ∧ divisor.tachygrams = setPoly {3} ∧
      ∀ L : Multiset (ℚ × Multiset ℚ), (∀ l ∈ L, l ∈ derived) →
        ¬ (quotient.actions = setPoly (L.map Prod.fst) ∧
          quotient.tachygrams = setPoly (L.bind Prod.snd)) := by
  intro derived
  refine ⟨⟨setPoly {0, 1}, setPoly ({2} + {3}), ()⟩, ⟨setPoly {0}, setPoly {3}, ()⟩,
    ⟨setPoly {1}, setPoly {2}, ()⟩, ?_, rfl, rfl, rfl, rfl, ?_⟩
  · refine ⟨rfl, ?_, ?_, rfl⟩
    · rw [← setPoly_add, Multiset.singleton_add, Multiset.insert_eq_cons]
    · rw [← setPoly_add, add_comm]
  · rintro L hL ⟨ha, ht⟩
    obtain ⟨l, rfl, hl⟩ := Multiset.map_eq_singleton.mp (setPoly_injective ha).symm
    have hmem := hL l (Multiset.mem_singleton_self l)
    simp only [derived, Multiset.insert_eq_cons, Multiset.mem_cons, Multiset.mem_singleton] at hmem
    rcases hmem with rfl | rfl | rfl <;> norm_num at hl
    dsimp only at ht
    have := setPoly_injective ht
    simp at this

end Tachyon
