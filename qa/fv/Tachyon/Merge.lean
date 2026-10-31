import Tachyon.Stamp

/-!
# Merge soundness

`StampMerge` adds leaf multisets. Merge enforces no deduplication; consensus rejects repeated
descriptors and tachygrams at publication.
-/

namespace Tachyon

variable {F A : Type*} [Field F]

theorem Merge.generatedBy {R : F → Multiset F} {left right merged : Stamp F A}
    {DL DR : Multiset F} (h : Merge left right merged)
    (hl : GeneratedBy R DL left) (hr : GeneratedBy R DR right) :
    GeneratedBy R (DL + DR) merged := by
  obtain ⟨hla, hlt⟩ := hl
  obtain ⟨hra, hrt⟩ := hr
  exact ⟨by rw [h.actions, hla, hra, setPoly_add],
    by rw [h.tachygrams, hlt, hrt, Multiset.add_bind, setPoly_add]⟩

end Tachyon
