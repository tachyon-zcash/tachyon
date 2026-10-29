import Tachyon.Merge
import Tachyon.Unmerge

/-!
# The stamp proof tree

`Derivable` is the set of stamps an idealized PCD verifier accepts: every accepted header is the
output of a registered step on accepted inputs, which idealizes PCD knowledge soundness.

Each leaf step (`OutputAction`, `SpendAction`, `FeeSeed`) emits one digest and the tachygrams `R`
assigns it at its anchor's epoch. `FeeFuse` and `ActionMerge` are merges and need no constructor of
their own. `StampLift` moves a stamp to another anchor in the same epoch; it stands in for the span
argument, under which a chain-node `anchor_end` pins every span member to that epoch.
-/

namespace Tachyon

variable {F A E : Type*} [Field F]

inductive Derivable (epoch : A → E) (R : E → F → Multiset F) : Stamp F A → Prop
  | leaf (d : F) (a : A) : Derivable epoch R ⟨setPoly {d}, setPoly (R (epoch a) d), a⟩
  | merge {left right merged : Stamp F A} :
      Derivable epoch R left → Derivable epoch R right → Merge left right merged →
        Derivable epoch R merged
  | unmerge {dividend divisor quotient : Stamp F A} :
      Derivable epoch R dividend → Derivable epoch R divisor →
        Unmerge dividend divisor quotient → Derivable epoch R quotient
  | lift {s : Stamp F A} (a : A) :
      Derivable epoch R s → epoch a = epoch s.anchor → Derivable epoch R { s with anchor := a }

variable {epoch : A → E} {R : E → F → Multiset F}

/-- Every derivable stamp is leaf-generated at its anchor's epoch. -/
theorem Derivable.leafGenerated [DecidableEq F] {s : Stamp F A} (h : Derivable epoch R s) :
    ∃ D, GeneratedBy (R (epoch s.anchor)) D s := by
  induction h with
  | leaf d a => exact ⟨{d}, rfl, by rw [Multiset.singleton_bind]⟩
  | merge _ _ hm ihl ihr =>
      obtain ⟨DL, hl⟩ := ihl
      obtain ⟨DR, hr⟩ := ihr
      rw [← hm.anchor] at hr
      rw [hm.merged_anchor]
      exact ⟨DL + DR, hm.generatedBy hl hr⟩
  | unmerge _ _ hu ihdividend ihdivisor =>
      obtain ⟨D, hdividend⟩ := ihdividend
      obtain ⟨D', hdivisor⟩ := ihdivisor
      rw [← hu.anchor] at hdivisor
      rw [hu.quotient_anchor]
      exact ⟨D - D', hu.generatedBy hdividend hdivisor⟩
  | lift a _ hepoch ih =>
      obtain ⟨D, hs⟩ := ih
      exact ⟨D, by rw [hepoch]; exact hs⟩

/-- Consensus rebuilds the action set from a bundle's covered descriptors and verifies the stamp
against it. A derivable stamp that passes publishes exactly the covered leaves' tachygrams. -/
theorem Derivable.published [DecidableEq F] {s : Stamp F A} (h : Derivable epoch R s) {covered : Multiset F}
    (hcovered : s.actions = setPoly covered) :
    s.tachygrams = setPoly (covered.bind (R (epoch s.anchor))) := by
  obtain ⟨D, hD, hT⟩ := h.leafGenerated
  rw [hT, setPoly_injective (hD.symm.trans hcovered)]

end Tachyon
