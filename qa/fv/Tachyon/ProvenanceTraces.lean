import Tachyon.ProofTree

/-!
# Leaf provenance through unmerge

`ActionsDerivable` and `StampDerivable` are propositions, so they cannot say which leaf derivation a
covered digest came from. `ActionsTrace` and `StampTrace` carry the same derivations as data, with
each leaf's provenance `Leaf d a` attached. A stamp trace records its leaves with sign:
`StampUnmerge` contributes the divisor's leaves as negative occurrences. The stamp's digest multiset
`D` satisfies `D + negative = positive` (`StampTrace.spec`), so division never yields a digest no
leaf derived: every covered digest is found among the positive leaves, with its provenance and an
anchor in the stamp's epoch (`StampTrace.findLeaf`).
-/

namespace Tachyon

universe u v w x

variable {F : Type u} {A : Type v} {E : Type w} [Field F] {IsFee : F → Prop} {epoch : A → E}
  {R : E → F → Multiset F} {Leaf : F → A → Type x}

/-- A leaf occurrence: its digest, its anchor, and its provenance. -/
structure LeafRecord (Leaf : F → A → Type x) where
  digest : F
  anchor : A
  provenance : Leaf digest anchor

/-- `ActionsDerivable` as data, with each leaf's provenance. -/
inductive ActionsTrace (IsFee : F → Prop) (epoch : A → E) (R : E → F → Multiset F)
    (Leaf : F → A → Type x) : Stamp F A → Type (max u v x)
  | action (d : F) (a : A) (provenance : Leaf d a) :
      ¬ IsFee d → ActionsTrace IsFee epoch R Leaf ⟨setPoly {d}, setPoly (R (epoch a) d), a⟩
  | merge {left right merged : Stamp F A} :
      ActionsTrace IsFee epoch R Leaf left → ActionsTrace IsFee epoch R Leaf right →
        Merge left right merged → ActionsTrace IsFee epoch R Leaf merged
  | lift {s : Stamp F A} (a : A) :
      ActionsTrace IsFee epoch R Leaf s → epoch a = epoch s.anchor →
        ActionsTrace IsFee epoch R Leaf { s with anchor := a }

/-- `StampDerivable` as data, with each leaf's provenance. -/
inductive StampTrace (IsFee : F → Prop) (epoch : A → E) (R : E → F → Multiset F)
    (Leaf : F → A → Type x) : Stamp F A → Type (max u v x)
  | feeFuse {left : Stamp F A} (f : F) (provenance : Leaf f left.anchor) :
      ActionsTrace IsFee epoch R Leaf left → IsFee f →
        StampTrace IsFee epoch R Leaf
          ⟨left.actions * setPoly {f}, left.tachygrams * setPoly (R (epoch left.anchor) f),
            left.anchor⟩
  | feeSeed (f : F) (a : A) (provenance : Leaf f a) :
      IsFee f → StampTrace IsFee epoch R Leaf ⟨setPoly {f}, setPoly (R (epoch a) f), a⟩
  | merge {left right merged : Stamp F A} :
      StampTrace IsFee epoch R Leaf left → StampTrace IsFee epoch R Leaf right →
        Merge left right merged → StampTrace IsFee epoch R Leaf merged
  | unmerge {dividend divisor quotient : Stamp F A} :
      StampTrace IsFee epoch R Leaf dividend → StampTrace IsFee epoch R Leaf divisor →
        Unmerge dividend divisor quotient → StampTrace IsFee epoch R Leaf quotient
  | lift {s : Stamp F A} (a : A) :
      StampTrace IsFee epoch R Leaf s → epoch a = epoch s.anchor →
        StampTrace IsFee epoch R Leaf { s with anchor := a }

theorem ActionsTrace.forget {s : Stamp F A} :
    ActionsTrace IsFee epoch R Leaf s → ActionsDerivable IsFee epoch R s
  | .action d a _ hd => .action d a hd
  | .merge left right hm => .merge left.forget right.forget hm
  | .lift a t hepoch => .lift a t.forget hepoch

theorem StampTrace.forget {s : Stamp F A} :
    StampTrace IsFee epoch R Leaf s → StampDerivable IsFee epoch R s
  | .feeFuse f _ left hf => .feeFuse f left.forget hf
  | .feeSeed f a _ hf => .feeSeed f a hf
  | .merge left right hm => .merge left.forget right.forget hm
  | .unmerge dividend divisor hu => .unmerge dividend.forget divisor.forget hu
  | .lift a t hepoch => .lift a t.forget hepoch

/-- The trace's leaf occurrences. -/
def ActionsTrace.leaves {s : Stamp F A} :
    ActionsTrace IsFee epoch R Leaf s → List (LeafRecord Leaf)
  | .action d a provenance _ => [⟨d, a, provenance⟩]
  | .merge left right _ => left.leaves ++ right.leaves
  | .lift _ t _ => t.leaves

mutual

/-- The trace's positive leaf occurrences. -/
def StampTrace.positive {s : Stamp F A} :
    StampTrace IsFee epoch R Leaf s → List (LeafRecord Leaf)
  | .feeFuse (left := left) f provenance actions _ => actions.leaves ++ [⟨f, left.anchor, provenance⟩]
  | .feeSeed f a provenance _ => [⟨f, a, provenance⟩]
  | .merge left right _ => left.positive ++ right.positive
  | .unmerge dividend divisor _ => dividend.positive ++ divisor.negative
  | .lift _ t _ => t.positive

/-- The trace's negative leaf occurrences: leaves divided out by `StampUnmerge`. -/
def StampTrace.negative {s : Stamp F A} :
    StampTrace IsFee epoch R Leaf s → List (LeafRecord Leaf)
  | .feeFuse .. => []
  | .feeSeed .. => []
  | .merge left right _ => left.negative ++ right.negative
  | .unmerge dividend divisor _ => dividend.negative ++ divisor.positive
  | .lift _ t _ => t.negative

end

/-- The digests of a list of leaf occurrences, as a multiset. -/
def leafDigests (leaves : List (LeafRecord Leaf)) : Multiset F :=
  (leaves.map LeafRecord.digest : List F)

omit [Field F] in
theorem leafDigests_append (l₁ l₂ : List (LeafRecord Leaf)) :
    leafDigests (l₁ ++ l₂) = leafDigests l₁ + leafDigests l₂ := by
  simp [leafDigests]

/-- An actions trace is generated by its leaves' digests, and every leaf is anchored in the
header's epoch. -/
theorem ActionsTrace.spec {s : Stamp F A} (t : ActionsTrace IsFee epoch R Leaf s) :
    GeneratedBy (R (epoch s.anchor)) (leafDigests t.leaves) s ∧
      ∀ l ∈ t.leaves, epoch l.anchor = epoch s.anchor := by
  induction t with
  | action d a provenance _ =>
      exact ⟨⟨rfl, by simp [leafDigests, ActionsTrace.leaves, Multiset.singleton_bind]⟩,
        by simp [ActionsTrace.leaves]⟩
  | merge _ _ hm ihl ihr =>
      obtain ⟨hl, hlanchor⟩ := ihl
      obtain ⟨hr, hranchor⟩ := ihr
      rw [← hm.anchor] at hr hranchor
      refine ⟨?_, fun l hl' => ?_⟩
      · rw [ActionsTrace.leaves, leafDigests_append, hm.merged_anchor]
        exact hm.generatedBy hl hr
      · rw [ActionsTrace.leaves, List.mem_append] at hl'
        rw [hm.merged_anchor]
        exact hl'.elim (hlanchor l) (hranchor l)
  | lift a _ hepoch ih =>
      obtain ⟨hs, hanchor⟩ := ih
      exact ⟨by rw [ActionsTrace.leaves, hepoch]; exact hs,
        fun l hl => (hanchor l hl).trans hepoch.symm⟩

variable [DecidableEq F]

/-- A stamp trace is generated by some digest multiset `D` with `D + negative = positive`, and
every leaf occurrence is anchored in the stamp's epoch. -/
theorem StampTrace.spec {s : Stamp F A} (t : StampTrace IsFee epoch R Leaf s) :
    ∃ D, GeneratedBy (R (epoch s.anchor)) D s ∧
      D + leafDigests t.negative = leafDigests t.positive ∧
      ∀ l ∈ t.positive ++ t.negative, epoch l.anchor = epoch s.anchor := by
  induction t with
  | feeFuse f provenance actions _ =>
      obtain ⟨hs, hanchor⟩ := actions.spec
      refine ⟨_, hs.fuse f _, ?_, fun l hl => ?_⟩
      · rw [StampTrace.positive, StampTrace.negative, leafDigests_append]
        simp [leafDigests]
      · simp only [StampTrace.positive, StampTrace.negative, List.append_nil, List.mem_append,
          List.mem_singleton] at hl
        rcases hl with hl | rfl
        · exact hanchor l hl
        · rfl
  | feeSeed f a provenance _ =>
      refine ⟨{f}, ⟨rfl, by rw [Multiset.singleton_bind]⟩, ?_, fun l hl => ?_⟩
      · simp [StampTrace.positive, StampTrace.negative, leafDigests]
      · simp only [StampTrace.positive, StampTrace.negative, List.append_nil,
          List.mem_singleton] at hl
        rw [hl]
  | merge _ _ hm ihl ihr =>
      obtain ⟨DL, hl, hlsum, hlanchor⟩ := ihl
      obtain ⟨DR, hr, hrsum, hranchor⟩ := ihr
      rw [← hm.anchor] at hr hranchor
      refine ⟨DL + DR, hm.merged_anchor ▸ hm.generatedBy hl hr, ?_, fun l hl' => ?_⟩
      · simp only [StampTrace.positive, StampTrace.negative, leafDigests_append, ← hlsum,
          ← hrsum]
        abel
      · simp only [StampTrace.positive, StampTrace.negative, List.mem_append] at hl'
        rw [hm.merged_anchor]
        rcases hl' with (hl' | hl') | (hl' | hl')
        · exact hlanchor l (List.mem_append_left _ hl')
        · exact hranchor l (List.mem_append_left _ hl')
        · exact hlanchor l (List.mem_append_right _ hl')
        · exact hranchor l (List.mem_append_right _ hl')
  | unmerge dividendTrace divisorTrace hu ihdividend ihdivisor =>
      obtain ⟨D₁, hdividend, hsum₁, hanchor₁⟩ := ihdividend
      obtain ⟨D₂, hdivisor, hsum₂, hanchor₂⟩ := ihdivisor
      rw [← hu.anchor] at hdivisor hanchor₂
      obtain ⟨hle, -⟩ := hu.columns hdividend hdivisor
      refine ⟨D₁ - D₂, hu.quotient_anchor ▸ hu.generatedBy hdividend hdivisor, ?_,
        fun l hl' => ?_⟩
      · simp only [StampTrace.positive, StampTrace.negative, leafDigests_append, ← hsum₁,
          ← hsum₂]
        calc D₁ - D₂ + (leafDigests dividendTrace.negative + (D₂ + leafDigests divisorTrace.negative))
            = (D₁ - D₂ + D₂) + leafDigests dividendTrace.negative +
                leafDigests divisorTrace.negative := by ac_rfl
          _ = D₁ + leafDigests dividendTrace.negative + leafDigests divisorTrace.negative := by
              rw [tsub_add_cancel_of_le hle]
      · simp only [StampTrace.positive, StampTrace.negative, List.mem_append] at hl'
        rw [hu.quotient_anchor]
        rcases hl' with (hl' | hl') | (hl' | hl')
        · exact hanchor₁ l (List.mem_append_left _ hl')
        · exact hanchor₂ l (List.mem_append_right _ hl')
        · exact hanchor₁ l (List.mem_append_right _ hl')
        · exact hanchor₂ l (List.mem_append_left _ hl')
  | lift a _ hepoch ih =>
      obtain ⟨D, hs, hsum, hanchor⟩ := ih
      exact ⟨D, by rw [hepoch]; exact hs, hsum, fun l hl => (hanchor l hl).trans hepoch.symm⟩

/-- Every digest a stamp covers is found among its positive leaf occurrences, with its provenance
and an anchor in the stamp's epoch. -/
def StampTrace.findLeaf {s : Stamp F A} (t : StampTrace IsFee epoch R Leaf s)
    {covered : Multiset F} (hcovered : s.actions = setPoly covered) {d : F} (hd : d ∈ covered) :
    {l : LeafRecord Leaf // l ∈ t.positive ∧ l.digest = d ∧ epoch l.anchor = epoch s.anchor} :=
  match hfind : t.positive.find? (fun l => decide (l.digest = d)) with
  | some l =>
      have hmem := List.mem_of_find?_eq_some hfind
      ⟨l, hmem, by simpa using List.find?_some hfind, by
        obtain ⟨_, -, -, hanchor⟩ := t.spec
        exact hanchor l (List.mem_append_left _ hmem)⟩
  | none => False.elim <| by
      obtain ⟨D, hs, hsum, -⟩ := t.spec
      have hD : D = covered := setPoly_injective (hs.1.symm.trans hcovered)
      have hpos : d ∈ leafDigests t.positive := hsum ▸ Multiset.mem_add.mpr (Or.inl (hD ▸ hd))
      obtain ⟨l, hl, hdigest⟩ := List.mem_map.mp (Multiset.mem_coe.mp hpos)
      exact (List.find?_eq_none.mp hfind) l hl (by simpa using hdigest)

end Tachyon
