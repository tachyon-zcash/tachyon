import Tachyon.ProvenanceTraces
import Tachyon.QueryIntegration

/-!
# Spend provenance

`doubleSpendBreak` takes, for each spend, the traced spendable its leaf came from and a chain node
trace for that spendable's anchor. Both follow from a stamp trace and the published anchor.

A lift in a stamp trace carries its traced span (`SpanLift`). Descending from a node at the stamp's
published anchor, each lift moves the node to its pre-lift anchor through `liftNodeOrBreak`, or
yields an observed collision (`SpanLift.descend`). Every positive leaf thus receives a node at the
stamp's epoch or a break (`StampTrace.positiveNodes`). A spend leaf's provenance records its traced
spendable, anchored at the leaf (`SpendLeaf`). `doubleSpendBreakOfTraces` composes these with
`doubleSpendBreak`: two verified bundles whose stamp traces hold spend leaves of one note compute an
observed collision or the query oracle's break.
-/

namespace Tachyon

open Polynomial AnchorBreaks SourceQueryBreaks

variable {F C P : Type*} [Field F] [DecidableEq F] [MulOneClass P] [DecidableEq P] [DecidableEq C]
  {m : Model P C F ℕ} {s : Stamp F F} {a : F}

/-- A lift's traced span: the header's anchor moves along `span` to `a`. -/
structure SpanLift (m : Model P C F ℕ) (s : Stamp F F) (a : F) where
  span : Chain.AnchorSpan F
  trace : SpanTrace m span
  step : Chain.StampLiftStep s span { s with anchor := a }

omit [DecidableEq F] [DecidableEq P] [DecidableEq C] in
theorem SpanLift.anchor_end (w : SpanLift m s a) : w.span.anchor_end = a :=
  (congrArg Stamp.anchor w.step.2).symm

/-- A node at the lifted anchor descends to a node at the pre-lift anchor, or yields an observed
collision. -/
def SpanLift.descend (w : SpanLift m s a) {e : ℕ} (node : NodeTrace m e a) :
    NodeTrace m e s.anchor ⊕' ObservedBreak m :=
  match liftNodeOrBreak m w.trace (cast (congrArg (NodeTrace m e) w.anchor_end.symm) node)
      s.anchor w.step.1 with
  | .inl decoded => .inl decoded.trace
  | .inr witness => .inr ⟨_, _, witness⟩

variable {IsFee : F → Prop} {epoch : F → ℕ} {R : ℕ → F → Multiset F} {Leaf : F → F → Type*}

/-- Each leaf of an actions trace with a node at its header's anchor, or an observed collision. -/
def ActionsTrace.leafNodes {e : ℕ} : {s : Stamp F F} →
    ActionsTrace IsFee epoch R Leaf (SpanLift m) s → NodeTrace m e s.anchor →
      List (Σ l : LeafRecord Leaf, NodeTrace m e l.anchor ⊕' ObservedBreak m)
  | _, .action d a provenance _, node => [⟨⟨d, a, provenance⟩, .inl node⟩]
  | _, .merge left right hm, node =>
      left.leafNodes (hm.merged_anchor ▸ node) ++
        right.leafNodes ((hm.merged_anchor.trans hm.anchor) ▸ node)
  | _, .lift _ t _ w, node =>
      match w.descend node with
      | .inl lower => t.leafNodes lower
      | .inr broken => t.leaves.map fun l => ⟨l, .inr broken⟩

theorem ActionsTrace.leafNodes_fst {e : ℕ} : {s : Stamp F F} →
    (t : ActionsTrace IsFee epoch R Leaf (SpanLift m) s) → (node : NodeTrace m e s.anchor) →
      (t.leafNodes node).map Sigma.fst = t.leaves
  | _, .action .., _ => rfl
  | _, .merge left right _, _ => by
      rw [ActionsTrace.leafNodes, List.map_append, left.leafNodes_fst, right.leafNodes_fst]
      rfl
  | _, .lift _ t _ w, node => by
      rw [ActionsTrace.leafNodes, ActionsTrace.leaves]
      split
      · exact t.leafNodes_fst _
      · simp only [List.map_map, Function.comp_def, List.map_id']

mutual

/-- Each positive leaf of a stamp trace with a node at the stamp's anchor epoch, or an observed
collision. -/
def StampTrace.positiveNodes {e : ℕ} : {s : Stamp F F} →
    StampTrace IsFee epoch R Leaf (SpanLift m) s → NodeTrace m e s.anchor →
      List (Σ l : LeafRecord Leaf, NodeTrace m e l.anchor ⊕' ObservedBreak m)
  | _, .feeFuse (left := left) f provenance actions _, node =>
      actions.leafNodes node ++ [⟨⟨f, left.anchor, provenance⟩, .inl node⟩]
  | _, .feeSeed f a provenance _, node => [⟨⟨f, a, provenance⟩, .inl node⟩]
  | _, .merge left right hm, node =>
      left.positiveNodes (hm.merged_anchor ▸ node) ++
        right.positiveNodes ((hm.merged_anchor.trans hm.anchor) ▸ node)
  | _, .unmerge dividend divisor hu, node =>
      dividend.positiveNodes (hu.quotient_anchor ▸ node) ++
        divisor.negativeNodes ((hu.quotient_anchor.trans hu.anchor) ▸ node)
  | _, .lift _ t _ w, node =>
      match w.descend node with
      | .inl lower => t.positiveNodes lower
      | .inr broken => t.positive.map fun l => ⟨l, .inr broken⟩

/-- Each negative leaf of a stamp trace with a node at the stamp's anchor epoch, or an observed
collision. -/
def StampTrace.negativeNodes {e : ℕ} : {s : Stamp F F} →
    StampTrace IsFee epoch R Leaf (SpanLift m) s → NodeTrace m e s.anchor →
      List (Σ l : LeafRecord Leaf, NodeTrace m e l.anchor ⊕' ObservedBreak m)
  | _, .feeFuse .., _ => []
  | _, .feeSeed .., _ => []
  | _, .merge left right hm, node =>
      left.negativeNodes (hm.merged_anchor ▸ node) ++
        right.negativeNodes ((hm.merged_anchor.trans hm.anchor) ▸ node)
  | _, .unmerge dividend divisor hu, node =>
      dividend.negativeNodes (hu.quotient_anchor ▸ node) ++
        divisor.positiveNodes ((hu.quotient_anchor.trans hu.anchor) ▸ node)
  | _, .lift _ t _ w, node =>
      match w.descend node with
      | .inl lower => t.negativeNodes lower
      | .inr broken => t.negative.map fun l => ⟨l, .inr broken⟩

end

mutual

theorem StampTrace.positiveNodes_fst {e : ℕ} : {s : Stamp F F} →
    (t : StampTrace IsFee epoch R Leaf (SpanLift m) s) → (node : NodeTrace m e s.anchor) →
      (t.positiveNodes node).map Sigma.fst = t.positive
  | _, .feeFuse _ _ actions _, node => by
      rw [StampTrace.positiveNodes, StampTrace.positive, List.map_append, actions.leafNodes_fst]
      rfl
  | _, .feeSeed .., _ => rfl
  | _, .merge left right _, _ => by
      rw [StampTrace.positiveNodes, StampTrace.positive, List.map_append, left.positiveNodes_fst,
        right.positiveNodes_fst]
  | _, .unmerge dividend divisor _, _ => by
      rw [StampTrace.positiveNodes, StampTrace.positive, List.map_append,
        dividend.positiveNodes_fst, divisor.negativeNodes_fst]
  | _, .lift _ t _ w, node => by
      rw [StampTrace.positiveNodes, StampTrace.positive]
      split
      · exact t.positiveNodes_fst _
      · simp only [List.map_map, Function.comp_def, List.map_id']

theorem StampTrace.negativeNodes_fst {e : ℕ} : {s : Stamp F F} →
    (t : StampTrace IsFee epoch R Leaf (SpanLift m) s) → (node : NodeTrace m e s.anchor) →
      (t.negativeNodes node).map Sigma.fst = t.negative
  | _, .feeFuse .., _ => rfl
  | _, .feeSeed .., _ => rfl
  | _, .merge left right _, _ => by
      rw [StampTrace.negativeNodes, StampTrace.negative, List.map_append, left.negativeNodes_fst,
        right.negativeNodes_fst]
  | _, .unmerge dividend divisor _, _ => by
      rw [StampTrace.negativeNodes, StampTrace.negative, List.map_append,
        dividend.negativeNodes_fst, divisor.positiveNodes_fst]
  | _, .lift _ t _ w, node => by
      rw [StampTrace.negativeNodes, StampTrace.negative]
      split
      · exact t.negativeNodes_fst _
      · simp only [List.map_map, Function.comp_def, List.map_id']

end

variable [OpeningSemantics P F]

/-- A spend at digest `d` and anchor `a`: a traced spendable anchored at `a`, and its `SpendAction`
at `a`'s epoch. -/
structure SpendLeaf (m : Model P C F ℕ) (ValidBucket : QrBucket F F → Prop)
    (Query : QrBucket F F → F → Type*) (nf : F → ℕ → F) (R : ℕ → F → Multiset F)
    (epoch : F → ℕ) (d a : F) where
  start : ℕ
  spendable : NoteSpendable F F
  trace : SpendableTrace m ValidBucket Query nf start spendable
  anchor_eq : spendable.anchor = a
  action : SpendAction R (epoch a) (spendBind nf spendable) d

variable {Δ Φ : Type*} {actionDigest : Δ → F} {feeDigest : Φ → F}
  {ValidBucket : QrBucket F F → Prop} {Query : QrBucket F F → F → Type*} {Q : Sort*}
  {noteNf : F → ℕ → F} {chain l₁ l₂ : List (Chain.Stamp F F)} {acceptedAnchor : ℕ → F → Prop}
  {descs₁ descs₂ : List Δ} {fee₁ fee₂ : Φ} {adjunctFees₁ adjunctFees₂ : List Φ}
  {stamp₁ stamp₂ : PublishedStamp F F} {p₁ p₂ : ℕ} {δ₁ δ₂ : Δ}

/-- Two verified bundles on a valid chain whose stamp traces each hold a positive leaf spending one
note, with the published anchors traced on the chain, compute an observed collision or the query
oracle's break. -/
def doubleSpendBreakOfTraces (oracle : ∀ b v, Query b v → Profiled.QueryComplete chain b v ⊕' Q)
    (hchain : Chain.Valid epoch acceptedAnchor chain)
    (h₁ : BundleVerified IsFee epoch R actionDigest feeDigest descs₁ fee₁ adjunctFees₁ stamp₁)
    (h₂ : BundleVerified IsFee epoch R actionDigest feeDigest descs₂ fee₂ adjunctFees₂ stamp₂)
    (hsplit : chain = l₁ ++ ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ :: l₂)
    (hs₂ : ⟨stamp₂.anchor, stamp₂.tachygrams, p₂⟩ ∈ l₂)
    (hδ₁ : δ₁ ∈ descs₁) (hδ₂ : δ₂ ∈ descs₂)
    (T₁ : StampTrace IsFee epoch R Leaf (SpanLift m)
      ⟨setPoly (coveredDigests actionDigest feeDigest descs₁ (fee₁ :: adjunctFees₁)),
        stamp₁.tachygramSet, stamp₁.anchor⟩)
    (T₂ : StampTrace IsFee epoch R Leaf (SpanLift m)
      ⟨setPoly (coveredDigests actionDigest feeDigest descs₂ (fee₂ :: adjunctFees₂)),
        stamp₂.tachygramSet, stamp₂.anchor⟩)
    (N₁ : NodeTrace m (epoch stamp₁.anchor) stamp₁.anchor)
    (N₂ : NodeTrace m (epoch stamp₂.anchor) stamp₂.anchor)
    (x₁ : Σ l : LeafRecord Leaf, NodeTrace m (epoch stamp₁.anchor) l.anchor ⊕' ObservedBreak m)
    (x₂ : Σ l : LeafRecord Leaf, NodeTrace m (epoch stamp₂.anchor) l.anchor ⊕' ObservedBreak m)
    (hx₁ : x₁ ∈ T₁.positiveNodes N₁) (hx₂ : x₂ ∈ T₂.positiveNodes N₂)
    (spend₁ : SpendLeaf m ValidBucket Query noteNf R epoch x₁.1.digest x₁.1.anchor)
    (spend₂ : SpendLeaf m ValidBucket Query noteNf R epoch x₂.1.digest x₂.1.anchor)
    (hdigest₁ : actionDigest δ₁ = x₁.1.digest) (hdigest₂ : actionDigest δ₂ = x₂.1.digest)
    (hcm : spend₁.spendable.cm = spend₂.spendable.cm) (hstart : spend₂.start ≤ p₁) :
    ObservedBreak m ⊕' Q :=
  match x₁.2, x₂.2 with
  | .inr broken, _ => .inl broken
  | .inl _, .inr broken => .inl broken
  | .inl node₁, .inl node₂ =>
      have hepoch₁ : epoch x₁.1.anchor = epoch stamp₁.anchor := by
        obtain ⟨_, -, -, hanchor⟩ := T₁.spec
        exact hanchor x₁.1 (List.mem_append_left _
          (T₁.positiveNodes_fst N₁ ▸ List.mem_map.mpr ⟨x₁, hx₁, rfl⟩))
      have hepoch₂ : epoch x₂.1.anchor = epoch stamp₂.anchor := by
        obtain ⟨_, -, -, hanchor⟩ := T₂.spec
        exact hanchor x₂.1 (List.mem_append_left _
          (T₂.positiveNodes_fst N₂ ▸ List.mem_map.mpr ⟨x₂, hx₂, rfl⟩))
      match doubleSpendBreak oracle hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂ spend₁.trace spend₂.trace hcm
          (cast (congrArg (NodeTrace m _) spend₁.anchor_eq.symm) node₁)
          (cast (congrArg (NodeTrace m _) spend₂.anchor_eq.symm) node₂)
          ((congrArg₂ R hepoch₁.symm hdigest₁).trans spend₁.action)
          ((congrArg₂ R hepoch₂.symm hdigest₂).trans spend₂.action)
          hstart with
      | .inl witness => .inl ⟨_, _, witness⟩
      | .inr broken => .inr broken

end Tachyon
