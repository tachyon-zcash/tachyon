import Tachyon.EvidenceDoubleSpend
import Tachyon.SpendProvenance

/-!
# Stamped spend provenance and replayed evidence in one reduction

The spendable provenance is stored in the positive leaf payload itself, not
supplied as an unrelated witness for the same digest. `SelectedSpend` indexes
the finite positive-leaf/node list and checks that its payload is a spend.
Its certificate is computed from that payload with `Option.get`, never chosen
from an existence proposition.

`stampedEvidenceBreak` combines merge/unmerge/lift provenance, published anchor
traces, spend binding, and the replayed evidence-query oracle. Two purported
spends of the same note return observed anchor/source/evidence collisions.
The same-note lineage-start condition and actual certified extraction inputs
remain explicit; this is not a PCD knowledge extractor or Rust fingerprint proof.
-/

namespace Tachyon

open Polynomial AnchorBreaks SourceQueryBreaks

variable {F P C : Type*} [Field F] [DecidableEq F] [Monoid P] [OpeningSemantics P F]
  [DecidableEq P] [DecidableEq C]

abbrev SpendLeafPayload (m : Model P C F ℕ) (ValidBucket : QrBucket F F → Prop)
    (Query : QrBucket F F → F → Type*) (nf : F → ℕ → F) (R : ℕ → F → Multiset F)
    (epoch : F → ℕ) (d a : F) := Option (SpendLeaf m ValidBucket Query nf R epoch d a)

variable {m : Model P C F ℕ} {ValidBucket : QrBucket F F → Prop}
  {Query : QrBucket F F → F → Type*} {nf : F → ℕ → F} {R : ℕ → F → Multiset F}
  {epoch : F → ℕ} {IsFee : F → Prop} {s : Stamp F F}

structure SelectedSpend
    (T : StampTrace IsFee epoch R (SpendLeafPayload m ValidBucket Query nf R epoch) (SpanLift m) s)
    {e : ℕ} (N : NodeTrace m e s.anchor) where
  index : Fin (T.positiveNodes N).length
  isSpend : ((T.positiveNodes N).get index).1.provenance.isSome

def SelectedSpend.occurrence
    {T : StampTrace IsFee epoch R (SpendLeafPayload m ValidBucket Query nf R epoch) (SpanLift m) s}
    {e : ℕ} {N : NodeTrace m e s.anchor} (selected : SelectedSpend T N) :=
  (T.positiveNodes N).get selected.index

def SelectedSpend.certificate
    {T : StampTrace IsFee epoch R (SpendLeafPayload m ValidBucket Query nf R epoch) (SpanLift m) s}
    {e : ℕ} {N : NodeTrace m e s.anchor} (selected : SelectedSpend T N) :
    SpendLeaf m ValidBucket Query nf R epoch selected.occurrence.1.digest selected.occurrence.1.anchor :=
  selected.occurrence.1.provenance.get selected.isSpend

theorem SelectedSpend.mem
    {T : StampTrace IsFee epoch R (SpendLeafPayload m ValidBucket Query nf R epoch) (SpanLift m) s}
    {e : ℕ} {N : NodeTrace m e s.anchor} (selected : SelectedSpend T N) :
    selected.occurrence ∈ T.positiveNodes N := List.get_mem _ _

variable {B D Δ Φ : Type*} [DecidableEq B] [DecidableEq D]
  {evidence : EvidenceReplay.Model B D} {decode : B → EvidenceQuery.BucketView F F}
  {actionDigest : Δ → F} {feeDigest : Φ → F} {chain l₁ l₂ : List (Chain.Stamp F F)}
  {acceptedAnchor : ℕ → F → Prop} {descs₁ descs₂ : List Δ} {fee₁ fee₂ : Φ}
  {adjunctFees₁ adjunctFees₂ : List Φ} {stamp₁ stamp₂ : PublishedStamp F F}
  {p₁ p₂ : ℕ} {δ₁ δ₂ : Δ} {c : F} {header₁ header₂ : Stamp F F}

def stampedEvidenceBreak
    (hc : ¬ IsSquare c) (hchain : Chain.Valid epoch acceptedAnchor chain)
    (h₁ : BundleVerified IsFee epoch R actionDigest feeDigest descs₁ fee₁ adjunctFees₁ stamp₁)
    (h₂ : BundleVerified IsFee epoch R actionDigest feeDigest descs₂ fee₂ adjunctFees₂ stamp₂)
    (hsplit : chain = l₁ ++ ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ :: l₂)
    (hs₂ : ⟨stamp₂.anchor, stamp₂.tachygrams, p₂⟩ ∈ l₂)
    (hδ₁ : δ₁ ∈ descs₁) (hδ₂ : δ₂ ∈ descs₂)
    (T₁ : StampTrace IsFee epoch R
      (SpendLeafPayload m ValidBucket
        (EvidenceQuery.Query m (OpeningSemantics.interpret : P →* F[X]) chain c evidence decode) nf R epoch)
      (SpanLift m) header₁)
    (T₂ : StampTrace IsFee epoch R
      (SpendLeafPayload m ValidBucket
        (EvidenceQuery.Query m (OpeningSemantics.interpret : P →* F[X]) chain c evidence decode) nf R epoch)
      (SpanLift m) header₂)
    (hstatement₁ : header₁.actions = setPoly (coveredDigests actionDigest feeDigest descs₁
        (fee₁ :: adjunctFees₁)) ∧ header₁.tachygrams = stamp₁.tachygramSet ∧ header₁.anchor = stamp₁.anchor)
    (hstatement₂ : header₂.actions = setPoly (coveredDigests actionDigest feeDigest descs₂
        (fee₂ :: adjunctFees₂)) ∧ header₂.tachygrams = stamp₂.tachygramSet ∧ header₂.anchor = stamp₂.anchor)
    (N₁ : NodeTrace m (epoch stamp₁.anchor) header₁.anchor)
    (N₂ : NodeTrace m (epoch stamp₂.anchor) header₂.anchor)
    (selected₁ : SelectedSpend T₁ N₁) (selected₂ : SelectedSpend T₂ N₂)
    (hdigest₁ : actionDigest δ₁ = selected₁.occurrence.1.digest)
    (hdigest₂ : actionDigest δ₂ = selected₂.occurrence.1.digest)
    (hcm : selected₁.certificate.spendable.cm = selected₂.certificate.spendable.cm)
    (hstart : selected₂.certificate.start ≤ p₁) : EvidenceQuery.Failure m evidence :=
  -- Use supplied headers plus erased statement equations instead of creating
  -- `setPoly covered` inside executable data. This adapts the composition of
  -- `doubleSpendBreakOfTraces` to the runtime/specification boundary while
  -- retaining its positive-node and provenance lemmas unchanged.
  match selected₁.occurrence.2, selected₂.occurrence.2 with
  | .inr broken, _ => .anchor broken
  | .inl _, .inr broken => .anchor broken
  | .inl node₁, .inl node₂ =>
      have hepoch₁ : epoch selected₁.occurrence.1.anchor = epoch stamp₁.anchor := by
        obtain ⟨_, _, _, hanchor⟩ := T₁.spec
        exact (hanchor _ (List.mem_append_left _
          (T₁.positiveNodes_fst N₁ ▸ List.mem_map.mpr ⟨_, selected₁.mem, rfl⟩))).trans
            (congrArg epoch hstatement₁.2.2)
      have hepoch₂ : epoch selected₂.occurrence.1.anchor = epoch stamp₂.anchor := by
        obtain ⟨_, _, _, hanchor⟩ := T₂.spec
        exact (hanchor _ (List.mem_append_left _
          (T₂.positiveNodes_fst N₂ ▸ List.mem_map.mpr ⟨_, selected₂.mem, rfl⟩))).trans
            (congrArg epoch hstatement₂.2.2)
      match doubleSpendBreak (EvidenceQuery.Query.oracle hc) hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂
          selected₁.certificate.trace selected₂.certificate.trace hcm
          (selected₁.certificate.anchor_eq.symm ▸ node₁)
          (selected₂.certificate.anchor_eq.symm ▸ node₂)
          ((congrArg₂ R hepoch₁.symm hdigest₁).trans selected₁.certificate.action)
          ((congrArg₂ R hepoch₂.symm hdigest₂).trans selected₂.certificate.action) hstart with
      | .inl witness => .anchor ⟨_, _, witness⟩
      | .inr queryBreak => queryBreak

end Tachyon
