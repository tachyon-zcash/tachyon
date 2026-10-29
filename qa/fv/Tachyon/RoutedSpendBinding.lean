import Tachyon.SpendableTraces

/-!
# No double spend, or a break

Two verified bundles on a valid chain spend one note. Each spend leaf comes from `SpendBind` and
`SpendAction` over a traced `NoteSpendable` anchored at a traced chain node in its stamp's anchor
epoch, and an oracle decides each of the second lineage's QR queries. Such a pair computes either a
collision among the two node traces and the two spendables' anchor preimages, or the oracle's break
on one query (`doubleSpendBreak`). Without either, the nullifier pairs, the lineage epoch and the
lineage hold, and `no_double_spend_of_bundles` rules the pair out.

`no_double_spend_of_no_collisions` is the execution-local corollary: collision freedom on those
finite inputs and an oracle that never breaks rule the double spend out.
-/

namespace Tachyon

open Polynomial AnchorBreaks

variable {F C A P Δ Φ : Type*} [Field F] [DecidableEq F] [MulOneClass P] [OpeningSemantics P F]
  {IsFee : F → Prop} {epoch : A → ℕ} {R : ℕ → F → Multiset F} {actionDigest : Δ → F}
  {feeDigest : Φ → F} {m : Model P C A ℕ} {ValidBucket : QrBucket F A → Prop} {Query : QrBucket F A → F → Type*}
  {Q : Sort*} {noteNf : F → ℕ → F} {sp₁ sp₂ : NoteSpendable F A}
  {chain l₁ l₂ : List (Chain.Stamp F A)} {acceptedAnchor : ℕ → A → Prop} {descs₁ descs₂ : List Δ}
  {fee₁ fee₂ : Φ} {adjunctFees₁ adjunctFees₂ : List Φ} {stamp₁ stamp₂ : PublishedStamp F A}
  {p₁ p₂ start₁ start : ℕ} {δ₁ δ₂ : Δ}

/-- A double spend across two verified bundles on a valid chain, from traced spendables of one note,
computes a collision scoped to the two node traces and the spendables' anchor preimages, or the
oracle's break on one of the second lineage's queries. -/
def doubleSpendBreak [DecidableEq P] [DecidableEq C] [DecidableEq A]
    (oracle : ∀ b v, Query b v → Profiled.QueryComplete chain b v ⊕' Q)
    (hchain : Chain.Valid epoch acceptedAnchor chain)
    (h₁ : BundleVerified IsFee epoch R actionDigest feeDigest descs₁ fee₁ adjunctFees₁ stamp₁)
    (h₂ : BundleVerified IsFee epoch R actionDigest feeDigest descs₂ fee₂ adjunctFees₂ stamp₂)
    (hsplit : chain = l₁ ++ ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ :: l₂)
    (hs₂ : ⟨stamp₂.anchor, stamp₂.tachygrams, p₂⟩ ∈ l₂)
    (hδ₁ : δ₁ ∈ descs₁) (hδ₂ : δ₂ ∈ descs₂)
    (t₁ : SpendableTrace m ValidBucket Query noteNf start₁ sp₁)
    (t₂ : SpendableTrace m ValidBucket Query noteNf start sp₂) (hcm : sp₁.cm = sp₂.cm)
    (node₁ : NodeTrace m (epoch stamp₁.anchor) sp₁.anchor)
    (node₂ : NodeTrace m (epoch stamp₂.anchor) sp₂.anchor)
    (haction₁ : SpendAction R (epoch stamp₁.anchor) (spendBind noteNf sp₁) (actionDigest δ₁))
    (haction₂ : SpendAction R (epoch stamp₂.anchor) (spendBind noteNf sp₂) (actionDigest δ₂))
    (hstart : start ≤ p₁) :
    ScopedBreak m (node₁.openings ++ node₂.openings)
      ((t₁.anchorInput :: node₁.inputs) ++ (t₂.anchorInput :: node₂.inputs)) ⊕' Q :=
  match t₁.spendPairOrBreak node₁ haction₁ with
  | .inr witness =>
      .inl (witness.weaken (fun _ h => List.mem_append_left _ h)
        (fun _ h => List.mem_append_left _ h))
  | .inl hpair₁ =>
      match t₂.anchorEpochOrBreak node₂ with
      | .inr witness =>
          .inl (witness.weaken (fun _ h => List.mem_append_right _ h)
            (fun _ h => List.mem_append_right _ h))
      | .inl hcurrent =>
          match t₂.lineageOrBreak oracle with
          | .inr broken => .inr broken
          | .inl ⟨_, hlineage⟩ => False.elim <| by
              rw [SpendAction, spendBind, hcurrent] at haction₂
              rw [hcm] at hpair₁
              exact no_double_spend_of_bundles hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂ hpair₁ haction₂
                (hcurrent ▸ hlineage) hstart

/-- With no collision among the two node traces and the spendables' anchor preimages, and an oracle
that never breaks, two verified bundles on a valid chain cannot both spend one note. -/
theorem no_double_spend_of_no_collisions [DecidableEq P] [DecidableEq C] [DecidableEq A]
    (oracle : ∀ b v, Query b v → Profiled.QueryComplete chain b v ⊕' Q) (hQ : Q → False)
    (hchain : Chain.Valid epoch acceptedAnchor chain)
    (h₁ : BundleVerified IsFee epoch R actionDigest feeDigest descs₁ fee₁ adjunctFees₁ stamp₁)
    (h₂ : BundleVerified IsFee epoch R actionDigest feeDigest descs₂ fee₂ adjunctFees₂ stamp₂)
    (hsplit : chain = l₁ ++ ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ :: l₂)
    (hs₂ : ⟨stamp₂.anchor, stamp₂.tachygrams, p₂⟩ ∈ l₂)
    (hδ₁ : δ₁ ∈ descs₁) (hδ₂ : δ₂ ∈ descs₂)
    (t₁ : SpendableTrace m ValidBucket Query noteNf start₁ sp₁)
    (t₂ : SpendableTrace m ValidBucket Query noteNf start sp₂) (hcm : sp₁.cm = sp₂.cm)
    (node₁ : NodeTrace m (epoch stamp₁.anchor) sp₁.anchor)
    (node₂ : NodeTrace m (epoch stamp₂.anchor) sp₂.anchor)
    (haction₁ : SpendAction R (epoch stamp₁.anchor) (spendBind noteNf sp₁) (actionDigest δ₁))
    (haction₂ : SpendAction R (epoch stamp₂.anchor) (spendBind noteNf sp₂) (actionDigest δ₂))
    (hstart : start ≤ p₁)
    (hlocal : NoCollisionsOn m (node₁.openings ++ node₂.openings)
      ((t₁.anchorInput :: node₁.inputs) ++ (t₂.anchorInput :: node₂.inputs))) : False :=
  match doubleSpendBreak oracle hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂ t₁ t₂ hcm node₁ node₂ haction₁
      haction₂ hstart with
  | .inl witness => witness.elim hlocal
  | .inr broken => hQ broken

end Tachyon
