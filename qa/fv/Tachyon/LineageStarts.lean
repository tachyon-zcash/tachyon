import Tachyon.RoutedSpendBinding

/-!
# Lineage starts

A spendable lineage starts at the epoch its note's `cm` entered: the stamp `SpendableInit` absorbs,
or the bucket `QrSpendableInit` opens. `doubleSpendBreak` assumes the second spend's lineage starts
no later than the first spend's publication. Without that assumption, two spends of one note compute
a break, or the second lineage starts after the first spend's publication, which is no earlier than
the first lineage's start (`doubleSpendBreakOrLaterStart`). Two spends whose lineages start in one
epoch therefore compute a break (`sameStartBreak`), so the spends of one `cm` have pairwise distinct
lineage starts.
-/

namespace Tachyon

open Polynomial AnchorBreaks

variable {F C A P Δ Φ : Type*} [Field F] [DecidableEq F] [MulOneClass P] [OpeningSemantics P F]
  {IsFee : F → Prop} {epoch : A → ℕ} {R : ℕ → F → Multiset F} {actionDigest : Δ → F}
  {feeDigest : Φ → F} {m : Model P C A ℕ} {ValidBucket : QrBucket F A → Prop}
  {Query : QrBucket F A → F → Type*} {Q : Sort*} {noteNf : F → ℕ → F} {sp₁ sp₂ : NoteSpendable F A}
  {chain l₁ l₂ : List (Chain.Stamp F A)} {acceptedAnchor : ℕ → A → Prop} {descs₁ descs₂ : List Δ}
  {fee₁ fee₂ : Φ} {adjunctFees₁ adjunctFees₂ : List Φ} {stamp₁ stamp₂ : PublishedStamp F A}
  {p₁ p₂ start₁ start : ℕ} {δ₁ δ₂ : Δ}

omit [DecidableEq F] in
/-- A lineage starts no later than its current epoch. -/
theorem SpendableTrace.start_le {start : ℕ} {sp : NoteSpendable F A} :
    SpendableTrace m ValidBucket Query noteNf start sp → start ≤ sp.epoch_current
  | .init .. => le_rfl
  | .qrInit _ _ _ _ _ _ hepochNext _ => by dsimp only; omega
  | .lift previous unspent _ hepoch _ => by
      have := previous.start_le
      have := unspent.forget.tested_nullifiers.1
      dsimp only
      omega

variable [DecidableEq P] [DecidableEq C] [DecidableEq A]

/-- Two verified bundles on a valid chain spend one note from traced spendables, the first earlier
in chain order. The second lineage starts after the first spend's publication `p₁`, and the first
lineage starts no later than `p₁`; or the pair computes a scoped collision or the oracle's break. -/
def doubleSpendBreakOrLaterStart (oracle : ∀ b v, Query b v → Profiled.QueryComplete chain b v ⊕' Q)
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
    (haction₂ : SpendAction R (epoch stamp₂.anchor) (spendBind noteNf sp₂) (actionDigest δ₂)) :
    (start₁ ≤ p₁ ∧ p₁ < start) ⊕'
      (ScopedBreak m (node₁.openings ++ node₂.openings)
        ((t₁.anchorInput :: node₁.inputs) ++ (t₂.anchorInput :: node₂.inputs)) ⊕' Q) :=
  match t₁.anchorEpochOrBreak node₁ with
  | .inr witness =>
      .inr (.inl (witness.weaken (fun _ h => List.mem_append_left _ h)
        (fun _ h => List.mem_append_left _ h)))
  | .inl hcurrent =>
      have hstart₁ : start₁ ≤ p₁ :=
        t₁.start_le.trans (hcurrent.trans_le
          (hchain.accepted ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ (by simp [hsplit])).recency.1)
      if hstart : start ≤ p₁ then
        .inr (doubleSpendBreak oracle hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂ t₁ t₂ hcm node₁ node₂
          haction₁ haction₂ hstart)
      else .inl ⟨hstart₁, Nat.lt_of_not_le hstart⟩

/-- Two verified bundles on a valid chain whose spends of one note have lineages starting in the
same epoch compute a scoped collision or the oracle's break. -/
def sameStartBreak (oracle : ∀ b v, Query b v → Profiled.QueryComplete chain b v ⊕' Q)
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
    (hsame : start₁ = start) :
    ScopedBreak m (node₁.openings ++ node₂.openings)
      ((t₁.anchorInput :: node₁.inputs) ++ (t₂.anchorInput :: node₂.inputs)) ⊕' Q :=
  match doubleSpendBreakOrLaterStart oracle hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂ t₁ t₂ hcm node₁ node₂
      haction₁ haction₂ with
  | .inl ⟨hstart₁, hlater⟩ => absurd (hsame ▸ hstart₁) (Nat.not_le_of_lt hlater)
  | .inr outcome => outcome

/-- With no collision among the two node traces and the spendables' anchor preimages, and an oracle
that never breaks, the second of two spends of one note on a valid chain has a lineage starting after
the first spend's publication, and after the first lineage's start. -/
theorem later_start_of_no_collisions
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
    (hlocal : NoCollisionsOn m (node₁.openings ++ node₂.openings)
      ((t₁.anchorInput :: node₁.inputs) ++ (t₂.anchorInput :: node₂.inputs))) :
    start₁ ≤ p₁ ∧ p₁ < start :=
  match doubleSpendBreakOrLaterStart oracle hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂ t₁ t₂ hcm node₁ node₂
      haction₁ haction₂ with
  | .inl hlater => hlater
  | .inr (.inl witness) => (witness.elim hlocal).elim
  | .inr (.inr broken) => (hQ broken).elim

end Tachyon
