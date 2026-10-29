import Tachyon.ProfiledSpendable

/-!
# No double spend with routed queries and spend binding

`no_double_spend_of_spend_binding` takes the second spend's lineage from buckets that hold their
whole epochs. A real QR bucket holds only the published values matching its profile.
`no_double_spend_of_routed_spend_binding` takes the lineage from routed queries instead, so each
tested nullifier needs completeness only for itself, and keeps both nullifier pairs and the lineage
epoch from `SpendBind` and `SpendAction`.
-/

namespace Tachyon

open Polynomial

variable {F A Δ Φ : Type*} [Field F] [DecidableEq F] {IsFee : F → Prop} {epoch : A → ℕ}
  {R : ℕ → F → Multiset F} {actionDigest : Δ → F} {feeDigest : Φ → F}

/-- Two verified bundles on a valid chain, the first earlier in chain order, cannot both spend one
note when each spend leaf comes from `SpendBind` and `SpendAction` over a derivable routed-query
`NoteSpendable` of that note anchored at a chain node in its stamp's anchor epoch, and the second
lineage starts from `start`. Every valid bucket ends on a boundary digest into the next epoch. -/
theorem no_double_spend_of_routed_spend_binding {ValidBucket : QrBucket F A → Prop} {c : F}
    {noteNf : F → ℕ → F} {nextStamp : A → ℕ → F[X] → A} {genesis : A} {e₀ : ℕ}
    {nextEpoch : A → ℕ → A} {sp₁ sp₂ : NoteSpendable F A} {chain l₁ l₂ : List (Chain.Stamp F A)}
    {acceptedAnchor : ℕ → A → Prop} {descs₁ descs₂ : List Δ} {fee₁ fee₂ : Φ}
    {adjunctFees₁ adjunctFees₂ : List Φ} {stamp₁ stamp₂ : PublishedStamp F A}
    {p₁ p₂ start₁ start : ℕ} {δ₁ δ₂ : Δ} (hc : ¬ IsSquare c)
    (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hseal : ∀ ⦃b : QrBucket F A⦄, ValidBucket b →
      ∃ prev, b.anchor_next = nextEpoch prev (b.epoch + 1))
    (hepoch : ∀ {e : ℕ} {a : A}, Chain.Node genesis e₀ nextStamp nextEpoch e a → epoch a = e)
    (hchain : Chain.Valid epoch acceptedAnchor chain)
    (h₁ : BundleVerified IsFee epoch R actionDigest feeDigest descs₁ fee₁ adjunctFees₁ stamp₁)
    (h₂ : BundleVerified IsFee epoch R actionDigest feeDigest descs₂ fee₂ adjunctFees₂ stamp₂)
    (hsplit : chain = l₁ ++ ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ :: l₂)
    (hs₂ : ⟨stamp₂.anchor, stamp₂.tachygrams, p₂⟩ ∈ l₂)
    (hδ₁ : δ₁ ∈ descs₁) (hδ₂ : δ₂ ∈ descs₂)
    (hsp₁ : Profiled.SpendableDerivable ValidBucket (Profiled.RoutedQuery chain c) noteNf nextStamp
      start₁ sp₁)
    (hsp₂ : Profiled.SpendableDerivable ValidBucket (Profiled.RoutedQuery chain c) noteNf nextStamp
      start sp₂)
    (hcm : sp₁.cm = sp₂.cm)
    (hnode₁ : Chain.Node genesis e₀ nextStamp nextEpoch (epoch stamp₁.anchor) sp₁.anchor)
    (hnode₂ : Chain.Node genesis e₀ nextStamp nextEpoch (epoch stamp₂.anchor) sp₂.anchor)
    (haction₁ : SpendAction epoch R (spendBind noteNf sp₁) (actionDigest δ₁))
    (haction₂ : SpendAction epoch R (spendBind noteNf sp₂) (actionDigest δ₂))
    (hstart : start ≤ p₁) : False := by
  have hpair₁ := hsp₁.forget.spend_pair hlaw hseal hepoch hnode₁ haction₁
  have hpair₂ := hsp₂.forget.spend_pair hlaw hseal hepoch hnode₂ haction₂
  rw [hepoch hnode₁, hcm] at hpair₁
  rw [hepoch hnode₂] at hpair₂
  have hcurrent := hsp₂.forget.anchor_epoch hlaw hseal hnode₂
  exact no_double_spend_of_bundles hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂ hpair₁ hpair₂
    (hcurrent ▸ (hsp₂.routed_lineage hc).2) hstart

end Tachyon
