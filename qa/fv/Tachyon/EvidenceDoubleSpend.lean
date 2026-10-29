import Tachyon.EvidenceQuery
import Tachyon.RuntimeQueryIntegration

/-!
# Double-spend reduction including evidence replay

This instantiates the runtime spendable traversal with replayed evidence-query
data. Contradictory accepted spends return one of three concrete failures:
an anchor-preimage collision, a source-commitment/source-anchor collision, or
an evidence-tree collision. Each failure carries its observed finite inputs.

The encoded evidence preimages and actual trace/certificate data are inputs;
neither PCD witness extraction nor Rust/Lean circuit equivalence is established
by this composition theorem. No global hash law, global query completeness,
or classical choice of replay/source provenance is assumed.
-/

namespace Tachyon

open Polynomial AnchorBreaks

variable {F P C A B D Δ Φ : Type*} [Field F] [DecidableEq F]
  [Monoid P] [OpeningSemantics P F] {IsFee : F → Prop} {epoch : A → ℕ}
  {R : ℕ → F → Multiset F} {actionDigest : Δ → F} {feeDigest : Φ → F}
  {m : Model P C A ℕ} {evidence : EvidenceReplay.Model B D}
  {decode : B → EvidenceQuery.BucketView F A} {ValidBucket : QrBucket F A → Prop}
  {noteNf : F → ℕ → F} {sp₁ sp₂ : NoteSpendable F A}
  {chain l₁ l₂ : List (Chain.Stamp F A)} {acceptedAnchor : ℕ → A → Prop}
  {descs₁ descs₂ : List Δ} {fee₁ fee₂ : Φ} {adjunctFees₁ adjunctFees₂ : List Φ}
  {stamp₁ stamp₂ : PublishedStamp F A} {p₁ p₂ start₁ start : ℕ} {δ₁ δ₂ : Δ} {c : F}

def doubleSpendEvidenceBreak [DecidableEq P] [DecidableEq C] [DecidableEq A]
    [DecidableEq B] [DecidableEq D]
    (hc : ¬ IsSquare c) (hchain : Chain.Valid epoch acceptedAnchor chain)
    (h₁ : BundleVerified IsFee epoch R actionDigest feeDigest descs₁ fee₁ adjunctFees₁ stamp₁)
    (h₂ : BundleVerified IsFee epoch R actionDigest feeDigest descs₂ fee₂ adjunctFees₂ stamp₂)
    (hsplit : chain = l₁ ++ ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ :: l₂)
    (hs₂ : ⟨stamp₂.anchor, stamp₂.tachygrams, p₂⟩ ∈ l₂)
    (hδ₁ : δ₁ ∈ descs₁) (hδ₂ : δ₂ ∈ descs₂)
    (t₁ : SpendableTrace m ValidBucket
      (EvidenceQuery.Query m (OpeningSemantics.interpret : P →* F[X]) chain c evidence decode)
      noteNf start₁ sp₁)
    (t₂ : SpendableTrace m ValidBucket
      (EvidenceQuery.Query m (OpeningSemantics.interpret : P →* F[X]) chain c evidence decode)
      noteNf start sp₂)
    (hcm : sp₁.cm = sp₂.cm)
    (node₁ : NodeTrace m (epoch stamp₁.anchor) sp₁.anchor)
    (node₂ : NodeTrace m (epoch stamp₂.anchor) sp₂.anchor)
    (haction₁ : SpendAction R (epoch stamp₁.anchor) (spendBind noteNf sp₁) (actionDigest δ₁))
    (haction₂ : SpendAction R (epoch stamp₂.anchor) (spendBind noteNf sp₂) (actionDigest δ₂))
    (hstart : start ≤ p₁) : EvidenceQuery.Failure m evidence :=
  match doubleSpendBreak (EvidenceQuery.Query.oracle hc) hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂
      t₁ t₂ hcm node₁ node₂ haction₁ haction₂ hstart with
  | .inl anchorBreak =>
      .anchor ⟨node₁.openings ++ node₂.openings,
        (t₁.anchorInput :: node₁.inputs) ++ (t₂.anchorInput :: node₂.inputs), anchorBreak⟩
  | .inr queryBreak => queryBreak

end Tachyon
