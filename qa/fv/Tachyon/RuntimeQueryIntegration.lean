import Tachyon.QueryIntegration

/-!
# Runtime-opening specialization of the checked double-spend reduction

`doubleSpendRuntimeBreak` generalizes the earlier polynomial-specification
wrapper to a runtime opening type `P`. Spendable traces and source certificates
use the same `OpeningSemantics.interpret`. The function compiles as an ordinary
definition: hashes, equality decisions and collision witnesses operate on
actual opening/anchor data. Mathematical polynomials remain specifications in
proof fields, rather than being constructed by the runtime reduction.

As in ragu's break-witness discipline, the result is explicit data: a finite
observed transcript and either a commitment collision or a domain-tagged hash
collision on it. No global injectivity, existential collision axiom or global
query-completeness premise is assumed. The caller must still supply actual
certified finite traces; no PCD knowledge extractor is implemented here.
-/

namespace Tachyon

open Polynomial AnchorBreaks SourceQueryBreaks

variable {F P C A Δ Φ : Type*} [Field F] [DecidableEq F] [Monoid P] [OpeningSemantics P F]
  {IsFee : F → Prop} {epoch : A → ℕ} {R : ℕ → F → Multiset F}
  {actionDigest : Δ → F} {feeDigest : Φ → F} {m : Model P C A ℕ}
  {ValidBucket : QrBucket F A → Prop} {noteNf : F → ℕ → F}
  {sp₁ sp₂ : NoteSpendable F A} {chain l₁ l₂ : List (Chain.Stamp F A)}
  {acceptedAnchor : ℕ → A → Prop} {descs₁ descs₂ : List Δ} {fee₁ fee₂ : Φ}
  {adjunctFees₁ adjunctFees₂ : List Φ} {stamp₁ stamp₂ : PublishedStamp F A}
  {p₁ p₂ start₁ start : ℕ} {δ₁ δ₂ : Δ} {c : F}

/-- Two accepted spends of one note compute a concrete observed break, now
over the runtime opening representation shared by all trace/certificate layers. -/
def doubleSpendRuntimeBreak [DecidableEq P] [DecidableEq C] [DecidableEq A]
    (hc : ¬ IsSquare c) (hchain : Chain.Valid epoch acceptedAnchor chain)
    (h₁ : BundleVerified IsFee epoch R actionDigest feeDigest descs₁ fee₁ adjunctFees₁ stamp₁)
    (h₂ : BundleVerified IsFee epoch R actionDigest feeDigest descs₂ fee₂ adjunctFees₂ stamp₂)
    (hsplit : chain = l₁ ++ ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ :: l₂)
    (hs₂ : ⟨stamp₂.anchor, stamp₂.tachygrams, p₂⟩ ∈ l₂)
    (hδ₁ : δ₁ ∈ descs₁) (hδ₂ : δ₂ ∈ descs₂)
    (t₁ : SpendableTrace m ValidBucket
      (Certificate m (OpeningSemantics.interpret : P →* F[X]) chain c) noteNf start₁ sp₁)
    (t₂ : SpendableTrace m ValidBucket
      (Certificate m (OpeningSemantics.interpret : P →* F[X]) chain c) noteNf start sp₂)
    (hcm : sp₁.cm = sp₂.cm)
    (node₁ : NodeTrace m (epoch stamp₁.anchor) sp₁.anchor)
    (node₂ : NodeTrace m (epoch stamp₂.anchor) sp₂.anchor)
    (haction₁ : SpendAction R (epoch stamp₁.anchor) (spendBind noteNf sp₁) (actionDigest δ₁))
    (haction₂ : SpendAction R (epoch stamp₂.anchor) (spendBind noteNf sp₂) (actionDigest δ₂))
    (hstart : start ≤ p₁) : ObservedBreak m :=
  match doubleSpendBreak (Certificate.oracle hc) hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂
      t₁ t₂ hcm node₁ node₂ haction₁ haction₂ hstart with
  | .inl anchorBreak =>
      ⟨node₁.openings ++ node₂.openings,
        (t₁.anchorInput :: node₁.inputs) ++ (t₂.anchorInput :: node₂.inputs), anchorBreak⟩
  | .inr queryBreak => queryBreak

end Tachyon
