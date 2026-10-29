import Tachyon.QueryCertificates
import Tachyon.RoutedSpendBinding

/-!
# Double-spend reduction with checked per-query source data

Instantiate the query-parametric spendable traversal with actual
`SourceQueryBreaks.Certificate` data. Every query is reduced by its witnessed
source trace, canonical publication trace, source seal, scalar class checks,
mask bounds/register equations and proven routing retention. No global source
or profile completeness premise, and no `HashLaw`, is supplied.

Two accepted spends of one note then return an `ObservedBreak`: either the
anchor-preimage collision from spend binding or a commitment/hash collision
from a particular query's source comparison. The returned finite transcript
and its `ScopedBreak` are retained as data. `ObservedBreak.elim` supplies the
execution-local corollary when that returned transcript is collision-free.

**Representation boundary:** this wrapper specializes ace's current
`SpendableTrace` to Mathlib's `F[X]` opening type. Its instances are
noncomputable, so the wrapper inherits `noncomputable`; it is a mathematical
data-valued reduction, not an extracted runnable Rust program. No witness is
selected from classical existence. The generic `AnchorBreaks`, source and span
reducers accept a runtime opening type and compile without `noncomputable`.
Keeping this specialization avoids silently changing the existing trace API;
a fully executable end-to-end specialization needs a separate runtime-opening
interpretation phase. This is a documented representation-driven departure
from ragu's directly executable algebraic-witness examples.
-/

namespace Tachyon

open Polynomial AnchorBreaks SourceQueryBreaks

variable {F C A Δ Φ : Type*} [Field F] [DecidableEq F]
  {IsFee : F → Prop} {epoch : A → ℕ} {R : ℕ → F → Multiset F}
  {actionDigest : Δ → F} {feeDigest : Φ → F} {m : Model F[X] C A ℕ}
  {ValidBucket : QrBucket F A → Prop} {noteNf : F → ℕ → F}
  {sp₁ sp₂ : NoteSpendable F A} {chain l₁ l₂ : List (Chain.Stamp F A)}
  {acceptedAnchor : ℕ → A → Prop} {descs₁ descs₂ : List Δ} {fee₁ fee₂ : Φ}
  {adjunctFees₁ adjunctFees₂ : List Φ} {stamp₁ stamp₂ : PublishedStamp F A}
  {p₁ p₂ start₁ start : ℕ} {δ₁ δ₂ : Δ} {c : F}

/-- Complete source-query/spend-binding composition: contradictory accepted
spends yield concrete colliding inputs on a recorded finite transcript. -/
noncomputable def doubleSpendObservedBreak [DecidableEq F[X]] [DecidableEq C] [DecidableEq A]
    (hc : ¬ IsSquare c) (hchain : Chain.Valid epoch acceptedAnchor chain)
    (h₁ : BundleVerified IsFee epoch R actionDigest feeDigest descs₁ fee₁ adjunctFees₁ stamp₁)
    (h₂ : BundleVerified IsFee epoch R actionDigest feeDigest descs₂ fee₂ adjunctFees₂ stamp₂)
    (hsplit : chain = l₁ ++ ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ :: l₂)
    (hs₂ : ⟨stamp₂.anchor, stamp₂.tachygrams, p₂⟩ ∈ l₂)
    (hδ₁ : δ₁ ∈ descs₁) (hδ₂ : δ₂ ∈ descs₂)
    (t₁ : SpendableTrace m ValidBucket (Certificate m (MonoidHom.id F[X]) chain c)
      noteNf start₁ sp₁)
    (t₂ : SpendableTrace m ValidBucket (Certificate m (MonoidHom.id F[X]) chain c)
      noteNf start sp₂)
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
