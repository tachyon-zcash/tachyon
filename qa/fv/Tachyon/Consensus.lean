import Tachyon.Consensus.Bundle
import Tachyon.Consensus.Chain
import Tachyon.Spendable

/-!
# No double spend

A spend anchored at epoch `a` publishes the note's nullifier pair `{nf a, nf (a + 1)}`. Two consensus
rules and one proof-tree fact rule out a second spend of the same note:

* **Anchor recency.** A stamp's anchor epoch is its publication epoch or the one before.
* **Two-epoch window.** A published tachygram is absent from every earlier block of its publication
  epoch and the one before.
* **Spendable lineage.** A spend anchored at epoch `a` proves, for each epoch `x` from its lineage
  start up to `a`, that `nf x` is absent from epoch `x`'s published tachygrams (`NoteUnspent`,
  checked per epoch by `QrUnspentInit` and `UnspentLift` against that epoch's `QrBucket`).

A second spend anchored within one epoch of the first's publication shares a nullifier with it and
fails the window. One anchored later crosses the first's publication epoch and fails its lineage.

`no_double_spend` states the argument over abstract epochs. `no_double_spend_of_valid` takes recency
and the window from `Chain.Valid`, leaving the lineage as a hypothesis. `no_double_spend_of_bundles`
takes each stamp's nullifier pair from bundle verification. `BundleVerified.no_double_spend` covers
two spends in one bundle. `no_double_spend_of_spendable` takes the lineage from a derivable
`NoteSpendable` whose buckets hold their whole epochs. `doubleSpendBreak` (`RoutedSpendBinding.lean`)
takes both nullifier pairs and the second lineage's epoch from traced spendables, returning a scoped
collision instead of assuming hash injectivity.

`ActionsDerivable.liftStep` and `StampDerivable.liftStep` discharge the lift constructors' epoch
hypothesis for a `Chain.StampLiftStep` along a derivable span that ends at a chain node.

The second spend's lineage must start no later than the first's publication. A lineage starting
from a later publication of the same `cm` spends a second paid note, not the first one again.
-/

namespace Tachyon

/-- A published spend: its anchor epoch, its publication epoch, and the epoch its spendable lineage
starts from. -/
structure SpendRecord where
  anchor : ℕ
  publication : ℕ
  lineageStart : ℕ

variable {F : Type*}

/-- The nullifier pair a spend publishes. -/
def SpendRecord.pair (nf : ℕ → F) (s : SpendRecord) : Multiset F :=
  {nf s.anchor, nf (s.anchor + 1)}

/-- Anchor recency: the anchor epoch is the publication epoch or the one before. -/
def SpendRecord.Recent (s : SpendRecord) : Prop :=
  s.anchor ≤ s.publication ∧ s.publication ≤ s.anchor + 1

/-- The spendable lineage: `nf x` is unpublished in each epoch `x` from the lineage start up to the
anchor epoch. -/
def SpendRecord.Lineage (published : ℕ → F → Prop) (nf : ℕ → F) (s : SpendRecord) : Prop :=
  ∀ x, s.lineageStart ≤ x → x < s.anchor → ¬ published x (nf x)

/-- Two spends of one note with nullifiers `nf`, the first earlier in chain order, cannot both be
accepted. `hwindow` is the two-epoch window applied to the second spend against the first. -/
theorem no_double_spend {published : ℕ → F → Prop} {nf : ℕ → F} {first second : SpendRecord}
    (hfirst : first.Recent) (hsecond : second.Recent)
    (hpublished : ∀ t ∈ first.pair nf, published first.publication t)
    (horder : first.publication ≤ second.publication)
    (hwindow : second.publication ≤ first.publication + 1 →
      Disjoint (first.pair nf) (second.pair nf))
    (hlineage : second.Lineage published nf)
    (hstart : second.lineageStart ≤ first.publication) : False := by
  obtain ⟨ha1, hp1⟩ := hfirst
  obtain ⟨ha2, hp2⟩ := hsecond
  by_cases hcross : first.publication < second.anchor
  · refine hlineage first.publication hstart hcross (hpublished _ ?_)
    rcases (by omega : first.publication = first.anchor ∨
        first.publication = first.anchor + 1) with he | he <;>
      simp [SpendRecord.pair, he]
  · have hdisjoint := hwindow (by omega)
    rcases (by omega : second.anchor = first.anchor ∨ second.anchor + 1 = first.anchor ∨
        second.anchor = first.anchor + 1) with he | he | he
    · exact Multiset.disjoint_left.mp hdisjoint
        (show nf first.anchor ∈ first.pair nf by simp [SpendRecord.pair])
        (by simp [SpendRecord.pair, he])
    · exact Multiset.disjoint_left.mp hdisjoint
        (show nf first.anchor ∈ first.pair nf by simp [SpendRecord.pair])
        (by simp [SpendRecord.pair, ← he])
    · exact Multiset.disjoint_left.mp hdisjoint
        (show nf (first.anchor + 1) ∈ first.pair nf by simp [SpendRecord.pair])
        (by simp [SpendRecord.pair, he])

/-- On a valid chain, two stamps that each publish a spend of the note with nullifiers `nf`, the
first earlier in chain order, contradict the second spend's lineage starting from `start`. -/
theorem no_double_spend_of_valid {A : Type*} {epoch : A → ℕ} {acceptedAnchor : ℕ → A → Prop}
    {chain l₁ l₂ : List (Chain.Stamp F A)} {s₁ s₂ : Chain.Stamp F A} {nf : ℕ → F} {start : ℕ}
    (hchain : Chain.Valid epoch acceptedAnchor chain)
    (hsplit : chain = l₁ ++ s₁ :: l₂) (hs₂ : s₂ ∈ l₂)
    (hpair₁ : {nf (epoch s₁.anchor), nf (epoch s₁.anchor + 1)} ≤ (s₁.tachygrams : Multiset F))
    (hpair₂ : {nf (epoch s₂.anchor), nf (epoch s₂.anchor + 1)} ≤ (s₂.tachygrams : Multiset F))
    (hlineage : ∀ x, start ≤ x → x < epoch s₂.anchor → ¬ Chain.published chain x (nf x))
    (hstart : start ≤ s₁.epoch) : False := by
  have hs₁mem : s₁ ∈ chain := by simp [hsplit]
  obtain ⟨horder, hwindow⟩ := hchain.disjoint_of_le_window hsplit hs₂ hpair₁ hpair₂
  exact no_double_spend (first := ⟨epoch s₁.anchor, s₁.epoch, start⟩)
    (second := ⟨epoch s₂.anchor, s₂.epoch, start⟩)
    (hchain.accepted s₁ hs₁mem).recency (hchain.accepted s₂ (by simp [hsplit, hs₂])).recency
    (Chain.published_of_le hs₁mem hpair₁) horder hwindow hlineage hstart

section Bundles

variable {A Δ Φ : Type*} [Field F] [DecidableEq F] {IsFee : F → Prop} {epoch : A → ℕ}
  {R : ℕ → F → Multiset F} {actionDigest : Δ → F} {feeDigest : Φ → F} {nf : ℕ → F}

/-- One verified bundle cannot cover two spends of the note with nullifiers `nf`. `R` derives a
spend's nullifier pair at its anchor's epoch. -/
theorem BundleVerified.no_double_spend {descs l₁ l₂ : List Δ} {fee : Φ} {adjunctFees : List Φ}
    {stamp : PublishedStamp F A} {δ₁ δ₂ : Δ}
    (h : BundleVerified IsFee epoch R actionDigest feeDigest descs fee adjunctFees stamp)
    (hsplit : descs = l₁ ++ δ₁ :: l₂) (hδ₂ : δ₂ ∈ l₂)
    (hspend₁ : R (epoch stamp.anchor) (actionDigest δ₁) =
      {nf (epoch stamp.anchor), nf (epoch stamp.anchor + 1)})
    (hspend₂ : R (epoch stamp.anchor) (actionDigest δ₂) =
      {nf (epoch stamp.anchor), nf (epoch stamp.anchor + 1)}) : False := by
  have hdisjoint := h.descs_disjoint hsplit hδ₂
  rw [hspend₁, hspend₂] at hdisjoint
  exact Multiset.disjoint_left.mp hdisjoint (Multiset.mem_cons_self _ _)
    (Multiset.mem_cons_self _ _)

/-- Two verified bundles on a valid chain, the first earlier in chain order, cannot both spend the
note with nullifiers `nf`, given the second spend's lineage from `start`. Each bundle's stamp enters
the chain at its publication epoch. -/
theorem no_double_spend_of_bundles {chain l₁ l₂ : List (Chain.Stamp F A)}
    {acceptedAnchor : ℕ → A → Prop} {descs₁ descs₂ : List Δ} {fee₁ fee₂ : Φ}
    {adjunctFees₁ adjunctFees₂ : List Φ} {stamp₁ stamp₂ : PublishedStamp F A} {p₁ p₂ start : ℕ}
    {δ₁ δ₂ : Δ} (hchain : Chain.Valid epoch acceptedAnchor chain)
    (h₁ : BundleVerified IsFee epoch R actionDigest feeDigest descs₁ fee₁ adjunctFees₁ stamp₁)
    (h₂ : BundleVerified IsFee epoch R actionDigest feeDigest descs₂ fee₂ adjunctFees₂ stamp₂)
    (hsplit : chain = l₁ ++ ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ :: l₂)
    (hs₂ : ⟨stamp₂.anchor, stamp₂.tachygrams, p₂⟩ ∈ l₂)
    (hδ₁ : δ₁ ∈ descs₁) (hδ₂ : δ₂ ∈ descs₂)
    (hspend₁ : R (epoch stamp₁.anchor) (actionDigest δ₁) =
      {nf (epoch stamp₁.anchor), nf (epoch stamp₁.anchor + 1)})
    (hspend₂ : R (epoch stamp₂.anchor) (actionDigest δ₂) =
      {nf (epoch stamp₂.anchor), nf (epoch stamp₂.anchor + 1)})
    (hlineage : ∀ x, start ≤ x → x < epoch stamp₂.anchor → ¬ Chain.published chain x (nf x))
    (hstart : start ≤ p₁) : False :=
  no_double_spend_of_valid hchain hsplit hs₂
    (hspend₁ ▸ h₁.leaf_published
      (Multiset.mem_coe.mpr (List.mem_append_left _ (List.mem_map_of_mem hδ₁))))
    (hspend₂ ▸ h₂.leaf_published
      (Multiset.mem_coe.mpr (List.mem_append_left _ (List.mem_map_of_mem hδ₂)))) hlineage hstart

open Polynomial in
/-- Two verified bundles on a valid chain, the first earlier in chain order, cannot both spend the
note `sp.cm` when the second spends from a derivable `NoteSpendable` `sp` at its anchor's epoch, its
lineage starts from `start`, and every valid bucket holds its whole epoch. -/
theorem no_double_spend_of_spendable {ValidBucket : QrBucket F A → Prop} {noteNf : F → ℕ → F}
    {nextStamp : A → ℕ → F[X] → A} {sp : NoteSpendable F A} {chain l₁ l₂ : List (Chain.Stamp F A)}
    {acceptedAnchor : ℕ → A → Prop} {descs₁ descs₂ : List Δ} {fee₁ fee₂ : Φ}
    {adjunctFees₁ adjunctFees₂ : List Φ} {stamp₁ stamp₂ : PublishedStamp F A} {p₁ p₂ start : ℕ}
    {δ₁ δ₂ : Δ} (hchain : Chain.Valid epoch acceptedAnchor chain)
    (h₁ : BundleVerified IsFee epoch R actionDigest feeDigest descs₁ fee₁ adjunctFees₁ stamp₁)
    (h₂ : BundleVerified IsFee epoch R actionDigest feeDigest descs₂ fee₂ adjunctFees₂ stamp₂)
    (hsplit : chain = l₁ ++ ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ :: l₂)
    (hs₂ : ⟨stamp₂.anchor, stamp₂.tachygrams, p₂⟩ ∈ l₂)
    (hδ₁ : δ₁ ∈ descs₁) (hδ₂ : δ₂ ∈ descs₂)
    (hspend₁ : R (epoch stamp₁.anchor) (actionDigest δ₁) =
      {noteNf sp.cm (epoch stamp₁.anchor), noteNf sp.cm (epoch stamp₁.anchor + 1)})
    (hspend₂ : R (epoch stamp₂.anchor) (actionDigest δ₂) =
      {noteNf sp.cm (epoch stamp₂.anchor), noteNf sp.cm (epoch stamp₂.anchor + 1)})
    (hcomplete : ∀ ⦃b : QrBucket F A⦄, ValidBucket b → CompleteBucket chain b)
    (hsp : SpendableDerivable ValidBucket noteNf nextStamp start sp)
    (hepoch : sp.epoch_current = epoch stamp₂.anchor) (hstart : start ≤ p₁) : False :=
  no_double_spend_of_bundles hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂ hspend₁ hspend₂
    (hepoch ▸ (hsp.lineage hcomplete).2) hstart

end Bundles

section Lift

open Polynomial

variable {E : Type*} [Field F] {IsFee : F → Prop} {epoch : F → E} {R : E → F → Multiset F}
  {genesis : F} {e₀ : E} {nextStamp : F → E → F[X] → F} {nextEpoch : F → E → F}
  {s s' : Stamp F F} {span : Chain.AnchorSpan F} {e : E}

/-- `ActionLift` along a derivable span ending at a chain node yields a derivable `Actions`
header, for an epoch labelling that agrees with the chain. -/
theorem ActionsDerivable.liftStep (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hepoch : ∀ {e : E} {a : F}, Chain.Node genesis e₀ nextStamp nextEpoch e a → epoch a = e)
    (hs : ActionsDerivable IsFee epoch R s) (hspan : Chain.SpanDerivable nextStamp span)
    (hlift : Chain.StampLiftStep s span s')
    (hend : Chain.Node genesis e₀ nextStamp nextEpoch e s'.anchor) :
    ActionsDerivable IsFee epoch R s' := by
  have hsame := hlift.epoch_eq hlaw hepoch hspan hend
  obtain ⟨-, rfl⟩ := hlift
  exact ActionsDerivable.lift span.anchor_end hs hsame

/-- `StampLift` along a derivable span ending at a chain node yields a derivable `Stamp` header,
for an epoch labelling that agrees with the chain. -/
theorem StampDerivable.liftStep (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hepoch : ∀ {e : E} {a : F}, Chain.Node genesis e₀ nextStamp nextEpoch e a → epoch a = e)
    (hs : StampDerivable IsFee epoch R s) (hspan : Chain.SpanDerivable nextStamp span)
    (hlift : Chain.StampLiftStep s span s')
    (hend : Chain.Node genesis e₀ nextStamp nextEpoch e s'.anchor) :
    StampDerivable IsFee epoch R s' := by
  have hsame := hlift.epoch_eq hlaw hepoch hspan hend
  obtain ⟨-, rfl⟩ := hlift
  exact StampDerivable.lift span.anchor_end hs hsame

end Lift

end Tachyon
