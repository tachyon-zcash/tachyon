import Tachyon.ProofTree
import Tachyon.Spend

/-!
# Stamp derivations with span lifts

`ActionsTree` and `StampTree` are `ActionsDerivable` and `StampDerivable` as data, with two leaf and
lift changes taken from the Rust steps:

- A `SpendAction` leaf takes a spend header `h` that `Spend` accepts. It derives the action set
  `{actionDigest g nf_current nf_next}` and the tachygram set `{nf_current, nf_next}` at `h`'s
  anchor (`crates/tachyon/src/stamp/proof/stamp.rs`). `g` stands for the digest's other inputs,
  `cv` and `rk`. The digest is a call in `Q`. `OutputAction`, `FeeSeed` and `FeeFuse` leaves are as
  in `ActionsDerivable` and `StampDerivable`.
- `ActionLift` and `StampLift` take a derivable `AnchorSpan` over the anchor-fold calls `q` and the
  `StampLiftStep` relation, instead of the bare `epoch a = epoch s.anchor` hypothesis.

Merge, unmerge and `FeeFuse` keep the anchor, and a lift's input anchor is a chain node at its
output's epoch (`StampLiftStep.node_same_epoch`). So when the root anchor is a chain node at epoch
`e`, every leaf's anchor is a chain node at `e` (`StampTree.leaves_node`), and the tree is
`StampDerivable` (`StampTree.derivable`).

`DigestLaw` states the pairing `R` for the spend digests in `Q`: an action digest absorbs its
tachygram pair's sum and product, which fix the pair.
-/

namespace Tachyon

open Polynomial

universe u v

variable {F : Type u} {Γ : Type v} [Field F]

/-- A leaf occurrence of a stamp derivation. -/
inductive TreeLeaf (F : Type u) (Γ : Type v) (Spend : SpendHeader F → Prop) : Type (max u v)
  | output (d a : F)
  | spend (h : SpendHeader F) (hspend : Spend h) (g : Γ)
  | fee (f a : F)

/-- The anchor a leaf derives at. -/
def TreeLeaf.anchor {Spend : SpendHeader F → Prop} : TreeLeaf F Γ Spend → F
  | .output _ a => a
  | .spend h _ _ => h.anchor
  | .fee _ a => a

/-- `Actions` derivations: `OutputAction` and `SpendAction` leaves, `ActionMerge` and
`ActionLift`. -/
inductive ActionsTree (IsFee : F → Prop) (epoch : F → ℕ) (R : ℕ → F → Multiset F)
    (q : Chain.AnchorQueries F F ℕ) (nextStamp : F → ℕ → F[X] → F) (actionDigest : Γ → F → F → F)
    (Q : Γ → F → F → Prop) (Spend : SpendHeader F → Prop) : Stamp F F → Type (max u v)
  | output (d a : F) :
      ¬ IsFee d →
        ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend
          ⟨setPoly {d}, setPoly (R (epoch a) d), a⟩
  | spend (h : SpendHeader F) (hspend : Spend h) (g : Γ) :
      Q g h.nf_current h.nf_next →
      ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend
        ⟨setPoly {actionDigest g h.nf_current h.nf_next},
          setPoly ({h.nf_current, h.nf_next} : Multiset F), h.anchor⟩
  | merge {left right merged : Stamp F F} :
      ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend left →
        ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend right →
        Merge left right merged → ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend merged
  | lift {s s' : Stamp F F} {span : Chain.AnchorSpan F} :
      ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend s →
        Chain.SpanDerivable q nextStamp span → Chain.StampLiftStep s span s' →
        ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend s'

/-- `Stamp` derivations: `FeeFuse` from `Actions`, `FeeSeed`, `StampMerge`, `StampUnmerge` and
`StampLift`. -/
inductive StampTree (IsFee : F → Prop) (epoch : F → ℕ) (R : ℕ → F → Multiset F)
    (q : Chain.AnchorQueries F F ℕ) (nextStamp : F → ℕ → F[X] → F) (actionDigest : Γ → F → F → F)
    (Q : Γ → F → F → Prop) (Spend : SpendHeader F → Prop) : Stamp F F → Type (max u v)
  | feeFuse {left : Stamp F F} (f : F) :
      ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend left → IsFee f →
        StampTree IsFee epoch R q nextStamp actionDigest Q Spend
          ⟨left.actions * setPoly {f}, left.tachygrams * setPoly (R (epoch left.anchor) f),
            left.anchor⟩
  | feeSeed (f a : F) :
      IsFee f →
        StampTree IsFee epoch R q nextStamp actionDigest Q Spend
          ⟨setPoly {f}, setPoly (R (epoch a) f), a⟩
  | merge {left right merged : Stamp F F} :
      StampTree IsFee epoch R q nextStamp actionDigest Q Spend left →
        StampTree IsFee epoch R q nextStamp actionDigest Q Spend right →
        Merge left right merged → StampTree IsFee epoch R q nextStamp actionDigest Q Spend merged
  | unmerge {dividend divisor quotient : Stamp F F} :
      StampTree IsFee epoch R q nextStamp actionDigest Q Spend dividend →
        StampTree IsFee epoch R q nextStamp actionDigest Q Spend divisor →
        Unmerge dividend divisor quotient →
        StampTree IsFee epoch R q nextStamp actionDigest Q Spend quotient
  | lift {s s' : Stamp F F} {span : Chain.AnchorSpan F} :
      StampTree IsFee epoch R q nextStamp actionDigest Q Spend s →
        Chain.SpanDerivable q nextStamp span → Chain.StampLiftStep s span s' →
        StampTree IsFee epoch R q nextStamp actionDigest Q Spend s'

variable {IsFee : F → Prop} {epoch : F → ℕ} {R : ℕ → F → Multiset F}
  {q : Chain.AnchorQueries F F ℕ} {nextStamp : F → ℕ → F[X] → F} {actionDigest : Γ → F → F → F}
  {Q : Γ → F → F → Prop} {Spend : SpendHeader F → Prop}

/-- The derivation's leaf occurrences. -/
def ActionsTree.leaves {s : Stamp F F} :
    ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend s → List (TreeLeaf F Γ Spend)
  | .output d a _ => [.output d a]
  | .spend h hspend g _ => [.spend h hspend g]
  | .merge left right _ => left.leaves ++ right.leaves
  | .lift t _ _ => t.leaves

/-- The derivation's leaf occurrences, dividends' and divisors' alike. -/
def StampTree.leaves {s : Stamp F F} :
    StampTree IsFee epoch R q nextStamp actionDigest Q Spend s → List (TreeLeaf F Γ Spend)
  | .feeFuse (left := left) f actions _ => actions.leaves ++ [.fee f left.anchor]
  | .feeSeed f a _ => [.fee f a]
  | .merge left right _ => left.leaves ++ right.leaves
  | .unmerge dividend divisor _ => dividend.leaves ++ divisor.leaves
  | .lift t _ _ => t.leaves

/-- The pairing `R` for the spend digest calls `Q`, idealizing `Tachyon-ActionDg` collision
resistance and its separation from `Tachyon-FeeDg` on those calls. A finite `Q` without a collision
satisfies it. -/
structure DigestLaw (IsFee : F → Prop) (R : ℕ → F → Multiset F)
    (actionDigest : Γ → F → F → F) (Q : Γ → F → F → Prop) : Prop where
  pair : ∀ e {g t₁ t₂}, Q g t₁ t₂ → R e (actionDigest g t₁ t₂) = {t₁, t₂}
  not_fee : ∀ {g t₁ t₂}, Q g t₁ t₂ → ¬ IsFee (actionDigest g t₁ t₂)

/-- Every spend leaf of an `Actions` derivation is a digest call in `Q`. -/
theorem ActionsTree.spend_queried {s : Stamp F F}
    (t : ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend s) {h : SpendHeader F}
    {hspend : Spend h} {g : Γ} (hl : (TreeLeaf.spend h hspend g : TreeLeaf F Γ Spend) ∈ t.leaves) :
    Q g h.nf_current h.nf_next := by
  induction t with
  | output => simp [ActionsTree.leaves] at hl
  | spend _ _ _ hq =>
    rw [ActionsTree.leaves, List.mem_singleton] at hl
    cases hl
    exact hq
  | merge _ _ _ ihl ihr =>
    rw [ActionsTree.leaves, List.mem_append] at hl
    exact hl.elim ihl ihr
  | lift _ _ _ ih => exact ih hl

/-- Every spend leaf of a `Stamp` derivation is a digest call in `Q`. -/
theorem StampTree.spend_queried {s : Stamp F F}
    (t : StampTree IsFee epoch R q nextStamp actionDigest Q Spend s) {h : SpendHeader F}
    {hspend : Spend h} {g : Γ} (hl : (TreeLeaf.spend h hspend g : TreeLeaf F Γ Spend) ∈ t.leaves) :
    Q g h.nf_current h.nf_next := by
  induction t with
  | feeFuse _ actions _ =>
    rw [StampTree.leaves, List.mem_append] at hl
    exact hl.elim actions.spend_queried (by simp)
  | feeSeed => simp [StampTree.leaves] at hl
  | merge _ _ _ ihl ihr =>
    rw [StampTree.leaves, List.mem_append] at hl
    exact hl.elim ihl ihr
  | unmerge _ _ _ ihdividend ihdivisor =>
    rw [StampTree.leaves, List.mem_append] at hl
    exact hl.elim ihdividend ihdivisor
  | lift _ _ _ ih => exact ih hl

variable {genesis : F} {e₀ : ℕ} {nextEpoch : F → ℕ → F}

/-- Every leaf of an `Actions` derivation whose anchor is in a stamp-closed anchor set at epoch `e`,
such as the chain nodes, is anchored in that set at `e`. -/
theorem ActionsTree.leaves_node {Good : ℕ → F → Prop}
    (hclosed : Chain.StampClosed q nextStamp Good) {s : Stamp F F}
    (t : ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend s) {e : ℕ} :
    Good e s.anchor → ∀ l ∈ t.leaves, Good e l.anchor := by
  induction t with
  | output d a _ => simp [ActionsTree.leaves, TreeLeaf.anchor]
  | spend h hspend g _ => simp [ActionsTree.leaves, TreeLeaf.anchor]
  | merge _ _ hm ihl ihr =>
    intro hs l hl
    rw [hm.merged_anchor] at hs
    rw [ActionsTree.leaves, List.mem_append] at hl
    exact hl.elim (ihl hs l) (ihr (hm.anchor ▸ hs) l)
  | lift _ hspan hlift ih => exact fun hs => ih (hlift.node_same_epoch hclosed hspan hs)

/-- Every leaf of a `Stamp` derivation whose anchor is in a stamp-closed anchor set at epoch `e`,
such as the chain nodes, is anchored in that set at `e`. -/
theorem StampTree.leaves_node {Good : ℕ → F → Prop}
    (hclosed : Chain.StampClosed q nextStamp Good) {s : Stamp F F}
    (t : StampTree IsFee epoch R q nextStamp actionDigest Q Spend s) {e : ℕ} :
    Good e s.anchor → ∀ l ∈ t.leaves, Good e l.anchor := by
  induction t with
  | feeFuse f actions _ =>
    intro hs l hl
    rw [StampTree.leaves, List.mem_append, List.mem_singleton] at hl
    rcases hl with hl | rfl
    · exact actions.leaves_node hclosed hs l hl
    · exact hs
  | feeSeed f a _ => simp [StampTree.leaves, TreeLeaf.anchor]
  | merge _ _ hm ihl ihr =>
    intro hs l hl
    rw [hm.merged_anchor] at hs
    rw [StampTree.leaves, List.mem_append] at hl
    exact hl.elim (ihl hs l) (ihr (hm.anchor ▸ hs) l)
  | unmerge _ _ hu ihdividend ihdivisor =>
    intro hs l hl
    rw [hu.quotient_anchor] at hs
    rw [StampTree.leaves, List.mem_append] at hl
    exact hl.elim (ihdividend hs l) (ihdivisor (hu.anchor ▸ hs) l)
  | lift _ hspan hlift ih => exact fun hs => ih (hlift.node_same_epoch hclosed hspan hs)

/-- An `Actions` derivation whose anchor is a chain node is `ActionsDerivable`: each lift preserves
the epoch. -/
theorem ActionsTree.derivable (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    (hepoch : ∀ {e : ℕ} {a : F}, Chain.Node q genesis e₀ nextStamp nextEpoch e a → epoch a = e)
    (hdigest : DigestLaw IsFee R actionDigest Q) {s : Stamp F F}
    (t : ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend s) {e : ℕ} :
    Chain.Node q genesis e₀ nextStamp nextEpoch e s.anchor → ActionsDerivable IsFee epoch R s := by
  induction t with
  | output d a hd => exact fun _ => .action d a hd
  | spend h _ g hq =>
    intro _
    have hleaf := ActionsDerivable.action (IsFee := IsFee) (epoch := epoch) (R := R)
      (actionDigest g h.nf_current h.nf_next) h.anchor (hdigest.not_fee hq)
    rwa [hdigest.pair _ hq] at hleaf
  | merge _ _ hm ihl ihr =>
    intro hs
    rw [hm.merged_anchor] at hs
    exact .merge (ihl hs) (ihr (hm.anchor ▸ hs)) hm
  | lift _ hspan hlift ih =>
    intro hs
    have hepoch_eq := hlift.epoch_eq hlaw hepoch hspan hs
    have hprev := ih (hlift.node_same_epoch (Chain.Node.stampClosed hlaw) hspan hs)
    obtain ⟨-, rfl⟩ := hlift
    exact .lift _ hprev hepoch_eq

/-- A `Stamp` derivation whose anchor is a chain node is `StampDerivable`: each lift preserves the
epoch. -/
theorem StampTree.derivable (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    (hepoch : ∀ {e : ℕ} {a : F}, Chain.Node q genesis e₀ nextStamp nextEpoch e a → epoch a = e)
    (hdigest : DigestLaw IsFee R actionDigest Q) {s : Stamp F F}
    (t : StampTree IsFee epoch R q nextStamp actionDigest Q Spend s) {e : ℕ} :
    Chain.Node q genesis e₀ nextStamp nextEpoch e s.anchor → StampDerivable IsFee epoch R s := by
  induction t with
  | feeFuse f actions hf => exact fun hs => .feeFuse f (actions.derivable hlaw hepoch hdigest hs) hf
  | feeSeed f a hf => exact fun _ => .feeSeed f a hf
  | merge _ _ hm ihl ihr =>
    intro hs
    rw [hm.merged_anchor] at hs
    exact .merge (ihl hs) (ihr (hm.anchor ▸ hs)) hm
  | unmerge _ _ hu ihdividend ihdivisor =>
    intro hs
    rw [hu.quotient_anchor] at hs
    exact .unmerge (ihdividend hs) (ihdivisor (hu.anchor ▸ hs)) hu
  | lift _ hspan hlift ih =>
    intro hs
    have hepoch_eq := hlift.epoch_eq hlaw hepoch hspan hs
    have hprev := ih (hlift.node_same_epoch (Chain.Node.stampClosed hlaw) hspan hs)
    obtain ⟨-, rfl⟩ := hlift
    exact .lift _ hprev hepoch_eq

end Tachyon
