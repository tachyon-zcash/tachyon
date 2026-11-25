import Tachyon.ProvenanceTraces
import Tachyon.Consensus.Spends

/-!
# Stamp derivations as provenance traces

`StampTree.toTrace` maps a stamp derivation anchored on a chain node to a `StampTrace` whose
provenance is the tree's own leaf, so `StampTrace.findLeaf` applies to the derivations the
double-spend results carry. A leaf's provenance records whether it is a `FeeSeed` or `FeeFuse`
leaf, and the steps make that agree with `IsFee` of its digest. So a covered digest in the fee
domain is found among the derivation's positive leaves as a fee leaf (`StampTree.fee_leaf`): no
action leaf supplies it, and no division leaves it without one. For a covered spend's bundle, the
bundle's own fee digest is such a digest once it is in the fee domain (`CoveredSpend.fee_leaf`).
-/

namespace Tachyon

open Polynomial

universe u v

variable {F : Type u} {Γ : Type v} [Field F] {Spend : SpendHeader F → Prop}

/-- A leaf's digest. -/
def TreeLeaf.digest (actionDigest : Γ → F → F → F) : TreeLeaf F Γ Spend → F
  | .output d _ => d
  | .spend h _ g => actionDigest g h.nf_current h.nf_next
  | .fee f _ => f

/-- The leaf is a `FeeSeed` or `FeeFuse` leaf. -/
def TreeLeaf.IsFeeLeaf : TreeLeaf F Γ Spend → Prop
  | .fee _ _ => True
  | _ => False

/-- A tree leaf with digest `d` at anchor `a`, which is a fee leaf exactly when `IsFee d`. -/
def TreeProvenance (IsFee : F → Prop) (actionDigest : Γ → F → F → F)
    (Spend : SpendHeader F → Prop) (d a : F) : Type (max u v) :=
  {l : TreeLeaf F Γ Spend // l.digest actionDigest = d ∧ l.anchor = a ∧ (l.IsFeeLeaf ↔ IsFee d)}

variable {IsFee : F → Prop} {epoch : F → ℕ} {R : ℕ → F → Multiset F}
  {q : Chain.AnchorQueries F F ℕ} {nextStamp : F → ℕ → F[X] → F} {actionDigest : Γ → F → F → F}
  {Q : Γ → F → F → Prop} {genesis : F} {e₀ : ℕ} {nextEpoch : F → ℕ → F}

/-- An `Actions` derivation anchored on a chain node, as a trace of its own leaves. -/
noncomputable def ActionsTree.toTrace (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    (hepoch : ∀ {e : ℕ} {a : F}, Chain.Node q genesis e₀ nextStamp nextEpoch e a → epoch a = e)
    (hdigest : DigestLaw IsFee R actionDigest Q) {s : Stamp F F}
    (t : ActionsTree IsFee epoch R q nextStamp actionDigest Q Spend s) {e : ℕ} :
    Chain.Node q genesis e₀ nextStamp nextEpoch e s.anchor →
      ActionsTrace IsFee epoch R (TreeProvenance IsFee actionDigest Spend) s := by
  induction t with
  | output d a hd =>
    exact fun _ => .action d a ⟨.output d a, rfl, rfl, ⟨False.elim, fun h => (hd h).elim⟩⟩ hd
  | spend h hspend g hq =>
    intro _
    have hstamp : (⟨setPoly {actionDigest g h.nf_current h.nf_next},
        setPoly (R (epoch h.anchor) (actionDigest g h.nf_current h.nf_next)), h.anchor⟩ :
          Stamp F F) =
        ⟨setPoly {actionDigest g h.nf_current h.nf_next},
          setPoly ({h.nf_current, h.nf_next} : Multiset F), h.anchor⟩ := by
      rw [hdigest.pair _ hq]
    exact hstamp ▸ .action _ h.anchor
      ⟨.spend h hspend g, rfl, rfl, ⟨False.elim, fun hf => (hdigest.not_fee hq hf).elim⟩⟩
      (hdigest.not_fee hq)
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

/-- A `Stamp` derivation anchored on a chain node, as a trace of its own leaves. -/
noncomputable def StampTree.toTrace (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    (hepoch : ∀ {e : ℕ} {a : F}, Chain.Node q genesis e₀ nextStamp nextEpoch e a → epoch a = e)
    (hdigest : DigestLaw IsFee R actionDigest Q) {s : Stamp F F}
    (t : StampTree IsFee epoch R q nextStamp actionDigest Q Spend s) {e : ℕ} :
    Chain.Node q genesis e₀ nextStamp nextEpoch e s.anchor →
      StampTrace IsFee epoch R (TreeProvenance IsFee actionDigest Spend) s := by
  induction t with
  | @feeFuse left f actions hf =>
    exact fun hs => .feeFuse f ⟨.fee f left.anchor, rfl, rfl, ⟨fun _ => hf, fun _ => trivial⟩⟩
      (actions.toTrace hlaw hepoch hdigest hs) hf
  | feeSeed f a hf =>
    exact fun _ => .feeSeed f a ⟨.fee f a, rfl, rfl, ⟨fun _ => hf, fun _ => trivial⟩⟩ hf
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

/-- A covered digest in the fee domain is found among a chain-anchored derivation's positive leaves
as a fee leaf, at an anchor in the stamp's epoch. -/
theorem StampTree.fee_leaf [DecidableEq F] (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    (hepoch : ∀ {e : ℕ} {a : F}, Chain.Node q genesis e₀ nextStamp nextEpoch e a → epoch a = e)
    (hdigest : DigestLaw IsFee R actionDigest Q) {covered : Multiset F} {T : F[X]} {a : F}
    (t : StampTree IsFee epoch R q nextStamp actionDigest Q Spend ⟨setPoly covered, T, a⟩) {e : ℕ}
    (hs : Chain.Node q genesis e₀ nextStamp nextEpoch e a) {f : F} (hf : f ∈ covered)
    (hfee : IsFee f) :
    ∃ l ∈ (t.toTrace hlaw hepoch hdigest hs).positive,
      l.provenance.1 = .fee f l.anchor ∧ epoch l.anchor = epoch a := by
  obtain ⟨l, hl, hd, he⟩ := (t.toTrace hlaw hepoch hdigest hs).findLeaf rfl hf
  refine ⟨l, hl, ?_, he⟩
  have hk : l.provenance.1.IsFeeLeaf := l.provenance.2.2.2.mpr (hd ▸ hfee)
  have hdig := l.provenance.2.1
  have hanc := l.provenance.2.2.1
  revert hk hdig hanc
  generalize l.provenance.1 = x
  cases x with
  | output => exact fun hk => hk.elim
  | spend => exact fun hk => hk.elim
  | fee f' a' =>
    intro _ hdig hanc
    simp only [TreeLeaf.digest] at hdig
    simp only [TreeLeaf.anchor] at hanc
    rw [hdig, hd, hanc]

/-- A covered spend's stamp proof supplies the bundle's own fee digest by a fee leaf among its
positive leaves, once that digest is in the fee domain. -/
theorem CoveredSpend.fee_leaf [DecidableEq F] (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    (hepoch : ∀ {e : ℕ} {a : F}, Chain.Node q genesis e₀ nextStamp nextEpoch e a → epoch a = e)
    (hdigest : DigestLaw IsFee R actionDigest Q) {Φ : Type*} {feeDigest : Φ → F → F}
    {actions : List (Γ × F × F)} {fee : Φ × F} {adjunctFees : List (Φ × F)} {s : Chain.Stamp F F}
    {cm : F}
    (p : CoveredSpend IsFee epoch R q nextStamp actionDigest Q Spend feeDigest actions fee adjunctFees
      s cm) {e : ℕ} (hs : Chain.Node q genesis e₀ nextStamp nextEpoch e s.anchor)
    (hfee : IsFee (feeDigest fee.1 fee.2)) :
    ∃ l ∈ (p.tree.toTrace hlaw hepoch hdigest hs).positive,
      l.provenance.1 = .fee (feeDigest fee.1 fee.2) l.anchor ∧ epoch l.anchor = epoch s.anchor :=
  p.tree.fee_leaf hlaw hepoch hdigest hs (by simp [coveredDigests]) hfee

end Tachyon
