import Tachyon.Consensus
import Tachyon.SpendTree

/-!
# No double spend from covered spend leaves

`no_double_spend_of_valid` takes each stamp's nullifier pair as a hypothesis. Here each pair follows
from a spend leaf the stamp covers.

A `CoveredSpend` of note `cm` in a published stamp `s` is what `Bundle::verify` and the stamp proof
supply: the action set consensus rebuilt from the covered digests, a derivation of the verified
header `(setPoly covered, setPoly s.tachygrams, s.anchor)`, and a `SpendAction` leaf of that
derivation whose header carries `cm` and whose action digest is covered.

Consensus makes `s.anchor` an end-of-block anchor, so a chain node at its epoch `e`. Every leaf of
the derivation is then anchored on a chain node at `e` (`StampTree.leaves_node`), so the spend's
lineage is at epoch `e` and the spend carries the note's nullifiers at `e` and `e + 1`
(`SpendDerivable.pair`). The derivation is `StampDerivable` (`StampTree.derivable`), so the stamp
publishes the covered leaf's tachygrams, which `DigestLaw` makes that pair.

"Same note" is equal `cm`. Every header from the spend back to its lineage start threads `cm`,
`SpendBind` ties the note secret to the lineage by `cm`, and `NoteSeed` makes `cm` determine the
master key (`NoteSecretDerivable.master_eq`), so the nullifier sequence is the note's.
-/

namespace Tachyon

open Polynomial

universe u v

variable {F : Type u} {Γ : Type v} [Field F]

/-- A spend of note `cm` covered by the published stamp `s`. -/
structure CoveredSpend (IsFee : F → Prop) (epoch : F → ℕ) (R : ℕ → F → Multiset F)
    (nextStamp : F → ℕ → F[X] → F) (actionDigest : Γ → F → F → F)
    (Spend : SpendHeader F → Prop) (s : Chain.Stamp F F) (cm : F) : Type (max u v) where
  covered : Multiset F
  tree : StampTree IsFee epoch R nextStamp actionDigest Spend
    ⟨setPoly covered, setPoly (s.tachygrams : Multiset F), s.anchor⟩
  header : SpendHeader F
  spend : Spend header
  witness : Γ
  leaf : (TreeLeaf.spend header spend witness : TreeLeaf F Γ Spend) ∈ tree.leaves
  cm_eq : header.cm = cm
  digest_covered : actionDigest witness header.nf_current header.nf_next ∈ covered

variable [DecidableEq F] {W P : Type*} {IsFee : F → Prop} {epoch : F → ℕ}
  {R : ℕ → F → Multiset F} {actionDigest : Γ → F → F → F} {genesis : F} {e₀ : ℕ}
  {nextStamp : F → ℕ → F[X] → F} {nextEpoch : F → ℕ → F} {Unspent : NoteUnspent F → Prop}
  {noteCommit : W → F → F → F} {paymentKey : P → F → F} {nfMaster : F → F → F}
  {nullifier : F → ℕ → F}

/-- A covered spend of note `cm`, in a stamp anchored on a chain node, publishes the note's
nullifiers at the anchor's epoch and the next. -/
theorem CoveredSpend.pair_le (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hepoch : ∀ {e : ℕ} {a : F}, Chain.Node genesis e₀ nextStamp nextEpoch e a → epoch a = e)
    (hunspent : UnspentSpec nextEpoch Unspent) (hnote : NoteLaw noteCommit paymentKey)
    (hdigest : DigestLaw IsFee R actionDigest) {s : Chain.Stamp F F} {cm master : F}
    (p : CoveredSpend IsFee epoch R nextStamp actionDigest
      (SpendDerivable nextStamp Unspent (NoteSecretDerivable noteCommit paymentKey nfMaster)
        nullifier) s cm)
    (hsecret : NoteSecretDerivable noteCommit paymentKey nfMaster ⟨cm, master⟩)
    (hs : Chain.Node genesis e₀ nextStamp nextEpoch (epoch s.anchor) s.anchor) :
    ({nullifier master (epoch s.anchor), nullifier master (epoch s.anchor + 1)} : Multiset F) ≤
      (s.tachygrams : Multiset F) := by
  have htachygrams : (s.tachygrams : Multiset F) = p.covered.bind (R (epoch s.anchor)) :=
    setPoly_injective ((p.tree.derivable hlaw hepoch hdigest hs).published rfl)
  obtain ⟨k, hk, hkcm, hcurrent, hnext⟩ :=
    p.spend.pair hlaw hunspent (p.tree.leaves_node hlaw hs _ p.leaf)
  obtain rfl : k.master = master := hk.master_eq hnote hsecret (hkcm.trans p.cm_eq)
  rw [htachygrams, ← hcurrent, ← hnext,
    ← hdigest.pair (epoch s.anchor) p.witness p.header.nf_current p.header.nf_next]
  exact Multiset.le_bind _ p.digest_covered

/-- On a valid chain, two stamps that each cover a spend of note `cm`, the first earlier in chain
order, contradict the second spend's lineage starting from `start`. -/
theorem no_double_spend_of_covered_spends (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hepoch : ∀ {e : ℕ} {a : F}, Chain.Node genesis e₀ nextStamp nextEpoch e a → epoch a = e)
    (hunspent : UnspentSpec nextEpoch Unspent) (hnote : NoteLaw noteCommit paymentKey)
    (hdigest : DigestLaw IsFee R actionDigest)
    {chain l₁ l₂ : List (Chain.Stamp F F)} {s₁ s₂ : Chain.Stamp F F} {cm master : F}
    {start : ℕ}
    (hchain : Chain.Valid epoch (Chain.BlockAnchor genesis e₀ nextStamp nextEpoch) chain)
    (hsplit : chain = l₁ ++ s₁ :: l₂) (hs₂ : s₂ ∈ l₂)
    (p₁ : CoveredSpend IsFee epoch R nextStamp actionDigest
      (SpendDerivable nextStamp Unspent (NoteSecretDerivable noteCommit paymentKey nfMaster)
        nullifier) s₁ cm)
    (p₂ : CoveredSpend IsFee epoch R nextStamp actionDigest
      (SpendDerivable nextStamp Unspent (NoteSecretDerivable noteCommit paymentKey nfMaster)
        nullifier) s₂ cm)
    (hsecret : NoteSecretDerivable noteCommit paymentKey nfMaster ⟨cm, master⟩)
    (hlineage : ∀ x, start ≤ x → x < epoch s₂.anchor →
      ¬ Chain.published chain x (nullifier master x))
    (hstart : start ≤ s₁.epoch) : False := by
  have hnode : ∀ s ∈ chain, Chain.Node genesis e₀ nextStamp nextEpoch (epoch s.anchor) s.anchor :=
    fun s hs => (hchain.accepted s hs).anchor_accepted.toNode
  exact no_double_spend_of_valid (nf := nullifier master) hchain hsplit hs₂
    (p₁.pair_le hlaw hepoch hunspent hnote hdigest hsecret (hnode s₁ (by simp [hsplit])))
    (p₂.pair_le hlaw hepoch hunspent hnote hdigest hsecret (hnode s₂ (by simp [hsplit, hs₂])))
    hlineage hstart

end Tachyon
