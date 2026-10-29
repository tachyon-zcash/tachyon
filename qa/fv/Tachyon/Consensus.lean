import Tachyon.Consensus.Bundle

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

end Tachyon
