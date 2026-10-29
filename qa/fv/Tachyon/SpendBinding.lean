import Tachyon.Spendable

/-!
# Spend binding

`SpendBind` takes a `NoteSpendable (cm, epoch_current, anchor)` and derives the note's nullifiers at
`epoch_current` and the epoch after, at the lineage's anchor. `SpendAction` publishes that pair as an
`Actions` leaf at the same anchor. A stamp covering the leaf evaluates its tachygrams at the stamp's
anchor epoch, which `SpendableTrace.anchorEpochOrBreak` pins to `epoch_current`.
-/

namespace Tachyon

variable {F A : Type*}

/-- A `SpendHeader` `(cm, nf_current, nf_next, anchor)`, without `pk` and `cv`. -/
structure SpendHeader (F A : Type*) where
  cm : F
  nf_current : F
  nf_next : F
  anchor : A

/-- `SpendBind`: the note's nullifiers at the lineage's epoch and the next, at the lineage's
anchor. -/
def spendBind (nf : F → ℕ → F) (sp : NoteSpendable F A) : SpendHeader F A :=
  ⟨sp.cm, nf sp.cm sp.epoch_current, nf sp.cm (sp.epoch_current + 1), sp.anchor⟩

/-- `SpendAction` on `h` emits digest `d` as an `Actions` leaf. Covered by a stamp at anchor epoch
`e`, its tachygrams under the pairing `R` are `h`'s nullifier pair. -/
def SpendAction (R : ℕ → F → Multiset F) (e : ℕ) (h : SpendHeader F A) (d : F) : Prop :=
  R e d = {h.nf_current, h.nf_next}

end Tachyon
