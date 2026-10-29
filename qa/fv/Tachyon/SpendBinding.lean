import Tachyon.Spendable

/-!
# Spend binding

`SpendBind` takes a `NoteSpendable (cm, epoch_current, anchor)` and derives the note's nullifiers at
`epoch_current` and the epoch after, at the lineage's anchor. `SpendAction` publishes that pair as an
`Actions` leaf at the same anchor.

`epoch_current` is not a free label. A derivable `NoteSpendable` whose anchor is a chain node sits in
its lineage's epoch (`SpendableDerivable.anchor_epoch`): `SpendableInit` absorbs the creation epoch
into a stamp absorption, and `QrSpendableInit` and `SpendableLift` end on a bucket's boundary digest
into the next epoch. A spend leaf from such a lineage therefore publishes the note's nullifier pair at
its anchor's epoch (`SpendableDerivable.spend_pair`).
-/

namespace Tachyon

open Polynomial

variable {F A : Type*} [Field F] {ValidBucket : QrBucket F A → Prop} {nf : F → ℕ → F}
  {nextStamp : A → ℕ → F[X] → A} {genesis : A} {e₀ : ℕ} {nextEpoch : A → ℕ → A}

/-- Every derivable `ArbitraryUnspent` ends at the boundary of a valid bucket for the epoch before
`u.epoch_next`. -/
theorem ArbitraryUnspentDerivable.closes_at_bucket {u : ArbitraryUnspent F A}
    (h : ArbitraryUnspentDerivable ValidBucket u) :
    ∃ b : QrBucket F A, ValidBucket b ∧ b.epoch + 1 = u.epoch_next ∧
      b.anchor_next = u.anchor_next := by
  induction h with
  | init b _ hb _ _ => exact ⟨b, hb, rfl, rfl⟩
  | lift b _ _ hb _ _ _ _ _ _ => exact ⟨b, hb, rfl, rfl⟩
  | fuse _ _ _ _ _ _ ihr => exact ihr

/-- A boundary digest into epoch `e'` is a chain node only at epoch `e'`. -/
theorem node_nextEpoch_epoch (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch) {e e' : ℕ}
    {a : A} (h : Chain.Node genesis e₀ nextStamp nextEpoch e (nextEpoch a e')) : e = e' := by
  generalize htarget : nextEpoch a e' = target at h
  cases h with
  | genesis =>
      by_contra hne
      exact hlaw.epoch_ne_genesis (fun h => hne h.symm) htarget
  | stamp _ _ _ => exact absurd htarget.symm hlaw.stamp_ne_epoch
  | epoch _ _ => exact (hlaw.nextEpoch_inj htarget).2.symm

/-- A derivable `NoteSpendable` anchored at a chain node of epoch `e` has `epoch_current = e`, when
every valid bucket ends on a boundary digest into the epoch after it. -/
theorem SpendableDerivable.anchor_epoch (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hseal : ∀ ⦃b : QrBucket F A⦄, ValidBucket b →
      ∃ prev, b.anchor_next = nextEpoch prev (b.epoch + 1))
    {start : ℕ} {sp : NoteSpendable F A} (h : SpendableDerivable ValidBucket nf nextStamp start sp)
    {e : ℕ} (hnode : Chain.Node genesis e₀ nextStamp nextEpoch e sp.anchor) :
    sp.epoch_current = e := by
  cases h with
  | init _ _ _ _ _ _ => exact (Chain.Node.of_nextStamp hlaw hnode).1
  | qrInit b _ hb _ _ hnext hepoch _ =>
      obtain ⟨prev, hprev⟩ := hseal hb
      rw [hepoch]
      rw [hnext, hprev] at hnode
      exact (node_nextEpoch_epoch hlaw hnode).symm
  | lift _ hnu _ _ _ =>
      cases hnu with
      | bind _ hu _ _ =>
          obtain ⟨b, hb, hepoch, hanchor⟩ := hu.closes_at_bucket
          obtain ⟨prev, hprev⟩ := hseal hb
          rw [← hepoch]
          rw [← hanchor, hprev] at hnode
          exact (node_nextEpoch_epoch hlaw hnode).symm

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

/-- `SpendAction` on `h` emits digest `d` as an `Actions` leaf at `h.anchor`, whose tachygrams under
the pairing `R` are `h`'s nullifier pair. -/
def SpendAction (epoch : A → ℕ) (R : ℕ → F → Multiset F) (h : SpendHeader F A) (d : F) : Prop :=
  R (epoch h.anchor) d = {h.nf_current, h.nf_next}

/-- A spend leaf from a derivable `NoteSpendable` anchored at a chain node publishes the note's
nullifier pair at its anchor's epoch, for an epoch labelling that agrees with the chain. -/
theorem SpendableDerivable.spend_pair (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hseal : ∀ ⦃b : QrBucket F A⦄, ValidBucket b →
      ∃ prev, b.anchor_next = nextEpoch prev (b.epoch + 1))
    {epoch : A → ℕ} (hepoch : ∀ {e : ℕ} {a : A}, Chain.Node genesis e₀ nextStamp nextEpoch e a →
      epoch a = e)
    {R : ℕ → F → Multiset F} {start e : ℕ} {sp : NoteSpendable F A} {d : F}
    (h : SpendableDerivable ValidBucket nf nextStamp start sp)
    (hnode : Chain.Node genesis e₀ nextStamp nextEpoch e sp.anchor)
    (haction : SpendAction epoch R (spendBind nf sp) d) :
    R (epoch sp.anchor) d = {nf sp.cm (epoch sp.anchor), nf sp.cm (epoch sp.anchor + 1)} := by
  have hcurrent : epoch sp.anchor = sp.epoch_current :=
    (hepoch hnode).trans (h.anchor_epoch hlaw hseal hnode).symm
  rw [hcurrent]
  rw [SpendAction, spendBind, hcurrent] at haction
  exact haction

end Tachyon
