import Tachyon.PastaIndexPremises
import Tachyon.ProfiledSpendable

/-!
# From the actual cubic division check to `UnspentBind`

The earlier lineage model represents indexed commitments by multisets of
`(epoch,value)` pairs. `IndexedContainment` proves the algebra justifying that
interpretation for the actual cubic encoding. This module connects the two:
the polynomial identity derives the multiset equation consumed by both bound
unspent predicates, instead of assuming that equation separately.

The finite indexed lists and their equalities to header semantics are supplied
by derivation provenance; these theorems are logical bridges, not algorithms
for factoring arbitrary witnessed polynomials or extracting data from PCD
acceptance. The quotient polynomial remains arbitrary. Commitment binding,
opening soundness, and the canonical field setup stay separate boundaries.
-/

namespace Tachyon.IndexedUnspentBind

open Polynomial

variable {p bound : ℕ} [Fact p.Prime]

def forgetIndex (label : Fin bound × ZMod p) : ℕ × ZMod p := (label.1.val, label.2)

/-- Exact division produces precisely the semantic indexed multiset equation
used by the abstract bind constructor, preserving repeated members. -/
theorem semantic_split {c : ZMod p} (hnoncube : ∀ x : ZMod p, x ^ 3 ≠ c)
    (hbound : 3 * bound ^ 2 < p)
    {elapsed derived : Multiset (Fin bound × ZMod p)} {q : (ZMod p)[X]}
    (hdivision : IndexedContainment.product (IndexedContainment.indexedFactor c) elapsed * q =
      IndexedContainment.product (IndexedContainment.indexedFactor c) derived) :
    derived.map forgetIndex = elapsed.map forgetIndex + (derived - elapsed).map forgetIndex := by
  have hle := (IndexedContainment.indexed_division hnoncube hbound hdivision).1
  rw [← Multiset.map_add, add_tsub_cancel_of_le hle]

theorem unprofiled_bind {A : Type*} {ValidBucket : QrBucket (ZMod p) A → Prop}
    {nf : ZMod p → ℕ → ZMod p} {u : ArbitraryUnspent (ZMod p) A} {n : NoteNullifiers (ZMod p)}
    {c : ZMod p} (hnoncube : ∀ x : ZMod p, x ^ 3 ≠ c) (hbound : 3 * bound ^ 2 < p)
    {elapsed derived : Multiset (Fin bound × ZMod p)} {q : (ZMod p)[X]}
    (hu : ArbitraryUnspentDerivable ValidBucket u) (hn : NullifiersDerivable nf n)
    (helapsed : u.elapsed = elapsed.map forgetIndex) (hderived : n.seq = derived.map forgetIndex)
    (hdivision : IndexedContainment.product (IndexedContainment.indexedFactor c) elapsed * q =
      IndexedContainment.product (IndexedContainment.indexedFactor c) derived) :
    NoteUnspentDerivable ValidBucket nf
      ⟨n.cm, u.anchor_start, u.epoch_start, u.epoch_next, u.anchor_next⟩ := by
  apply NoteUnspentDerivable.bind ((derived - elapsed).map forgetIndex) hu hn
  rw [hderived, helapsed]
  exact semantic_split hnoncube hbound hdivision

theorem profiled_bind {A : Type*} {ValidBucket : QrBucket (ZMod p) A → Prop}
    {AllowedQuery : QrBucket (ZMod p) A → ZMod p → Prop}
    {nf : ZMod p → ℕ → ZMod p} {u : ArbitraryUnspent (ZMod p) A} {n : NoteNullifiers (ZMod p)}
    {c : ZMod p} (hnoncube : ∀ x : ZMod p, x ^ 3 ≠ c) (hbound : 3 * bound ^ 2 < p)
    {elapsed derived : Multiset (Fin bound × ZMod p)} {q : (ZMod p)[X]}
    (hu : Profiled.UnspentDerivable ValidBucket AllowedQuery u) (hn : NullifiersDerivable nf n)
    (helapsed : u.elapsed = elapsed.map forgetIndex) (hderived : n.seq = derived.map forgetIndex)
    (hdivision : IndexedContainment.product (IndexedContainment.indexedFactor c) elapsed * q =
      IndexedContainment.product (IndexedContainment.indexedFactor c) derived) :
    Profiled.NoteUnspentDerivable ValidBucket AllowedQuery nf
      ⟨n.cm, u.anchor_start, u.epoch_start, u.epoch_next, u.anchor_next⟩ := by
  apply Profiled.NoteUnspentDerivable.bind ((derived - elapsed).map forgetIndex) hu hn
  rw [hderived, helapsed]
  exact semantic_split hnoncube hbound hdivision

/-- Actual indexed cubic division supplies the genuine-nullifier attribution
in a profile-aware exclusion lineage. Completeness is needed only at certified
queries, not for the entire routed bucket. -/
theorem lineage_of_polynomial_bind {A : Type*} {ValidBucket : QrBucket (ZMod p) A → Prop}
    {AllowedQuery : QrBucket (ZMod p) A → ZMod p → Prop}
    {chain : List (Chain.Stamp (ZMod p) A)}
    {nf : ZMod p → ℕ → ZMod p} {u : ArbitraryUnspent (ZMod p) A} {n : NoteNullifiers (ZMod p)}
    {c : ZMod p} (hnoncube : ∀ x : ZMod p, x ^ 3 ≠ c) (hbound : 3 * bound ^ 2 < p)
    {elapsed derived : Multiset (Fin bound × ZMod p)} {q : (ZMod p)[X]}
    (hu : Profiled.UnspentDerivable ValidBucket AllowedQuery u) (hn : NullifiersDerivable nf n)
    (helapsed : u.elapsed = elapsed.map forgetIndex) (hderived : n.seq = derived.map forgetIndex)
    (hdivision : IndexedContainment.product (IndexedContainment.indexedFactor c) elapsed * q =
      IndexedContainment.product (IndexedContainment.indexedFactor c) derived)
    (hcomplete : ∀ ⦃b : QrBucket (ZMod p) A⦄ ⦃v : ZMod p⦄,
      ValidBucket b → AllowedQuery b v → Profiled.QueryComplete chain b v) :
    u.epoch_start < u.epoch_next ∧
      ∀ x, u.epoch_start ≤ x → x < u.epoch_next → ¬ Chain.published chain x (nf n.cm x) :=
  (profiled_bind hnoncube hbound hu hn helapsed hderived hdivision).lineage hcomplete

end Tachyon.IndexedUnspentBind
