import Mathlib.Data.Fin.Basic

/-!
Ported from `qa/fv/Ragu/Foundation/RelationWitness/Basic.lean` at `tachyon-zcash/ragu` commit
`ecf68e3f`, itself ported from `Zcash/Common/RelationWitness.lean` at `zcash/ironwood` commit
`3c056cbebf2880b54f801c348cb67ce7dc9f2a05`. Tachyon adapts the namespace and keeps only the
declarations it uses.
-/

/-!
# Sequencing computed outcome branches

Reductions following the breaks-as-computed-data discipline conclude `A ⊕' R`: either the intended
result or an explicit break witness. Unlike `A ∨ R`, this shape cannot be case-split classically: a
`PSum` value must be computed.
-/

namespace Tachyon

universe v w

/-- Traverse a `Fin`-indexed family of computed outcomes left to right: every left-hand value, or
the first right-hand value as data, without existential search. -/
def finForallOrRelationWitness {n : Nat} {A : Fin n → Sort v} {R : Sort w}
    (outcome : ∀ i, A i ⊕' R) : (∀ i, A i) ⊕' R := by
  induction n with
  | zero => exact PSum.inl fun i => Fin.elim0 i
  | succ n ih =>
      cases hhead : outcome 0 with
      | inr relation => exact PSum.inr relation
      | inl head =>
          cases htail : ih (fun i => outcome i.succ) with
          | inr relation => exact PSum.inr relation
          | inl tail => exact PSum.inl (Fin.cases head tail)

end Tachyon
