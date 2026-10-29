import Mathlib.Algebra.BigOperators.GroupWithZero.Action
import Mathlib.Algebra.Field.Defs
import Mathlib.Algebra.Module.Defs
import Mathlib.Data.Fintype.Basic
import Mathlib.Tactic.Abel

/-!
Ported from `qa/fv/Ragu/Foundation/AlgebraicRelation/DiscreteLog.lean` and
`qa/fv/Ragu/Foundation/IPA/CommitFold.lean` at `tachyon-zcash/ragu` commit
`ecf68e3f`, themselves ported from `zcash/ironwood` commit
`3c056cbebf2880b54f801c348cb67ce7dc9f2a05`. Tachyon adapts the namespace and keeps only the
declarations it uses.

`NontrivialDLRelation` is indexed by its generator family rather than by ragu's `URS`: Tachyon's
set commitments are Pedersen commitments over fixed host generators and carry no URS structure.
-/

/-!
# Nontrivial linear (discrete-log) relations, as computed data

A nontrivial `F`-linear relation among generators, carried as data (the coefficients) so a
reduction computes it rather than asserting its existence. In a prime-order group such a relation
always exists propositionally, so an ∃-closed `Prop` would be vacuous; the content is that a
reduction produces one, discharged against discrete-log-relation hardness at the computational
layer.
-/

namespace Tachyon

variable {F G : Type*} [Field F] [AddCommGroup G] [Module F G]

/-- A nontrivial `F`-linear (discrete-log) relation among the generators `(g, U, W)`, as data:
coefficients `(a, α, β)` not all zero that the generators send to `0`. -/
structure NontrivialRelation {n : ℕ} (g : Fin n → G) (U W : G) where
  a : Fin n → F
  α : F
  β : F
  nontrivial : a ≠ 0 ∨ α ≠ 0 ∨ β ≠ 0
  relation : (∑ i, a i • g i) + α • U + β • W = 0

/-- The commitment over arbitrary generators `g`: `⟨a, g⟩ = Σᵢ aᵢ • gᵢ`. -/
def commitGen {n : ℕ} (g : Fin n → G) (a : Fin n → F) : G := ∑ i, a i • g i

/-- Subtractivity in the witness. -/
theorem commitGen_sub {n : ℕ} (g : Fin n → G) (a a' : Fin n → F) :
    commitGen g (a - a') = commitGen g a - commitGen g a' := by
  simp only [commitGen, Pi.sub_apply, sub_smul, Finset.sum_sub_distrib]

/-- A nontrivial discrete-log relation among the generators `g`, as data: a nonzero coefficient
vector the generators send to `0`. -/
structure NontrivialDLRelation {n : ℕ} (g : Fin n → G) where
  coeffs : Fin n → F
  nontrivial : coeffs ≠ 0
  relation : commitGen g coeffs = 0

/-- **The binding reduction, as a computed relation.** A binding collision, two distinct openings
of one commitment, yields the nontrivial discrete-log relation `a − a'` among the generators. -/
def NontrivialDLRelation.ofCollision {n : ℕ} {g : Fin n → G} {a a' : Fin n → F}
    (hcol : commitGen g a = commitGen g a') (hne : a ≠ a') : NontrivialDLRelation (F := F) g :=
  ⟨a - a', sub_ne_zero.mpr hne, by rw [commitGen_sub, hcol, sub_self]⟩

end Tachyon
