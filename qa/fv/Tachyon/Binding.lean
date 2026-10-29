import Mathlib.Algebra.Polynomial.Coeff
import Mathlib.Algebra.Polynomial.Degree.Operations
import Tachyon.Foundation.DiscreteLogRelation

/-!
# Set-commitment binding

A `Stamp` header carries Pedersen commitments to its action-set and tachygram-set polynomials, each
over the first `n` coefficients (`ProductionRank`, `n = 8192`). The proof-tree model reads each
header as the polynomials it opens to. That reading is well-defined up to a computed break: two
distinct openings of one commitment, both of degree below `n`, yield a nontrivial discrete-log
relation among the commitment generators (`NontrivialDLRelation.ofPolyCollision`).
-/

namespace Tachyon

open Polynomial

variable {F G : Type*} [Field F] [AddCommGroup G] [Module F G] {n : ℕ}

/-- The Pedersen commitment to the first `n` coefficients of `p` over generators `g`. -/
noncomputable def polyCommit (g : Fin n → G) (p : F[X]) : G :=
  commitGen g fun i => p.coeff i

/-- Polynomials of degree below `n` are determined by their first `n` coefficients. -/
theorem eq_of_coeff_fin {p q : F[X]} (hp : p.natDegree < n) (hq : q.natDegree < n)
    (h : (fun i : Fin n => p.coeff i) = fun i : Fin n => q.coeff i) : p = q := by
  ext k
  by_cases hk : k < n
  · exact congrFun h ⟨k, hk⟩
  · rw [coeff_eq_zero_of_natDegree_lt (by omega), coeff_eq_zero_of_natDegree_lt (by omega)]

/-- **Set-commitment binding, as a computed relation.** Two distinct polynomials of degree below
`n` with one commitment yield a nontrivial relation among the generators. -/
noncomputable def NontrivialDLRelation.ofPolyCollision {g : Fin n → G} {p q : F[X]}
    (hp : p.natDegree < n) (hq : q.natDegree < n) (hcol : polyCommit g p = polyCommit g q)
    (hne : p ≠ q) : NontrivialDLRelation (F := F) g :=
  .ofCollision hcol fun h => hne (eq_of_coeff_fin hp hq h)

end Tachyon
