import Mathlib.Algebra.Polynomial.Roots

/-!
# Set polynomials

A set polynomial is the monic product $\prod_{r \in s} (X - r)$ over a multiset of roots `s`.
The `Stamp` header commits to two of them: the action set over action digests and the
tachygram set over tachygrams. Multiplication of set polynomials is multiset sum of roots,
which is what `StampMerge` enforces. Exact division is multiset difference, which is what
`StampUnmerge` relies on.
-/

namespace Tachyon

open Polynomial

variable {F : Type*} [Field F]

/-- The monic polynomial whose roots, with multiplicity, are `s`. -/
noncomputable def setPoly (s : Multiset F) : F[X] :=
  (s.map fun r => X - C r).prod

@[simp] theorem roots_setPoly (s : Multiset F) : (setPoly s).roots = s :=
  roots_multiset_prod_X_sub_C s

theorem setPoly_injective : Function.Injective (setPoly (F := F)) := fun s t h => by
  rw [← roots_setPoly s, h, roots_setPoly]

theorem setPoly_ne_zero (s : Multiset F) : setPoly s ≠ 0 :=
  (monic_multiset_prod_of_monic _ _ fun r _ => monic_X_sub_C r).ne_zero

@[simp] theorem setPoly_zero : setPoly (0 : Multiset F) = 1 := by
  simp [setPoly]

theorem setPoly_add (s t : Multiset F) : setPoly (s + t) = setPoly s * setPoly t := by
  simp [setPoly, Multiset.map_add, Multiset.prod_add]

/-- Exact division of set polynomials is multiset difference: if `setPoly r * q = setPoly d`,
then `r ≤ d` and `q = setPoly (d - r)`. The quotient `q` is an arbitrary polynomial, so this is
what pins a witnessed quotient. -/
theorem setPoly_mul_eq [DecidableEq F] {r d : Multiset F} {q : F[X]} (h : setPoly r * q = setPoly d) :
    r ≤ d ∧ q = setPoly (d - r) := by
  have hq : q ≠ 0 := by
    rintro rfl
    exact setPoly_ne_zero d (by simpa using h.symm)
  have hroots : d = r + q.roots := by
    rw [← roots_setPoly d, ← h, roots_mul (mul_ne_zero (setPoly_ne_zero r) hq), roots_setPoly]
  have hle : r ≤ d := hroots ▸ Multiset.le_add_right r q.roots
  refine ⟨hle, mul_left_cancel₀ (setPoly_ne_zero r) ?_⟩
  rw [h, ← setPoly_add, add_tsub_cancel_of_le hle]

end Tachyon
