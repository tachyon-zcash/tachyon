import Tachyon.ProfileMask
import Mathlib.Algebra.Polynomial.SpecificDegree
import Mathlib.Algebra.Field.ZMod

/-!
# Irreducible indexed nullifier factors

`collections/indexed_multiset.rs` encodes `(i,v)` as
`(v + (i+1)X)^3 - 2`. This module proves that a nonzero slope and a cubic
non-residue give an irreducible cubic. It also proves the documented bounded
index rule: if `i,j < bound` and `3*bound² < p`, equality of the factors over
`ZMod p` pins both their indices and their values.

The square-root-sized bound is important: equality of slope cubes factors
into a linear term and a quadratic sum. The quadratic sum is a positive integer
below `p`, so it cannot vanish in the field. No invalid argument that cube maps
are generally injective in the scalar field is used.

This phase addresses irreducibility and equality of factors. Using factors in
a multiset-divisibility proof additionally needs uniqueness up to association,
not merely this equality statement; that is a separate obligation.
-/

namespace Tachyon.IndexedCubic

open Polynomial

variable {F : Type*} [Field F]

noncomputable def factor (c slope value : F) : F[X] := (C slope * X + C value) ^ 3 - C c

theorem natDegree_factor {c slope value : F} (hslope : slope ≠ 0) :
    (factor c slope value).natDegree = 3 := by
  rw [factor, natDegree_sub_C, natDegree_pow, natDegree_add_C,
    natDegree_C_mul_X _ hslope]

theorem factor_irreducible {c slope value : F} (hslope : slope ≠ 0)
    (hnoncube : ∀ x : F, x ^ 3 ≠ c) : Irreducible (factor c slope value) := by
  apply irreducible_of_degree_le_three_of_not_isRoot
  · simp [natDegree_factor hslope]
  · intro x hx
    apply hnoncube (slope * x + value)
    exact sub_eq_zero.mp (by simpa [factor, IsRoot.def] using hx)

theorem factor_expanded (c slope value : F) :
    factor c slope value = C (slope ^ 3) * X ^ 3 + C (3 * slope ^ 2 * value) * X ^ 2 +
      C (3 * slope * value ^ 2) * X + C (value ^ 3 - c) := by
  simp only [factor, map_mul, map_pow, map_sub, map_ofNat]
  ring

theorem coeff_three (c slope value : F) : (factor c slope value).coeff 3 = slope ^ 3 := by
  rw [factor_expanded]
  simp only [coeff_add, coeff_C_mul, coeff_C, coeff_X_pow, coeff_X]
  norm_num

theorem coeff_two (c slope value : F) : (factor c slope value).coeff 2 = 3 * slope ^ 2 * value := by
  rw [factor_expanded]
  simp only [coeff_add, coeff_C_mul, coeff_C, coeff_X_pow, coeff_X]
  norm_num

theorem value_eq_of_factor_eq {c slope v w : F} (hslope : slope ≠ 0) (hthree : (3 : F) ≠ 0)
    (heq : factor c slope v = factor c slope w) : v = w := by
  have hcoeff := congrArg (fun q : F[X] => q.coeff 2) heq
  change (factor c slope v).coeff 2 = (factor c slope w).coeff 2 at hcoeff
  rw [coeff_two, coeff_two] at hcoeff
  exact mul_left_cancel₀ (mul_ne_zero hthree (pow_ne_zero 2 hslope)) hcoeff

/-- The bounded slopes `i+1`, not arbitrary field elements, have injective
cubes under the documented quadratic bound. -/
theorem index_eq_of_cube_eq {p bound i j : ℕ} [Fact p.Prime]
    (hi : i < bound) (hj : j < bound) (hp : 3 * bound ^ 2 < p)
    (hcube : ((i + 1 : ℕ) : ZMod p) ^ 3 = ((j + 1 : ℕ) : ZMod p) ^ 3) : i = j := by
  have hin : i + 1 ≤ bound := hi
  have hjn : j + 1 ≤ bound := hj
  have hprod : (((i + 1 : ℕ) : ZMod p) - ((j + 1 : ℕ) : ZMod p)) *
      (((i + 1 : ℕ) : ZMod p) ^ 2 + ((i + 1 : ℕ) : ZMod p) * ((j + 1 : ℕ) : ZMod p) +
        ((j + 1 : ℕ) : ZMod p) ^ 2) = 0 := by
    calc
      _ = (((i + 1 : ℕ) : ZMod p) ^ 3 - ((j + 1 : ℕ) : ZMod p) ^ 3) := by ring
      _ = 0 := sub_eq_zero.mpr hcube
  have hbound_pos : 0 < bound := by omega
  have hsmall : bound < p := by nlinarith
  rcases mul_eq_zero.mp hprod with heq | hzero
  · have hn := ProfileMask.nat_eq_of_cast_eq (hin.trans_lt hsmall) (hjn.trans_lt hsmall)
      (sub_eq_zero.mp heq)
    nlinarith
  · have hi2 := Nat.mul_self_le_mul_self hin
    have hj2 := Nat.mul_self_le_mul_self hjn
    have hij := Nat.mul_le_mul hin hjn
    have hsum : (i + 1) ^ 2 + (i + 1) * (j + 1) + (j + 1) ^ 2 < p := by
      nlinarith
    have hcast : (((i + 1) ^ 2 + (i + 1) * (j + 1) + (j + 1) ^ 2 : ℕ) : ZMod p) =
        ((0 : ℕ) : ZMod p) := by
      simpa only [Nat.cast_add, Nat.cast_pow, Nat.cast_mul, Nat.cast_zero] using hzero
    have hn := ProfileMask.nat_eq_of_cast_eq hsum (by omega : 0 < p) hcast
    nlinarith

/-- Equality of indexed cubic encodings pins the epoch and nullifier value.
The non-cube hypothesis is needed for irreducibility, not for this equality
argument; a prime and the stated size bound suffice here. -/
theorem indexed_factor_injective {p bound i j : ℕ} [Fact p.Prime] {c v w : ZMod p}
    (hi : i < bound) (hj : j < bound) (hp : 3 * bound ^ 2 < p)
    (heq : factor c ((i + 1 : ℕ) : ZMod p) v = factor c ((j + 1 : ℕ) : ZMod p) w) :
    i = j ∧ v = w := by
  have hcoeff := congrArg (fun q : (ZMod p)[X] => q.coeff 3) heq
  change (factor c ((i + 1 : ℕ) : ZMod p) v).coeff 3 =
    (factor c ((j + 1 : ℕ) : ZMod p) w).coeff 3 at hcoeff
  rw [coeff_three, coeff_three] at hcoeff
  have hij := index_eq_of_cube_eq hi hj hp hcoeff
  subst j
  refine ⟨rfl, value_eq_of_factor_eq ?_ ?_ heq⟩
  · intro hz
    have hsmall : i + 1 < p := by nlinarith
    have hn := ProfileMask.nat_eq_of_cast_eq hsmall (by nlinarith : 0 < p) (by simpa using hz)
    omega
  · intro hz
    have hsmall : 3 < p := by nlinarith
    have hn := ProfileMask.nat_eq_of_cast_eq hsmall (by nlinarith : 0 < p) (by simpa using hz)
    omega

section Example

local instance : Fact (Nat.Prime 7) := ⟨by decide⟩

/-- The index bound cannot simply be dropped: slopes one and two have the
same cube modulo seven, so they encode the same polynomial at value zero. -/
theorem indices_can_collide_without_bound :
    factor (2 : ZMod 7) 1 0 = factor (2 : ZMod 7) 2 0 ∧ (0 : ℕ) ≠ 1 := by
  have hcube : (2 : ZMod 7) ^ 3 = 1 := by decide
  exact ⟨by simp [factor_expanded, hcube], by decide⟩

end Example

end Tachyon.IndexedCubic
