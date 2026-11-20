import Mathlib.Algebra.Polynomial.SpecificDegree
import Mathlib.Tactic.LinearCombination
import Tachyon.Unspent

/-!
# Rust's indexed-member encoding

`collections/indexed_multiset.rs` encodes a member `m` at epoch index `i` as
`(m + (i + 1) X) ^ 3 - c` (`cubicMember`). It satisfies `MemberLaw` up to `emax` over any field in
which `c` is not a cube, `3 ≠ 0`, each `i + 1` is nonzero, and no two distinct `i + 1` have equal
cubes, that is no ratio of them is a nontrivial cube root of unity (`cubicMember_law`).
-/

namespace Tachyon

open Polynomial

variable {F : Type*} [Field F]

/-- `(m + (i + 1) X) ^ 3 - c`. -/
noncomputable def cubicMember (c : F) (i : ℕ) (m : F) : F[X] :=
  (C m + C ((i : F) + 1) * X) ^ 3 - C c

theorem cubicMember_eq (c : F) (i : ℕ) (m : F) :
    cubicMember c i m = C (((i : F) + 1) ^ 3) * X ^ 3 + C (3 * ((i : F) + 1) ^ 2 * m) * X ^ 2 +
      C (3 * ((i : F) + 1) * m ^ 2) * X + C (m ^ 3 - c) := by
  simp only [cubicMember, map_mul, map_pow, map_sub, map_add, map_ofNat, map_one, map_natCast]
  ring

theorem cubicMember_natDegree {c : F} {i : ℕ} (hi : (i : F) + 1 ≠ 0) (m : F) :
    (cubicMember c i m).natDegree = 3 := by
  rw [cubicMember_eq]
  exact natDegree_cubic (pow_ne_zero 3 hi)

/-- Rust's encoding satisfies `MemberLaw` up to `emax` when `c` is not a cube (so no member has a
root and each is irreducible), `3 ≠ 0` and each `i + 1 ≠ 0` (so each member has degree 3 and its
coefficients can be compared), and the cubes of `i + 1` are distinct (so two members that divide
each other have equal index). -/
theorem cubicMember_law {c : F} {emax : ℕ} (hc : ∀ y : F, y ^ 3 ≠ c) (h3 : (3 : F) ≠ 0)
    (hnz : ∀ i ≤ emax, (i : F) + 1 ≠ 0)
    (hidx : ∀ i ≤ emax, ∀ j ≤ emax, ((i : F) + 1) ^ 3 = ((j : F) + 1) ^ 3 → i = j) :
    MemberLaw (cubicMember c) emax where
  prime {i m} hi := by
    refine (irreducible_of_degree_le_three_of_not_isRoot
      (by simp [cubicMember_natDegree (hnz i hi)]) fun x hx => ?_).prime
    simp only [cubicMember, IsRoot.def, eval_sub, eval_pow, eval_add, eval_mul, eval_C,
      eval_X] at hx
    exact hc _ (sub_eq_zero.mp hx)
  dvd_inj {i j m w} hi hj h := by
    have hc0 : c ≠ 0 := fun h0 => hc 0 (by rw [h0]; ring)
    have hp0 : cubicMember c i m ≠ 0 := fun h0 => by
      have := cubicMember_natDegree (c := c) (hnz i hi) m
      rw [h0] at this
      simp at this
    obtain ⟨r, hr⟩ := h
    have hr0 : r ≠ 0 := by
      rintro rfl
      have := cubicMember_natDegree (c := c) (hnz j hj) w
      rw [hr, mul_zero] at this
      simp at this
    have hrdeg : r.natDegree = 0 := by
      have := congrArg natDegree hr
      rw [natDegree_mul hp0 hr0, cubicMember_natDegree (hnz j hj),
        cubicMember_natDegree (hnz i hi)] at this
      omega
    rw [eq_C_of_natDegree_eq_zero hrdeg, cubicMember_eq, cubicMember_eq] at hr
    have h3' := congrArg (coeff · 3) hr
    have h2' := congrArg (coeff · 2) hr
    have h0' := congrArg (coeff · 0) hr
    simp only [coeff_add, coeff_mul_C, coeff_C_mul, coeff_X_pow, coeff_C, coeff_X] at h3' h2' h0'
    norm_num at h3' h2' h0'
    have ha : (i : F) + 1 ≠ 0 := hnz i hi
    have hb : (j : F) + 1 ≠ 0 := hnz j hj
    have hij := hidx i hi j hj
    generalize hA : (i : F) + 1 = a at h3' h2' h0' ha hij
    generalize hB : (j : F) + 1 = b at h3' h2' h0' hb hij
    generalize r.coeff 0 = u at h3' h2' h0'
    have h2'' : b ^ 2 * w = a ^ 2 * m * u := by
      apply mul_left_cancel₀ h3
      linear_combination h2'
    have hwa : w * a = b * m := by
      have : a ^ 2 * b ^ 2 * (w * a - b * m) = 0 := by
        linear_combination a ^ 3 * h2'' - a ^ 2 * m * h3'
      rcases mul_eq_zero.mp this with h | h
      · exact absurd h (mul_ne_zero (pow_ne_zero 2 ha) (pow_ne_zero 2 hb))
      · exact sub_eq_zero.mp h
    have hw3 : w ^ 3 = m ^ 3 * u := by
      have : a ^ 3 * (w ^ 3 - m ^ 3 * u) = 0 := by
        linear_combination ((w * a) ^ 2 + w * a * (b * m) + (b * m) ^ 2) * hwa + m ^ 3 * h3'
      rcases mul_eq_zero.mp this with h | h
      · exact absurd h (pow_ne_zero 3 ha)
      · exact sub_eq_zero.mp h
    have hu : u = 1 := by
      have : c * (u - 1) = 0 := by linear_combination h0' - hw3
      rcases mul_eq_zero.mp this with h | h
      · exact absurd h hc0
      · exact sub_eq_zero.mp h
    subst hu
    have hab : a ^ 3 = b ^ 3 := by linear_combination -h3'
    obtain rfl := hij hab
    obtain rfl : a = b := hA.symm.trans hB
    refine ⟨rfl, ?_⟩
    rw [mul_comm] at hwa
    exact (mul_left_cancel₀ ha hwa).symm

end Tachyon
