import Tachyon.IndexedCubic
import Mathlib.Tactic.LinearCombination

/-!
# Indexed cubic factors are unique up to association

Irreducible divisibility gives association, not equality. This closes that
distinction for the indexed nullifier encoding. In characteristic other than
three and for nonzero `c`, a constant-unit rescaling of `(uX+v)^3-c` that is
another factor of the same form must have scale one. The fixed nonzero `c`
removes the apparent unit ambiguity.

Combining this with `IndexedCubic`'s bound then pins the index and value from
association. This is the hypothesis required by unique-factorization arguments
about indexed nullifier multiset products.
-/

namespace Tachyon.IndexedCubic

open Polynomial

variable {F : Type*} [Field F]

theorem coeff_zero (c slope value : F) : (factor c slope value).coeff 0 = value ^ 3 - c := by
  simp [factor, coeff_zero_eq_eval_zero]

/-- The three relevant coefficients force a unit scaling to be one. -/
theorem scale_eq_one {a b v w c k : F} (ha : a ≠ 0) (hb : b ≠ 0) (hc : c ≠ 0)
    (hthree : (3 : F) ≠ 0)
    (hscale : factor c a v * C k = factor c b w) : k = 1 := by
  have h3 := congrArg (fun q : F[X] => q.coeff 3) hscale
  have h2 := congrArg (fun q : F[X] => q.coeff 2) hscale
  have h0 := congrArg (fun q : F[X] => q.coeff 0) hscale
  change (factor c a v * C k).coeff 3 = (factor c b w).coeff 3 at h3
  change (factor c a v * C k).coeff 2 = (factor c b w).coeff 2 at h2
  change (factor c a v * C k).coeff 0 = (factor c b w).coeff 0 at h0
  rw [coeff_mul_C, coeff_three, coeff_three] at h3
  rw [coeff_mul_C, coeff_two, coeff_two] at h2
  rw [coeff_mul_C, coeff_zero, coeff_zero] at h0
  have h2' : a ^ 2 * v * k = b ^ 2 * w := by
    apply mul_left_cancel₀ hthree
    linear_combination h2
  have hlinear : a * w = b * v := by
    have hz : b ^ 2 * (a * w - b * v) = 0 := by
      linear_combination v * h3 - a * h2'
    exact sub_eq_zero.mp ((mul_eq_zero.mp hz).resolve_left (pow_ne_zero 2 hb))
  have hcube : a ^ 3 * w ^ 3 = b ^ 3 * v ^ 3 := by
    calc
      _ = (a * w) ^ 3 := by ring
      _ = (b * v) ^ 3 := congrArg (fun x : F => x ^ 3) hlinear
      _ = _ := by ring
  have hk : a ^ 3 * c * (k - 1) = 0 := by
    linear_combination -a ^ 3 * h0 - hcube + v ^ 3 * h3
  exact sub_eq_zero.mp ((mul_eq_zero.mp hk).resolve_left (mul_ne_zero (pow_ne_zero 3 ha) hc))

/-- In the nondegenerate encoding, association already means exact polynomial
equality. The slope/value label decoding is a separate bounded-index step. -/
theorem factor_eq_of_associated {a b v w c : F} (ha : a ≠ 0) (hb : b ≠ 0) (hc : c ≠ 0)
    (hthree : (3 : F) ≠ 0) (h : Associated (factor c a v) (factor c b w)) :
    factor c a v = factor c b w := by
  obtain ⟨unit, hunit⟩ := h
  obtain ⟨k, _, hconstant⟩ := Polynomial.isUnit_iff.mp unit.isUnit
  have hscale : factor c a v * C k = factor c b w := by rwa [hconstant]
  have hk := scale_eq_one ha hb hc hthree hscale
  simpa [hk] using hscale

/-- Association of the bounded indexed cubic encodings identifies both labels,
as needed to turn irreducible-factor divisibility into indexed containment. -/
theorem indexed_associated_injective {p bound i j : ℕ} [Fact p.Prime] {c v w : ZMod p}
    (hi : i < bound) (hj : j < bound) (hp : 3 * bound ^ 2 < p) (hc : c ≠ 0)
    (h : Associated (factor c ((i + 1 : ℕ) : ZMod p) v)
      (factor c ((j + 1 : ℕ) : ZMod p) w)) : i = j ∧ v = w := by
  have hbpos : 0 < bound := by omega
  have hsmall : bound < p := by nlinarith
  have hthree : (3 : ZMod p) ≠ 0 := by
    intro hz
    have hnat := ProfileMask.nat_eq_of_cast_eq (by nlinarith : 3 < p)
      (by nlinarith : 0 < p) (by simpa using hz)
    omega
  have hcast : ∀ n : ℕ, n < bound → ((n + 1 : ℕ) : ZMod p) ≠ 0 := by
    intro n hn hz
    have hnat := ProfileMask.nat_eq_of_cast_eq (lt_of_le_of_lt hn hsmall)
      (by nlinarith : 0 < p) (by simpa using hz)
    omega
  exact indexed_factor_injective hi hj hp
    (factor_eq_of_associated (hcast i hi) (hcast j hj) hc hthree h)

end Tachyon.IndexedCubic
