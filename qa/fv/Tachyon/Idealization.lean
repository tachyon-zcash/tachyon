import Tachyon.SetPoly

/-!
# Idealized polynomial checks

The proof-tree model takes each `enforce_poly_product` as the identity
`product = multiplicand * multiplier`, and each `enforce_poly_roots` as `accumulator = setPoly roots`.
The circuit checks each at one Fiat-Shamir challenge `z`, derived after every operand is committed,
so the operands are fixed before `z` exists. For fixed operands that violate the identity, few
challenges pass: at most `2n` for a product of degree-`n` operands, and at most `n` for an
accumulator of degree `n` over at most `n` roots. A uniform `z` therefore passes with probability at
most `2n / |F|` or `n / |F|`.

Commitment binding, which makes the committed operands the polynomials the model reasons about, is
assumed and not proven here.
-/

namespace Tachyon

open Polynomial

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]

/-- A product check over operands of degree at most `n` that violate the identity passes at no more
than `2n` challenges. -/
theorem card_product_check_le {a b c : F[X]} {n : ℕ} (hne : c ≠ a * b) (ha : a.natDegree ≤ n)
    (hb : b.natDegree ≤ n) (hc : c.natDegree ≤ n) :
    (Finset.univ.filter fun z => c.eval z = a.eval z * b.eval z).card ≤ 2 * n := by
  have hp : c - a * b ≠ 0 := sub_ne_zero.mpr hne
  calc (Finset.univ.filter fun z => c.eval z = a.eval z * b.eval z).card
      ≤ (c - a * b).roots.toFinset.card := by
        refine Finset.card_le_card fun z hz => ?_
        rw [Finset.mem_filter] at hz
        rw [Multiset.mem_toFinset, mem_roots hp, IsRoot.def, eval_sub, eval_mul, hz.2, sub_self]
    _ ≤ (c - a * b).roots.card := Multiset.toFinset_card_le _
    _ ≤ (c - a * b).natDegree := card_roots' _
    _ ≤ 2 * n := by
        refine (natDegree_sub_le _ _).trans (max_le (by omega) ?_)
        exact (natDegree_mul_le).trans (by omega)

/-- A roots check of a degree-`n` accumulator against at most `n` roots, where the accumulator is not
the roots' set polynomial, passes at no more than `n` challenges. -/
theorem card_roots_check_le {acc : F[X]} {roots : Multiset F} {n : ℕ} (hne : acc ≠ setPoly roots)
    (hacc : acc.natDegree ≤ n) (hroots : Multiset.card roots ≤ n) :
    (Finset.univ.filter fun z => acc.eval z = (roots.map fun r => z - r).prod).card ≤ n := by
  have hp : acc - setPoly roots ≠ 0 := sub_ne_zero.mpr hne
  have hdeg : (setPoly roots).natDegree = Multiset.card roots :=
    natDegree_multiset_prod_X_sub_C_eq_card roots
  calc (Finset.univ.filter fun z => acc.eval z = (roots.map fun r => z - r).prod).card
      ≤ (acc - setPoly roots).roots.toFinset.card := by
        refine Finset.card_le_card fun z hz => ?_
        rw [Finset.mem_filter] at hz
        rw [Multiset.mem_toFinset, mem_roots hp, IsRoot.def, eval_sub, hz.2, setPoly,
          eval_multiset_prod, Multiset.map_map]
        simp
    _ ≤ (acc - setPoly roots).roots.card := Multiset.toFinset_card_le _
    _ ≤ (acc - setPoly roots).natDegree := card_roots' _
    _ ≤ n := (natDegree_sub_le _ _).trans (max_le hacc (hdeg ▸ hroots))

end Tachyon
