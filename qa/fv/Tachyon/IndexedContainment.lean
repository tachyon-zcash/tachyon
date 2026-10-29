import Tachyon.IndexedAssociates
import Mathlib.RingTheory.Polynomial.UniqueFactorization

/-!
# Indexed polynomial division is multiset containment

The irreducibility and association-injectivity results now justify the
multiset interpretation used at `UnspentBind`: dividing a product of indexed
cubic factors by another such product removes exactly the indexed members,
including their multiplicities. A witnessed quotient is arbitrary and is
forced to be the product of the remaining factors.

The concrete theorem uses bounded labels `(Fin bound × ZMod p)`, a cubic
non-residue `c`, and `3*bound² < p`. It does not assume that an unindexed root
polynomial represents the indexed encoding. Commitment binding and random
opening checks remain separate from this exact polynomial algebra.
-/

namespace Tachyon.IndexedContainment

open Polynomial

variable {F I : Type*} [Field F]

noncomputable def product (f : I → F[X]) (s : Multiset I) : F[X] := (s.map f).prod

theorem product_cons (f : I → F[X]) (i : I) (s : Multiset I) :
    product f (i ::ₘ s) = f i * product f s := by simp [product]

theorem product_add (f : I → F[X]) (s t : Multiset I) :
    product f (s + t) = product f s * product f t := by
  simp [product, Multiset.map_add, Multiset.prod_add]

theorem product_ne_zero (f : I → F[X]) (hirr : ∀ i, Irreducible (f i)) (s : Multiset I) :
    product f s ≠ 0 := by
  induction s using Multiset.induction_on with
  | empty => simp [product]
  | cons i s ih => simpa [product] using mul_ne_zero (hirr i).ne_zero ih

theorem member_of_dvd (f : I → F[X]) (hirr : ∀ i, Irreducible (f i))
    (hlabels : ∀ i j, Associated (f i) (f j) → i = j) (i : I) (s : Multiset I)
    (hdvd : f i ∣ product f s) : i ∈ s := by
  induction s using Multiset.induction_on with
  | empty =>
    have hunit : IsUnit (f i) := isUnit_of_dvd_one (by simpa [product] using hdvd)
    exact False.elim ((hirr i).not_isUnit hunit)
  | cons j s ih =>
    have hprime : Prime (f i) := irreducible_iff_prime.mp (hirr i)
    rw [product_cons] at hdvd
    rcases hprime.dvd_mul.mp hdvd with hj | hs
    · have heq := hlabels i j ((hirr i).associated_of_dvd (hirr j) hj)
      exact heq ▸ Multiset.mem_cons_self j s
    · exact Multiset.mem_cons_of_mem (ih hs)

theorem product_dvd_iff_le [DecidableEq I] (f : I → F[X])
    (hirr : ∀ i, Irreducible (f i)) (hlabels : ∀ i j, Associated (f i) (f j) → i = j)
    (r d : Multiset I) : product f r ∣ product f d ↔ r ≤ d := by
  constructor
  · intro hdiv
    induction r using Multiset.induction_on generalizing d with
    | empty => exact zero_le
    | cons i r ih =>
      rw [product_cons] at hdiv
      have hfactor : f i ∣ product f d :=
        (dvd_mul_right (f i) (product f r)).trans hdiv
      have hmem := member_of_dvd f hirr hlabels i d hfactor
      have hd : d = i ::ₘ d.erase i := (Multiset.cons_erase hmem).symm
      have hcancel : product f r ∣ product f (d.erase i) := by
        apply (mul_dvd_mul_iff_left (hirr i).ne_zero).mp
        rw [hd, product_cons] at hdiv
        exact hdiv
      rw [hd]
      exact Multiset.cons_le_cons i (ih _ hcancel)
  · intro hle
    exact Multiset.prod_dvd_prod_of_le (Multiset.map_le_map hle)

/-- The quotient need not itself be given as an encoded multiset. -/
theorem product_division [DecidableEq I] (f : I → F[X])
    (hirr : ∀ i, Irreducible (f i)) (hlabels : ∀ i j, Associated (f i) (f j) → i = j)
    {r d : Multiset I} {q : F[X]} (h : product f r * q = product f d) :
    r ≤ d ∧ q = product f (d - r) := by
  have hle := (product_dvd_iff_le f hirr hlabels r d).mp ⟨q, h.symm⟩
  refine ⟨hle, mul_left_cancel₀ (product_ne_zero f hirr r) ?_⟩
  rw [h, ← product_add, add_tsub_cancel_of_le hle]

noncomputable def indexedFactor {p bound : ℕ} [Fact p.Prime] (c : ZMod p)
    (label : Fin bound × ZMod p) : (ZMod p)[X] :=
  IndexedCubic.factor c ((label.1.val + 1 : ℕ) : ZMod p) label.2

/-- Exact polynomial division of the actual cubic encoding gives indexed
multiset subtraction, under the field/index conditions in the Rust design. -/
theorem indexed_division {p bound : ℕ} [Fact p.Prime] {c : ZMod p}
    (hnoncube : ∀ x : ZMod p, x ^ 3 ≠ c) (hbound : 3 * bound ^ 2 < p)
    {r d : Multiset (Fin bound × ZMod p)} {q : (ZMod p)[X]}
    (h : product (indexedFactor c) r * q = product (indexedFactor c) d) :
    r ≤ d ∧ q = product (indexedFactor c) (d - r) := by
  have hc : c ≠ 0 := by
    intro hz
    exact hnoncube 0 (by simp [hz])
  apply product_division (indexedFactor c) ?_ ?_ h
  · intro label
    apply IndexedCubic.factor_irreducible ?_ hnoncube
    intro hz
    have hsmall : label.1.val + 1 < p := by
      have hi := label.1.isLt
      nlinarith
    have heq := ProfileMask.nat_eq_of_cast_eq hsmall (by omega : 0 < p) (by simpa using hz)
    omega
  · intro left right hassoc
    obtain ⟨hi, hv⟩ := IndexedCubic.indexed_associated_injective left.1.isLt right.1.isLt hbound hc hassoc
    exact Prod.ext (Fin.ext hi) hv

/-- `UnspentBind`'s exact identity binds every elapsed value to the genuine
nullifier at that very index, even when the quotient witness is arbitrary. -/
theorem indexed_bind_values {p bound : ℕ} [Fact p.Prime] {c : ZMod p}
    (hnoncube : ∀ x : ZMod p, x ^ 3 ≠ c) (hbound : 3 * bound ^ 2 < p)
    {elapsed derivation : Multiset (Fin bound × ZMod p)} {q : (ZMod p)[X]}
    (nf : ℕ → ZMod p) (hderived : ∀ label ∈ derivation, label.2 = nf label.1.val)
    (hdivision : product (indexedFactor c) elapsed * q = product (indexedFactor c) derivation) :
    ∀ label ∈ elapsed, label.2 = nf label.1.val := by
  have hle := (indexed_division hnoncube hbound hdivision).1
  exact fun label hmem => hderived label (Multiset.mem_of_le hle hmem)

/-- Repeated factors subtract by multiplicity: two copies of an indexed
member cannot be divided out of a single copy. -/
theorem cannot_remove_twice {p bound : ℕ} [Fact p.Prime] {c : ZMod p}
    (hnoncube : ∀ x : ZMod p, x ^ 3 ≠ c) (hbound : 3 * bound ^ 2 < p)
    (label : Fin bound × ZMod p) (q : (ZMod p)[X]) :
    product (indexedFactor c) ({label} + {label}) * q ≠ product (indexedFactor c) {label} := by
  intro h
  have hcard := Multiset.card_le_card (indexed_division hnoncube hbound h).1
  simp at hcard

end Tachyon.IndexedContainment
