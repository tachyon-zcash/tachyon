import Mathlib.Algebra.CharP.Defs
import Mathlib.Algebra.Module.BigOperators
import Mathlib.Algebra.Order.BigOperators.Group.Finset
import Mathlib.Algebra.Order.Group.Abs
import Mathlib.Tactic

/-!
# Value balance

A value commitment is $\mathsf{cv} = [v]\mathcal{V} + [\mathsf{rcv}]\mathcal{R}$. Consensus derives
$\mathsf{bvk} = \sum_i \mathsf{cv}_i - [\mathsf{vBalance}]\mathcal{V}$ from the bundle's action
commitments and its max fee commitment, and verifies the binding signature under it. Each
commitment's opening `(v, rcv)` is known to whoever produced its leaf: `SpendBind` and the output
binding compute `cv` in-circuit from the note's value, and `FeeFuse` computes the max fee commitment
from the max fee note.

The group is cyclic of prime order, so $\mathcal{V}$ and $\mathcal{R}$ always satisfy some linear
relation, and binding is computational. `balance_or_log` is the reduction: a binding signing key for
commitments with known openings either balances the values in the scalar field or yields the
discrete log of $\mathcal{V}$ to base $\mathcal{R}$. `int_balance_or_log` lifts the balance to the
integers when the values are small next to the characteristic.
-/

namespace Tachyon

variable {K G ι : Type*} [Field K] [AddCommGroup G] [Module K G]

/-- The value commitment $[v]\mathcal{V} + [\mathsf{rcv}]\mathcal{R}$. -/
def valueCommit (V R : G) (v rcv : K) : G :=
  v • V + rcv • R

/-- A binding signing key `bsk` with `bvk = [bsk]R`, over commitments to values `v` with trapdoors
`rcv`, either balances `v` against `vBalance` or yields the discrete log of `V` to base `R`. -/
theorem balance_or_log {V R : G} (s : Finset ι) (v rcv : ι → K) (vBalance bsk : K)
    (hbvk : ∑ i ∈ s, valueCommit V R (v i) (rcv i) - vBalance • V = bsk • R) :
    ∑ i ∈ s, v i = vBalance ∨ ∃ x : K, V = x • R := by
  by_cases hbal : ∑ i ∈ s, v i = vBalance
  · exact Or.inl hbal
  · right
    have hne : ∑ i ∈ s, v i - vBalance ≠ 0 := sub_ne_zero.mpr hbal
    have hsum : ∑ i ∈ s, valueCommit V R (v i) (rcv i) =
        (∑ i ∈ s, v i) • V + (∑ i ∈ s, rcv i) • R := by
      simp only [valueCommit, Finset.sum_add_distrib, Finset.sum_smul]
    have hrel : (∑ i ∈ s, v i - vBalance) • V = (bsk - ∑ i ∈ s, rcv i) • R := by
      rw [hsum] at hbvk
      rw [sub_smul, sub_smul, ← hbvk]
      abel
    refine ⟨(∑ i ∈ s, v i - vBalance)⁻¹ * (bsk - ∑ i ∈ s, rcv i), ?_⟩
    rw [mul_smul, ← hrel, smul_smul, inv_mul_cancel₀ hne, one_smul]

/-- Integer values bounded by `M`, with `(|s| + 1) M` below the characteristic `p`, committed under
a binding signing key, either balance in `ℤ` or yield the discrete log of `V` to base `R`. -/
theorem int_balance_or_log {p : ℕ} [CharP K p] {V R : G} (s : Finset ι) (v : ι → ℤ)
    (rcv : ι → K) (vBalance : ℤ) (bsk : K) {M : ℕ} (hv : ∀ i ∈ s, |v i| ≤ M)
    (hvb : |vBalance| ≤ M) (hp : (s.card + 1) * M < p)
    (hbvk : ∑ i ∈ s, valueCommit V R (v i : K) (rcv i) - (vBalance : K) • V = bsk • R) :
    ∑ i ∈ s, v i = vBalance ∨ ∃ x : K, V = x • R := by
  refine (balance_or_log s (fun i => (v i : K)) rcv (vBalance : K) bsk hbvk).imp (fun hbal => ?_)
    id
  have hzero : ((∑ i ∈ s, v i - vBalance : ℤ) : K) = 0 := by
    push_cast
    exact sub_eq_zero.mpr hbal
  have hbound : |∑ i ∈ s, v i - vBalance| < p := by
    calc |∑ i ∈ s, v i - vBalance|
        ≤ |∑ i ∈ s, v i| + |vBalance| := abs_sub _ _
      _ ≤ ∑ i ∈ s, |v i| + |vBalance| := by gcongr; exact Finset.abs_sum_le_sum_abs _ _
      _ ≤ ∑ _i ∈ s, (M : ℤ) + M := by gcongr with i hi; exact hv i hi
      _ = ((s.card + 1) * M : ℕ) := by rw [Finset.sum_const, nsmul_eq_mul]; push_cast; ring
      _ < p := by exact_mod_cast hp
  exact sub_eq_zero.mp (Int.eq_zero_of_abs_lt_dvd ((CharP.intCast_eq_zero_iff K p _).mp hzero)
    hbound)

end Tachyon
