import Mathlib.Algebra.CharP.Defs
import Mathlib.Algebra.Module.BigOperators
import Mathlib.Algebra.Order.BigOperators.Group.Finset
import Mathlib.Algebra.Order.Group.Abs
import Mathlib.Tactic
import Tachyon.Foundation.DiscreteLogRelation

/-!
# Value balance

A value commitment is $\mathsf{cv} = [v]\mathcal{V} + [\mathsf{rcv}]\mathcal{R}$. Consensus derives
$\mathsf{bvk} = \sum_i \mathsf{cv}_i - [\mathsf{vBalance}]\mathcal{V}$ from the bundle's action
commitments and its max fee commitment, and verifies the binding signature under it. Each
commitment's opening `(v, rcv)` is known to whoever produced its leaf: `SpendBind` and the output
binding compute `cv` in-circuit from the note's value, using private fixed-base certificates.
`FeeValueCommit` computes the max fee commitment and `FeeBind` ties its blind and maximum to the
max fee note before `FeeFuse` consumes the certified roots. `StepBudget` proves that erasing these
helper subgraphs recovers the value equations used here.

The group is cyclic of prime order, so $\mathcal{V}$ and $\mathcal{R}$ always satisfy some linear
relation, and binding is computational. Following the breaks-as-computed-data discipline, an
unbalanced binding signature computes a nontrivial relation among $(\mathcal{V}, \mathcal{R})$
(`NontrivialRelation.ofImbalance`). `balanceOrRelation` returns the balance in the scalar field or
that relation, and `intBalanceOrRelation` lifts the balance to the integers when the values are small
next to the characteristic.
-/

namespace Tachyon

variable {K G ι : Type*} [Field K] [AddCommGroup G] [Module K G]

/-- The value commitment $[v]\mathcal{V} + [\mathsf{rcv}]\mathcal{R}$. -/
def valueCommit (V R : G) (v rcv : K) : G :=
  v • V + rcv • R

theorem sum_valueCommit {V R : G} (s : Finset ι) (v rcv : ι → K) :
    ∑ i ∈ s, valueCommit V R (v i) (rcv i) = (∑ i ∈ s, v i) • V + (∑ i ∈ s, rcv i) • R := by
  simp only [valueCommit, Finset.sum_add_distrib, Finset.sum_smul]

/-- **The binding-signature reduction, as a computed relation.** A binding signing key `bsk` with
`bvk = [bsk]R`, over commitments to values `v` that do not balance against `vBalance`, yields the
nontrivial relation `(Σ v − vBalance, Σ rcv − bsk)` among `(V, R)`. -/
def NontrivialRelation.ofImbalance {V R : G} (s : Finset ι) (v rcv : ι → K) (vBalance bsk : K)
    (hbvk : ∑ i ∈ s, valueCommit V R (v i) (rcv i) - vBalance • V = bsk • R)
    (himbalance : ∑ i ∈ s, v i ≠ vBalance) :
    NontrivialRelation (F := K) (Fin.elim0 : Fin 0 → G) V R where
  a := 0
  α := ∑ i ∈ s, v i - vBalance
  β := ∑ i ∈ s, rcv i - bsk
  nontrivial := Or.inr (Or.inl (sub_ne_zero.mpr himbalance))
  relation := by
    rw [sum_valueCommit, ← sub_eq_zero] at hbvk
    rw [Fin.sum_univ_zero, zero_add, sub_smul, sub_smul, ← hbvk]
    abel

/-- A binding signing key over value commitments with known openings balances the values in the
scalar field, or computes a nontrivial relation among `(V, R)`. -/
def balanceOrRelation [DecidableEq K] {V R : G} (s : Finset ι) (v rcv : ι → K) (vBalance bsk : K)
    (hbvk : ∑ i ∈ s, valueCommit V R (v i) (rcv i) - vBalance • V = bsk • R) :
    (∑ i ∈ s, v i = vBalance) ⊕' NontrivialRelation (F := K) (Fin.elim0 : Fin 0 → G) V R :=
  if hbalance : ∑ i ∈ s, v i = vBalance then .inl hbalance
  else .inr (.ofImbalance s v rcv vBalance bsk hbvk hbalance)

/-- Integer values bounded by `M`, with `(|s| + 1) M` below the characteristic `p`, committed under
a binding signing key, balance in `ℤ` or compute a nontrivial relation among `(V, R)`. -/
def intBalanceOrRelation [DecidableEq K] {p : ℕ} [CharP K p] {V R : G} (s : Finset ι)
    (v : ι → ℤ) (rcv : ι → K) (vBalance : ℤ) (bsk : K) {M : ℕ} (hv : ∀ i ∈ s, |v i| ≤ M)
    (hvb : |vBalance| ≤ M) (hp : (s.card + 1) * M < p)
    (hbvk : ∑ i ∈ s, valueCommit V R (v i : K) (rcv i) - (vBalance : K) • V = bsk • R) :
    (∑ i ∈ s, v i = vBalance) ⊕' NontrivialRelation (F := K) (Fin.elim0 : Fin 0 → G) V R :=
  match balanceOrRelation s (fun i => (v i : K)) rcv (vBalance : K) bsk hbvk with
  | .inr relation => .inr relation
  | .inl hbalance => .inl <| by
      have hzero : ((∑ i ∈ s, v i - vBalance : ℤ) : K) = 0 := by
        push_cast
        exact sub_eq_zero.mpr hbalance
      have hbound : |∑ i ∈ s, v i - vBalance| < p := by
        calc |∑ i ∈ s, v i - vBalance|
            ≤ |∑ i ∈ s, v i| + |vBalance| := abs_sub _ _
          _ ≤ ∑ i ∈ s, |v i| + |vBalance| := by gcongr; exact Finset.abs_sum_le_sum_abs _ _
          _ ≤ ∑ _i ∈ s, (M : ℤ) + M := by gcongr with i hi; exact hv i hi
          _ = ((s.card + 1) * M : ℕ) := by rw [Finset.sum_const, nsmul_eq_mul]; push_cast; ring
          _ < p := by exact_mod_cast hp
      exact sub_eq_zero.mp (Int.eq_zero_of_abs_lt_dvd
        ((CharP.intCast_eq_zero_iff K p _).mp hzero) hbound)

end Tachyon
