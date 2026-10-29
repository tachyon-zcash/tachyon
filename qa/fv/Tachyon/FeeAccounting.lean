import Tachyon.Value

/-!
# Fee accounting

A spend commits `+v` for the spent note (`SpendBind`), an output commits `-v` for the created note
(`OutputBind`), and the bundle's max fee commitment is `-maxFee` for the max fee note (`FeeFuse`).
`FeeFuse` also creates the change note at `maxFee - fee` and checks both in range. Under the binding
signature, value spent equals value created, including the change note, plus the fee and the value
balance, unless the bundle yields the discrete log of $\mathcal{V}$ to base $\mathcal{R}$.
-/

namespace Tachyon

variable {K G ι κ : Type*} [Field K] [AddCommGroup G] [Module K G]

/-- A bundle's spends, outputs and max fee, committed under a binding signing key, account for every
spent unit as created value, change, fee or value balance, or yield the discrete log of `V` to base
`R`. Values are bounded by `M`, and `(|spends| + |outputs| + 2) M` stays below the characteristic. -/
theorem fee_accounting_or_log {p : ℕ} [CharP K p] {V R : G} (spends : Finset ι)
    (outputs : Finset κ) (spent : ι → ℤ) (created : κ → ℤ) (rcvSpend : ι → K) (rcvOutput : κ → K)
    (maxFee fee change vBalance : ℤ) (blind bsk : K) {M : ℕ}
    (hspent : ∀ i ∈ spends, |spent i| ≤ M) (hcreated : ∀ j ∈ outputs, |created j| ≤ M)
    (hmax : |maxFee| ≤ M) (hvb : |vBalance| ≤ M) (hchange : change = maxFee - fee)
    (hp : (spends.card + outputs.card + 2) * M < p)
    (hbvk : ∑ i ∈ spends, valueCommit V R (spent i : K) (rcvSpend i) +
        ∑ j ∈ outputs, valueCommit V R (-created j : K) (rcvOutput j) +
        valueCommit V R (-maxFee : K) blind - (vBalance : K) • V = bsk • R) :
    ∑ i ∈ spends, spent i = ∑ j ∈ outputs, created j + change + fee + vBalance ∨
      ∃ x : K, V = x • R := by
  have hcommit : ∑ i ∈ spends, valueCommit V R (spent i : K) (rcvSpend i) +
      ∑ j ∈ outputs, valueCommit V R (-created j : K) (rcvOutput j) +
      valueCommit V R (-maxFee : K) blind =
      valueCommit V R ((∑ i ∈ spends, spent i - ∑ j ∈ outputs, created j - maxFee : ℤ) : K)
        (∑ i ∈ spends, rcvSpend i + ∑ j ∈ outputs, rcvOutput j + blind) := by
    simp only [valueCommit, Finset.sum_add_distrib, ← Finset.sum_smul, Finset.sum_neg_distrib]
    push_cast
    module
  rw [hcommit] at hbvk
  refine (balance_or_log ({()} : Finset Unit)
    (fun _ => ((∑ i ∈ spends, spent i - ∑ j ∈ outputs, created j - maxFee : ℤ) : K))
    (fun _ => ∑ i ∈ spends, rcvSpend i + ∑ j ∈ outputs, rcvOutput j + blind) (vBalance : K) bsk
    (by simpa using hbvk)).imp (fun hbal => ?_) id
  simp only [Finset.sum_singleton] at hbal
  have hzero : ((∑ i ∈ spends, spent i - ∑ j ∈ outputs, created j - maxFee - vBalance : ℤ) : K) =
      0 := by
    push_cast at hbal ⊢
    exact sub_eq_zero.mpr hbal
  have hspent_le : ∑ i ∈ spends, spent i ≤ spends.card * M := by
    simpa using Finset.sum_le_sum fun i hi => (abs_le.mp (hspent i hi)).2
  have hspent_ge : -(spends.card * M : ℤ) ≤ ∑ i ∈ spends, spent i := by
    have := Finset.sum_le_sum fun i hi => (abs_le.mp (hspent i hi)).1
    simp only [Finset.sum_neg_distrib, Finset.sum_const, nsmul_eq_mul] at this
    linarith
  have hcreated_le : ∑ j ∈ outputs, created j ≤ outputs.card * M := by
    simpa using Finset.sum_le_sum fun j hj => (abs_le.mp (hcreated j hj)).2
  have hcreated_ge : -(outputs.card * M : ℤ) ≤ ∑ j ∈ outputs, created j := by
    have := Finset.sum_le_sum fun j hj => (abs_le.mp (hcreated j hj)).1
    simp only [Finset.sum_neg_distrib, Finset.sum_const, nsmul_eq_mul] at this
    linarith
  have hp' : (spends.card * M + outputs.card * M + 2 * M : ℤ) < p := by
    have h : (((spends.card + outputs.card + 2) * M : ℕ) : ℤ) < p := by exact_mod_cast hp
    push_cast at h
    linarith
  obtain ⟨hmax_lo, hmax_hi⟩ := abs_le.mp hmax
  obtain ⟨hvb_lo, hvb_hi⟩ := abs_le.mp hvb
  have hbound : |∑ i ∈ spends, spent i - ∑ j ∈ outputs, created j - maxFee - vBalance| < p :=
    abs_lt.mpr ⟨by linarith, by linarith⟩
  have heq := Int.eq_zero_of_abs_lt_dvd ((CharP.intCast_eq_zero_iff K p _).mp hzero) hbound
  omega

end Tachyon
