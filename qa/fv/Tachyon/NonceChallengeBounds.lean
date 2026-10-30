import Tachyon.OutputPairing

/-!
# Fixed-target nonce-challenge counting bounds

For a nonzero generator and a lossless word-to-scalar encoding,
`word ↦ offset + [embed word]G` is injective. At most one nonce word hits a
fixed target point, and at most `k` words hit `k` fixed targets.

These are deterministic counting statements, analogous to the fixed-operand
root-count bounds in `Idealization.lean`. Dividing by the word-space size gives
the corresponding bound for a uniform fresh word. This does NOT prove that a
Poseidon nonce output is uniform, that a prover fixed its owner key/target
before querying, or that the spend/payment-key/note dependency cycle admits
the required forking reduction. Those causal/security-game obligations remain
necessary for spend/spend and mixed spend/output pairing.
-/

namespace Tachyon.NonceChallengeBounds

open scoped BigOperators

variable {V K G : Type*} [Field K] [AddCommGroup G] [Module K G]
  [DecidableEq K] [DecidableEq G]

def randomizedKey (embed : V → K) (base offset : G) (word : V) : G := offset + embed word • base

omit [DecidableEq G] in
theorem randomizedKey_injective (embed : V → K) (hembed : Function.Injective embed)
    (base offset : G) (hbase : base ≠ 0) : Function.Injective (randomizedKey embed base offset) := by
  intro left right hkey
  apply hembed
  exact OutputPairing.scalar_eq_of_smul_eq hbase (add_left_cancel hkey)

variable [Fintype V]

theorem card_fixed_target_le_one (embed : V → K) (hembed : Function.Injective embed)
    (base offset target : G) (hbase : base ≠ 0) :
    (Finset.univ.filter fun word => randomizedKey embed base offset word = target).card ≤ 1 := by
  apply Finset.card_le_one.mpr
  intro left hleft right hright
  exact randomizedKey_injective embed hembed base offset hbase
    ((Finset.mem_filter.mp hleft).2.trans (Finset.mem_filter.mp hright).2.symm)

theorem card_fixed_targets_le (embed : V → K) (hembed : Function.Injective embed)
    (base offset : G) (targets : Finset G) (hbase : base ≠ 0) :
    (Finset.univ.filter fun word => randomizedKey embed base offset word ∈ targets).card ≤ targets.card := by
  let candidates := Finset.univ.filter fun word => randomizedKey embed base offset word ∈ targets
  calc
    candidates.card = (candidates.image (randomizedKey embed base offset)).card :=
      (Finset.card_image_of_injective _ (randomizedKey_injective embed hembed base offset hbase)).symm
    _ ≤ targets.card := Finset.card_le_card (by
      intro point hpoint
      obtain ⟨word, hword, rfl⟩ := Finset.mem_image.mp hpoint
      exact (Finset.mem_filter.mp hword).2)

/-- For a nonempty word space, these ratios are uniform-word probabilities.
This numeric inequality also covers the empty case, with no random-oracle
claim about the concrete Poseidon function. -/
theorem uniform_fixed_targets_bound (embed : V → K) (hembed : Function.Injective embed)
    (base offset : G) (targets : Finset G) (hbase : base ≠ 0) :
    ((Finset.univ.filter fun word => randomizedKey embed base offset word ∈ targets).card : ℚ) /
        Fintype.card V ≤ (targets.card : ℚ) / Fintype.card V := by
  apply div_le_div_of_nonneg_right
  · exact_mod_cast card_fixed_targets_le embed hembed base offset targets hbase
  · positivity

end Tachyon.NonceChallengeBounds
