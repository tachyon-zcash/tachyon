import Tachyon.SpendAuthorization
import Mathlib.Tactic.Abel

/-!
# Computed owner-key extraction from a fork, or challenge equality

This is Schnorr special soundness for a randomized key `ak + alpha*G`.
Two accepted responses with the same nonce point and different challenges
compute the scalar of `ak` relative to `G`. If the challenges coincide, the
reduction returns that equality as a miss. This follows ragu's computed
`programmedExtractOrMiss` / discrete-log-witness discipline.

The two challenges are interactive/forked transcript data. They are NOT claimed
to be two different outputs of one deterministic hash on identical inputs.
Producing a suitable fork from a Fiat-Shamir signature forger, bounding the
challenge-equality probability, and proving concrete RedPallas unforgeability
are separate security-game layers. Nothing here extracts a secret from one
ordinary valid signature or classically chooses a logarithm.
-/

namespace Tachyon.Authorization

variable {K G : Type*} [Field K] [AddCommGroup G] [Module K G]

/-- Same data shape as ragu's `DiscreteLogWitness`: an explicit scalar, not an
existential discrete-log assumption. The base is nonzero in the intended curve. -/
structure OwnerLog (base owner : G) where
  scalar : K
  equation : scalar • base = owner

structure Fork (base key : G) where
  nonce : G
  challenge₁ : K
  challenge₂ : K
  response₁ : K
  response₂ : K
  accepted₁ : response₁ • base = nonce + challenge₁ • key
  accepted₂ : response₂ • base = nonce + challenge₂ • key

variable [DecidableEq K]

/-- The returned logarithm is computed by subtraction, inversion and removing
the known key randomizer. No group discrete-log solver is assumed. -/
def ownerLogOrMiss (base owner : G) (alpha : K) (fork : Fork (K := K) base (owner + alpha • base)) :
    OwnerLog (K := K) base owner ⊕' (fork.challenge₁ = fork.challenge₂) := by
  by_cases heq : fork.challenge₁ = fork.challenge₂
  · exact .inr heq
  · have hdelta : fork.challenge₁ - fork.challenge₂ ≠ 0 := sub_ne_zero.mpr heq
    have hdifference : (fork.response₁ - fork.response₂) • base =
        (fork.challenge₁ - fork.challenge₂) • (owner + alpha • base) := by
      calc
        _ = fork.response₁ • base - fork.response₂ • base := sub_smul _ _ _
        _ = (fork.nonce + fork.challenge₁ • (owner + alpha • base)) -
            (fork.nonce + fork.challenge₂ • (owner + alpha • base)) := by
          rw [fork.accepted₁, fork.accepted₂]
        _ = _ := by rw [sub_smul]; abel
    apply PSum.inl
    refine ⟨(fork.challenge₁ - fork.challenge₂)⁻¹ * (fork.response₁ - fork.response₂) - alpha, ?_⟩
    rw [sub_smul, mul_smul, hdifference, smul_smul, inv_mul_cancel₀ hdelta, one_smul]
    exact add_sub_cancel_right owner (alpha • base)

namespace ForkExamples

def fork : Fork (K := ℚ) (1 : ℚ) (3 + (2 : ℚ) • (1 : ℚ)) :=
  ⟨7, 1, 2, 12, 17, by norm_num, by norm_num⟩

def sameChallenge : Fork (K := ℚ) (1 : ℚ) (3 + (2 : ℚ) • (1 : ℚ)) :=
  ⟨7, 1, 1, 12, 12, by norm_num, by norm_num⟩

#guard match ownerLogOrMiss (1 : ℚ) 3 2 fork with
  | .inl witness => witness.scalar == 3
  | .inr _ => false

#guard match ownerLogOrMiss (1 : ℚ) 3 2 sameChallenge with
  | .inl _ => false
  | .inr _ => true

end ForkExamples

end Tachyon.Authorization
