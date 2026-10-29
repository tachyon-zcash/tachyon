import Tachyon.Consensus.Chain
import Mathlib.Data.Fintype.EquivFin

/-!
# The global hash law is a symbolic reference model

`Chain.HashLaw` is useful for statements in a collision-free symbolic model.
It cannot literally hold for concrete finite anchor outputs. This is not just
an artifact of using natural epochs: even with a bounded epoch type, its stamp
clause would inject every polynomial into a finite anchor domain.

Concrete reductions use `AnchorBreaks`, `SourceBreakReduction`, `AnchorTraces`,
`SpanTraces` and `SourceQueryBreaks` instead: the result or computed colliding
inputs from the actual finite trace. Computational hardness is a separate
security statement, following ragu's break-witness discipline.

We retain the old mathematical law and its conditional theorems as a symbolic
reference, rather than changing their meanings or silently instantiating them
with finite hashes. These impossibility results make that boundary explicit.
-/

namespace Tachyon.Chain

open Polynomial

theorem HashLaw.not_finite_anchors {F A E : Type*} [Field F] [Finite A]
    (genesis : A) (e₀ : E) (nextStamp : A → E → F[X] → A) (nextEpoch : A → E → A) :
    ¬ HashLaw genesis e₀ nextStamp nextEpoch := by
  intro h
  apply not_injective_infinite_finite (nextStamp genesis e₀)
  intro p q heq
  exact (h.nextStamp_inj heq).2.2

theorem HashLaw.not_finite_anchors_nat_epochs {F A : Type*} [Field F] [Finite A]
    (genesis : A) (e₀ : ℕ) (nextStamp : A → ℕ → F[X] → A) (nextEpoch : A → ℕ → A) :
    ¬ HashLaw genesis e₀ nextStamp nextEpoch := by
  intro h
  apply not_injective_infinite_finite (nextEpoch genesis)
  intro e e' heq
  exact (h.nextEpoch_inj heq).2

end Tachyon.Chain

/--
info: 'Tachyon.Chain.HashLaw.not_finite_anchors' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms Tachyon.Chain.HashLaw.not_finite_anchors
