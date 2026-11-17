import Tachyon.Qr

/-!
# Challenge-indexed QR guards

`Qr.Split` and `Qr.SideCheck` intentionally over-approximate QR routing for
root retention. This module refines those idealized relations with the two
evaluation guards in `QrIntakeSplit` and `QrSideDescend`:
`parent(zeta) != 1` and `nonResidue(zeta) != residue(zeta)` respectively.
`Split.refines_iff` and `sideCheck_iff` give the exact additional predicates;
forgetting them recovers the existing relations and their retention proofs.

The guards are evaluated at supplied challenges, not replaced by polynomial
inequality, monicity, root-list nonemptiness or disjointness. In particular,
scaled constants and differently scaled polynomials with equal roots remain
possible. Split and descent are different steps, so `Route` records a separate
pair of challenges for each hop, rather than sharing one challenge tree-wide.

This is a local refinement of the polynomial-identity model, NOT equivalence
with the Rust circuit. Product and sibling checks are still idealized as full
polynomial identities; commitments, challenge generation, metadata and profile
gadgets retain their existing boundaries. The guarded route is not threaded
through `RoutedIntakes`, checked queries or evidence replay. Its exclusion
theorem requires source completeness and a matching profile explicitly.
-/

namespace Tachyon.Qr.Guarded

open Polynomial

variable {F : Type*} [Field F]

/-- An idealized split with the split step's actual evaluation guard. -/
structure Split (parent : F[X]) (r zeta : F) extends Qr.Split parent r where
  nonunit : parent.eval zeta ≠ 1

/-- Every old split whose parent passes this guard has a guarded refinement. -/
def Split.ofSplit {parent : F[X]} {r zeta : F} (s : Qr.Split parent r)
    (h : parent.eval zeta ≠ 1) : Split parent r zeta :=
  { toSplit := s, nonunit := h }

/-- Refinement adds exactly the parent-evaluation guard, nothing about roots
or leading coefficients. The existential here is not a cryptographic break. -/
theorem Split.refines_iff {parent : F[X]} {r zeta : F} (s : Qr.Split parent r) :
    (∃ guarded : Split parent r zeta, guarded.toSplit = s) ↔ parent.eval zeta ≠ 1 := by
  constructor
  · rintro ⟨guarded, _⟩
    exact guarded.nonunit
  · intro h
    exact ⟨Split.ofSplit s h, rfl⟩

/-- Descent adds its side-evaluation guard to the old selection/hint relation.
The split guard is separate, since the split was checked at a different challenge. -/
def SideCheck (c zeta : F) {parent : F[X]} {r : F} (s : Qr.Split parent r)
    (bit : Bool) (interpolant quotient : F[X]) : Prop :=
  Qr.SideCheck c s bit interpolant quotient ∧
    s.nonResidue.eval zeta ≠ s.residue.eval zeta

/-- Local guard faithfulness relative to the existing idealized side check. -/
theorem sideCheck_iff {c zeta r : F} {parent : F[X]} {s : Qr.Split parent r}
    {bit : Bool} {u q : F[X]} :
    SideCheck c zeta s bit u q ↔
      Qr.SideCheck c s bit u q ∧ s.nonResidue.eval zeta ≠ s.residue.eval zeta :=
  Iff.rfl

theorem SideCheck.forget {c zeta r : F} {parent : F[X]} {s : Qr.Split parent r}
    {bit : Bool} {u q : F[X]} (h : SideCheck c zeta s bit u q) :
    Qr.SideCheck c s bit u q :=
  h.1

/-- Adding the descent guard preserves matching-root retention. -/
theorem SideCheck.retains {c zeta r v : F} (hc : ¬ IsSquare c)
    {parent : F[X]} {s : Qr.Split parent r} {bit : Bool} {u q : F[X]}
    (h : SideCheck c zeta s bit u q) (hmatch : Matches r v bit)
    (hroot : parent.eval v = 0) : (s.selected bit).eval v = 0 :=
  h.forget.retains hc hmatch hroot

/-- A local guarded route with one (split, descent) challenge pair per hop.
Neither challenges nor their distribution are extracted from a real proof. -/
inductive Route (c : F) : F → F[X] → List Bool → List (F × F) → F[X] → Prop
  | root (r : F) (parent : F[X]) : Route c r parent [] [] parent
  | descend {r splitZeta descendZeta : F} {parent leaf u q : F[X]}
      {bit : Bool} {bits : List Bool} {challenges : List (F × F)}
      (s : Split parent r splitZeta) :
      SideCheck c descendZeta s.toSplit bit u q →
      Route c (r + 1) (s.toSplit.selected bit) bits challenges leaf →
      Route c r parent (bit :: bits) ((splitZeta, descendZeta) :: challenges) leaf

/-- Forget both local guards and the recorded challenges. -/
theorem Route.forget {c r : F} {parent leaf : F[X]} {bits : List Bool}
    {challenges : List (F × F)} (h : Route c r parent bits challenges leaf) :
    Qr.Route c r parent bits leaf := by
  induction h with
  | root => exact Qr.Route.root _ _
  | descend s hside _ ih => exact Qr.Route.descend s.toSplit hside.forget ih

/-- Every hop records both challenges, including when the profile is empty. -/
theorem Route.challenges_length {c r : F} {parent leaf : F[X]} {bits : List Bool}
    {challenges : List (F × F)} (h : Route c r parent bits challenges leaf) :
    challenges.length = bits.length := by
  induction h with
  | root => rfl
  | descend _ _ _ ih => simpa using ih

theorem Route.retains {c r v : F} (hc : ¬ IsSquare c) {parent leaf : F[X]}
    {bits : List Bool} {challenges : List (F × F)}
    (h : Route c r parent bits challenges leaf) (hmatch : MatchesProfile r v bits)
    (hroot : parent.eval v = 0) : leaf.eval v = 0 :=
  h.forget.retains hc hmatch hroot

theorem Route.source_ne_zero {c r v : F} (hc : ¬ IsSquare c) {parent leaf : F[X]}
    {bits : List Bool} {challenges : List (F × F)}
    (h : Route c r parent bits challenges leaf) (hmatch : MatchesProfile r v bits)
    (hne : leaf.eval v ≠ 0) : parent.eval v ≠ 0 :=
  h.forget.source_ne_zero hc hmatch hne

/-- Exclusion for this local guarded route, conditional on source completeness
and profile matching, not on an asserted end-to-end circuit correspondence. -/
theorem Route.not_published {A : Type*} {chain : List (Chain.Stamp F A)} {e : ℕ}
    {c r v : F} (hc : ¬ IsSquare c) {parent leaf : F[X]} {bits : List Bool}
    {challenges : List (F × F)}
    (hsource : ∀ t, Chain.published chain e t → parent.eval t = 0)
    (h : Route c r parent bits challenges leaf) (hmatch : MatchesProfile r v bits)
    (hne : leaf.eval v ≠ 0) : ¬ Chain.published chain e v :=
  h.forget.not_published hc hsource hmatch hne

/-- The constant-one parent is rejected at every split challenge. -/
theorem split_one_rejected (r zeta : F) : ¬ Nonempty (Split (1 : F[X]) r zeta) := by
  rintro ⟨s⟩
  exact s.nonunit (by simp)

/-- Nonconstant is insufficient: `X` is rejected when the challenge is one. -/
theorem split_X_at_one_rejected (r : F) : ¬ Nonempty (Split (X : F[X]) r 1) := by
  rintro ⟨s⟩
  exact s.nonunit (by simp)

/-- Polynomial inequality alone is insufficient for the descent guard. -/
theorem equal_evaluations_rejected {c zeta r : F} {parent : F[X]}
    (s : Qr.Split parent r) (bit : Bool) (u q : F[X])
    (heq : s.nonResidue.eval zeta = s.residue.eval zeta) :
    ¬ SideCheck c zeta s bit u q :=
  fun h => h.2 heq

namespace Examples

/-- A nonconstant parent rejected at one passes the split guard at zero. -/
theorem split_challenge_matters :
    Nonempty (Split (X : ℚ[X]) 0 0) ∧ ¬ Nonempty (Split (X : ℚ[X]) 0 1) := by
  exact ⟨⟨Split.ofSplit ⟨X, 1, by simp⟩ (by norm_num)⟩,
    split_X_at_one_rejected 0⟩

/-- The old side relation can pass for distinct polynomials with equal
evaluations. Thus descent's new guard is not just polynomial inequality. -/
theorem distinct_sides_equal_evaluations :
    ∃ s : Split (X ^ 3 : ℚ[X]) 1 0,
      s.nonResidue ≠ s.residue ∧
      Qr.SideCheck 2 s.toSplit false (1 + C (1 / 2) * X) (C (1 / 4)) ∧
      ¬ SideCheck 2 0 s.toSplit false (1 + C (1 / 2) * X) (C (1 / 4)) := by
  let s : Split (X ^ 3 : ℚ[X]) 1 0 :=
    ⟨⟨X, X ^ 2, by ring⟩, by norm_num⟩
  refine ⟨s, ?_, ?_, ?_⟩
  · intro heq
    have h := congrArg (fun p : ℚ[X] => p.eval 2) heq
    norm_num [s] at h
  · refine ⟨⟨1 + C (1 / 2) * X, C (1 / 4), by norm_num [s]⟩, rfl, rfl, ?_⟩
    change (1 + C (1 / 2 : ℚ) * X) ^ 2 - C 1 * (X + C 1) = X ^ 2 * C (1 / 4)
    norm_num
    ring_nf
    norm_num [← C_mul, ← C_pow]
    rw [mul_right_comm (C (1 / 2 : ℚ)) X 2,
       (C_ofNat 2).symm, ← C_mul]
    norm_num
  · exact equal_evaluations_rejected s.toSplit false _ _ (by norm_num [s])

/-- Reciprocal non-monic scaling is allowed. Both children have exactly the
root zero; at the descent challenge one their evaluations differ. -/
theorem scaled_equal_roots_pass :
    ∃ s : Split (X ^ 2 : ℚ[X]) 1 0,
      (∀ v : ℚ, s.nonResidue.eval v = 0 ↔ s.residue.eval v = 0) ∧
      s.nonResidue.leadingCoeff ≠ 1 ∧ s.residue.leadingCoeff ≠ 1 ∧
      SideCheck 2 1 s.toSplit false 1 (C (-2)) := by
  let s : Split (X ^ 2 : ℚ[X]) 1 0 :=
    ⟨⟨C 2 * X, C (1 / 2) * X, by
      ring_nf
      norm_num [← C_mul]⟩, by norm_num⟩
  refine ⟨s, ?_, ?_, ?_, ?_⟩
  · intro v
    simp [s]
  · norm_num [s]
  · norm_num [s]
  · refine ⟨⟨⟨1, C (-2), by norm_num [s]⟩, rfl, rfl, ?_⟩, ?_⟩
    · change (1 : ℚ[X]) ^ 2 - C 1 * (X + C 1) = (C (1 / 2) * X) * C (-2)
      norm_num
      ring_nf
      norm_num [← C_mul]
      rw [mul_right_comm (C (1 / 2 : ℚ)) X (C 2), ← C_mul]
      norm_num
    · norm_num [s]

/-- A nonempty guarded route may use different split and descent challenges. -/
theorem route_uses_distinct_challenges :
    ∃ leaf : ℚ[X], Route 2 1 (X ^ 2) [false] [(0, 1)] leaf := by
  obtain ⟨s, _, _, _, hside⟩ := scaled_equal_roots_pass
  exact ⟨s.toSplit.selected false, Route.descend s hside (Route.root _ _)⟩

/-- A rootless, scaled-constant parent and two rootless children can pass both
guards and a full idealized side check. Nonempty root lists are not required. -/
theorem scaled_constants_pass :
    ∃ s : Split (C (2 : ℚ)) 0 0,
      (∀ v : ℚ, s.nonResidue.eval v ≠ 0 ∧ s.residue.eval v ≠ 0) ∧
      SideCheck 2 0 s.toSplit false 0 (-X) := by
  let s : Split (C (2 : ℚ)) 0 0 := ⟨⟨C 2, 1, by simp⟩, by norm_num⟩
  refine ⟨s, ?_, ?_⟩
  · intro v
    norm_num [s]
  · refine ⟨⟨⟨0, -X, by norm_num [s]⟩, rfl, rfl, ?_⟩, ?_⟩
    · simp [Qr.Split.sibling, s]
    · norm_num [s]

end Examples

end Tachyon.Qr.Guarded
