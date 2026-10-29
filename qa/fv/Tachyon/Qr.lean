import Tachyon.Spendable
import Mathlib.Algebra.Group.Even

/-!
# QR routing preserves every matching root

The polynomial checks in `QrIntakeSplit` and `QrSideDescend`
(`crates/tachyon/src/stamp/proof/qr.rs:347-528`) do not require that a selected child
contains only its own class. They require that it loses no root in that class.
An extra root makes a later nonzero opening harder, never easier.

`Split` models the product check and exceptional-value guard. `SideCheck` models
the sibling's interpolant/quotient identity, with multiplier `1` when selecting
the non-residue side and `c` when selecting the residue side. The discriminants
advance by one, as in the Rust code. `Route.retains` composes root retention along
any finite profile, including the empty profile.

`Route.not_published` proves sound exclusion when the source polynomial contains
the epoch's published values and the queried value matches the selected profile.
Source completeness and the matching profile are explicit hypotheses: this file
does not prove chain sealing, evidence-tree replay, or the boolean-mask gadget.
In particular it does not identify one routed bucket with the entire epoch.
`CompleteBucket` in `Spendable.lean` is stronger than the target-specific property
of a real routed bucket; that interface needs a later profile-aware refinement.

Commitment binding and the random-opening-to-polynomial-identity idealization
are the same boundaries as in the stamp model. The field's fixed multiplier is
assumed to be a non-square; no assumption that the field is finite is needed.
-/

namespace Tachyon.Qr

open Polynomial

variable {F : Type*} [Field F]

/-- A partition of an intake, including `QrIntakeSplit`'s opening at `-r`. -/
structure Split (parent : F[X]) (r : F) where
  nonResidue : F[X]
  residue : F[X]
  product : parent = nonResidue * residue
  exceptional : nonResidue.eval (-r) ≠ 0

/-- `false` selects the non-residue side; `true` selects the residue side. -/
def Split.selected {parent : F[X]} {r : F} (s : Split parent r) (bit : Bool) : F[X] :=
  if bit then s.residue else s.nonResidue

def Split.sibling {parent : F[X]} {r : F} (s : Split parent r) (bit : Bool) : F[X] :=
  if bit then s.nonResidue else s.residue

/-- The exact polynomial identity checked by `QrSideDescend`. Both witnesses are
arbitrary polynomials; no degree or root-list assumption is imposed on them. -/
def SideCheck (c : F) {parent : F[X]} {r : F} (s : Split parent r) (bit : Bool)
    (interpolant quotient : F[X]) : Prop :=
  interpolant ^ 2 - C (if bit then c else 1) * (X + C r) = s.sibling bit * quotient

/-- The tested value takes the chosen class at discriminant `r`. Zero is square,
so the exceptional value `-r` belongs to the residue side. -/
def Matches (r v : F) (bit : Bool) : Prop :=
  if bit then IsSquare (v + r) else ¬ IsSquare (v + r)

/-- A non-square times a nonzero square cannot be square. -/
theorem not_square_mul {c x : F} (hc : ¬ IsSquare c) (hx : x ≠ 0)
    (hsq : IsSquare x) : ¬ IsSquare (c * x) := by
  intro hprod
  exact hc (by simpa [hx] using hprod.div hsq)

/-- A matching value cannot be a root of the sibling. For the residue branch,
the exceptional guard is essential to exclude zero before dividing squares. -/
theorem SideCheck.sibling_ne_zero {c r v : F} (hc : ¬ IsSquare c)
    {parent : F[X]} {s : Split parent r} {bit : Bool} {u q : F[X]}
    (hcheck : SideCheck c s bit u q) (hmatch : Matches r v bit) :
    (s.sibling bit).eval v ≠ 0 := by
  intro hzero
  have hev := congrArg (fun p : F[X] => p.eval v) hcheck
  simp only [eval_sub, eval_pow, eval_mul, eval_C, eval_add, eval_X, hzero,
    zero_mul, sub_eq_zero] at hev
  cases bit with
  | false =>
    have hsq : IsSquare (v + r) := by
      apply (isSquare_iff_exists_sq _).mpr
      exact ⟨u.eval v, by simpa using hev.symm⟩
    exact hmatch hsq
  | true =>
    have hnonzero : v + r ≠ 0 := by
      intro hz
      have hv : v = -r := eq_neg_of_add_eq_zero_left hz
      exact s.exceptional (by simpa [Split.sibling, hv] using hzero)
    apply not_square_mul hc hnonzero hmatch
    exact (isSquare_iff_exists_sq _).mpr ⟨u.eval v, by simpa using hev.symm⟩

/-- The factorization and sibling class certificate force a parent's matching
root to remain a root of the selected child. -/
theorem SideCheck.retains {c r v : F} (hc : ¬ IsSquare c)
    {parent : F[X]} {s : Split parent r} {bit : Bool} {u q : F[X]}
    (hcheck : SideCheck c s bit u q) (hmatch : Matches r v bit)
    (hroot : parent.eval v = 0) : (s.selected bit).eval v = 0 := by
  have hprod : parent = s.selected bit * s.sibling bit := by
    cases bit <;> simpa [Split.selected, Split.sibling, mul_comm] using s.product
  rw [hprod, eval_mul] at hroot
  exact (mul_eq_zero.mp hroot).resolve_right (hcheck.sibling_ne_zero hc hmatch)

/-- The class profile a value follows, starting at discriminant `r`. -/
def MatchesProfile (r v : F) : List Bool → Prop
  | [] => True
  | bit :: bits => Matches r v bit ∧ MatchesProfile (r + 1) v bits

/-- A chain of split/descent steps. Intermediate polynomials need not be monic
or set polynomials, making the retention claim valid even for stray factors. -/
inductive Route (c : F) : F → F[X] → List Bool → F[X] → Prop
  | root (r : F) (parent : F[X]) : Route c r parent [] parent
  | descend {r : F} {parent leaf u q : F[X]} {bit : Bool} {bits : List Bool}
      (s : Split parent r) :
      SideCheck c s bit u q →
      Route c (r + 1) (s.selected bit) bits leaf →
      Route c r parent (bit :: bits) leaf

/-- No root matching the entire profile is lost by a sequence of descents. -/
theorem Route.retains {c r v : F} (hc : ¬ IsSquare c)
    {parent leaf : F[X]} {bits : List Bool} (hroute : Route c r parent bits leaf)
    (hmatch : MatchesProfile r v bits) (hroot : parent.eval v = 0) :
    leaf.eval v = 0 := by
  induction hroute with
  | root => exact hroot
  | descend s hside _ ih =>
    exact ih hmatch.2 (hside.retains hc hmatch.1 hroot)

/-- Target-specific completeness: for a value matching this route, a nonzero
leaf opening certifies a nonzero source opening. -/
theorem Route.source_ne_zero {c r v : F} (hc : ¬ IsSquare c)
    {parent leaf : F[X]} {bits : List Bool} (hroute : Route c r parent bits leaf)
    (hmatch : MatchesProfile r v bits) (hne : leaf.eval v ≠ 0) :
    parent.eval v ≠ 0 :=
  fun hroot => hne (hroute.retains hc hmatch hroot)

/-- A nonzero opening in a matching routed bucket proves absence from the
epoch, provided the source contains the epoch's published values. -/
theorem Route.not_published {A : Type*} {chain : List (Chain.Stamp F A)} {e : ℕ}
    {c r v : F} (hc : ¬ IsSquare c) {parent leaf : F[X]} {bits : List Bool}
    (hsource : ∀ t, Chain.published chain e t → parent.eval t = 0)
    (hroute : Route c r parent bits leaf) (hmatch : MatchesProfile r v bits)
    (hne : leaf.eval v ≠ 0) : ¬ Chain.published chain e v :=
  fun hpub => hroute.source_ne_zero hc hmatch hne (hsource v hpub)

/-- Without the exceptional opening, the product and sibling identities can
both hold while discarding the square value zero into the non-residue side.
The selected residue polynomial `1` then opens nonzero at a source root. -/
theorem exceptional_guard_needed (c : F) :
    ∃ parent nonResidue residue u q : F[X],
      parent = nonResidue * residue ∧
      u ^ 2 - C c * X = nonResidue * q ∧
      parent.eval 0 = 0 ∧ IsSquare (0 : F) ∧ residue.eval 0 ≠ 0 := by
  refine ⟨X, X, 1, 0, -C c, by simp, ?_, by simp, ?_, by simp⟩
  · ring
  · exact ⟨0, by simp⟩

end Tachyon.Qr
