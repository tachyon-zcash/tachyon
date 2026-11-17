import Tachyon.QueryCertificates
import Tachyon.Binding

/-!
# Scoped anchor breaks through commitment/bridge composition

Here `m.commit` denotes the composition `bridge ∘ pc`, and `C` denotes bridge
outputs, not Pedersen points. Factorization is supplied on the actual finite
opening scope. It is a premise about canonical encoding, not a consequence of
PCD soundness: this module does not prove that intermediate bridge encodings
are canonical. A hash break is still a break of `m.eval`; calling it a concrete
Poseidon collision additionally requires the actual tagged coordinate encoding.

Classification preserves the original collision and its exact finite scope.
Only equality of actual Pedersen commitments enters `ofPolyCollision`. Generic
runtime opening inequality is not polynomial inequality; the DL specialization
therefore uses `F[X]` and inherits Binding's noncomputable representation boundary.
It does not claim a runtime encoding is faithful or extract witnesses from PCD.
-/

namespace Tachyon.AnchorBreaks

universe u v w z t

variable {P : Type u} {C : Type v} {A : Type w} {E : Type z} {G : Type t}
  {m : Model P C A E} {pc : P → G} {bridge : G → C}
  {ps : List P} {xs : List (Input C A E)}

/-- A composite opening collision is either an actual commitment equality or
a bridge collision on distinct commitment points. The old collision is retained. -/
inductive ScopedPrimitiveBreak (m : Model P C A E) (pc : P → G) (bridge : G → C)
    (ps : List P) (xs : List (Input C A E))
  | pedersen (collision : CommitmentCollision m)
      (covered : collision.left ∈ ps ∧ collision.right ∈ ps)
      (equal : pc collision.left = pc collision.right)
  | bridge (collision : CommitmentCollision m)
      (covered : collision.left ∈ ps ∧ collision.right ∈ ps)
      (distinct : pc collision.left ≠ pc collision.right)
      (equal : bridge (pc collision.left) = bridge (pc collision.right))
  | hash (collision : HashCollision m)
      (covered : collision.left ∈ xs ∧ collision.right ∈ xs)

def ScopedPrimitiveBreak.forget (w : ScopedPrimitiveBreak m pc bridge ps xs) :
    ScopedBreak m ps xs :=
  match w with
  | .pedersen col covered _ => ⟨.commitment col, covered⟩
  | .bridge col covered _ _ => ⟨.commitment col, covered⟩
  | .hash col covered => ⟨.hash col, covered⟩

/-- Refine the break returned by an existing reducer, with no new injectivity
assumption. Canonical factorization is required only on its finite scope. -/
def ScopedBreak.refineComposition [DecidableEq G] (w : ScopedBreak m ps xs)
    (hfactor : ∀ p ∈ ps, m.commit p = bridge (pc p)) :
    ScopedPrimitiveBreak m pc bridge ps xs := by
  obtain ⟨witness, covered⟩ := w
  cases witness with
  | commitment col =>
    by_cases h : pc col.left = pc col.right
    · exact .pedersen col covered h
    · exact .bridge col covered h
        ((hfactor _ covered.1).symm.trans (col.equal.trans (hfactor _ covered.2)))
  | hash col => exact .hash col covered

@[simp]
theorem ScopedBreak.forget_refineComposition [DecidableEq G] (w : ScopedBreak m ps xs)
    (hfactor : ∀ p ∈ ps, m.commit p = bridge (pc p)) :
    (w.refineComposition hfactor).forget = w := by
  obtain ⟨witness, covered⟩ := w
  cases witness with
  | commitment col =>
    simp only [ScopedBreak.refineComposition]
    split <;> rfl
  | hash col => rfl

end Tachyon.AnchorBreaks

namespace Tachyon.SourceQueryBreaks

open Polynomial AnchorBreaks

variable {P C A G : Type*}
  {m : Model P C A ℕ} {pc : P → G} {bridge : G → C}

/-- The observed transcript remains data, including all epoch/seal preimages. -/
structure ObservedPrimitiveBreak (m : Model P C A ℕ) (pc : P → G) (bridge : G → C) where
  openings : List P
  inputs : List (Input C A ℕ)
  collision : ScopedPrimitiveBreak m pc bridge openings inputs

def ObservedPrimitiveBreak.forget (w : ObservedPrimitiveBreak m pc bridge) : ObservedBreak m :=
  ⟨w.openings, w.inputs, w.collision.forget⟩

/-- Postprocesses, in particular, `doubleSpendObservedBreak` without changing
its trace traversal, success conditions, or per-query transcript. -/
def ObservedBreak.refineComposition [DecidableEq G] (w : ObservedBreak m)
    (hfactor : ∀ p ∈ w.openings, m.commit p = bridge (pc p)) :
    ObservedPrimitiveBreak m pc bridge :=
  ⟨w.openings, w.inputs, w.collision.refineComposition hfactor⟩

@[simp]
theorem ObservedBreak.forget_refineComposition [DecidableEq G] (w : ObservedBreak m)
    (hfactor : ∀ p ∈ w.openings, m.commit p = bridge (pc p)) :
    (w.refineComposition hfactor).forget = w := by
  cases w
  simp [ObservedBreak.refineComposition, ObservedPrimitiveBreak.forget]

variable {F : Type*} [Field F] [Monoid P]
  [DecidableEq P] [DecidableEq C] [DecidableEq A] [DecidableEq G]
  {interpret : P →* F[X]} {chain : List (Chain.Stamp F A)} {c : F}
  {b : QrBucket F A} {value : F}

/-- The actual checked source-query reduction, with its returned break split
into primitive layers. No source/profile completeness premise is added. -/
def Certificate.primitiveOutcome (hc : ¬ IsSquare c)
    (q : Certificate m interpret chain c b value)
    (hfactor : ∀ p ∈ q.openings, m.commit p = bridge (pc p)) :
    Profiled.QueryComplete chain b value ⊕' ScopedPrimitiveBreak m pc bridge q.openings q.inputs :=
  match q.outcome hc with
  | .inl success => .inl success
  | .inr witness => .inr (witness.refineComposition hfactor)

@[simp]
theorem Certificate.forget_primitiveOutcome (hc : ¬ IsSquare c)
    (q : Certificate m interpret chain c b value)
    (hfactor : ∀ p ∈ q.openings, m.commit p = bridge (pc p)) :
    (match q.primitiveOutcome hc hfactor with
      | .inl success => .inl success
      | .inr witness => .inr witness.forget) = q.outcome hc := by
  cases hout : q.outcome hc <;> simp [Certificate.primitiveOutcome, hout]

end Tachyon.SourceQueryBreaks

namespace Tachyon.AnchorBreaks

open Polynomial

variable {F G C A E : Type*} [Field F] [AddCommGroup G] [Module F G] {n : ℕ}
  {g : Fin n → G} {m : Model F[X] C A E} {bridge : G → C}
  {ps : List F[X]} {xs : List (Input C A E)}

/-- A bounded polynomial collision together with the relation computed from
its actual Pedersen equality. Neither the source collision nor scope is lost. -/
structure ScopedPolyDLRelation (m : Model F[X] C A E) (g : Fin n → G)
    (ps : List F[X]) (xs : List (Input C A E)) where
  collision : CommitmentCollision m
  covered : collision.left ∈ ps ∧ collision.right ∈ ps
  equal : polyCommit g collision.left = polyCommit g collision.right
  relation : NontrivialDLRelation (F := F) g

def ScopedPolyDLRelation.forget (w : ScopedPolyDLRelation m g ps xs) : ScopedBreak m ps xs :=
  ⟨.commitment w.collision, w.covered⟩

/-- The bridge and anchor-hash branches are not fed to the Pedersen adapter. -/
inductive ScopedPolyBreak (m : Model F[X] C A E) (g : Fin n → G) (bridge : G → C)
    (ps : List F[X]) (xs : List (Input C A E))
  | pedersen (witness : ScopedPolyDLRelation m g ps xs)
  | bridge (collision : CommitmentCollision m)
      (covered : collision.left ∈ ps ∧ collision.right ∈ ps)
      (distinct : polyCommit g collision.left ≠ polyCommit g collision.right)
      (equal : bridge (polyCommit g collision.left) = bridge (polyCommit g collision.right))
  | hash (collision : HashCollision m)
      (covered : collision.left ∈ xs ∧ collision.right ∈ xs)

def ScopedPolyBreak.forget (w : ScopedPolyBreak m g bridge ps xs) : ScopedBreak m ps xs :=
  match w with
  | .pedersen witness => witness.forget
  | .bridge col covered _ _ => ⟨.commitment col, covered⟩
  | .hash col covered => ⟨.hash col, covered⟩

/-- Rank bounds are supplied on the compared stamp openings, not inferred
from finiteness or assumed for every source accumulator. -/
noncomputable def ScopedPrimitiveBreak.toPolyBreak
    (w : ScopedPrimitiveBreak m (polyCommit g) bridge ps xs)
    (hbound : ∀ p ∈ ps, p.natDegree < n) : ScopedPolyBreak m g bridge ps xs :=
  match w with
  | .pedersen col covered equal =>
      .pedersen ⟨col, covered, equal, NontrivialDLRelation.ofPolyCollision
        (hbound _ covered.1) (hbound _ covered.2) equal col.distinct⟩
  | .bridge col covered distinct equal => .bridge col covered distinct equal
  | .hash col covered => .hash col covered

@[simp]
theorem ScopedPrimitiveBreak.forget_toPolyBreak
    (w : ScopedPrimitiveBreak m (polyCommit g) bridge ps xs)
    (hbound : ∀ p ∈ ps, p.natDegree < n) :
    (w.toPolyBreak hbound).forget = w.forget := by
  cases w <;> rfl

end Tachyon.AnchorBreaks

namespace Tachyon.SourceQueryBreaks

open Polynomial AnchorBreaks

variable {F G C A : Type*} [Field F] [AddCommGroup G] [Module F G] {n : ℕ}
  {g : Fin n → G} {m : Model F[X] C A ℕ} {bridge : G → C}
  [DecidableEq G]
  {chain : List (Chain.Stamp F A)} {c : F} {b : QrBucket F A} {value : F}

/-- The recorded observation and all its finite inputs survive DL adaptation. -/
structure ObservedPolyBreak (m : Model F[X] C A ℕ) (g : Fin n → G) (bridge : G → C) where
  openings : List F[X]
  inputs : List (Input C A ℕ)
  collision : ScopedPolyBreak m g bridge openings inputs

def ObservedPolyBreak.forget (w : ObservedPolyBreak m g bridge) : ObservedBreak m :=
  ⟨w.openings, w.inputs, w.collision.forget⟩

/-- Directly accepts the output of `doubleSpendObservedBreak`; bounds and
canonical factorization are supplied on the observation it actually returned. -/
noncomputable def ObservedBreak.polyRefine (w : ObservedBreak m)
    (hfactor : ∀ p ∈ w.openings, m.commit p = bridge (polyCommit g p))
    (hbound : ∀ p ∈ w.openings, p.natDegree < n) : ObservedPolyBreak m g bridge :=
  ⟨w.openings, w.inputs, (w.collision.refineComposition hfactor).toPolyBreak hbound⟩

@[simp]
theorem ObservedBreak.forget_polyRefine (w : ObservedBreak m)
    (hfactor : ∀ p ∈ w.openings, m.commit p = bridge (polyCommit g p))
    (hbound : ∀ p ∈ w.openings, p.natDegree < n) :
    (w.polyRefine hfactor hbound).forget = w := by
  cases w
  simp [ObservedBreak.polyRefine, ObservedPolyBreak.forget]

variable [DecidableEq F[X]] [DecidableEq C] [DecidableEq A]

/-- A real Certificate reduction specialized through the existing Pedersen
binding adapter. Canonical factorization and both rank bounds remain premises. -/
noncomputable def Certificate.polyOutcome (hc : ¬ IsSquare c)
    (q : Certificate m (MonoidHom.id F[X]) chain c b value)
    (hfactor : ∀ p ∈ q.openings, m.commit p = bridge (polyCommit g p))
    (hbound : ∀ p ∈ q.openings, p.natDegree < n) :
    Profiled.QueryComplete chain b value ⊕' ScopedPolyBreak m g bridge q.openings q.inputs :=
  match q.primitiveOutcome hc hfactor with
  | .inl success => .inl success
  | .inr witness => .inr (witness.toPolyBreak hbound)

@[simp]
theorem Certificate.forget_polyOutcome (hc : ¬ IsSquare c)
    (q : Certificate m (MonoidHom.id F[X]) chain c b value)
    (hfactor : ∀ p ∈ q.openings, m.commit p = bridge (polyCommit g p))
    (hbound : ∀ p ∈ q.openings, p.natDegree < n) :
    (match q.polyOutcome hc hfactor hbound with
      | .inl success => .inl success
      | .inr witness => .inr witness.forget) = q.outcome hc := by
  cases hout : q.outcome hc <;>
    simp [Certificate.polyOutcome, Certificate.primitiveOutcome, hout]

end Tachyon.SourceQueryBreaks
