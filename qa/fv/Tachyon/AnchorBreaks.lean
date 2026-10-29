import Mathlib.Data.List.Basic

/-!
# Anchor equalities, or computed collision witnesses

This follows ragu's `Foundation/RelationWitness/Basic.lean` and
`Foundation/IPA/CommitFold.lean`: reductions return `Result ⊕' Break`, with the
break carried as data. No hash or commitment is assumed globally injective.
All branches use supplied decidable equality instances, not `Classical.choice`.

Unlike ragu's discrete-log relation, an anchor break has two possible layers:
distinct openings may share a commitment, or distinct domain-tagged hash inputs
may share an anchor output. Keeping those separate avoids claiming a Poseidon
collision when the actual equal preimages came from a commitment collision.
The opening type is generic, allowing bounded witnesses as well as idealized
polynomials, without imposing an impossible global finite-domain injection.

`ScopedBreak` records membership in the finite comparison transcript.
`NoCollisionsOn` is consequently an execution-local condition, not a universal
claim about the hash. The reduction remains valid when that condition fails:
it then returns the concrete conflicting inputs.

These are algebraic reductions, not a Poseidon collision-resistance theorem,
PCD witness extractor or complexity analysis. The hashes and commitment map are
actual functions; cryptographic security is used only to interpret the computed
break branch, as with ragu's computed algebraic relations.
-/

namespace Tachyon.AnchorBreaks

universe u v w z

/-- Domain-tagged, statement-level preimages. A stamp hashes a commitment,
not the polynomial or coefficient vector opening that commitment. -/
inductive Input (C : Type v) (A : Type w) (E : Type z)
  | stamp (previous : A) (epoch : E) (commitment : C)
  | epoch (previous : A) (entered : E)
  deriving DecidableEq

/-- An anchor implementation, with no injectivity assumptions. Genesis is the
epoch-domain hash of the designated origin and genesis epoch. -/
structure Model (P : Type u) (C : Type v) (A : Type w) (E : Type z) where
  commit : P → C
  stampHash : A → E → C → A
  epochHash : A → E → A
  origin : A
  genesisEpoch : E

variable {P : Type u} {C : Type v} {A : Type w} {E : Type z}

def Model.eval (m : Model P C A E) : Input C A E → A
  | .stamp a e c => m.stampHash a e c
  | .epoch a e => m.epochHash a e

def Model.stampInput (m : Model P C A E) (a : A) (e : E) (p : P) : Input C A E :=
  .stamp a e (m.commit p)

def Model.nextStamp (m : Model P C A E) (a : A) (e : E) (p : P) : A :=
  m.eval (m.stampInput a e p)

def Model.genesis (m : Model P C A E) : A :=
  m.epochHash m.origin m.genesisEpoch

/-- Distinct opening data with the same commitment. -/
structure CommitmentCollision (m : Model P C A E) where
  left : P
  right : P
  distinct : left ≠ right
  equal : m.commit left = m.commit right

/-- Distinct tagged hash preimages with the same anchor output. Cross-domain
equalities are ordinary collisions because the tag is part of the preimage. -/
structure HashCollision (m : Model P C A E) where
  left : Input C A E
  right : Input C A E
  distinct : left ≠ right
  equal : m.eval left = m.eval right

inductive Break (m : Model P C A E)
  | commitment (collision : CommitmentCollision m)
  | hash (collision : HashCollision m)

/-- The witness's two inputs actually occur in this finite transcript. -/
def Break.Covered {m : Model P C A E} (openings : List P) (inputs : List (Input C A E)) :
    Break m → Prop
  | .commitment w => w.left ∈ openings ∧ w.right ∈ openings
  | .hash w => w.left ∈ inputs ∧ w.right ∈ inputs

structure ScopedBreak (m : Model P C A E) (openings : List P) (inputs : List (Input C A E)) where
  witness : Break m
  covered : witness.Covered openings inputs

/-- Collision freedom only on the supplied finite execution inputs. It is not
assumed by the computed reductions themselves. -/
structure NoCollisionsOn (m : Model P C A E) (openings : List P)
    (inputs : List (Input C A E)) : Prop where
  commitment : ∀ p ∈ openings, ∀ q ∈ openings, m.commit p = m.commit q → p = q
  hash : ∀ x ∈ inputs, ∀ y ∈ inputs, m.eval x = m.eval y → x = y

def ScopedBreak.elim {m : Model P C A E} {openings : List P} {inputs : List (Input C A E)}
    (w : ScopedBreak m openings inputs) (h : NoCollisionsOn m openings inputs) : False := by
  obtain ⟨witness, covered⟩ := w
  cases witness with
  | commitment col => exact col.distinct (h.commitment _ covered.1 _ covered.2 col.equal)
  | hash col => exact col.distinct (h.hash _ covered.1 _ covered.2 col.equal)

/-- Propagate a computed break, following ragu's `bindOrRelationWitness`.
This small combinator is local to avoid adding or changing package manifests. -/
def mapOutcome {X : Sort*} {Y : Sort*} {R : Sort*} (outcome : X ⊕' R) (f : X → Y) : Y ⊕' R :=
  match outcome with
  | .inl value => .inl (f value)
  | .inr witness => .inr witness

variable [DecidableEq P] [DecidableEq C] [DecidableEq A] [DecidableEq E]

/-- One actual hash comparison either has identical tagged inputs or exhibits
a collision between exactly those two inputs. -/
def hashEqOrBreak (m : Model P C A E) (x y : Input C A E) (heq : m.eval x = m.eval y) :
    (x = y) ⊕' ScopedBreak m [] [x, y] :=
  if h : x = y then .inl h
  else .inr ⟨.hash ⟨x, y, h, heq⟩, ⟨List.mem_cons_self, by simp⟩⟩

/-- A stamp equality is decoded at both layers. Equal hash preimages but
unequal openings return a commitment collision, not a hash collision. -/
def stampEqOrBreak (m : Model P C A E) (a a' : A) (e e' : E) (p p' : P)
    (heq : m.nextStamp a e p = m.nextStamp a' e' p') :
    (a = a' ∧ e = e' ∧ p = p') ⊕'
      ScopedBreak m [p, p'] [m.stampInput a e p, m.stampInput a' e' p'] := by
  by_cases hin : m.stampInput a e p = m.stampInput a' e' p'
  · obtain ⟨ha, he, hc⟩ := Input.stamp.inj hin
    by_cases hp : p = p'
    · exact .inl ⟨ha, he, hp⟩
    · exact .inr ⟨.commitment ⟨p, p', hp, hc⟩, ⟨List.mem_cons_self, by simp⟩⟩
  · exact .inr ⟨.hash ⟨_, _, hin, heq⟩, ⟨List.mem_cons_self, by simp⟩⟩

/-- Epoch-domain equality either decodes its inputs or returns their collision. -/
def epochEqOrBreak (m : Model P C A E) (a a' : A) (e e' : E)
    (heq : m.epochHash a e = m.epochHash a' e') :
    (a = a' ∧ e = e') ⊕' ScopedBreak m [] [.epoch a e, .epoch a' e'] :=
  mapOutcome (hashEqOrBreak m (.epoch a e) (.epoch a' e') heq) Input.epoch.inj

/-- A stamp/epoch equality directly provides distinct domain-tagged preimages. -/
def crossDomainBreak (m : Model P C A E) (a a' : A) (e e' : E) (p : P)
    (heq : m.nextStamp a e p = m.epochHash a' e') :
    ScopedBreak m [p] [m.stampInput a e p, .epoch a' e'] :=
  ⟨.hash ⟨m.stampInput a e p, .epoch a' e', (by intro h; cases h), heq⟩,
    ⟨List.mem_cons_self, by simp⟩⟩

/-- The conditional input-decoding theorem is an execution-local corollary.
The total `stampEqOrBreak` reduction remains usable if this premise fails. -/
theorem stamp_eq_of_no_collisions (m : Model P C A E) (a a' : A) (e e' : E) (p p' : P)
    (heq : m.nextStamp a e p = m.nextStamp a' e' p')
    (hlocal : NoCollisionsOn m [p, p'] [m.stampInput a e p, m.stampInput a' e' p']) :
    a = a' ∧ e = e' ∧ p = p' := by
  cases stampEqOrBreak m a a' e e' p p' heq with
  | inl result => exact result
  | inr witness => exact False.elim (witness.elim hlocal)

/-- Constant finite functions are legitimate models and yield an actual
cross-domain witness, rather than making the model's premises inconsistent. -/
def constantModel : Model Bool Unit Unit Unit :=
  ⟨fun _ => (), fun _ _ _ => (), fun _ _ => (), (), ()⟩

def constantModelBreak : ScopedBreak constantModel [false]
    [constantModel.stampInput () () false, .epoch () ()] :=
  crossDomainBreak constantModel () () () () false rfl

-- These kernel-evaluated examples distinguish the two actual break layers.
-- Shared commitment preimages must produce a commitment break, not a spurious
-- claim of distinct Poseidon inputs.
#guard match stampEqOrBreak constantModel () () () () false true rfl with
  | .inl _ => false
  | .inr result => match result.witness with
    | .commitment _ => true
    | .hash _ => false

def distinctCommitmentsModel : Model Bool Bool Unit Unit :=
  ⟨id, fun _ _ _ => (), fun _ _ => (), (), ()⟩

#guard match stampEqOrBreak distinctCommitmentsModel () () () () false true rfl with
  | .inl _ => false
  | .inr result => match result.witness with
    | .commitment _ => false
    | .hash _ => true

end Tachyon.AnchorBreaks
