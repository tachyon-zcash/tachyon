import Tachyon.AnchorBreaks
import Tachyon.SourceSealing

/-!
# Source equality or a computed break on the actual finite traces

`RunTrace` is data, unlike `SourceSealing.Run : Prop`. This distinction is
required to compute the offending commitment/hash inputs, following ragu's
breaks-as-computed-data discipline. A forgetful map recovers the earlier
proposition when the opening type is a polynomial ring.

`sameSourceOrBreak` walks backwards through two supplied execution traces. It
either establishes their common boundary start and source product, or returns
a scoped collision witness drawn from those traces. The companion corollary
assumes collision freedom only on those finite openings and hash preimages.
No global injectivity hypothesis, classical choice, or witness extraction from
a bare PCD acceptance proposition is used by the computed reduction.
-/

namespace Tachyon.AnchorBreaks

universe u v w z

variable {P : Type u} {C : Type v} {A : Type w} {E : Type z}

/-- Enlarge a witness's finite scope when composing computed reductions. -/
def ScopedBreak.weaken {m : Model P C A E} {ps qs : List P} {xs ys : List (Input C A E)}
    (w : ScopedBreak m ps xs) (hp : ps ⊆ qs) (hx : xs ⊆ ys) : ScopedBreak m qs ys := by
  obtain ⟨witness, covered⟩ := w
  refine ⟨witness, ?_⟩
  cases witness with
  | commitment col => exact ⟨hp covered.1, hp covered.2⟩
  | hash col => exact ⟨hx covered.1, hx covered.2⟩

variable [Monoid P]

/-- A finite data-valued source trace, with multiplication and stamp folds
recorded in the output indices. Openings may be bounded coefficient vectors. -/
inductive RunTrace (m : Model P C A E) (e : E) : A → A → P → Type (max u w)
  | empty (a : A) : RunTrace m e a a 1
  | append {start finish : A} {acc : P} (previous : RunTrace m e start finish acc) (stamp : P) :
      RunTrace m e start (m.nextStamp finish e stamp) (acc * stamp)

def RunTrace.openings {m : Model P C A E} {e : E} {a b : A} {p : P} : RunTrace m e a b p → List P
  | .empty _ => []
  | .append previous stamp => stamp :: previous.openings

def RunTrace.inputs {m : Model P C A E} {e : E} {a b : A} {p : P} :
    RunTrace m e a b p → List (Input C A E)
  | .empty _ => []
  | .append (finish := finish) previous stamp =>
      m.stampInput finish e stamp :: previous.inputs

variable [DecidableEq P] [DecidableEq C] [DecidableEq A] [DecidableEq E]

/-- The source-product reduction. Both initial predecessors are explicit data;
only their boundary-hash equalities are propositions. The witness scope is
exactly the two finite traces plus those two initial boundary preimages. -/
def sameSourceOrBreak (m : Model P C A E) (e : E)
    {a b a' b' : A} {p q : P} (left : RunTrace m e a b p) (right : RunTrace m e a' b' q)
    (leftPrev rightPrev : A) (hleft : a = m.epochHash leftPrev e)
    (hright : a' = m.epochHash rightPrev e) (hend : b = b') :
    (a = a' ∧ p = q) ⊕' ScopedBreak m (left.openings ++ right.openings)
      (left.inputs ++ right.inputs ++ [.epoch leftPrev e, .epoch rightPrev e]) := by
  cases left with
  | empty =>
    cases right with
    | empty => exact .inl ⟨hend, rfl⟩
    | append previous stamp =>
      apply PSum.inr
      apply (crossDomainBreak m _ leftPrev e e stamp (hend.symm.trans hleft)).weaken
      · intro x hx
        simp only [RunTrace.openings, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
        aesop
      · intro x hx
        simp only [RunTrace.inputs, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
        aesop
  | append previous stamp =>
    cases right with
    | empty =>
      apply PSum.inr
      apply (crossDomainBreak m _ rightPrev e e stamp (hend.trans hright)).weaken
      · intro x hx
        simp only [RunTrace.openings, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
        aesop
      · intro x hx
        simp only [RunTrace.inputs, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
        aesop
    | append previous' stamp' =>
      cases stampEqOrBreak m _ _ e e stamp stamp' hend with
      | inr witness =>
        apply PSum.inr
        apply witness.weaken
        · intro x hx
          simp only [RunTrace.openings, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
          aesop
        · intro x hx
          simp only [RunTrace.inputs, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
          aesop
      | inl result =>
        obtain ⟨hprev, _, hstamp⟩ := result
        cases sameSourceOrBreak m e previous previous' leftPrev rightPrev hleft hright hprev with
        | inl result => exact .inl ⟨result.1, by rw [result.2, hstamp]⟩
        | inr witness =>
          apply PSum.inr
          apply witness.weaken
          · intro x hx
            simp only [RunTrace.openings, List.mem_append, List.mem_cons] at hx ⊢
            aesop
          · intro x hx
            simp only [RunTrace.inputs, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
            aesop
termination_by structural left

/-- Boundary-run uniqueness on this finite execution, not on the entire hash
domain. The total computed reduction is available without `hlocal`. -/
theorem same_source_of_no_collisions (m : Model P C A E) (e : E)
    {a b a' b' : A} {p q : P} (left : RunTrace m e a b p) (right : RunTrace m e a' b' q)
    (leftPrev rightPrev : A) (hleft : a = m.epochHash leftPrev e)
    (hright : a' = m.epochHash rightPrev e) (hend : b = b')
    (hlocal : NoCollisionsOn m (left.openings ++ right.openings)
      (left.inputs ++ right.inputs ++ [.epoch leftPrev e, .epoch rightPrev e])) :
    a = a' ∧ p = q := by
  cases sameSourceOrBreak m e left right leftPrev rightPrev hleft hright hend with
  | inl result => exact result
  | inr witness => exact False.elim (witness.elim hlocal)

/-- The seal comparison first decodes the next-epoch boundary digest, then
compares the two source traces. Any break is scoped to those traces, their
initial boundary inputs and the two final sealing inputs. -/
def sealedSourceOrBreak (m : Model P C A E) (e nextE : E)
    {a b a' b' : A} {p q : P} (left : RunTrace m e a b p) (right : RunTrace m e a' b' q)
    (leftPrev rightPrev : A) (hleft : a = m.epochHash leftPrev e)
    (hright : a' = m.epochHash rightPrev e)
    (hseal : m.epochHash b nextE = m.epochHash b' nextE) :
    (a = a' ∧ p = q) ⊕' ScopedBreak m (left.openings ++ right.openings)
      (left.inputs ++ right.inputs ++
        [.epoch leftPrev e, .epoch rightPrev e, .epoch b nextE, .epoch b' nextE]) := by
  cases epochEqOrBreak m b b' nextE nextE hseal with
  | inr witness =>
    apply PSum.inr
    apply witness.weaken
    · intro x hx
      cases hx
    · intro x hx
      simp only [List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
      aesop
  | inl result =>
    cases sameSourceOrBreak m e left right leftPrev rightPrev hleft hright result.1 with
    | inl success => exact .inl success
    | inr witness =>
      apply PSum.inr
      apply witness.weaken (fun _ hx => hx)
      intro x hx
      simp only [List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
      aesop

/-- Whole-source equality under collision freedom restricted to the finite
run and seal transcript. This does not impose a global `HashLaw`. -/
theorem sealed_source_of_no_collisions (m : Model P C A E) (e nextE : E)
    {a b a' b' : A} {p q : P} (left : RunTrace m e a b p) (right : RunTrace m e a' b' q)
    (leftPrev rightPrev : A) (hleft : a = m.epochHash leftPrev e)
    (hright : a' = m.epochHash rightPrev e)
    (hseal : m.epochHash b nextE = m.epochHash b' nextE)
    (hlocal : NoCollisionsOn m (left.openings ++ right.openings)
      (left.inputs ++ right.inputs ++
        [.epoch leftPrev e, .epoch rightPrev e, .epoch b nextE, .epoch b' nextE])) :
    a = a' ∧ p = q := by
  cases sealedSourceOrBreak m e nextE left right leftPrev rightPrev hleft hright hseal with
  | inl result => exact result
  | inr witness => exact False.elim (witness.elim hlocal)

namespace Examples

-- The anchor domain is finite and all hashes collide; the reductions remain
-- total and compute witnesses rather than assuming this implementation away.
def model : Model ℕ Unit Unit Unit :=
  ⟨fun _ => (), fun _ _ _ => (), fun _ _ => (), (), ()⟩

def two : RunTrace model () () () 2 := (RunTrace.empty ()).append 2
def three : RunTrace model () () () 3 := (RunTrace.empty ()).append 3
def six : RunTrace model () () () 6 := ((RunTrace.empty ()).append 2).append 3

#guard match sealedSourceOrBreak model () () two three () () rfl rfl rfl with
  | .inl _ => false
  | .inr w => match w.witness with
    | .commitment col => col.left == 2 && col.right == 3
    | .hash _ => false

#guard match sealedSourceOrBreak model () () (RunTrace.empty ()) two () () rfl rfl rfl with
  | .inl _ => false
  | .inr w => match w.witness with
    | .commitment _ => false
    | .hash _ => true

#guard match sealedSourceOrBreak model () () six six () () rfl rfl rfl with
  | .inl _ => true
  | .inr _ => false

end Examples

end Tachyon.AnchorBreaks

namespace Tachyon.SourceSealing

open Polynomial AnchorBreaks

variable {F C A : Type*} [Field F] {m : Model F[X] C A ℕ}

/-- Data traces retain the earlier source-run specification. This direction
does not require extracting computational data from a proposition. -/
theorem RunTrace.toRun {e : ℕ} {a b : A} {p : F[X]} (trace : RunTrace m e a b p) :
    Run m.nextStamp e a b p := by
  induction trace with
  | empty => exact Run.empty _
  | append previous stamp ih => exact Run.append stamp ih

end Tachyon.SourceSealing
