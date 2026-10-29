import Tachyon.AnchorTraces

/-!
# Computed span/lift reductions on finite data traces

This is the data-valued counterpart of `Chain.SpanDerivable`. It follows the
ragu-style computed-break interface and never extracts data by eliminating the
old proposition. A successful predecessor decode preserves the finite scope
of the endpoint's node trace; this lets successive span decodes compose their
collision witnesses without imposing global hash injectivity.
-/

namespace Tachyon.AnchorBreaks

variable {P C A E : Type*} [One P]

/-- A decoded node's computational trace remains inside one fixed execution
scope. This certificate is propagated, not obtained by classical selection. -/
structure ScopedNode (m : Model P C A E) (openings : List P) (inputs : List (Input C A E))
    (e : E) (a : A) where
  trace : NodeTrace m e a
  openings_subset : trace.openings ⊆ openings
  inputs_subset : trace.inputs ⊆ inputs

structure ScopedPredecessor (m : Model P C A E) (ps : List P) (xs : List (Input C A E))
    (beforeEpoch epoch : E) (before : A) where
  epoch_eq : beforeEpoch = epoch
  node : ScopedNode m ps xs epoch before

variable [DecidableEq P] [DecidableEq C] [DecidableEq A] [DecidableEq E]

/-- A stronger predecessor certificate for repeated decoding in one fixed
scope. It uses the same comparison primitive as `stampPredecessorOrBreak`,
and additionally retains prefix-scope proofs needed by span composition. -/
def scopedPredecessorOrBreak (m : Model P C A E) {ps : List P} {xs : List (Input C A E)}
    {e : E} {a : A} (endpoint : ScopedNode m ps xs e a)
    (before : A) (beforeEpoch : E) (p : P)
    (hp : p ∈ ps) (hx : m.stampInput before beforeEpoch p ∈ xs)
    (heq : m.nextStamp before beforeEpoch p = a) :
    ScopedPredecessor m ps xs beforeEpoch e before ⊕' ScopedBreak m ps xs := by
  obtain ⟨trace, hopen, hinput⟩ := endpoint
  cases trace with
  | genesis =>
    apply PSum.inr
    apply (crossDomainBreak m before m.origin beforeEpoch m.genesisEpoch p heq).weaken
    · intro x hmem
      exact (List.mem_singleton.mp hmem) ▸ hp
    · intro x hmem
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hmem
      rcases hmem with rfl | rfl
      · exact hx
      · exact hinput List.mem_cons_self
  | epoch previous _ _ =>
    apply PSum.inr
    apply (crossDomainBreak m before _ beforeEpoch e p heq).weaken
    · intro x hmem
      have he : x = p := List.mem_singleton.mp hmem
      exact he ▸ hp
    · intro x hmem
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hmem
      rcases hmem with rfl | rfl
      · exact hx
      · exact hinput List.mem_cons_self
  | stamp previous stamp _ =>
    cases stampEqOrBreak m before _ beforeEpoch _ p stamp heq with
    | inr witness =>
      apply PSum.inr
      apply witness.weaken
      · intro x hmem
        simp only [List.mem_cons, List.not_mem_nil, or_false] at hmem
        rcases hmem with rfl | rfl
        · exact hp
        · exact hopen List.mem_cons_self
      · intro x hmem
        simp only [List.mem_cons, List.not_mem_nil, or_false] at hmem
        rcases hmem with rfl | rfl
        · exact hx
        · exact hinput List.mem_cons_self
    | inl result =>
      obtain ⟨ha, he, _⟩ := result
      cases ha
      exact .inl ⟨he, previous, fun _ hm => hopen (List.mem_cons_of_mem _ hm),
        fun _ hm => hinput (List.mem_cons_of_mem _ hm)⟩

end Tachyon.AnchorBreaks

namespace Tachyon.AnchorBreaks

open Polynomial

universe u v z q

variable {F : Type u} {C : Type v} {E : Type z} {P : Type q} [Field F] [One P]

/-- The seed/fuse span derivation as data. Polynomial identities remain the
same idealized opening checks as before; no global hash laws are assumed.
The seed carries its polynomial representation and an equality certificate:
Mathlib's `setPoly` is noncomputable, so constructing it inside runtime trace
data would violate the computed-break discipline. Its use is confined to the
erased specification proof, just as circuit/specification layers are separate
in ragu. The opening type `P` is likewise runtime data, not forced to be the
noncomputable Mathlib polynomial representation. -/
inductive SpanTrace (m : Model P C F E) : Chain.AnchorSpan F → Type (max u z q)
  | seed (a : F) (e : E) (p : P) (hne : p ≠ 1) {members : F[X]}
      (singleton : members = setPoly {m.nextStamp a e p}) :
      SpanTrace m ⟨a, members, m.nextStamp a e p⟩
  | fuse {left right : Chain.AnchorSpan F} {combined : F[X]}
      (l : SpanTrace m left) (r : SpanTrace m right)
      (join : left.anchor_end = right.anchor_start)
      (product : combined = left.members * right.members) :
      SpanTrace m ⟨left.anchor_start, combined, right.anchor_end⟩

def SpanTrace.openings {m : Model P C F E} {span : Chain.AnchorSpan F} : SpanTrace m span → List P
  | .seed _ _ p _ _ => [p]
  | .fuse l r _ _ => l.openings ++ r.openings

def SpanTrace.inputs {m : Model P C F E} {span : Chain.AnchorSpan F} :
    SpanTrace m span → List (Input C F E)
  | .seed a e p _ _ => [m.stampInput a e p]
  | .fuse l r _ _ => l.inputs ++ r.inputs

omit [One P] in
theorem SpanTrace.forget {m : Model F[X] C F E} {span : Chain.AnchorSpan F}
    (t : SpanTrace m span) : Chain.SpanDerivable m.nextStamp span := by
  induction t with
  | seed a e p hne hmem =>
    rw [hmem]
    exact .seed a e p hne
  | fuse _ _ hjoin hprod ihl ihr => exact .fuse ihl ihr hjoin hprod

/-- Successful span decoding supplies finite-scope node traces for its start
and an executable lookup for every committed member. -/
structure SpanBound (m : Model P C F E) (ps : List P) (xs : List (Input C F E))
    (e : E) (span : Chain.AnchorSpan F) where
  start : ScopedNode m ps xs e span.anchor_start
  lookup : (a : F) → Option (ScopedNode m ps xs e a)
  complete : ∀ a, span.members.eval a = 0 → (lookup a).isSome

variable [DecidableEq P] [DecidableEq F] [DecidableEq C] [DecidableEq E]

/-- Decode a span backwards against its accepted endpoint, propagating the
first concrete collision and retaining all node scopes for recursive calls. -/
def spanBoundOrBreak (m : Model P C F E) {ps : List P} {xs : List (Input C F E)}
    {e : E} {span : Chain.AnchorSpan F} (trace : SpanTrace m span)
    (endpoint : ScopedNode m ps xs e span.anchor_end)
    (hps : trace.openings ⊆ ps) (hxs : trace.inputs ⊆ xs) :
    SpanBound m ps xs e span ⊕' ScopedBreak m ps xs := by
  cases trace with
  | seed a seedEpoch p _ hmembers =>
    cases scopedPredecessorOrBreak m endpoint a seedEpoch p
        (hps List.mem_cons_self) (hxs List.mem_cons_self) rfl with
    | inr witness => exact .inr witness
    | inl result =>
      apply PSum.inl
      refine ⟨result.node, fun v => if hv : v = m.nextStamp a seedEpoch p then
        some (hv.symm ▸ endpoint) else none, ?_⟩
      intro v hroot
      have hv : v = m.nextStamp a seedEpoch p := by
        simpa [hmembers, setPoly, sub_eq_zero] using hroot
      simp [hv]
  | fuse left right hjoin hprod =>
    cases spanBoundOrBreak m right endpoint
        (fun _ hp => hps (List.mem_append_right _ hp))
        (fun _ hx => hxs (List.mem_append_right _ hx)) with
    | inr witness => exact .inr witness
    | inl rightBound =>
      cases spanBoundOrBreak m left (hjoin.symm ▸ rightBound.start)
          (fun _ hp => hps (List.mem_append_left _ hp))
          (fun _ hx => hxs (List.mem_append_left _ hx)) with
      | inr witness => exact .inr witness
      | inl leftBound =>
        apply PSum.inl
        refine ⟨leftBound.start, fun a => (leftBound.lookup a).orElse fun _ => rightBound.lookup a, ?_⟩
        intro a hroot
        have hzero := hroot
        dsimp only at hzero
        rw [hprod, eval_mul] at hzero
        rcases mul_eq_zero.mp hzero with hl | hr
        · have hsome := leftBound.complete a hl
          cases hlookup : leftBound.lookup a <;> simp_all
        · have hsome := rightBound.complete a hr
          cases hlookup : leftBound.lookup a <;> simp_all
termination_by structural trace

/-- The `StampLift`/`ActionLift` membership equation computes the input
anchor's same-epoch node trace or a collision in the span/endpoint execution. -/
def liftNodeOrBreak (m : Model P C F E) {e : E} {span : Chain.AnchorSpan F}
    (trace : SpanTrace m span) (endpoint : NodeTrace m e span.anchor_end)
    (anchor : F) (hcheck : span.members.eval anchor * (anchor - span.anchor_start) = 0) :
    ScopedNode m (trace.openings ++ endpoint.openings) (trace.inputs ++ endpoint.inputs) e anchor ⊕'
      ScopedBreak m (trace.openings ++ endpoint.openings) (trace.inputs ++ endpoint.inputs) := by
  let endScoped : ScopedNode m (trace.openings ++ endpoint.openings)
      (trace.inputs ++ endpoint.inputs) e span.anchor_end :=
    ⟨endpoint, fun _ hp => List.mem_append_right _ hp, fun _ hx => List.mem_append_right _ hx⟩
  cases spanBoundOrBreak m trace endScoped
      (fun _ hp => List.mem_append_left _ hp) (fun _ hx => List.mem_append_left _ hx) with
  | inr witness => exact .inr witness
  | inl bound =>
    by_cases hstart : anchor = span.anchor_start
    · exact .inl (hstart.symm ▸ bound.start)
    · have hroot : span.members.eval anchor = 0 :=
        (mul_eq_zero.mp hcheck).resolve_right (fun h => hstart (sub_eq_zero.mp h))
      exact .inl ((bound.lookup anchor).get (bound.complete anchor hroot))

/-- Successful lift decoding under collision freedom on this finite span and
endpoint trace. The returned predecessor trace remains computational data. -/
def liftNodeOfNoCollisions (m : Model P C F E) {e : E} {span : Chain.AnchorSpan F}
    (trace : SpanTrace m span) (endpoint : NodeTrace m e span.anchor_end)
    (anchor : F) (hcheck : span.members.eval anchor * (anchor - span.anchor_start) = 0)
    (hlocal : NoCollisionsOn m (trace.openings ++ endpoint.openings)
      (trace.inputs ++ endpoint.inputs)) :
    ScopedNode m (trace.openings ++ endpoint.openings) (trace.inputs ++ endpoint.inputs) e anchor :=
  match liftNodeOrBreak m trace endpoint anchor hcheck with
  | .inl result => result
  | .inr witness => False.elim (witness.elim hlocal)

namespace SpanExamples

def model : Model ℕ Unit ℚ Bool :=
  ⟨fun _ => (), fun _ _ _ => 0, fun _ _ => 0, 0, false⟩

-- These examples use the noncomputable Mathlib polynomial specification `X`.
-- They are checked by kernel reduction, rather than advertised as executable
-- constructors for that specification object. The generic decoder above is
-- a computable definition and its opening data here is the computable `ℕ`.
noncomputable def span : SpanTrace model ⟨0, X, 0⟩ :=
  .seed 0 false 2 (by decide)
    (by simp [setPoly, Model.nextStamp, Model.eval, Model.stampInput, model])

-- A genesis endpoint with that same output instead yields a cross-domain
-- collision, rather than deriving a bogus predecessor from hash injectivity.
example : (match liftNodeOrBreak model span NodeTrace.genesis 0 (by simp) with
    | .inl _ => false
    | .inr result => match result.witness with
      | .hash _ => true
      | .commitment _ => false) = true := by rfl

end SpanExamples

end Tachyon.AnchorBreaks
