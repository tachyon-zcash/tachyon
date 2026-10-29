import Tachyon.SourceBreakReduction

/-!
# Anchor trace decoding with computed breaks

`NodeTrace` supplies computational chain provenance, rather than selecting a
witness classically from `Chain.Node : Prop`. Epoch-label and predecessor
reductions return the decoded result or a concrete, finite-scope collision.
The old proposition is recovered by `NodeTrace.toNode`, in the safe direction
from data to proof. PCD knowledge extraction remains an external prerequisite
for supplying such traces; no extraction theorem is claimed here.
-/

namespace Tachyon.AnchorBreaks

universe u v w z

variable {P : Type u} {C : Type v} {A : Type w} {E : Type z}

def Input.label : Input C A E → E
  | .stamp _ e _ => e
  | .epoch _ e => e

variable [One P]

/-- Finite chain provenance, preserving the existing empty-stamp and genesis-
epoch guards. Previous epochs and anchors are explicit data in the trace. -/
inductive NodeTrace (m : Model P C A E) : E → A → Type (max u w z)
  | genesis : NodeTrace m m.genesisEpoch m.genesis
  | stamp {e : E} {a : A} (previous : NodeTrace m e a) (p : P) (hne : p ≠ 1) :
      NodeTrace m e (m.nextStamp a e p)
  | epoch {e : E} {a : A} (previous : NodeTrace m e a) (entered : E)
      (hne : entered ≠ m.genesisEpoch) : NodeTrace m entered (m.epochHash a entered)

def NodeTrace.openings {m : Model P C A E} {e : E} {a : A} : NodeTrace m e a → List P
  | .genesis => []
  | .stamp previous p _ => p :: previous.openings
  | .epoch previous _ _ => previous.openings

def NodeTrace.outputInput {m : Model P C A E} {e : E} {a : A} : NodeTrace m e a → Input C A E
  | .genesis => .epoch m.origin m.genesisEpoch
  | .stamp (a := previousAnchor) (e := previousEpoch) _ p _ =>
      m.stampInput previousAnchor previousEpoch p
  | .epoch (a := previousAnchor) _ entered _ => .epoch previousAnchor entered

def NodeTrace.inputs {m : Model P C A E} {e : E} {a : A} : NodeTrace m e a → List (Input C A E)
  | .genesis => [.epoch m.origin m.genesisEpoch]
  | .stamp (a := previousAnchor) (e := previousEpoch) previous p _ =>
      m.stampInput previousAnchor previousEpoch p :: previous.inputs
  | .epoch (a := previousAnchor) previous entered _ => .epoch previousAnchor entered :: previous.inputs

theorem NodeTrace.outputInput_mem {m : Model P C A E} {e : E} {a : A} (t : NodeTrace m e a) :
    t.outputInput ∈ t.inputs := by
  cases t <;> exact List.mem_cons_self

theorem NodeTrace.outputInput_eval {m : Model P C A E} {e : E} {a : A} (t : NodeTrace m e a) :
    m.eval t.outputInput = a := by
  cases t <;> rfl

theorem NodeTrace.outputInput_label {m : Model P C A E} {e : E} {a : A} (t : NodeTrace m e a) :
    t.outputInput.label = e := by
  cases t <;> rfl

variable [DecidableEq P] [DecidableEq C] [DecidableEq A] [DecidableEq E]

/-- Decoding the epoch of a supplied hash preimage at a traced chain node
requires only this comparison, or yields its explicit hash collision. -/
def inputLabelOrBreak (m : Model P C A E) {e : E} {a : A} (input : Input C A E)
    (trace : NodeTrace m e a) (heq : m.eval input = a) :
    (input.label = e) ⊕' ScopedBreak m trace.openings (input :: trace.inputs) := by
  cases hashEqOrBreak m input trace.outputInput (heq.trans trace.outputInput_eval.symm) with
  | inl result => exact .inl ((congrArg Input.label result).trans trace.outputInput_label)
  | inr witness =>
    apply PSum.inr
    apply witness.weaken
    · intro p hp
      cases hp
    · intro x hx
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hx
      rcases hx with rfl | rfl
      · exact List.mem_cons_self
      · exact List.mem_cons_of_mem _ trace.outputInput_mem

/-- Epoch uniqueness is a computed reduction over the two finite traces,
not a consequence of impossible global hash injectivity. -/
def nodeEpochOrBreak (m : Model P C A E) {e e' : E} {a a' : A}
    (left : NodeTrace m e a) (right : NodeTrace m e' a') (heq : a = a') :
    (e = e') ⊕' ScopedBreak m (left.openings ++ right.openings) (left.inputs ++ right.inputs) := by
  cases inputLabelOrBreak m left.outputInput right (left.outputInput_eval.trans heq) with
  | inl result => exact .inl (left.outputInput_label.symm.trans result)
  | inr witness =>
    apply PSum.inr
    apply witness.weaken
    · intro p hp
      exact List.mem_append_right _ hp
    · intro x hx
      rcases List.mem_cons.mp hx with rfl | hx
      · exact List.mem_append_left _ left.outputInput_mem
      · exact List.mem_append_right _ hx

/-- Decoding a stamp predecessor returns its trace as data, not merely an
existence proposition, so downstream reductions can keep computing. -/
structure StampPredecessor (m : Model P C A E) (beforeEpoch epoch : E) (before : A) where
  epoch_eq : beforeEpoch = epoch
  trace : NodeTrace m epoch before

def stampPredecessorOrBreak (m : Model P C A E) {e : E} {a : A} (trace : NodeTrace m e a)
    (before : A) (beforeEpoch : E) (p : P) (heq : m.nextStamp before beforeEpoch p = a) :
    StampPredecessor m beforeEpoch e before ⊕'
      ScopedBreak m (p :: trace.openings) (m.stampInput before beforeEpoch p :: trace.inputs) := by
  cases trace with
  | genesis =>
    apply PSum.inr
    apply (crossDomainBreak m before m.origin beforeEpoch m.genesisEpoch p heq).weaken
    · intro x hx
      simpa only [NodeTrace.openings] using hx
    · intro x hx
      simpa only [NodeTrace.inputs] using hx
  | epoch previous _ _ =>
    apply PSum.inr
    apply (crossDomainBreak m before _ beforeEpoch e p heq).weaken
    · intro x hx
      simp only [NodeTrace.openings, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
      aesop
    · intro x hx
      simp only [NodeTrace.inputs, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
      aesop
  | stamp previous stamp _ =>
    cases stampEqOrBreak m before _ beforeEpoch _ p stamp heq with
    | inl result =>
      exact .inl ⟨result.2.1, result.1.symm ▸ previous⟩
    | inr witness =>
      apply PSum.inr
      apply witness.weaken
      · intro x hx
        simp only [NodeTrace.openings, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
        aesop
      · intro x hx
        simp only [NodeTrace.inputs, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
        aesop

omit [DecidableEq P] in
/-- Execution-local epoch uniqueness, obtained by discharging the returned
finite-scope break branch. -/
theorem node_epoch_eq_of_no_collisions (m : Model P C A E) {e e' : E} {a a' : A}
    (left : NodeTrace m e a) (right : NodeTrace m e' a') (heq : a = a')
    (hlocal : NoCollisionsOn m (left.openings ++ right.openings) (left.inputs ++ right.inputs)) :
    e = e' := by
  cases nodeEpochOrBreak m left right heq with
  | inl result => exact result
  | inr witness => exact False.elim (witness.elim hlocal)

namespace TraceExamples

def model : Model ℕ Unit Unit Bool :=
  ⟨fun _ => (), fun _ _ _ => (), fun _ _ => (), (), false⟩

def start : NodeTrace model false () := .genesis
def laterEpoch : NodeTrace model true () := .epoch start true (by decide)
def stamped : NodeTrace model false () := .stamp start 2 (by decide)

#guard match nodeEpochOrBreak model start laterEpoch rfl with
  | .inl _ => false
  | .inr result => match result.witness with
    | .hash _ => true
    | .commitment _ => false

#guard match stampPredecessorOrBreak model stamped () false 2 rfl with
  | .inl _ => true
  | .inr _ => false

#guard match stampPredecessorOrBreak model stamped () false 3 rfl with
  | .inl _ => false
  | .inr result => match result.witness with
    | .hash _ => false
    | .commitment col => col.left == 3 && col.right == 2

#guard match stampPredecessorOrBreak model start () false 2 rfl with
  | .inl _ => false
  | .inr result => match result.witness with
    | .hash _ => true
    | .commitment _ => false

end TraceExamples

end Tachyon.AnchorBreaks

namespace Tachyon.Chain

open Polynomial AnchorBreaks

variable {F C A E : Type*} [Field F] {m : Model F[X] C A E}

/-- Forgetting trace data yields the original chain-node proposition; the
reverse direction is not treated as a computational witness extractor. -/
theorem NodeTrace.toNode {e : E} {a : A} (t : NodeTrace m e a) :
    Node m.genesis m.genesisEpoch m.nextStamp m.epochHash e a := by
  induction t with
  | genesis => exact Node.genesis
  | stamp _ p hne ih => exact Node.stamp p ih hne
  | epoch _ entered hne ih => exact Node.epoch ih hne

end Tachyon.Chain
