import Tachyon.ProofTree
import Tachyon.SpanTraces

/-!
# Lifts along traced spans

`ActionsDerivable.lift` and `StampDerivable.lift` take the epoch equality between a header's anchor
and the span's `anchor_end`. `ActionLift` and `StampLift` check only that the anchor is the span's
start or a member. Along a traced span ending at a traced chain node, the anchor decodes to a node
at the endpoint's epoch; compared with the anchor's own traced epoch, that gives the lift's epoch
equality or a collision scoped to the span and the two node traces (`ActionsDerivable.liftOrBreak`,
`StampDerivable.liftOrBreak`). No global hash injectivity is assumed.
-/

namespace Tachyon

open AnchorBreaks

variable {P C F E : Type*} [Field F] [One P] [DecidableEq P] [DecidableEq C] [DecidableEq F]
  [DecidableEq E] {m : Model P C F E} {IsFee : F → Prop} {epoch : F → E}
  {R : E → F → Multiset F} {s s' : Stamp F F} {span : Chain.AnchorSpan F}

/-- The span's start or member `anchor` decodes to a node at the endpoint's epoch; against the
anchor's traced epoch, that is the lift's epoch equality or a collision in the combined scope. -/
def liftEpochOrBreak (trace : SpanTrace m span)
    (endpoint : NodeTrace m (epoch span.anchor_end) span.anchor_end)
    (start : NodeTrace m (epoch s.anchor) s.anchor) (hlift : Chain.StampLiftStep s span s') :
    (epoch span.anchor_end = epoch s.anchor) ⊕'
      ScopedBreak m (trace.openings ++ endpoint.openings ++ start.openings)
        (trace.inputs ++ endpoint.inputs ++ start.inputs) :=
  match liftNodeOrBreak m trace endpoint s.anchor hlift.1 with
  | .inr witness =>
      .inr (witness.weaken (fun _ h => List.mem_append_left _ h)
        (fun _ h => List.mem_append_left _ h))
  | .inl decoded =>
      match nodeEpochOrBreak m decoded.trace start rfl with
      | .inl hepoch => .inl hepoch
      | .inr witness =>
          .inr (witness.weaken
            (fun _ h => (List.mem_append.mp h).elim
              (fun h => List.mem_append_left _ (decoded.openings_subset h))
              (fun h => List.mem_append_right _ h))
            (fun _ h => (List.mem_append.mp h).elim
              (fun h => List.mem_append_left _ (decoded.inputs_subset h))
              (fun h => List.mem_append_right _ h)))

/-- `ActionLift` along a traced span ending at a traced chain node yields a derivable `Actions`
header, or a scoped collision. -/
def ActionsDerivable.liftOrBreak (hs : ActionsDerivable IsFee epoch R s)
    (trace : SpanTrace m span) (endpoint : NodeTrace m (epoch span.anchor_end) span.anchor_end)
    (start : NodeTrace m (epoch s.anchor) s.anchor) (hlift : Chain.StampLiftStep s span s') :
    ActionsDerivable IsFee epoch R s' ⊕'
      ScopedBreak m (trace.openings ++ endpoint.openings ++ start.openings)
        (trace.inputs ++ endpoint.inputs ++ start.inputs) :=
  mapOutcome (liftEpochOrBreak trace endpoint start hlift) fun hepoch => by
    obtain ⟨-, rfl⟩ := hlift
    exact .lift span.anchor_end hs hepoch

/-- `StampLift` along a traced span ending at a traced chain node yields a derivable `Stamp`
header, or a scoped collision. -/
def StampDerivable.liftOrBreak (hs : StampDerivable IsFee epoch R s)
    (trace : SpanTrace m span) (endpoint : NodeTrace m (epoch span.anchor_end) span.anchor_end)
    (start : NodeTrace m (epoch s.anchor) s.anchor) (hlift : Chain.StampLiftStep s span s') :
    StampDerivable IsFee epoch R s' ⊕'
      ScopedBreak m (trace.openings ++ endpoint.openings ++ start.openings)
        (trace.inputs ++ endpoint.inputs ++ start.inputs) :=
  mapOutcome (liftEpochOrBreak trace endpoint start hlift) fun hepoch => by
    obtain ⟨-, rfl⟩ := hlift
    exact .lift span.anchor_end hs hepoch

omit [DecidableEq P] [DecidableEq C] [DecidableEq F] [DecidableEq E] in
/-- With no collision in the span and the two node traces, `StampLift` along a traced span ending at
a traced chain node yields a derivable `Stamp` header. -/
theorem StampDerivable.lift_of_no_collisions (hs : StampDerivable IsFee epoch R s)
    (trace : SpanTrace m span) (endpoint : NodeTrace m (epoch span.anchor_end) span.anchor_end)
    (start : NodeTrace m (epoch s.anchor) s.anchor) (hlift : Chain.StampLiftStep s span s')
    (hlocal : NoCollisionsOn m (trace.openings ++ endpoint.openings ++ start.openings)
      (trace.inputs ++ endpoint.inputs ++ start.inputs)) :
    StampDerivable IsFee epoch R s' := by
  classical
  exact match hs.liftOrBreak trace endpoint start hlift with
  | .inl derivable => derivable
  | .inr witness => (witness.elim hlocal).elim

end Tachyon
