import Tachyon.PublicationNodes
import Tachyon.SpendProvenance

/-!
# Span decoding retains publication provenance

Ordinary lift decoding returns `NodeTrace` data and intentionally forgets
which public stamp each opening came from. That metadata cannot be recreated
by casting the result. This stronger decoder propagates a `LinkedNode` through
the same seed/fuse comparisons, retaining the public-entry certificates.

The separate decoder is deliberate: its success payload is strictly stronger
than the old one, and it avoids silently extracting missing provenance from a
proposition or changing the earlier compiled trace API. Both versions use the
same primitive comparisons and finite-scope collision witnesses.
-/

namespace Tachyon.PublicationNodes

open Polynomial AnchorBreaks

variable {F P C : Type*} [Field F] [Monoid P]

structure ScopedLinked (m : Model P C F ℕ) (interpret : P →* F[X])
    (chain : List (Chain.Stamp F F)) (ps : List P) (xs : List (Input C F ℕ)) (e : ℕ) (a : F) where
  archive : LinkedNode m interpret chain e a
  openings_subset : archive.node.openings ⊆ ps
  inputs_subset : archive.node.inputs ⊆ xs

structure LinkedPredecessor (m : Model P C F ℕ) (interpret : P →* F[X])
    (chain : List (Chain.Stamp F F)) (ps : List P) (xs : List (Input C F ℕ))
    (beforeEpoch epoch : ℕ) (before : F) where
  epoch_eq : beforeEpoch = epoch
  predecessor : ScopedLinked m interpret chain ps xs epoch before

variable [DecidableEq F] [DecidableEq P] [DecidableEq C]

def linkedPredecessorOrBreak (m : Model P C F ℕ) (interpret : P →* F[X])
    {chain : List (Chain.Stamp F F)} {ps : List P} {xs : List (Input C F ℕ)} {e : ℕ} {a : F}
    (endpoint : ScopedLinked m interpret chain ps xs e a) (before : F) (beforeEpoch : ℕ) (p : P)
    (hp : p ∈ ps) (hx : m.stampInput before beforeEpoch p ∈ xs)
    (heq : m.nextStamp before beforeEpoch p = a) :
    LinkedPredecessor m interpret chain ps xs beforeEpoch e before ⊕' ScopedBreak m ps xs := by
  obtain ⟨archive, hopen, hinput⟩ := endpoint
  cases archive with
  | genesis =>
    apply PSum.inr
    apply (crossDomainBreak m before m.origin beforeEpoch m.genesisEpoch p heq).weaken
    · intro x hm
      exact (List.mem_singleton.mp hm) ▸ hp
    · intro x hm
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hm
      rcases hm with rfl | rfl
      · exact hx
      · exact hinput List.mem_cons_self
  | epoch earlier entered _ =>
    apply PSum.inr
    apply (crossDomainBreak m before _ beforeEpoch e p heq).weaken
    · intro x hm
      exact (List.mem_singleton.mp hm) ▸ hp
    · intro x hm
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hm
      rcases hm with rfl | rfl
      · exact hx
      · exact hinput List.mem_cons_self
  | stamp earlier entry actual _ _ _ _ =>
    cases stampEqOrBreak m before _ beforeEpoch e p actual heq with
    | inr witness =>
      apply PSum.inr
      apply witness.weaken
      · intro x hm
        simp only [List.mem_cons, List.not_mem_nil, or_false] at hm
        rcases hm with rfl | rfl
        · exact hp
        · exact hopen List.mem_cons_self
      · intro x hm
        simp only [List.mem_cons, List.not_mem_nil, or_false] at hm
        rcases hm with rfl | rfl
        · exact hx
        · exact hinput List.mem_cons_self
    | inl equalities =>
      obtain ⟨ha, he, _⟩ := equalities
      cases ha
      exact .inl ⟨he, earlier,
        fun _ hm => hopen (List.mem_cons_of_mem _ hm),
        fun _ hm => hinput (List.mem_cons_of_mem _ hm)⟩

structure LinkedSpanBound (m : Model P C F ℕ) (interpret : P →* F[X])
    (chain : List (Chain.Stamp F F)) (ps : List P) (xs : List (Input C F ℕ))
    (e : ℕ) (span : Chain.AnchorSpan F) where
  start : ScopedLinked m interpret chain ps xs e span.anchor_start
  lookup : (a : F) → Option (ScopedLinked m interpret chain ps xs e a)
  complete : ∀ a, span.members.eval a = 0 → (lookup a).isSome

def linkedSpanBoundOrBreak (m : Model P C F ℕ) (interpret : P →* F[X])
    {chain : List (Chain.Stamp F F)} {ps : List P} {xs : List (Input C F ℕ)}
    {e : ℕ} {span : Chain.AnchorSpan F} (trace : SpanTrace m span)
    (endpoint : ScopedLinked m interpret chain ps xs e span.anchor_end)
    (hps : trace.openings ⊆ ps) (hxs : trace.inputs ⊆ xs) :
    LinkedSpanBound m interpret chain ps xs e span ⊕' ScopedBreak m ps xs := by
  cases trace with
  | seed a seedEpoch p _ hmembers =>
    cases linkedPredecessorOrBreak m interpret endpoint a seedEpoch p
        (hps List.mem_cons_self) (hxs List.mem_cons_self) rfl with
    | inr witness => exact .inr witness
    | inl result =>
      apply PSum.inl
      refine ⟨result.predecessor, fun v => if hv : v = m.nextStamp a seedEpoch p then
        some (hv.symm ▸ endpoint) else none, ?_⟩
      intro v hroot
      have hv : v = m.nextStamp a seedEpoch p := by
        simpa [hmembers, setPoly, sub_eq_zero] using hroot
      simp [hv]
  | fuse left right hjoin hprod =>
    cases linkedSpanBoundOrBreak m interpret right endpoint
        (fun _ hp => hps (List.mem_append_right _ hp))
        (fun _ hx => hxs (List.mem_append_right _ hx)) with
    | inr witness => exact .inr witness
    | inl rightBound =>
      cases linkedSpanBoundOrBreak m interpret left (hjoin.symm ▸ rightBound.start)
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

/-- A successful lift supplies a publication-linked input node, not just an
ordinary hash trace. Every failure remains scoped to the span and archive. -/
def liftLinkedOrBreak (m : Model P C F ℕ) (interpret : P →* F[X])
    {chain : List (Chain.Stamp F F)} {e : ℕ} {span : Chain.AnchorSpan F}
    (trace : SpanTrace m span) (endpoint : LinkedNode m interpret chain e span.anchor_end)
    (anchor : F) (hcheck : span.members.eval anchor * (anchor - span.anchor_start) = 0) :
    ScopedLinked m interpret chain (trace.openings ++ endpoint.node.openings)
      (trace.inputs ++ endpoint.node.inputs) e anchor ⊕'
      ScopedBreak m (trace.openings ++ endpoint.node.openings) (trace.inputs ++ endpoint.node.inputs) := by
  let endScoped : ScopedLinked m interpret chain (trace.openings ++ endpoint.node.openings)
      (trace.inputs ++ endpoint.node.inputs) e span.anchor_end :=
    ⟨endpoint, fun _ hp => List.mem_append_right _ hp, fun _ hx => List.mem_append_right _ hx⟩
  cases linkedSpanBoundOrBreak m interpret trace endScoped
      (fun _ hp => List.mem_append_left _ hp) (fun _ hx => List.mem_append_left _ hx) with
  | inr witness => exact .inr witness
  | inl bound =>
    by_cases hstart : anchor = span.anchor_start
    · exact .inl (hstart.symm ▸ bound.start)
    · have hroot : span.members.eval anchor = 0 :=
        (mul_eq_zero.mp hcheck).resolve_right (fun h => hstart (sub_eq_zero.mp h))
      exact .inl ((bound.lookup anchor).get (bound.complete anchor hroot))

end Tachyon.PublicationNodes

namespace Tachyon

open Polynomial AnchorBreaks PublicationNodes SourceQueryBreaks

variable {F P C : Type*} [Field F] [Monoid P] [DecidableEq F] [DecidableEq P] [DecidableEq C]
  {m : Model P C F ℕ} {interpret : P →* F[X]} {chain : List (Chain.Stamp F F)}
  {s : Stamp F F} {a : F}

/-- Publication provenance survives the same lifted stamp path used for
positive/negative leaf traversal, or yields the observed scoped collision. -/
def SpanLift.descendLinked (w : SpanLift m s a) {e : ℕ}
    (archive : LinkedNode m interpret chain e a) :
    LinkedNode m interpret chain e s.anchor ⊕' ObservedBreak m :=
  match liftLinkedOrBreak m interpret w.trace
      (cast (congrArg (LinkedNode m interpret chain e) w.anchor_end.symm) archive) s.anchor w.step.1 with
  | .inl decoded => .inl decoded.archive
  | .inr witness => .inr ⟨_, _, witness⟩

end Tachyon
