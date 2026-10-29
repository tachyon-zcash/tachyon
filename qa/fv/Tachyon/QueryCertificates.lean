import Tachyon.SourceQueryBreaks

/-!
# Data-valued checked-query certificates and a common break outcome

Each unspent opening must carry its source/profile certificate as actual data,
not merely `Nonempty Certificate : Prop`, if a reduction is to compute a break
from it. `Certificate` packages exactly the inputs to `queryCompleteOrBreak`.

Different queries have different finite source transcripts. `ObservedBreak`
carries the transcript alongside its scoped collision witness, allowing a
single break type to compose query outcomes across a finite unspent lineage.
The scope is retained, not replaced by a universal no-collision assumption.

`Certificate.oracle` has the generic interface used by a data-valued query
traversal: query completeness or the first concrete break. It constructs no
certificate by classical witness selection, and does not extract PCD witnesses.
The caller supplies certified source data from its witness/extraction layer.
-/

namespace Tachyon.SourceQueryBreaks

open Polynomial AnchorBreaks

universe u v w z

variable {F : Type u} {P : Type v} {C : Type w} {A : Type z} [Field F] [Monoid P]

/-- A break together with the finite query transcript in which it was found. -/
structure ObservedBreak (m : Model P C A ℕ) where
  openings : List P
  inputs : List (Input C A ℕ)
  collision : ScopedBreak m openings inputs

def ObservedBreak.elim {m : Model P C A ℕ} (w : ObservedBreak m)
    (h : NoCollisionsOn m w.openings w.inputs) : False := w.collision.elim h

/-- Runtime query evidence, with polynomial and circuit equations in erased
proof fields. No source-completeness or matching-profile axiom is included. -/
structure Certificate (m : Model P C A ℕ) (interpret : P →* F[X])
    (chain : List (Chain.Stamp F A)) (c : F) (b : QrBucket F A) (value : F) where
  firstDiscriminant : F
  profile : List Bool
  start : A
  finish : A
  realStart : A
  realFinish : A
  accumulator : P
  canonical : P
  source : RunTrace m b.epoch start finish accumulator
  published : PublicationTrace m interpret b.epoch realStart
    (SourceSealing.epochPublications chain b.epoch) realFinish canonical
  previous : A
  realPrevious : A
  opens : start = m.epochHash previous b.epoch
  real_opens : realStart = m.epochHash realPrevious b.epoch
  sealed_endpoint : b.anchor_next = m.epochHash finish (b.epoch + 1)
  accepted_endpoint : b.anchor_next = m.epochHash realFinish (b.epoch + 1)
  profileCheck : ProfileQuery.QueryCheck c firstDiscriminant value profile
  retention : Qr.MatchesProfile firstDiscriminant value profile →
    (interpret accumulator).eval value = 0 → b.contents.eval value = 0

def Certificate.openings {m : Model P C A ℕ} {interpret : P →* F[X]}
    {chain : List (Chain.Stamp F A)} {c : F} {b : QrBucket F A} {value : F}
    (q : Certificate m interpret chain c b value) : List P :=
  q.source.openings ++ q.published.run.openings

def Certificate.inputs {m : Model P C A ℕ} {interpret : P →* F[X]}
    {chain : List (Chain.Stamp F A)} {c : F} {b : QrBucket F A} {value : F}
    (q : Certificate m interpret chain c b value) : List (Input C A ℕ) :=
  q.source.inputs ++ q.published.run.inputs ++
    [.epoch q.previous b.epoch, .epoch q.realPrevious b.epoch,
     .epoch q.finish (b.epoch + 1), .epoch q.realFinish (b.epoch + 1)]

variable [DecidableEq P] [DecidableEq C] [DecidableEq A]

def Certificate.outcome {m : Model P C A ℕ} {interpret : P →* F[X]}
    {chain : List (Chain.Stamp F A)} {c : F} {b : QrBucket F A} {value : F}
    (hc : ¬ IsSquare c) (q : Certificate m interpret chain c b value) :
    Profiled.QueryComplete chain b value ⊕' ScopedBreak m q.openings q.inputs :=
  queryCompleteOrBreak m interpret q.source q.published q.previous q.realPrevious q.opens
    q.real_opens q.sealed_endpoint q.accepted_endpoint hc q.profileCheck q.retention

/-- A uniform oracle outcome suitable for traversing a finite query lineage.
The returned break retains that query's concrete finite transcript as data. -/
def Certificate.oracle {m : Model P C A ℕ} {interpret : P →* F[X]}
    {chain : List (Chain.Stamp F A)} {c : F} (hc : ¬ IsSquare c)
    (b : QrBucket F A) (value : F) (q : Certificate m interpret chain c b value) :
    Profiled.QueryComplete chain b value ⊕' ObservedBreak m :=
  match q.outcome hc with
  | .inl success => .inl success
  | .inr witness => .inr ⟨q.openings, q.inputs, witness⟩

theorem Certificate.complete_of_no_collisions {m : Model P C A ℕ} {interpret : P →* F[X]}
    {chain : List (Chain.Stamp F A)} {c : F} {b : QrBucket F A} {value : F}
    (hc : ¬ IsSquare c) (q : Certificate m interpret chain c b value)
    (hlocal : NoCollisionsOn m q.openings q.inputs) : Profiled.QueryComplete chain b value := by
  cases q.outcome hc with
  | inl success => exact success
  | inr witness => exact False.elim (witness.elim hlocal)

end Tachyon.SourceQueryBreaks
