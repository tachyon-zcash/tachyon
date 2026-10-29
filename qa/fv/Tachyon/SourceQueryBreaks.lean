import Tachyon.SpanTraces
import Tachyon.RoutedIntakes

/-!
# Checked source queries or computed finite-execution breaks

The canonical publication trace carries concrete opening data and proofs that
each opening represents its stamp's public tachygrams. The interpretation map
is used only in mathematical specifications; no Mathlib polynomial is created
inside the computed reduction. This separates runtime data from the polynomial
model, in the same spirit as ragu's circuit/specification separation.

`queryCompleteOrBreak` replaces the global `HashLaw` in source sealing with a
computed comparison of the witnessed source and canonical publication traces.
It returns query completeness or an explicit commitment/hash collision in the
finite run/seal transcript. The source's next-entry anchor and chronological
publication list are consensus inputs, rather than inferred from the weaker
`Chain.Valid` predicate.
-/

namespace Tachyon.SourceQueryBreaks

open Polynomial AnchorBreaks

universe u v w z

variable {F : Type u} {P : Type v} {C : Type w} {A : Type z} [Field F] [Monoid P]

/-- Data-valued publication provenance, with a fixed semantic interpretation
of the concrete openings. Stamp encodings are certified, not constructed. -/
inductive PublicationTrace (m : Model P C A ℕ) (interpret : P →* F[X]) (e : ℕ) :
    A → List (List F) → A → P → Type (max u v z)
  | empty (a : A) : PublicationTrace m interpret e a [] a 1
  | publish {start finish : A} {pubs : List (List F)} {acc : P}
      (previous : PublicationTrace m interpret e start pubs finish acc)
      (tachygrams : List F) (opening : P)
      (encoding : interpret opening = setPoly (tachygrams : Multiset F)) :
      PublicationTrace m interpret e start (pubs ++ [tachygrams])
        (m.nextStamp finish e opening) (acc * opening)

def PublicationTrace.run {m : Model P C A ℕ} {interpret : P →* F[X]} {e : ℕ}
    {start finish : A} {pubs : List (List F)} {acc : P}
    (t : PublicationTrace m interpret e start pubs finish acc) : RunTrace m e start finish acc := by
  cases t with
  | empty => exact RunTrace.empty _
  | publish previous _ opening _ => exact RunTrace.append previous.run opening
termination_by structural t

/-- The canonical trace's accumulator denotes exactly all published roots. -/
theorem PublicationTrace.source_spec {m : Model P C A ℕ} {interpret : P →* F[X]} {e : ℕ}
    {start finish : A} {pubs : List (List F)} {acc : P}
    (t : PublicationTrace m interpret e start pubs finish acc) :
    interpret acc = SourceSealing.sourcePoly pubs := by
  induction t with
  | empty => simp [SourceSealing.sourcePoly]
  | publish _ ts opening hencode ih =>
    simp [map_mul, ih, hencode, SourceSealing.sourcePoly]

variable [DecidableEq P] [DecidableEq C] [DecidableEq A]

/-- Compute query completeness or a scoped cryptographic break. The profile
is derived from scalar class/mask/register checks, not assumed to match. -/
def queryCompleteOrBreak (m : Model P C A ℕ) (interpret : P →* F[X])
    {chain : List (Chain.Stamp F A)} {b : QrBucket F A} {r c value : F}
    {bits : List Bool} {start finish realStart realFinish : A} {acc canonical : P}
    (source : RunTrace m b.epoch start finish acc)
    (published : PublicationTrace m interpret b.epoch realStart
      (SourceSealing.epochPublications chain b.epoch) realFinish canonical)
    (previous realPrevious : A) (hstart : start = m.epochHash previous b.epoch)
    (hreal : realStart = m.epochHash realPrevious b.epoch)
    (hseal : b.anchor_next = m.epochHash finish (b.epoch + 1))
    (haccepted : b.anchor_next = m.epochHash realFinish (b.epoch + 1))
    (hc : ¬ IsSquare c) (hcheck : ProfileQuery.QueryCheck c r value bits)
    (hretains : Qr.MatchesProfile r value bits →
      (interpret acc).eval value = 0 → b.contents.eval value = 0) :
    Profiled.QueryComplete chain b value ⊕'
      ScopedBreak m (source.openings ++ published.run.openings)
        (source.inputs ++ published.run.inputs ++
          [.epoch previous b.epoch, .epoch realPrevious b.epoch,
           .epoch finish (b.epoch + 1), .epoch realFinish (b.epoch + 1)]) := by
  cases sealedSourceOrBreak m b.epoch (b.epoch + 1) source published.run previous realPrevious
      hstart hreal (hseal.symm.trans haccepted) with
  | inr witness => exact .inr witness
  | inl result =>
    apply PSum.inl
    intro hpub
    apply hretains (hcheck.matches hc)
    rw [result.2, published.source_spec]
    exact SourceSealing.sourcePoly_complete chain b.epoch value hpub

/-- Execution-local query soundness follows by discharging only breaks on the
specified finite trace inputs. -/
theorem query_complete_of_no_collisions (m : Model P C A ℕ) (interpret : P →* F[X])
    {chain : List (Chain.Stamp F A)} {b : QrBucket F A} {r c value : F}
    {bits : List Bool} {start finish realStart realFinish : A} {acc canonical : P}
    (source : RunTrace m b.epoch start finish acc)
    (published : PublicationTrace m interpret b.epoch realStart
      (SourceSealing.epochPublications chain b.epoch) realFinish canonical)
    (previous realPrevious : A) (hstart : start = m.epochHash previous b.epoch)
    (hreal : realStart = m.epochHash realPrevious b.epoch)
    (hseal : b.anchor_next = m.epochHash finish (b.epoch + 1))
    (haccepted : b.anchor_next = m.epochHash realFinish (b.epoch + 1))
    (hc : ¬ IsSquare c) (hcheck : ProfileQuery.QueryCheck c r value bits)
    (hretains : Qr.MatchesProfile r value bits →
      (interpret acc).eval value = 0 → b.contents.eval value = 0)
    (hlocal : NoCollisionsOn m (source.openings ++ published.run.openings)
      (source.inputs ++ published.run.inputs ++
        [.epoch previous b.epoch, .epoch realPrevious b.epoch,
         .epoch finish (b.epoch + 1), .epoch realFinish (b.epoch + 1)])) :
    Profiled.QueryComplete chain b value := by
  cases queryCompleteOrBreak m interpret source published previous realPrevious hstart hreal
      hseal haccepted hc hcheck hretains with
  | inl result => exact result
  | inr witness => exact False.elim (witness.elim hlocal)

omit [DecidableEq P] [DecidableEq A] in
/-- The retention input to the computed reduction is supplied by the earlier
route/merge proof, so sources routed before merging are supported as well.
This lemma uses no hash laws; it connects only the polynomial specifications. -/
theorem retention_of_intake {interpret : P →* F[X]} {acc : P} {c r value : F}
    {bits : List Bool} {source : SourceSealing.RootIntake F A} {contents : F[X]}
    {nextStampSpec : A → ℕ → F[X] → A} (hc : ¬ IsSquare c)
    (h : RoutedIntakes.Derivable nextStampSpec c r bits source contents)
    (hpoly : source.contents = interpret acc) :
    Qr.MatchesProfile r value bits → (interpret acc).eval value = 0 → contents.eval value = 0 := by
  intro hmatch hroot
  exact h.retains hc hmatch (hpoly.symm ▸ hroot)

end Tachyon.SourceQueryBreaks
