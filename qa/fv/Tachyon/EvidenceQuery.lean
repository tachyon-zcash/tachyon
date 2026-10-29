import Tachyon.EvidenceReplay
import Tachyon.QueryCertificates

/-!
# Checked QR queries from replayed evidence leaves

Evidence leaves carry query-independent source provenance as data. Replay
recovers that exact source, and a per-value class/mask/register check then
constructs the checked query certificate. The oracle returns query completeness
or an explicit evidence-tree/source-anchor break, preserving each finite scope.

The evidence hash input type `B` is the encoded public preimage. `decode` gives
its bucket fields, discriminant and boolean profile. Correct canonical encoding
and extraction of certified tree/source data from accepted PCD are external
boundaries, not supplied by a global injectivity or `Nonempty` assumption.
Neither private source provenance nor queried values are added to the public
leaf hash preimage by this model.
-/

namespace Tachyon.EvidenceQuery

open Polynomial AnchorBreaks SourceQueryBreaks

variable {F P C A B D : Type*} [Field F] [Monoid P]

structure BucketView (F A : Type*) [Field F] where
  bucket : QrBucket F A
  firstDiscriminant : F
  profile : List Bool

/-- The same source provenance can serve multiple matching queries. Scalar
class witnesses are supplied per query rather than hashed in the public leaf. -/
structure SourceData (m : Model P C A ℕ) (interpret : P →* F[X])
    (chain : List (Chain.Stamp F A)) (c : F) (view : BucketView F A) where
  start : A
  finish : A
  realStart : A
  realFinish : A
  accumulator : P
  canonical : P
  source : RunTrace m view.bucket.epoch start finish accumulator
  published : PublicationTrace m interpret view.bucket.epoch realStart
    (SourceSealing.epochPublications chain view.bucket.epoch) realFinish canonical
  previous : A
  realPrevious : A
  opens : start = m.epochHash previous view.bucket.epoch
  real_opens : realStart = m.epochHash realPrevious view.bucket.epoch
  sealed_endpoint : view.bucket.anchor_next = m.epochHash finish (view.bucket.epoch + 1)
  accepted_endpoint : view.bucket.anchor_next = m.epochHash realFinish (view.bucket.epoch + 1)
  retention : ∀ value, Qr.MatchesProfile view.firstDiscriminant value view.profile →
    (interpret accumulator).eval value = 0 → view.bucket.contents.eval value = 0

def SourceData.certificate {m : Model P C A ℕ} {interpret : P →* F[X]}
    {chain : List (Chain.Stamp F A)} {c : F} {view : BucketView F A}
    (source : SourceData m interpret chain c view) (value : F)
    (hcheck : ProfileQuery.QueryCheck c view.firstDiscriminant value view.profile) :
    Certificate m interpret chain c view.bucket value where
  firstDiscriminant := view.firstDiscriminant
  profile := view.profile
  start := source.start
  finish := source.finish
  realStart := source.realStart
  realFinish := source.realFinish
  accumulator := source.accumulator
  canonical := source.canonical
  source := source.source
  published := source.published
  previous := source.previous
  realPrevious := source.realPrevious
  opens := source.opens
  real_opens := source.real_opens
  sealed_endpoint := source.sealed_endpoint
  accepted_endpoint := source.accepted_endpoint
  profileCheck := hcheck
  retention := source.retention value

structure ObservedEvidenceBreak (evidence : EvidenceReplay.Model B D) where
  inputs : List (EvidenceReplay.Input B D)
  collision : EvidenceReplay.Collision evidence inputs

inductive Failure (m : Model P C A ℕ) (evidence : EvidenceReplay.Model B D)
  | anchor (witness : ObservedBreak m)
  | replay (witness : ObservedEvidenceBreak evidence)

def Failure.CollisionFree {m : Model P C A ℕ} {evidence : EvidenceReplay.Model B D} :
    Failure m evidence → Prop
  | .anchor w => NoCollisionsOn m w.openings w.inputs
  | .replay w => EvidenceReplay.NoCollisionsOn evidence w.inputs

def Failure.elim {m : Model P C A ℕ} {evidence : EvidenceReplay.Model B D}
    (w : Failure m evidence) (h : w.CollisionFree) : False :=
  match w with
  | .anchor w => w.elim h
  | .replay w => w.collision.elim h

/-- A bucket opening request carries an actual certified evidence tree/path,
plus its per-value profile equations. No source is selected from a proposition. -/
structure Query (m : Model P C A ℕ) (interpret : P →* F[X])
    (chain : List (Chain.Stamp F A)) (c : F) (evidence : EvidenceReplay.Model B D)
    (decode : B → BucketView F A) (bucket : QrBucket F A) (value : F) where
  encoded : B
  root : D
  target : D
  tree : EvidenceReplay.Tree evidence (fun b => SourceData m interpret chain c (decode b)) root
  path : EvidenceReplay.Path evidence root target
  opening : evidence.leafHash encoded = target
  header : (decode encoded).bucket = bucket
  profileCheck : ProfileQuery.QueryCheck c (decode encoded).firstDiscriminant value
    (decode encoded).profile

variable [DecidableEq P] [DecidableEq C] [DecidableEq A] [DecidableEq B] [DecidableEq D]

/-- The replay-plus-source oracle composes two explicit break reductions and
retains whether the failure was an evidence hash or a source/commitment break. -/
def Query.oracle {m : Model P C A ℕ} {interpret : P →* F[X]}
    {chain : List (Chain.Stamp F A)} {c : F} {evidence : EvidenceReplay.Model B D}
    {decode : B → BucketView F A} (hc : ¬ IsSquare c)
    (bucket : QrBucket F A) (value : F) (q : Query m interpret chain c evidence decode bucket value) :
    Profiled.QueryComplete chain bucket value ⊕' Failure m evidence := by
  cases EvidenceReplay.replayOrCollision evidence q.tree q.path q.encoded q.opening with
  | inr witness =>
    exact .inr (.replay ⟨q.tree.inputs ++ q.path.inputs ++ [.leaf q.encoded], witness⟩)
  | inl source =>
    cases (source.certificate value q.profileCheck).outcome hc with
    | inr witness =>
      exact .inr (.anchor ⟨_, _, witness⟩)
    | inl complete =>
      exact .inl (q.header ▸ complete)

/-- A local corollary refers only to a failure actually returned for this
request; it makes no universal absence-of-collisions assertion. -/
theorem Query.complete_of_local_no_collisions {m : Model P C A ℕ} {interpret : P →* F[X]}
    {chain : List (Chain.Stamp F A)} {c : F} {evidence : EvidenceReplay.Model B D}
    {decode : B → BucketView F A} {bucket : QrBucket F A} {value : F}
    (hc : ¬ IsSquare c) (q : Query m interpret chain c evidence decode bucket value)
    (hlocal : ∀ w, Query.oracle hc bucket value q = .inr w → w.CollisionFree) :
    Profiled.QueryComplete chain bucket value := by
  cases hout : Query.oracle hc bucket value q with
  | inl result => exact result
  | inr witness => exact False.elim (witness.elim (hlocal witness hout))

end Tachyon.EvidenceQuery
