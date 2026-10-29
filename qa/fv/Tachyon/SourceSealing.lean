import Tachyon.ProfiledSpendable

/-!
# Epoch source completeness from the sealed anchor endpoint

This file is the symbolic `HashLaw` reference proof. `SourceBreakReduction`
and `SourceQueryBreaks` give the concrete finite-trace reductions, returning
the result or explicit colliding inputs without the global law.

A root intake or summary starts from a free anchor, multiplies the same stamp
polynomials that it absorbs into the running anchor, and may concatenate runs.
`Run` abstracts that common mechanism before QR profile routing. It permits an
empty run, as required for `QrEmptyIntakeSeed`.

`Run.unique_from_boundaries` proves that two runs starting on epoch-boundary
digests and ending at the same anchor have identical starts and polynomial
products. The argument peels stamp folds backwards by injectivity; a stamp fold
cannot be mistaken for a boundary digest. No injectivity of products is assumed.

`Run.sealed_source_eq` applies the `QrBucketSeal` next-epoch fold: checking the
sealed endpoint against the next entry anchor computed from all publications
forces the source to be precisely the epoch's product. Consequently
`routedQuery_of_sealed` builds a profile-aware query certificate without assuming
source completeness separately.

The accepted next-entry anchor is represented by the canonical epoch fold of
the supplied publication list. Relating that list and accepted endpoint to a
block validator is a consensus input, not inferred from `Chain.Valid`, which
only models membership/recency/window checks. Hash binding/domain separation
are explicit `Chain.HashLaw` hypotheses. This module models the root source;
it does not assert that a single routed child contains the entire epoch.
-/

namespace Tachyon.SourceSealing

open Polynomial

variable {F A : Type*} [Field F]

/-- The polynomial product of the epoch's published stamp tachygram lists. -/
noncomputable def sourcePoly (publications : List (List F)) : F[X] :=
  (publications.map fun ts : List F => setPoly (ts : Multiset F)).prod

/-- Absorb the publications in their chronological order at their real epoch. -/
noncomputable def epochEnd (nextStamp : A → ℕ → F[X] → A) (e : ℕ) (start : A)
    (publications : List (List F)) : A :=
  Chain.foldBlock nextStamp e start (publications.map fun ts : List F => setPoly (ts : Multiset F))

/-- A source run multiplies precisely the polynomials that its anchor absorbs.
As an over-approximation, arbitrary polynomial operands are allowed here. -/
inductive Run (nextStamp : A → ℕ → F[X] → A) (e : ℕ) : A → A → F[X] → Prop
  | empty (a : A) : Run nextStamp e a a 1
  | append {start finish : A} {acc : F[X]} (stamp : F[X]) :
      Run nextStamp e start finish acc →
      Run nextStamp e start (nextStamp finish e stamp) (acc * stamp)

variable {nextStamp : A → ℕ → F[X] → A} {nextEpoch : A → ℕ → A} {e : ℕ}

/-- Concatenation models summary/intake merges with equal adjacent anchors. -/
theorem Run.concat {a b c : A} {p q : F[X]}
    (hl : Run nextStamp e a b p) (hr : Run nextStamp e b c q) :
    Run nextStamp e a c (p * q) := by
  induction hr with
  | empty => simpa using hl
  | append stamp _ ih => simpa [mul_assoc] using Run.append stamp ih

/-- The canonical publication fold is a source run with its actual product. -/
theorem Run.of_publications (start : A) (publications : List (List F)) :
    Run nextStamp e start (epochEnd nextStamp e start publications) (sourcePoly publications) := by
  induction publications generalizing start with
  | nil => simpa [epochEnd, Chain.foldBlock, sourcePoly] using Run.empty (nextStamp := nextStamp) (e := e) start
  | cons ts rest ih =>
    have hfirst : Run nextStamp e start (nextStamp start e (setPoly (ts : Multiset F)))
        (setPoly (ts : Multiset F)) := by
      simpa using Run.append (setPoly (ts : Multiset F)) (Run.empty start)
    simpa [epochEnd, Chain.foldBlock, sourcePoly] using hfirst.concat (ih _)

/-- The common root-header data of summaries and depth-zero QR intakes. -/
structure RootIntake (F A : Type*) [Field F] where
  epoch : ℕ
  start : A
  finish : A
  contents : F[X]

/-- Root source producers: `SummarySeed` / `QrStampIntakeSeed`,
`SummaryAdvance`, `QrIntakeMerge` at the root profile, and `QrEmptyIntakeSeed`.
`QrSummaryIntake` changes no root data and is represented by the same predicate.
As in `Run`, omitted nonidentity/empty-commit checks only enlarge this model. -/
inductive RootIntakeDerivable (nextStamp : A → ℕ → F[X] → A) : RootIntake F A → Prop
  | seed (e : ℕ) (a : A) (stamp : F[X]) :
      RootIntakeDerivable nextStamp ⟨e, a, nextStamp a e stamp, stamp⟩
  | empty (e : ℕ) (a : A) : RootIntakeDerivable nextStamp ⟨e, a, a, 1⟩
  | advance {s : RootIntake F A} (stamp : F[X]) :
      RootIntakeDerivable nextStamp s →
      RootIntakeDerivable nextStamp
        ⟨s.epoch, s.start, nextStamp s.finish s.epoch stamp, s.contents * stamp⟩
  | merge {left right : RootIntake F A} :
      RootIntakeDerivable nextStamp left → RootIntakeDerivable nextStamp right →
      left.epoch = right.epoch → left.finish = right.start →
      RootIntakeDerivable nextStamp
        ⟨left.epoch, left.start, right.finish, left.contents * right.contents⟩

/-- Every derivable root source certifies the same anchor/polynomial run. -/
theorem RootIntakeDerivable.run {s : RootIntake F A}
    (h : RootIntakeDerivable nextStamp s) : Run nextStamp s.epoch s.start s.finish s.contents := by
  induction h with
  | seed e a stamp => simpa using Run.append stamp (Run.empty a)
  | empty e a => exact Run.empty a
  | advance stamp _ ih => exact Run.append stamp ih
  | merge _ _ hepoch hjoin ihl ihr =>
    rw [← hepoch, ← hjoin] at ihr
    exact ihl.concat ihr

/-- Boundary starts plus a common endpoint pin the whole run. In particular,
choosing a free predecessor cannot hide a missing or invented source stamp. -/
theorem Run.unique_from_boundaries {genesis : A} {e₀ : ℕ}
    (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    {a b a' b' : A} {p q : F[X]}
    (hl : Run nextStamp e a b p) (hr : Run nextStamp e a' b' q)
    (hleft : ∃ prev, a = nextEpoch prev e) (hright : ∃ prev, a' = nextEpoch prev e)
    (hend : b = b') : a = a' ∧ p = q := by
  induction hl generalizing a' b' q with
  | empty =>
    cases hr with
    | empty => exact ⟨hend, rfl⟩
    | append stamp _ =>
      obtain ⟨prev, hprev⟩ := hleft
      exact False.elim (hlaw.stamp_ne_epoch (hend.symm.trans hprev))
  | append stamp _ ih =>
    cases hr with
    | empty =>
      obtain ⟨prev, hprev⟩ := hright
      exact False.elim (hlaw.stamp_ne_epoch (hend.trans hprev))
    | append stamp' hrun' =>
      obtain ⟨hprev, _, hstamp⟩ := hlaw.nextStamp_inj hend
      obtain ⟨hstart, hpoly⟩ := ih hrun' hright hprev
      exact ⟨hstart, by rw [hpoly, hstamp]⟩

/-- The next-entry endpoint produced by sealing pins the source to all epoch
publications, even though the source's initial predecessor was free. -/
theorem Run.sealed_source_eq {genesis : A} {e₀ : ℕ}
    (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    {start finish realPrev : A} {source : F[X]} {publications : List (List F)}
    (hsource : Run nextStamp e start finish source)
    (hopen : ∃ prev, start = nextEpoch prev e)
    (hseal : nextEpoch finish (e + 1) =
      nextEpoch (epochEnd nextStamp e (nextEpoch realPrev e) publications) (e + 1)) :
    source = sourcePoly publications := by
  have hend := (hlaw.nextEpoch_inj hseal).1
  exact (hsource.unique_from_boundaries hlaw (Run.of_publications _ publications)
    hopen ⟨realPrev, rfl⟩ hend).2

/-- Every published root occurs in the epoch source product, with no
uniqueness or disjointness requirement on the publications. -/
theorem sourcePoly_eval_zero {publications : List (List F)} {ts : List F} {v : F}
    (hts : ts ∈ publications) (hv : v ∈ ts) : (sourcePoly publications).eval v = 0 := by
  have hroot : (setPoly (ts : Multiset F)).eval v = 0 := by
    have hmem : v ∈ (setPoly (ts : Multiset F)).roots := by simpa using hv
    exact (mem_roots (setPoly_ne_zero _)).mp hmem
  unfold sourcePoly
  rw [eval_list_prod]
  apply List.prod_eq_zero_iff.mpr
  have hpoly : setPoly (ts : Multiset F) ∈
      publications.map (fun xs : List F => setPoly (xs : Multiset F)) := List.mem_map_of_mem hts
  exact List.mem_map.mpr ⟨setPoly (ts : Multiset F), hpoly, hroot⟩

/-- The canonical publication lists for one epoch of a chronological chain. -/
def epochPublications (chain : List (Chain.Stamp F A)) (e : ℕ) : List (List F) :=
  (chain.filter fun s => s.epoch = e).map Chain.Stamp.tachygrams

theorem sourcePoly_complete (chain : List (Chain.Stamp F A)) (e : ℕ) :
    ∀ v, Chain.published chain e v → (sourcePoly (epochPublications chain e)).eval v = 0 := by
  rintro v ⟨s, hs, he, hv⟩
  apply sourcePoly_eval_zero (ts := s.tachygrams) ?_ hv
  exact List.mem_map.mpr ⟨s, List.mem_filter.mpr ⟨hs, by simpa using he⟩, rfl⟩

/-- An empty source can seal onto the accepted next-entry anchor only if the
epoch published no tachygram. This justifies `QrEmptyIntakeSeed` even when its
initial anchor is freely witnessed. -/
theorem sealed_empty_no_publication {genesis : A} {e₀ : ℕ}
    (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    {chain : List (Chain.Stamp F A)} {start realPrev : A}
    (hopen : ∃ prev, start = nextEpoch prev e)
    (hseal : nextEpoch start (e + 1) = nextEpoch
      (epochEnd nextStamp e (nextEpoch realPrev e) (epochPublications chain e)) (e + 1)) :
    ∀ v, ¬ Chain.published chain e v := by
  have heq := (Run.empty start).sealed_source_eq hlaw hopen hseal
  intro v hpub
  have hz := sourcePoly_complete chain e v hpub
  rw [← heq, eval_one] at hz
  exact one_ne_zero hz

/-- A bucket's next anchor is both its source's seal and the canonical next
entry of the publication list. These checks derive the complete source needed
by a matching routed query; no `CompleteBucket` premise is used. -/
theorem routedQuery_of_sealed {genesis : A} {e₀ : ℕ}
    (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    {chain : List (Chain.Stamp F A)} {b : QrBucket F A} {c r v : F}
    {source : F[X]} {start finish realPrev : A} {bits : List Bool}
    (hrun : Run nextStamp b.epoch start finish source)
    (hopen : ∃ prev, start = nextEpoch prev b.epoch)
    (hseal : b.anchor_next = nextEpoch finish (b.epoch + 1))
    (haccepted : b.anchor_next = nextEpoch
      (epochEnd nextStamp b.epoch (nextEpoch realPrev b.epoch)
        (epochPublications chain b.epoch)) (b.epoch + 1))
    (hroute : Qr.Route c r source bits b.contents)
    (hmatch : Qr.MatchesProfile r v bits) : Profiled.RoutedQuery chain c b v := by
  have heq := hrun.sealed_source_eq hlaw hopen (hseal.symm.trans haccepted)
  exact ⟨⟨r, source, bits, heq ▸ sourcePoly_complete chain b.epoch, hroute, hmatch⟩⟩

/-- The same certificate, starting directly from a derivable root intake. -/
theorem RootIntakeDerivable.routedQuery {genesis : A} {e₀ : ℕ}
    (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    {chain : List (Chain.Stamp F A)} {s : RootIntake F A} {b : QrBucket F A}
    {c r v : F} {realPrev : A} {bits : List Bool}
    (h : RootIntakeDerivable nextStamp s) (hepoch : s.epoch = b.epoch)
    (hopen : ∃ prev, s.start = nextEpoch prev s.epoch)
    (hseal : b.anchor_next = nextEpoch s.finish (s.epoch + 1))
    (haccepted : b.anchor_next = nextEpoch
      (epochEnd nextStamp b.epoch (nextEpoch realPrev b.epoch)
        (epochPublications chain b.epoch)) (b.epoch + 1))
    (hroute : Qr.Route c r s.contents bits b.contents)
    (hmatch : Qr.MatchesProfile r v bits) : Profiled.RoutedQuery chain c b v := by
  apply routedQuery_of_sealed hlaw (hepoch ▸ h.run) (hepoch ▸ hopen)
    (hepoch ▸ hseal) haccepted hroute hmatch

end Tachyon.SourceSealing
