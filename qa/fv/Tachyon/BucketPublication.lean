import Tachyon.EvidenceQuery

/-!
# A sealed bucket root was actually published, or there is a computed break

Matching-root retention is one-way: it prevents missing queried values, but
does not by itself forbid invented roots. The actual split/merge provenance
also gives `contents ∣ source`. This module proves that property and combines
it with the canonical publication product and the finite source/seal reduction.

`publicationOrBreak` supplies the converse needed at `QrSpendableInit`: a root
of the certified bucket belongs to its epoch's publications, or the supplied
source traces compute a commitment/hash collision. No matching-profile premise
is needed for inclusion. `CertifiedSource` extends the existing query source
data with divisibility, rather than changing the earlier one-way query API.
-/

namespace Tachyon.RoutedIntakes

open Polynomial

variable {F A : Type*} [Field F]

theorem selected_dvd_parent {parent : F[X]} {r : F} (s : Qr.Split parent r) (bit : Bool) :
    s.selected bit ∣ parent := by
  cases bit with
  | false => exact ⟨s.residue, s.product⟩
  | true => exact ⟨s.nonResidue, s.product.trans (mul_comm _ _)⟩

/-- Routing may retain strays of the other class, but every root is still
drawn from the source: a selected child always divides its parent. -/
theorem Derivable.contents_dvd_source {nextStamp : A → ℕ → F[X] → A} {c r : F}
    {bits : List Bool} {source : SourceSealing.RootIntake F A} {contents : F[X]}
    (h : Derivable nextStamp c r bits source contents) : contents ∣ source.contents := by
  induction h with
  | root => exact dvd_refl _
  | merge _ _ _ _ ihl ihr => exact mul_dvd_mul ihl ihr
  | descend split _ _ ih => exact (selected_dvd_parent split _).trans ih

end Tachyon.RoutedIntakes

namespace Tachyon.BucketPublication

open Polynomial AnchorBreaks SourceQueryBreaks

variable {F : Type*} [Field F]

theorem source_root_iff (publications : List (List F)) (value : F) :
    (SourceSealing.sourcePoly publications).eval value = 0 ↔
      ∃ ts ∈ publications, value ∈ ts := by
  induction publications with
  | nil => simp [SourceSealing.sourcePoly]
  | cons ts rest ih =>
    have hprod : SourceSealing.sourcePoly (ts :: rest) =
        setPoly (ts : Multiset F) * SourceSealing.sourcePoly rest := by
      simp [SourceSealing.sourcePoly]
    have hroots : (setPoly (ts : Multiset F)).eval value = 0 ↔ value ∈ ts := by
      rw [← IsRoot.def, ← mem_roots (setPoly_ne_zero _), roots_setPoly]
      exact Multiset.mem_coe
    rw [hprod, eval_mul, mul_eq_zero, hroots, ih]
    simp [List.mem_cons, or_and_right, exists_or]

theorem canonical_root_iff {A : Type*} (chain : List (Chain.Stamp F A)) (e : ℕ) (value : F) :
    (SourceSealing.sourcePoly (SourceSealing.epochPublications chain e)).eval value = 0 ↔
      Chain.published chain e value := by
  rw [source_root_iff]
  simp only [SourceSealing.epochPublications, List.mem_map, List.mem_filter, decide_eq_true_eq,
    Chain.published]
  constructor
  · rintro ⟨ts, ⟨s, ⟨hs, he⟩, rfl⟩, hv⟩
    exact ⟨s, hs, he, hv⟩
  · rintro ⟨s, hs, he, hv⟩
    exact ⟨s.tachygrams, ⟨s, ⟨hs, he⟩, rfl⟩, hv⟩

variable {P C A : Type*} [Monoid P] [DecidableEq P] [DecidableEq C] [DecidableEq A]

/-- Inclusion is derived from the actual finite source comparison. A plain
`QueryComplete` or root-retention premise would not justify this reduction. -/
def publicationOrBreak (m : Model P C A ℕ) (interpret : P →* F[X])
    {chain : List (Chain.Stamp F A)} {b : QrBucket F A} {value : F}
    {start finish realStart realFinish : A} {acc canonical : P}
    (source : RunTrace m b.epoch start finish acc)
    (published : PublicationTrace m interpret b.epoch realStart
      (SourceSealing.epochPublications chain b.epoch) realFinish canonical)
    (previous realPrevious : A) (hstart : start = m.epochHash previous b.epoch)
    (hreal : realStart = m.epochHash realPrevious b.epoch)
    (hseal : b.anchor_next = m.epochHash finish (b.epoch + 1))
    (haccepted : b.anchor_next = m.epochHash realFinish (b.epoch + 1))
    (hdivides : b.contents ∣ interpret acc) (hroot : b.contents.eval value = 0) :
    Chain.published chain b.epoch value ⊕'
      ScopedBreak m (source.openings ++ published.run.openings)
        (source.inputs ++ published.run.inputs ++
          [.epoch previous b.epoch, .epoch realPrevious b.epoch,
           .epoch finish (b.epoch + 1), .epoch realFinish (b.epoch + 1)]) := by
  cases sealedSourceOrBreak m b.epoch (b.epoch + 1) source published.run previous realPrevious
      hstart hreal (hseal.symm.trans haccepted) with
  | inr witness => exact .inr witness
  | inl result =>
    apply PSum.inl
    apply (canonical_root_iff chain b.epoch value).mp
    have hsourceRoot : (interpret acc).eval value = 0 := by
      obtain ⟨complement, hproduct⟩ := hdivides
      rw [hproduct, eval_mul, hroot, zero_mul]
    simpa only [result.2, published.source_spec] using hsourceRoot

/-- Query-independent source provenance with the additional no-invented-root
property. It forgets directly to the earlier `SourceData` query interface. -/
structure CertifiedSource (m : Model P C A ℕ) (interpret : P →* F[X])
    (chain : List (Chain.Stamp F A)) (c : F) (view : EvidenceQuery.BucketView F A) extends
    EvidenceQuery.SourceData m interpret chain c view where
  divides : view.bucket.contents ∣ interpret accumulator

/-- Strengthen the existing source data using actual routed-intake factor
provenance. No public-query interface or runtime source field is changed. -/
def CertifiedSource.ofIntake {m : Model P C A ℕ} {interpret : P →* F[X]}
    {chain : List (Chain.Stamp F A)} {c r : F} {view : EvidenceQuery.BucketView F A}
    {bits : List Bool} {s : SourceSealing.RootIntake F A}
    {nextStampSpec : A → ℕ → F[X] → A}
    (source : EvidenceQuery.SourceData m interpret chain c view)
    (hintake : RoutedIntakes.Derivable nextStampSpec c r bits s view.bucket.contents)
    (hpoly : s.contents = interpret source.accumulator) : CertifiedSource m interpret chain c view :=
  ⟨source, hpoly ▸ hintake.contents_dvd_source⟩

def CertifiedSource.publicationOrBreak {m : Model P C A ℕ} {interpret : P →* F[X]}
    {chain : List (Chain.Stamp F A)} {c : F} {view : EvidenceQuery.BucketView F A}
    (source : CertifiedSource m interpret chain c view) (value : F)
    (hroot : view.bucket.contents.eval value = 0) :
    Chain.published chain view.bucket.epoch value ⊕' ObservedBreak m := by
  cases Tachyon.BucketPublication.publicationOrBreak m interpret source.source source.published source.previous source.realPrevious
      source.opens source.real_opens source.sealed_endpoint source.accepted_endpoint source.divides hroot with
  | inl proof => exact .inl proof
  | inr witness => exact .inr ⟨_, _, witness⟩

end Tachyon.BucketPublication
