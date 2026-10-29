import Tachyon.ProfileQuery

/-!
# Routing and merging epoch intakes in either order

Builders may split each source segment before merging adjacent intakes with
the same profile. A single `Qr.Route` from a complete epoch source does not
directly represent that construction order. `Derivable` below models both
descent and same-profile merge, while retaining a ghost root-source header.
`source_run` proves that the ghost source absorbs the same stamp polynomials;
`retains` proves that every matching source root remains in the routed intake.

`CheckedIntake.complete` combines this provenance with source sealing and the
profile-mask/class checks. It supplies target-specific query completeness for
the profile-aware spendable model, including builders that route and merge in
arbitrary order. It makes no claim that a child contains only its own class.
-/

namespace Tachyon.RoutedIntakes

open Polynomial

variable {F A : Type*} [Field F]

theorem matches_append (r v : F) (pre suf : List Bool) :
    Qr.MatchesProfile r v (pre ++ suf) ↔
      Qr.MatchesProfile r v pre ∧
        Qr.MatchesProfile (r + (pre.length : F)) v suf := by
  induction pre generalizing r with
  | nil => simp [Qr.MatchesProfile]
  | cons bit rest ih =>
    simp [Qr.MatchesProfile, ih, Nat.cast_add, Nat.cast_one, add_comm, add_left_comm,
      and_assoc]

/-- `source` records the unrouted segment; the final polynomial is the actual
routed intake. Common first discriminant and profile are enforced by indices. -/
inductive Derivable (nextStamp : A → ℕ → F[X] → A) (c r : F) :
    List Bool → SourceSealing.RootIntake F A → F[X] → Prop
  | root {s : SourceSealing.RootIntake F A} :
      SourceSealing.RootIntakeDerivable nextStamp s → Derivable nextStamp c r [] s s.contents
  | merge {bits : List Bool} {left right : SourceSealing.RootIntake F A} {lp rp : F[X]} :
      Derivable nextStamp c r bits left lp → Derivable nextStamp c r bits right rp →
      left.epoch = right.epoch → left.finish = right.start →
      Derivable nextStamp c r bits
        ⟨left.epoch, left.start, right.finish, left.contents * right.contents⟩ (lp * rp)
  | descend {bits : List Bool} {source : SourceSealing.RootIntake F A}
      {parent u q : F[X]} {bit : Bool} (s : Qr.Split parent (r + (bits.length : F))) :
      Derivable nextStamp c r bits source parent → Qr.SideCheck c s bit u q →
      Derivable nextStamp c r (bits ++ [bit]) source (s.selected bit)

variable {nextStamp : A → ℕ → F[X] → A} {nextEpoch : A → ℕ → A} {c r : F}

/-- Routing never changes source extent or its anchor-bound polynomial product. -/
theorem Derivable.source_run {bits : List Bool} {s : SourceSealing.RootIntake F A}
    {contents : F[X]} (h : Derivable nextStamp c r bits s contents) :
    SourceSealing.Run nextStamp s.epoch s.start s.finish s.contents := by
  induction h with
  | root hs => exact hs.run
  | merge _ _ hepoch hjoin ihl ihr =>
    rw [← hepoch, ← hjoin] at ihr
    exact ihl.concat ihr
  | descend _ _ _ ih => exact ih

/-- Arbitrary interleavings of routing and adjacent same-profile merges retain
every source root that matches the full profile. -/
theorem Derivable.retains (hc : ¬ IsSquare c) {bits : List Bool}
    {s : SourceSealing.RootIntake F A} {contents : F[X]}
    (h : Derivable nextStamp c r bits s contents) {v : F}
    (hmatch : Qr.MatchesProfile r v bits) (hroot : s.contents.eval v = 0) :
    contents.eval v = 0 := by
  induction h with
  | root => exact hroot
  | merge _ _ _ _ ihl ihr =>
    dsimp only at hroot
    rw [eval_mul] at hroot ⊢
    rcases mul_eq_zero.mp hroot with hl | hr
    · rw [ihl hmatch hl, zero_mul]
    · rw [ihr hmatch hr, mul_zero]
  | descend split _ hside ih =>
    obtain ⟨hprefix, hlast⟩ := (matches_append _ _ _ _).mp hmatch
    exact hside.retains hc hlast.1 (ih hprefix hroot)

/-- A concrete bucket query with source provenance, accepted seal, and actual
profile-check equations. `realPrev` identifies the accepted epoch entry. -/
structure CheckedIntake (chain : List (Chain.Stamp F A))
    (nextStamp : A → ℕ → F[X] → A) (nextEpoch : A → ℕ → A) (c : F)
    (b : QrBucket F A) (v : F) where
  firstDiscriminant : F
  profile : List Bool
  source : SourceSealing.RootIntake F A
  realPrev : A
  derivation : Derivable nextStamp c firstDiscriminant profile source b.contents
  epoch : source.epoch = b.epoch
  opens : ∃ prev, source.start = nextEpoch prev source.epoch
  sealed_endpoint : b.anchor_next = nextEpoch source.finish (source.epoch + 1)
  accepted : b.anchor_next = nextEpoch
    (SourceSealing.epochEnd nextStamp b.epoch (nextEpoch realPrev b.epoch)
      (SourceSealing.epochPublications chain b.epoch)) (b.epoch + 1)
  profileCheck : ProfileQuery.QueryCheck c firstDiscriminant v profile

/-- All source publications matching the queried class remain roots of the
bucket, even when routing precedes merges. -/
theorem CheckedIntake.complete {genesis : A} {e₀ : ℕ}
    (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch) (hc : ¬ IsSquare c)
    {chain : List (Chain.Stamp F A)} {b : QrBucket F A} {v : F}
    (h : CheckedIntake chain nextStamp nextEpoch c b v) : Profiled.QueryComplete chain b v := by
  have hrun := h.derivation.source_run
  have hpoly := hrun.sealed_source_eq hlaw h.opens
    (h.sealed_endpoint.symm.trans (by simpa only [h.epoch] using h.accepted))
  intro hpub
  apply h.derivation.retains hc (h.profileCheck.matches hc)
  rw [hpoly]
  exact SourceSealing.sourcePoly_complete chain b.epoch v hpub

/-- Checked intakes discharge the profile-aware lineage's query-completeness
premise. The original header types and their anchor-threading clients remain
unchanged, through `Profiled.SpendableDerivable.forget`. -/
theorem lineage_of_checked_intakes {genesis : A} {e₀ : ℕ}
    (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch) (hc : ¬ IsSquare c)
    {chain : List (Chain.Stamp F A)} {ValidBucket : QrBucket F A → Prop} {nf : F → ℕ → F}
    {start : ℕ} {sp : NoteSpendable F A}
    (hsp : Profiled.SpendableDerivable ValidBucket
      (fun b v => Nonempty (CheckedIntake chain nextStamp nextEpoch c b v)) nf nextStamp start sp) :
    start ≤ sp.epoch_current ∧
      ∀ x, start ≤ x → x < sp.epoch_current → ¬ Chain.published chain x (nf sp.cm x) := by
  apply hsp.lineage
  intro b v _ hquery
  obtain ⟨h⟩ := hquery
  exact h.complete hlaw hc

end Tachyon.RoutedIntakes
