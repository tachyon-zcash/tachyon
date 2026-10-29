import Tachyon.ProfileMask
import Tachyon.SourceSealing
import Mathlib.Data.Nat.Digits.Defs

/-!
# Profile checks imply the routed query's matching-profile premise

`ClassCheck` states the scalar equations in `enforce_value_profile`, after
boolean selection: `root² = (if bit then 1 else c) * (v+r)`, with the non-residue
side forbidden at zero. Its class bit therefore agrees with `Qr.Matches`.

The packed register is injective on boolean lists of a fixed length, including
leading zeros. `matches_of_field_checks` combines this fact with the mask-prefix
and no-wrap bounds from `ProfileMask`: equality of the checked packed register
and the bucket profile forces the entire profile to match the queried value.

The result feeds directly into source sealing's routed-query certificate.
This uses genuine booleans, canonical depth, explicit arithmetic bounds, and
the same modulus for the mask register checks. It does not derive those range
or boolean constraints from untyped field witnesses.
-/

namespace Tachyon.ProfileQuery

open Polynomial

variable {F : Type*} [Field F]

/-- A single boolean-selected class row of `enforce_value_profile`. -/
def ClassCheck (c r v : F) (bit : Bool) (root : F) : Prop :=
  root ^ 2 = (if bit then 1 else c) * (v + r) ∧ (if bit then 1 else v + r) ≠ 0

theorem ClassCheck.matches {c r v root : F} {bit : Bool} (hc : ¬ IsSquare c)
    (h : ClassCheck c r v bit root) : Qr.Matches r v bit := by
  cases bit with
  | false =>
    intro hsq
    exact Qr.not_square_mul hc h.2 hsq ((isSquare_iff_exists_sq _).mpr ⟨root, h.1.symm⟩)
  | true =>
    exact (isSquare_iff_exists_sq _).mpr ⟨root, by simpa using h.1.symm⟩

/-- Each row has its witnessed class root at consecutive discriminants. -/
def ClassChecks (c r v : F) : List Bool → Prop
  | [] => True
  | bit :: rest => (∃ root, ClassCheck c r v bit root) ∧ ClassChecks c (r + 1) v rest

theorem ClassChecks.matches {c r v : F} {bits : List Bool} (hc : ¬ IsSquare c)
    (h : ClassChecks c r v bits) : Qr.MatchesProfile r v bits := by
  induction bits generalizing r with
  | nil => trivial
  | cons bit rest ih =>
    obtain ⟨⟨root, hroot⟩, hrest⟩ := h
    exact ⟨hroot.matches hc, ih hrest⟩

/-- All fixed-width rows may be checked, while only a prefix is compared with
the bucket profile. Checks after that prefix do not affect this implication. -/
theorem ClassChecks.take {c r v : F} {bits : List Bool}
    (h : ClassChecks c r v bits) (n : ℕ) : ClassChecks c r v (bits.take n) := by
  induction bits generalizing r n with
  | nil => simp [ClassChecks]
  | cons bit rest ih =>
    cases n with
    | zero => trivial
    | succ n => exact ⟨h.1, ih h.2 n⟩

/-- Big-endian packing, matching the circuit's `a := 2*a + bit` update. -/
def pack (bits : List Bool) : ℕ :=
  bits.foldl (fun a bit => 2 * a + bit.toNat) 0

theorem fold_eq_ofDigits (bits : List Bool) (a : ℕ) :
    bits.foldl (fun acc bit => 2 * acc + bit.toNat) a =
      a * 2 ^ bits.length + Nat.ofDigits 2 (bits.reverse.map Bool.toNat) := by
  induction bits generalizing a with
  | nil => simp
  | cons bit rest ih =>
    simp only [List.foldl_cons, ih, List.length_cons, pow_succ, List.reverse_cons,
      List.map_append, List.map_singleton, Nat.ofDigits_append, Nat.ofDigits_singleton,
      List.length_map, List.length_reverse]
    ring

/-- A fixed depth makes even profiles with leading zeros unambiguous. -/
theorem pack_injective_of_length_eq {left right : List Bool}
    (hlen : left.length = right.length) (hpack : pack left = pack right) : left = right := by
  have hdigits : Nat.ofDigits 2 (left.reverse.map Bool.toNat) =
      Nat.ofDigits 2 (right.reverse.map Bool.toNat) := by
    simpa [pack, fold_eq_ofDigits] using hpack
  have hnat := Nat.ofDigits_inj_of_len_eq (by decide : 1 < 2)
    (by simpa using hlen)
    (by rintro n hn; obtain ⟨b, _, rfl⟩ := List.mem_map.mp hn; cases b <;> decide)
    (by rintro n hn; obtain ⟨b, _, rfl⟩ := List.mem_map.mp hn; cases b <;> decide) hdigits
  have hbool : Function.Injective Bool.toNat := by
    intro a b h
    cases a <;> cases b <;> simp_all
  exact List.reverse_injective (hbool.list_map hnat)

/-- A bucket profile with the checked depth and packed value is exactly the
selected class prefix, hence matches the query at every routed discriminant. -/
theorem matches_of_field_checks {c r v : F} (hc : ¬ IsSquare c)
    (s : Finset ℕ) (width d p : ℕ) (classes : ℕ → Bool) (bits : List Bool)
    (hwidth : s ⊆ Finset.range width) (hd : d < p)
    (hp : 2 * width * width + 1 < p) (hpackbound : 2 ^ d ≤ p)
    (hweight : (s.card : ZMod p) = (d : ZMod p))
    (hindex : (2 : ZMod p) * (∑ i ∈ s, (i : ZMod p)) =
      (d : ZMod p) * ((d : ZMod p) - 1))
    (hlen : bits.length = d)
    (hpacked : (pack bits : ZMod p) = (ProfileMask.packedProfile s classes : ZMod p))
    (hclasses : ClassChecks c r v ((List.range d).map classes)) :
    Qr.MatchesProfile r v bits := by
  have hs := ProfileMask.eq_range_of_field_checks s width d p hwidth hd hp hweight hindex
  have hcard : s.card = d := by simp [hs]
  have hprefix : ProfileMask.packedProfile s classes = pack ((List.range d).map classes) := by
    simp [ProfileMask.packedProfile, ProfileMask.selectedBits, hs, Finset.sort_range,
      ProfileMask.accumulate_eq, pack]
  have hleft : pack bits < p := by
    have hbound : pack bits < 2 ^ d := by
      simpa [pack, hlen] using ProfileMask.fold_bits_lt bits 0
    exact hbound.trans_le hpackbound
  have hright : ProfileMask.packedProfile s classes < p :=
    (ProfileMask.packedProfile_lt s classes).trans_le (hcard ▸ hpackbound)
  have heq := ProfileMask.nat_eq_of_cast_eq hleft hright hpacked
  rw [hprefix] at heq
  have hbits := pack_injective_of_length_eq (by simpa using hlen) heq
  rw [hbits]
  exact hclasses.matches hc

/-- The explicit mask/register and class-row obligations for a bucket query.
These are checked equations and range premises, not a matching-profile axiom. -/
structure QueryCheck (c r v : F) (bits : List Bool) where
  mask : Finset ℕ
  width : ℕ
  depth : ℕ
  modulus : ℕ
  classes : ℕ → Bool
  mask_bound : mask ⊆ Finset.range width
  depth_canonical : depth < modulus
  sums_no_wrap : 2 * width * width + 1 < modulus
  packing_no_wrap : 2 ^ depth ≤ modulus
  weight : (mask.card : ZMod modulus) = (depth : ZMod modulus)
  index_sum : (2 : ZMod modulus) * (∑ i ∈ mask, (i : ZMod modulus)) =
    (depth : ZMod modulus) * ((depth : ZMod modulus) - 1)
  profile_depth : bits.length = depth
  packed : (pack bits : ZMod modulus) = (ProfileMask.packedProfile mask classes : ZMod modulus)
  class_rows : ClassChecks c r v ((List.range depth).map classes)

theorem QueryCheck.matches {c r v : F} {bits : List Bool} (hc : ¬ IsSquare c)
    (h : QueryCheck c r v bits) : Qr.MatchesProfile r v bits :=
  matches_of_field_checks hc h.mask h.width h.depth h.modulus h.classes bits h.mask_bound
    h.depth_canonical h.sums_no_wrap h.packing_no_wrap h.weight h.index_sum
    h.profile_depth h.packed h.class_rows

/-- Checked scalar rows, mask/register equations, routing and the accepted
source seal together supply a routed-query certificate. Neither source
completeness nor profile matching is assumed as a separate premise. -/
theorem routedQuery_of_checks_and_seal {A : Type*} {genesis : A} {e₀ : ℕ}
    {nextStamp : A → ℕ → F[X] → A} {nextEpoch : A → ℕ → A}
    (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    {chain : List (Chain.Stamp F A)} {s : SourceSealing.RootIntake F A} {b : QrBucket F A}
    {c r v : F} {realPrev : A} {bits : List Bool} (hc : ¬ IsSquare c)
    (hsource : SourceSealing.RootIntakeDerivable nextStamp s) (hepoch : s.epoch = b.epoch)
    (hopen : ∃ prev, s.start = nextEpoch prev s.epoch)
    (hseal : b.anchor_next = nextEpoch s.finish (s.epoch + 1))
    (haccepted : b.anchor_next = nextEpoch
      (SourceSealing.epochEnd nextStamp b.epoch (nextEpoch realPrev b.epoch)
        (SourceSealing.epochPublications chain b.epoch)) (b.epoch + 1))
    (hroute : Qr.Route c r s.contents bits b.contents) (hcheck : QueryCheck c r v bits) :
    Profiled.RoutedQuery chain c b v :=
  hsource.routedQuery hlaw hepoch hopen hseal haccepted hroute (hcheck.matches hc)

end Tachyon.ProfileQuery
