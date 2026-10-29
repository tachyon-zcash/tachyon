import Mathlib.Algebra.BigOperators.Intervals
import Mathlib.Algebra.BigOperators.Ring.Finset
import Mathlib.Data.Finset.Sort
import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic.Linarith
import Mathlib.Tactic.Ring

/-!
# The QR profile mask is a prefix

`enforce_value_profile` (`crates/tachyon/src/stamp/proof/qr.rs`) uses a fixed-width
boolean mask. If its weight is `d` and twice the sum of selected indices is
`d * (d - 1)`, only indices `0, ..., d-1` can be selected.

A `Finset ℕ` models the selected positions of a boolean mask; repeated positions
are impossible. `eq_range_of_min_sum` proves the integer statement.
`eq_range_of_field_checks` justifies the passage from modular checks to integer
equalities with explicit width, canonical-depth and no-wrap bounds. No boolean
constraint or range check is inferred from an unconstrained field witness.
-/

namespace Tachyon.ProfileMask

open Finset
open scoped BigOperators

/-- Among sets of `d` distinct nonnegative indices, the prefix has the unique
minimum index sum. The proof compares the missing and excess positions. -/
theorem eq_range_of_equal_sum (s : Finset ℕ) (d : ℕ) (hcard : s.card = d)
    (hsum : ∑ i ∈ s, i = ∑ i ∈ range d, i) : s = range d := by
  have hcount : (s \ range d).card = (range d \ s).card := by
    apply card_sdiff_comm
    simpa using hcard
  by_contra hne
  have hexcess : (s \ range d).Nonempty := by
    by_contra hn
    have hsub : s ⊆ range d := sdiff_eq_empty_iff_subset.mp (not_nonempty_iff_eq_empty.mp hn)
    exact hne (eq_of_subset_of_card_le hsub (by simpa using hcard.symm.le))
  have hmissing : (range d \ s).Nonempty := by
    rw [← card_pos, ← hcount]
    exact card_pos.mpr hexcess
  have hlow : d * (s \ range d).card ≤ ∑ i ∈ s \ range d, i := by
    calc
      _ = ∑ _i ∈ s \ range d, d := by simp [mul_comm]
      _ ≤ _ := sum_le_sum fun i hi => by
        have hnot := (mem_sdiff.mp hi).2
        simpa using hnot
  have hhigh : (∑ i ∈ range d \ s, i) < d * (range d \ s).card := by
    obtain ⟨i, hi⟩ := hmissing
    calc
      _ < ∑ _i ∈ range d \ s, d := by
        apply sum_lt_sum
        · intro j hj
          exact (mem_range.mp (mem_sdiff.mp hj).1).le
        · exact ⟨i, hi, mem_range.mp (mem_sdiff.mp hi).1⟩
      _ = _ := by simp [mul_comm]
  have hleft := sum_inter_add_sum_diff s (range d) (fun i => i)
  have hright := sum_inter_add_sum_diff (range d) s (fun i => i)
  rw [inter_comm (range d) s] at hright
  rw [hcount] at hlow
  omega

/-- The two integer mask checks force the prefix, including depth zero. -/
theorem eq_range_of_min_sum (s : Finset ℕ) (d : ℕ) (hcard : s.card = d)
    (hsum : 2 * (∑ i ∈ s, i) = d * (d - 1)) : s = range d := by
  apply eq_range_of_equal_sum s d hcard
  have hprefix := sum_range_id_mul_two d
  omega

/-- Modular equalities between values below the modulus are integer equalities. -/
theorem nat_eq_of_cast_eq {p a b : ℕ} (ha : a < p) (hb : b < p)
    (h : (a : ZMod p) = (b : ZMod p)) : a = b := by
  have hm := (ZMod.natCast_eq_natCast_iff' a b p).mp h
  simpa [Nat.mod_eq_of_lt ha, Nat.mod_eq_of_lt hb] using hm

/-- A conservative width bound excludes modular wraparound in both mask sums.
The modulus need not be prime for this arithmetic implication. -/
theorem eq_range_of_field_checks (s : Finset ℕ) (width d p : ℕ)
    (hwidth : s ⊆ range width) (hd : d < p) (hp : 2 * width * width + 1 < p)
    (hweight : (s.card : ZMod p) = (d : ZMod p))
    (hindex : (2 : ZMod p) * (∑ i ∈ s, (i : ZMod p)) =
      (d : ZMod p) * ((d : ZMod p) - 1)) : s = range d := by
  have hcard_le : s.card ≤ width := by simpa using card_le_card hwidth
  have hcard_lt : s.card < p := by nlinarith
  have hcard : s.card = d := nat_eq_of_cast_eq hcard_lt hd hweight
  have hsum_le : (∑ i ∈ s, i) ≤ width * width := by
    calc
      _ ≤ ∑ _i ∈ s, width := sum_le_sum fun i hi => (mem_range.mp (hwidth hi)).le
      _ = s.card * width := by simp
      _ ≤ width * width := Nat.mul_le_mul_right width hcard_le
  apply eq_range_of_min_sum s d hcard
  have hlhs : 2 * (∑ i ∈ s, i) < p := by nlinarith
  have hd_le : d ≤ width := hcard ▸ hcard_le
  have hrhs : d * (d - 1) < p := by
    have hm := Nat.mul_le_mul hd_le (Nat.sub_le d 1 |>.trans hd_le)
    nlinarith
  apply nat_eq_of_cast_eq hlhs hrhs
  cases d with
  | zero => simpa only [Nat.cast_mul, Nat.cast_ofNat, Nat.cast_sum, Nat.cast_zero,
      zero_mul] using hindex
  | succ d =>
    simpa only [Nat.cast_mul, Nat.cast_ofNat, Nat.cast_sum, Nat.cast_sub (Nat.succ_pos d),
      Nat.cast_one] using hindex

/-- Class bits selected in increasing position order. -/
def selectedBits (s : Finset ℕ) (classes : ℕ → Bool) : List Bool :=
  (s.sort).map classes

/-- The mask checks therefore select exactly the first `d` class bits, in the
same order as the fixed-width loop. -/
theorem selectedBits_eq_prefix (s : Finset ℕ) (d : ℕ) (classes : ℕ → Bool)
    (hcard : s.card = d) (hsum : 2 * (∑ i ∈ s, i) = d * (d - 1)) :
    selectedBits s classes = (List.range d).map classes := by
  rw [selectedBits, eq_range_of_min_sum s d hcard hsum, sort_range]

/-- One iteration of the circuit's bit accumulator `a + m * (a + b)`. -/
def accumulate (a : ℕ) (selected bit : Bool) : ℕ :=
  a + selected.toNat * (a + bit.toNat)

theorem accumulate_eq (a : ℕ) (selected bit : Bool) :
    accumulate a selected bit = if selected then 2 * a + bit.toNat else a := by
  cases selected <;> simp [accumulate, two_mul, add_assoc]

/-- The final packed profile after visiting the selected positions. -/
def packedProfile (s : Finset ℕ) (classes : ℕ → Bool) : ℕ :=
  (selectedBits s classes).foldl (fun a bit => accumulate a true bit) 0

theorem packedProfile_eq_prefix (s : Finset ℕ) (d : ℕ) (classes : ℕ → Bool)
    (hcard : s.card = d) (hsum : 2 * (∑ i ∈ s, i) = d * (d - 1)) :
    packedProfile s classes =
      ((List.range d).map classes).foldl (fun a bit => 2 * a + bit.toNat) 0 := by
  simp only [packedProfile, selectedBits_eq_prefix s d classes hcard hsum, accumulate_eq, ite_true]

/-- Visiting unselected positions has no effect on the register. This is the
loop recurrence, before replacing the selected positions by the proven prefix. -/
def scan : List (Bool × Bool) → ℕ → ℕ
  | [], a => a
  | (selected, bit) :: rest, a => scan rest (accumulate a selected bit)

theorem scan_eq_selected_fold (entries : List (Bool × Bool)) (a : ℕ) :
    scan entries a =
      (entries.filterMap fun entry => if entry.1 then some entry.2 else none).foldl
        (fun acc bit => 2 * acc + bit.toNat) a := by
  induction entries generalizing a with
  | nil => rfl
  | cons entry rest ih =>
    rcases entry with ⟨selected, bit⟩
    cases selected <;> simp [scan, accumulate_eq, ih]

/-- Packing `n` booleans into a register starting at `a` stays below
`2^n * (a+1)`. In particular the zero-initialized 32-bit profile is below `2^32`. -/
theorem fold_bits_lt (bits : List Bool) (a : ℕ) :
    bits.foldl (fun acc bit => 2 * acc + bit.toNat) a < 2 ^ bits.length * (a + 1) := by
  induction bits generalizing a with
  | nil => simp
  | cons bit rest ih =>
    simp only [List.foldl_cons, List.length_cons, pow_succ]
    calc
      _ < 2 ^ rest.length * (2 * a + bit.toNat + 1) := ih _
      _ ≤ 2 ^ rest.length * 2 * (a + 1) := by
        have hb : bit.toNat ≤ 1 := by cases bit <;> decide
        calc
          _ ≤ 2 ^ rest.length * (2 * (a + 1)) := Nat.mul_le_mul_left _ (by omega)
          _ = _ := by ring

theorem packedProfile_lt (s : Finset ℕ) (classes : ℕ → Bool) :
    packedProfile s classes < 2 ^ s.card := by
  have h := fold_bits_lt (selectedBits s classes) 0
  simpa [packedProfile, accumulate_eq, selectedBits] using h

/-- The final field equality pins the packed integer profile when both the
register and the public profile encoding are below the modulus. -/
theorem packedProfile_eq_of_cast_eq (s : Finset ℕ) (classes : ℕ → Bool) (p bits : ℕ)
    (hp : 2 ^ s.card ≤ p) (hbits : bits < p)
    (hcheck : (packedProfile s classes : ZMod p) = (bits : ZMod p)) :
    packedProfile s classes = bits :=
  nat_eq_of_cast_eq ((packedProfile_lt s classes).trans_le hp) hbits hcheck

/-- Without a no-wrap bound, the field checks need not force a prefix. Over
modulus two, selecting position one at depth one satisfies both equations. -/
theorem small_modulus_accepts_nonprefix :
    let s : Finset ℕ := {1}
    (s.card : ZMod 2) = 1 ∧
      (2 : ZMod 2) * (∑ i ∈ s, (i : ZMod 2)) = 1 * (1 - 1) ∧
      s ≠ range 1 := by
  decide

end Tachyon.ProfileMask
