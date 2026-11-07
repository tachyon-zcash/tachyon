import Mathlib.Data.Nat.Digits.Lemmas
import Mathlib.Algebra.GroupWithZero.Action.Defs
import Mathlib.Tactic

/-!
# Private fixed-base certificates

The arithmetic interpretation of `stamp/proof/scale.rs`. Natural numbers are canonical
integer encodings, not circuit-field residues. `Word` is the ordered radix-8 view of
the 255 Boolean bits: in particular window 42 crosses the 128-bit limb boundary.
The circuit correspondence requires Boolean allocation, injective limb recomposition,
and the coordinate selectors/complete-add gadget. No certificate equation is an axiom.
-/

namespace Tachyon.FixedBase

variable {H : Type*} [AddCommGroup H]

structure Limbs where
  lo : ℕ
  hi : ℕ
  deriving DecidableEq

def Limbs.value (s : Limbs) : ℕ := s.lo + 2 ^ 128 * s.hi

def Limbs.canonical (q : ℕ) (s : Limbs) : Prop :=
  s.lo < 2 ^ 128 ∧ s.hi < 2 ^ 127 ∧ s.value < q

def split (s : ℕ) : Limbs := ⟨s % 2 ^ 128, s / 2 ^ 128⟩

@[simp] theorem split_value (s : ℕ) : (split s).value = s := Nat.mod_add_div _ _

theorem limbs_injective {a b : Limbs} (ha : a.lo < 2 ^ 128) (hb : b.lo < 2 ^ 128)
    (h : a.value = b.value) : a = b := by
  have hlo : a.lo = b.lo := by
    have := congrArg (· % 2 ^ 128) h
    simp only [Limbs.value, Nat.add_mul_mod_self_left] at this
    rwa [Nat.mod_eq_of_lt ha, Nat.mod_eq_of_lt hb] at this
  have hhi : a.hi = b.hi := by
    dsimp [Limbs.value] at h
    rw [hlo] at h
    exact Nat.eq_of_mul_eq_mul_left (by decide : 0 < 2 ^ 128) (Nat.add_left_cancel h)
  cases a; cases b; simp_all

/-- Both integer limbs are compared, never only the recomposed Fp residue. -/
theorem exact_limb_match {a b : Limbs} (hlo : a.lo = b.lo) (hhi : a.hi = b.hi) :
    a.value = b.value := by simp [Limbs.value, hlo, hhi]

structure Word (n : ℕ) where
  digits : List ℕ
  length_eq : digits.length = n
  bounded : ∀ d ∈ digits, d < 8

def Word.value {n : ℕ} (w : Word n) : ℕ := Nat.ofDigits 8 w.digits

theorem Word.value_lt {n : ℕ} (w : Word n) : w.value < 8 ^ n := by
  simpa [Word.value, w.length_eq] using Nat.ofDigits_lt_base_pow_length (by decide : 1 < 8) w.bounded

theorem Word.digits_eq {n : ℕ} {a b : Word n} (h : a.value = b.value) : a.digits = b.digits :=
  Nat.injOn_ofDigits (by decide : 1 < 8) n ⟨a.length_eq, a.bounded⟩
    ⟨b.length_eq, b.bounded⟩ h

def wordOf (n s : ℕ) (hs : s < 8 ^ n) : Word n :=
  ⟨Nat.digitsAppend 8 n s, Nat.length_digitsAppend (by decide) n hs,
    fun d h => Nat.lt_of_mem_digitsAppend (by decide : 1 < 8) n d h⟩

@[simp] theorem wordOf_value (n s : ℕ) (hs : s < 8 ^ n) : (wordOf n s hs).value = s := by
  simp [wordOf, Word.value, Nat.digitsAppend, Nat.ofDigits_append_replicate_zero,
    Nat.ofDigits_digits]

/-- Native table entries, including the zero digit, in the complete group. -/
def table (B : H) (j d : ℕ) : H := (d * 8 ^ j) • B

/-- The fixed binary selector uses the same three Boolean bits for both coordinates. -/
def digit (a b c : Bool) : ℕ := a.toNat + 2 * b.toNat + 4 * c.toNat

theorem digit_bound (a b c : Bool) : digit a b c < 8 := by
  cases a <;> cases b <;> cases c <;> decide

theorem zero_digit (a b c : Bool) : digit a b c = 0 ↔ a = false ∧ b = false ∧ c = false := by
  cases a <;> cases b <;> cases c <;> decide

def select8 {X : Type*} (row : Fin 8 → X) (a b c : Bool) : X :=
  if c then (if b then (if a then row 7 else row 6) else (if a then row 5 else row 4))
  else (if b then (if a then row 3 else row 2) else (if a then row 1 else row 0))

/-- Applies independently to x and y; it does not assume a witnessed lookup. -/
theorem select8_correct {X : Type*} (row : Fin 8 → X) (a b c : Bool) :
    select8 row a b c = row ⟨digit a b c, digit_bound a b c⟩ := by
  cases a <;> cases b <;> cases c <;> rfl

theorem table_zero (B : H) (j : ℕ) : table B j 0 = 0 := by simp [table]

theorem table_successor (B : H) (j d : ℕ) :
    table B j (d + 1) = table B j d + (8 ^ j) • B := by
  simp [table, add_mul, add_nsmul]

/-- The bit-to-limb encoding is injective at its integer interpretation. Its
field interpretation additionally needs each limb range to be below p. -/
theorem boolean_recomposition_injective {a b : List ℕ}
    (ha : a.length = 255 ∧ ∀ x ∈ a, x < 2)
    (hb : b.length = 255 ∧ ∀ x ∈ b, x < 2)
    (h : Nat.ofDigits 2 a = Nat.ofDigits 2 b) : a = b :=
  Nat.injOn_ofDigits (by decide : 1 < 2) 255 ha hb h

theorem hash_limb_match (hash : ℕ) (s : Limbs) (h : s = split hash) : s.value = hash := by
  rw [h, split_value]

/-- Sum of the actual fixed-table selections, not a freely witnessed product. -/
def windows (B : H) : ℕ → List ℕ → H
  | _, [] => 0
  | j, d :: ds => table B j d + windows B (j + 1) ds

theorem windows_correct (B : H) (ds : List ℕ) (j : ℕ) :
    windows B j ds = (8 ^ j * Nat.ofDigits 8 ds) • B := by
  induction ds generalizing j with
  | nil => simp [windows]
  | cons d ds ih =>
      rw [windows, ih, Nat.ofDigits_cons, mul_add, add_nsmul]
      simp only [table, pow_succ]
      congr 1 <;> congr 1 <;> ring

def partialSum (B : H) (w : Word 85) (k : ℕ) : H := windows B 0 (w.digits.take k)

theorem prefix_end (B : H) (w : Word 85) : partialSum B w 85 = w.value • B := by
  have ht : w.digits.take 85 = w.digits := List.take_of_length_le (by rw [w.length_eq])
  simp [partialSum, windows_correct, ht, Word.value]

/-- A finite carrier plus a Boolean tag. The sentinel with tag false is itself. -/
structure Tagged (H : Type*) where
  carrier : H
  identity : Bool

def Tagged.Valid (J : H) (t : Tagged H) : Prop :=
  t.carrier ≠ 0 ∧ (t.identity = true → t.carrier = J)

def Tagged.decode (t : Tagged H) : H := if t.identity then 0 else t.carrier

def encode [DecidableEq H] (J P : H) : Tagged H := if P = 0 then ⟨J, true⟩ else ⟨P, false⟩

@[simp] theorem decode_encode [DecidableEq H] (J P : H) : (encode J P).decode = P := by
  by_cases h : P = 0 <;> simp [encode, Tagged.decode, h]

theorem encode_valid [DecidableEq H] {J : H} (hJ : J ≠ 0) (P : H) :
    (encode J P).Valid J := by
  by_cases h : P = 0 <;> simp [encode, Tagged.Valid, h, hJ]

inductive Base | blind | action deriving DecidableEq
inductive Phase | start | middle | finish deriving DecidableEq

def boundary : Phase → ℕ | .start => 24 | .middle => 54 | .finish => 85

/-- These are the serialized suffixes in the pinned registry, not Rust type identity. -/
def suffix (b : Base) (p : Phase) : ℕ :=
  (match b with | .blind => 17 | .action => 20) +
  (match p with | .start => 0 | .middle => 1 | .finish => 2)

theorem suffix_injective {b c : Base} {p r : Phase} (h : suffix b p = suffix c r) :
    b = c ∧ p = r := by
  cases b <;> cases c <;> cases p <;> cases r <;> simp_all [suffix]

structure State (H : Type*) where
  scalar : Limbs
  point : Tagged H

/-- Idealized accepted PCDs. There is exactly one producer per authenticated suffix.
The witness's complete digit array is reconstructed at every stage; the two limb
equalities force its integer value, hence its digits, to equal the predecessor's. -/
inductive Accepted (bases : Base → H) (J : H) (q : ℕ) : Base → Phase → State H → Prop
  | start (b : Base) (w : Word 85) (s : State H) :
      s.scalar.canonical q → s.scalar.value = w.value → s.point.Valid J →
      s.point.decode = partialSum (bases b) w 24 → Accepted bases J q b .start s
  | middle {b : Base} {input : State H} (w : Word 85) (s : State H) :
      Accepted bases J q b .start input → input.scalar.value = w.value →
      s.scalar = input.scalar → s.point.Valid J →
      s.point.decode = input.point.decode + windows (bases b) 24 ((w.digits.drop 24).take 30) →
      Accepted bases J q b .middle s
  | finish {b : Base} {input : State H} (w : Word 85) (s : State H) :
      Accepted bases J q b .middle input → input.scalar.value = w.value →
      s.scalar = input.scalar → s.point.Valid J →
      s.point.decode = input.point.decode + windows (bases b) 54 (w.digits.drop 54) →
      Accepted bases J q b .finish s

theorem windows_append (B : H) (xs ys : List ℕ) (j : ℕ) :
    windows B j (xs ++ ys) = windows B j xs + windows B (j + xs.length) ys := by
  induction xs generalizing j with
  | nil => simp [windows]
  | cons x xs ih => simp [windows, ih, add_assoc, Nat.add_comm]

theorem prefix_middle (B : H) (w : Word 85) :
    partialSum B w 24 + windows B 24 ((w.digits.drop 24).take 30) = partialSum B w 54 := by
  have hlen : (w.digits.take 24).length = 24 := by simp [w.length_eq]
  have htake : w.digits.take 54 = w.digits.take 24 ++ (w.digits.drop 24).take 30 := by
    exact List.take_add (i := 24) (j := 30)
  rw [partialSum, partialSum, htake, windows_append, hlen, zero_add]

theorem prefix_finish (B : H) (w : Word 85) :
    partialSum B w 54 + windows B 54 (w.digits.drop 54) = partialSum B w 85 := by
  have hlen : (w.digits.take 54).length = 54 := by simp [w.length_eq]
  have htake : w.digits.take 85 = w.digits := List.take_of_length_le (by rw [w.length_eq])
  change windows B 0 (w.digits.take 54) + windows B 54 (w.digits.drop 54) = _
  have h := windows_append B (w.digits.take 54) (w.digits.drop 54) 0
  simpa [hlen, partialSum, htake] using h.symm

/-- Induction over the only registered producers establishes every stage boundary. -/
theorem Accepted.invariant {bases : Base → H} {J : H} {q : ℕ} {b : Base} {p : Phase}
    {s : State H} (h : Accepted bases J q b p s) :
    s.scalar.canonical q ∧ s.point.Valid J ∧
      ∃ w : Word 85, s.scalar.value = w.value ∧ s.point.decode = partialSum (bases b) w (boundary p) := by
  induction h with
  | start w s hc hv hp he => exact ⟨hc, hp, w, hv, he⟩
  | middle w s _ hv hs hp he ih =>
      obtain ⟨hc, _, v, hv', he'⟩ := ih
      have hd := Word.digits_eq (hv'.symm.trans hv)
      have hpref (B : H) : partialSum B v 24 = partialSum B w 24 := by simp [partialSum, hd]
      exact ⟨hs ▸ hc, hp, w, hs ▸ hv, by
        rw [he, he']; simp only [boundary]; rw [hpref]; exact prefix_middle _ w⟩
  | finish w s _ hv hs hp he ih =>
      obtain ⟨hc, _, v, hv', he'⟩ := ih
      have hd := Word.digits_eq (hv'.symm.trans hv)
      have hpref (B : H) : partialSum B v 54 = partialSum B w 54 := by simp [partialSum, hd]
      exact ⟨hs ▸ hc, hp, w, hs ▸ hv, by
        rw [he, he']; simp only [boundary]; rw [hpref]; exact prefix_finish _ w⟩

theorem Accepted.product {bases : Base → H} {J : H} {q : ℕ} {b : Base} {s : State H}
    (h : Accepted bases J q b .finish s) : s.point.decode = s.scalar.value • bases b := by
  obtain ⟨_, _, w, hv, hp⟩ := h.invariant
  simpa [boundary, prefix_end, hv] using hp

theorem canonical_width {q : ℕ} {s : Limbs} (h : s.canonical q) : s.value < 8 ^ 85 := by
  obtain ⟨hl, hh, _⟩ := h
  dsimp [Limbs.value]
  norm_num at hl hh ⊢
  omega

/-- Honest old scalar openings construct all three stages, including zero partials. -/
theorem Accepted.complete [DecidableEq H] {bases : Base → H} {J : H} (hJ : J ≠ 0)
    {q : ℕ} (b : Base) (s : State H) (hc : s.scalar.canonical q) (hp : s.point.Valid J)
    (he : s.point.decode = s.scalar.value • bases b) : Accepted bases J q b .finish s := by
  let w := wordOf 85 s.scalar.value (canonical_width hc)
  have hw : w.value = s.scalar.value := wordOf_value _ _ _
  let first : State H := ⟨s.scalar, encode J (partialSum (bases b) w 24)⟩
  let middle : State H := ⟨s.scalar, encode J (partialSum (bases b) w 54)⟩
  have hfirst : Accepted bases J q b .start first :=
    .start b w first hc hw.symm (encode_valid hJ _) (decode_encode _ _)
  have hmiddle : Accepted bases J q b .middle middle :=
    .middle w middle hfirst hw.symm rfl (encode_valid hJ _) (by
      dsimp [middle, first]; rw [decode_encode, decode_encode]; exact (prefix_middle _ w).symm)
  exact .finish w s hmiddle hw.symm rfl hp (by
    dsimp [middle]; rw [decode_encode, prefix_finish, prefix_end, hw]; exact he)

theorem accepted_iff [DecidableEq H] {bases : Base → H} {J : H} (hJ : J ≠ 0)
    {q : ℕ} {b : Base} {s : State H} :
    Accepted bases J q b .finish s ↔
      s.scalar.canonical q ∧ s.point.Valid J ∧ s.point.decode = s.scalar.value • bases b := by
  constructor
  · intro h; exact ⟨h.invariant.1, h.invariant.2.1, h.product⟩
  · rintro ⟨hc, hp, he⟩; exact Accepted.complete hJ b s hc hp he

/-- An authenticated result cannot skip Start or Middle, or change base. -/
theorem Accepted.unique_producer {bases : Base → H} {J : H} {q : ℕ} {b : Base} {s : State H}
    (h : Accepted bases J q b .finish s) :
    ∃ input, Accepted bases J q b .middle input ∧ s.scalar = input.scalar := by
  cases h with
  | finish _ _ h _ hs _ _ => exact ⟨_, h, hs⟩

/-- Substitution rule for semantic consumers. It retains all of the consumer's
other checks; the arithmetic input cannot absorb a free residual point. -/
theorem consumer_refinement [DecidableEq H] {bases : Base → H} {J : H} (hJ : J ≠ 0)
    {q : ℕ} (b : Base) (s : Limbs) (hc : s.canonical q) (consumer : H → Prop) :
    (∃ point, Accepted bases J q b .finish ⟨s, point⟩ ∧ consumer point.decode) ↔
      consumer (s.value • bases b) := by
  constructor
  · rintro ⟨point, h, hp⟩
    simpa [h.product] using hp
  · intro hp
    refine ⟨encode J (s.value • bases b), ?_, by simpa using hp⟩
    exact Accepted.complete hJ b _ hc (encode_valid hJ _) (decode_encode _ _)

/-- Bounded amount windows reuse the 51-bit range decomposition. Both signs are
obtained by choosing V or -V; there is no full-width amount certificate. -/
theorem amount_product (B : H) (w : Word 17) : windows B 0 w.digits = w.value • B := by
  simp [windows_correct, Word.value]

theorem amount_bound {v complement money : ℕ} (h : v + complement = money) : v ≤ money := by omega

end Tachyon.FixedBase
