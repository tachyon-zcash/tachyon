import Tachyon.StepBudget
import Tachyon.ScalarEncodings
import Tachyon.NoteValues
import Tachyon.PaidCreations

/-!
# Boolean windows, Pasta limbs, and accounting adapters

Refine the radix-8 integer/group model to the ordered Boolean decomposition.
Grouping is over the entire bit array: no padding is inserted at bit 128.
The Pasta bounds discharge the injectivity premises of both field-limb checks.
The final adapters supply the existing value/accounting reductions directly.
-/

namespace Tachyon.WindowEncodings

open FixedBase ScalarEncodings

def pack : List Bool → List ℕ
  | [] => []
  | [a] => [a.toNat]
  | [a, b] => [a.toNat + 2 * b.toNat]
  | a :: b :: c :: rest => digit a b c :: pack rest

theorem pack_value : ∀ bs : List Bool,
    Nat.ofDigits 8 (pack bs) = Nat.ofDigits 2 (bs.map Bool.toNat)
  | [] => rfl
  | [a] => by simp [pack]
  | [a, b] => by simp [pack, Nat.ofDigits_cons]
  | a :: b :: c :: rest => by
      rw [pack, Nat.ofDigits_cons, pack_value rest]
      simp only [List.map_cons, Nat.ofDigits_cons]
      dsimp [digit]
      ring

theorem pack_length : ∀ bs : List Bool, (pack bs).length = (bs.length + 2) / 3
  | [] => rfl
  | [a] => by simp [pack]
  | [a, b] => by simp [pack]
  | a :: b :: c :: rest => by
      simp only [pack, List.length_cons, pack_length rest]
      omega

theorem pack_bounded : ∀ bs : List Bool, ∀ d ∈ pack bs, d < 8
  | [] => by simp [pack]
  | [a] => by cases a <;> simp [pack]
  | [a, b] => by cases a <;> cases b <;> simp [pack]
  | a :: b :: c :: rest => by
      intro d hd
      simp only [pack, List.mem_cons] at hd
      rcases hd with rfl | hd
      · exact digit_bound a b c
      · exact pack_bounded rest d hd

def booleanWord (bs : List Bool) (hlen : bs.length = 255) : Word 85 :=
  ⟨pack bs, by rw [pack_length, hlen], pack_bounded bs⟩

theorem booleanWord_value (bs : List Bool) (hlen : bs.length = 255) :
    (booleanWord bs hlen).value = Nat.ofDigits 2 (bs.map Bool.toNat) := pack_value bs

def bitLimbs (bs : List Bool) : Limbs :=
  ⟨Nat.ofDigits 2 ((bs.take 128).map Bool.toNat), Nat.ofDigits 2 ((bs.drop 128).map Bool.toNat)⟩

theorem bitLimbs_value (bs : List Bool) (hlen : bs.length = 255) :
    (bitLimbs bs).value = Nat.ofDigits 2 (bs.map Bool.toNat) := by
  have h := Nat.ofDigits_append (b := 2)
    (l1 := (bs.take 128).map Bool.toNat) (l2 := (bs.drop 128).map Bool.toNat)
  simpa [hlen, ← List.map_append, bitLimbs, Limbs.value] using h.symm

/-- Windowing the whole ordered array agrees exactly with the unpadded 128/127
limb split. In particular, the triple at 126/127/128 belongs to one digit. -/
theorem cross_limb_window (bs : List Bool) (hlen : bs.length = 255) :
    (booleanWord bs hlen).value = (bitLimbs bs).lo + 2 ^ 128 * (bitLimbs bs).hi := by
  rw [booleanWord_value, ← bitLimbs_value bs hlen]
  rfl

theorem bitLimbs_bounds (bs : List Bool) (hlen : bs.length = 255) :
    (bitLimbs bs).lo < 2 ^ 128 ∧ (bitLimbs bs).hi < 2 ^ 127 := by
  have hb (xs : List Bool) : ∀ x ∈ xs.map Bool.toNat, x < 2 := by
    intro x hx
    obtain ⟨b, _, rfl⟩ := List.mem_map.mp hx
    cases b <;> decide
  constructor
  · simpa [bitLimbs, hlen] using Nat.ofDigits_lt_base_pow_length (by decide : 1 < 2) (hb (bs.take 128))
  · simpa [bitLimbs, hlen] using Nat.ofDigits_lt_base_pow_length (by decide : 1 < 2) (hb (bs.drop 128))

theorem bitLimbs_split (bs : List Bool) (hlen : bs.length = 255) :
    bitLimbs bs = split (Nat.ofDigits 2 (bs.map Bool.toNat)) := by
  apply limbs_injective (bitLimbs_bounds bs hlen).1 (Nat.mod_lt _ (by decide))
  rw [bitLimbs_value bs hlen, split_value]

theorem split_hash_canonical (h : ZMod noteModulus) :
    (split h.val).canonical scalarModulus := by
  haveI : NeZero noteModulus := ⟨by decide⟩
  refine ⟨Nat.mod_lt _ (by decide), ?_, ?_⟩
  · change h.val / 2 ^ 128 < 2 ^ 127
    apply (Nat.div_lt_iff_lt_mul (by decide : 0 < 2 ^ 128)).mpr
    exact h.val_lt.trans_le (by decide : noteModulus ≤ 2 ^ 127 * 2 ^ 128)
  · rw [split_value]
    exact h.val_lt.trans_le note_le_scalar

/-- Equality of the two encoded Fp limbs is lossless because each limb is
strictly below p. A recomposed residue alone does not have this property. -/
theorem field_limbs_injective {a b : Limbs}
    (ha : a.canonical scalarModulus) (hb : b.canonical scalarModulus)
    (hlo : (a.lo : ZMod noteModulus) = (b.lo : ZMod noteModulus))
    (hhi : (a.hi : ZMod noteModulus) = (b.hi : ZMod noteModulus)) : a = b := by
  have hl : a.lo = b.lo := ProfileMask.nat_eq_of_cast_eq
    (ha.1.trans_le (by decide : 2 ^ 128 ≤ noteModulus))
    (hb.1.trans_le (by decide : 2 ^ 128 ≤ noteModulus)) hlo
  have hh : a.hi = b.hi := ProfileMask.nat_eq_of_cast_eq
    (ha.2.1.trans_le (by decide : 2 ^ 127 ≤ noteModulus))
    (hb.2.1.trans_le (by decide : 2 ^ 127 ≤ noteModulus)) hhi
  cases a; cases b; simp_all

theorem hash_match {s : Limbs} (hs : s.canonical scalarModulus) (h : ZMod noteModulus)
    (hlo : (s.lo : ZMod noteModulus) = ((split h.val).lo : ZMod noteModulus))
    (hhi : (s.hi : ZMod noteModulus) = ((split h.val).hi : ZMod noteModulus)) : s.value = h.val :=
  hash_limb_match h.val s (field_limbs_injective hs (split_hash_canonical h) hlo hhi)

theorem modular_alias_rejected (h : ZMod noteModulus) :
    split (h.val + noteModulus) ≠ split h.val := by
  intro heq
  have hv := congrArg Limbs.value heq
  simp only [split_value] at hv
  have hp : 0 < noteModulus := by decide
  omega

def amountWord (amount : Fin moneyBound) : Word 17 :=
  wordOf 17 amount.val (amount.isLt.trans_le (by decide : moneyBound ≤ 8 ^ 17))

theorem bounded_amount_product {G : Type*} [AddCommGroup G] (B : G) (amount : Fin moneyBound) :
    windows B 0 (amountWord amount).digits = amount.val • B := by
  rw [amount_product]
  simp [amountWord]

end Tachyon.WindowEncodings

namespace Tachyon.StepBudget

variable {F A K G : Type*} [Field F] [Field K] [AddCommGroup G] [Module K G] [DecidableEq G]

/-- Supply the unchanged existing value-opening/accounting interface from the
new accepted output path, through the proved old/new refinement. -/
def outputValueOpening (m : Model F G) (hJ : m.sentinel ≠ 0) (n : Note F) (s : FixedBase.Limbs)
    (hc : s.canonical m.scalarModulus) (o : Output F G) (rk : G)
    (h : NewOutputBind (K := K) m n s o) : ValueOpening (K := K) m.valueBase m.blindBase G where
  cv := o.cv
  rk := rk
  value := -(n.amount : ℤ)
  rcv := s.value
  opens := by simpa using ((outputBind_refinement m hJ n s hc o).mp h).2

def spendValueOpening (m : Model F G) (hJ : m.sentinel ≠ 0) (valid : NoteSpendable F A → Prop)
    (s : FixedBase.Limbs) (hc : s.canonical m.scalarModulus) (o : Spend F A G) (rk : G)
    (h : NewSpendBind (K := K) m valid s o) : ValueOpening (K := K) m.valueBase m.blindBase G where
  cv := o.cv
  rk := rk
  value := o.prepared.amount
  rcv := s.value
  opens := by simpa using ((spendBind_refinement m hJ valid s hc o).mp h).2.2

theorem feeValueOpening (m : Model F G) (hJ : m.sentinel ≠ 0) (n : Note F) (fee : ℕ)
    (hc : (feeScalar m n).canonical m.scalarModulus) (cv : G) (r : Ready F)
    (h : ReadyAccepted (K := K) m n fee cv r) :
    cv = valueCommit m.valueBase m.blindBase ((-(n.amount : ℤ)) : K) ((feeScalar m n).value : K) := by
  simpa using (h.provenance hJ hc).2

def Model.taggedDigest (m : Model F G) : TaggedDigest G G F := ⟨m.actionDigest, m.feeDigest⟩

/-- The new action path supplies the existing paid-creation interface, with
the same descriptor preimage and signed debit, via the checked refinement. -/
def outputDigestOpening (m : Model F G) (hJ : m.sentinel ≠ 0) (n : Note F) (s : FixedBase.Limbs)
    (hc : s.canonical m.scalarModulus) (o : Output F G) (theta : F) (a : Action F A G)
    (hb : NewOutputBind (K := K) m n s o) (ha : NewOutputAction m o theta a) :
    DigestOpening K m.taggedDigest m.valueBase m.blindBase a.digest (-(n.amount : ℤ)) where
  input := .action o.cv a.rk
  rcv := s.value
  digest := ha.1.2.1.symm
  opens := (outputValueOpening m hJ n s hc o a.rk hb).opens

def spendDigestOpening (m : Model F G) (hJ : m.sentinel ≠ 0) (valid : NoteSpendable F A → Prop)
    (s : FixedBase.Limbs) (hc : s.canonical m.scalarModulus) (o : Spend F A G)
    (pak : Pak F G) (theta : F) (a : Action F A G)
    (hb : NewSpendBind (K := K) m valid s o) (ha : NewSpendAction m o pak theta a) :
    DigestOpening K m.taggedDigest m.valueBase m.blindBase a.digest (o.prepared.amount : ℤ) where
  input := .action o.cv a.rk
  rcv := s.value
  digest := ha.1.2.2.2.2.1.symm
  opens := (spendValueOpening m hJ valid s hc o a.rk hb).opens

def feeDigestOpening (m : Model F G) (hJ : m.sentinel ≠ 0) (n : Note F) (fee : ℕ)
    (hc : (feeScalar m n).canonical m.scalarModulus) (cv : G) (r : Ready F)
    (h : ReadyAccepted (K := K) m n fee cv r) :
    DigestOpening K m.taggedDigest m.valueBase m.blindBase r.digest (-(n.amount : ℤ)) where
  input := .fee cv fee
  rcv := (feeScalar m n).value
  digest := by
    obtain ⟨_, _, _, _, _, _, _, hd, _, _⟩ := (h.provenance hJ hc).1
    exact hd.symm
  opens := by simpa [DigestInput.commitment] using feeValueOpening m hJ n fee hc cv r h

end Tachyon.StepBudget
