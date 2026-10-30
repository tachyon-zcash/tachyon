import Tachyon.FeePairing
import Tachyon.PastaIndexPremises

/-!
# Lossless bounded amount and Pasta word encodings

The base-field hash words and value-commitment scalars are different fields.
The native embedding uses the canonical natural representative, not a field
homomorphism. `lift_injective` proves it is lossless when the target modulus
is at least the source modulus. Likewise bounded amounts embed injectively.

This injectivity is an arithmetic fact about finite canonical encodings into
a sufficiently large target, not the impossible global injectivity of a
compressing cryptographic hash. A small example verifies that addition need
not be preserved across different characteristics.

The fee-pairing reduction can therefore discard its two pure encoding-failure
branches. It still returns concrete digest/blind-hash collisions or computed
DL relations. Primality of the Pasta scalar modulus remains an explicit caller
proof, as with the base modulus in `PastaIndexPremises`; no new dependency or
primality axiom is added.
-/

namespace Tachyon.ScalarEncodings

def lift (p q : ℕ) (x : ZMod p) : ZMod q := x.val

theorem lift_injective {p q : ℕ} [NeZero p] (hmod : p ≤ q) : Function.Injective (lift p q) := by
  intro x y heq
  apply ZMod.val_injective p
  exact ProfileMask.nat_eq_of_cast_eq (x.val_lt.trans_le hmod) (y.val_lt.trans_le hmod) heq

theorem amount_injective {money q : ℕ} (hbound : money ≤ q) :
    Function.Injective (fun x : Fin money => (x.val : ZMod q)) := by
  intro x y heq
  apply Fin.ext
  exact ProfileMask.nat_eq_of_cast_eq (x.isLt.trans_le hbound) (y.isLt.trans_le hbound) heq

theorem lift_need_not_preserve_addition :
    lift 5 7 ((4 : ZMod 5) + 1) ≠ lift 5 7 (4 : ZMod 5) + lift 5 7 (1 : ZMod 5) := by decide

def noteModulus : ℕ := PastaIndexPremises.modulus
def scalarModulus : ℕ := 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
def moneyBound : ℕ := 2_100_000_000_000_000 + 1

theorem note_le_scalar : noteModulus ≤ scalarModulus := by decide
theorem money_fits_note : moneyBound ≤ noteModulus := by decide
theorem money_fits_scalar : moneyBound ≤ scalarModulus := by decide

def noteWordLift : ZMod noteModulus → ZMod scalarModulus := lift noteModulus scalarModulus

theorem noteWordLift_injective : Function.Injective noteWordLift := by
  haveI : NeZero noteModulus := ⟨by decide⟩
  exact lift_injective note_le_scalar

end Tachyon.ScalarEncodings

namespace Tachyon.FeePairing

variable {V K G : Type*} [Field K] [AddCommGroup G] [Module K G] {money : ℕ}

inductive CryptoBreak (m : Model V K G money)
  | digest (witness : Authorization.Collision m.digestHash)
  | blind (witness : Authorization.Collision m.blindHash)
  | relation (witness : NontrivialRelation (F := K) (Fin.elim0 : Fin 0 → G) m.valueBase m.blindBase)

/-- Pure encoding injectivity refines the earlier five-way break without
assuming any hash or Pedersen commitment is globally injective. -/
def refineBreak (m : Model V K G money) (hembed : Function.Injective m.embed)
    (hamount : Function.Injective (fun x : Fin money => (x.val : K))) : Break m → CryptoBreak m
  | .digest w => .digest w
  | .blind w => .blind w
  | .relation w => .relation w
  | .embedding w => False.elim (w.distinct (hembed w.equal))
  | .amount w => False.elim (w.distinct (hamount w.equal))

variable [DecidableEq V] [DecidableEq K] [DecidableEq G]

def changeEqOrCryptoBreak (m : Model V K G money) (left right : Frame V money)
    (hembed : Function.Injective m.embed)
    (hamount : Function.Injective (fun x : Fin money => (x.val : K)))
    (hdigest : m.digest left = m.digest right) :
    (m.change left = m.change right) ⊕' CryptoBreak m :=
  match changeEqOrBreak m left right hdigest with
  | .inl result => .inl result
  | .inr witness => .inr (refineBreak m hembed hamount witness)

end Tachyon.FeePairing

namespace Tachyon.ScalarEncodings

variable {G : Type*} [AddCommGroup G] [Fact scalarModulus.Prime] [Module (ZMod scalarModulus) G]
  [DecidableEq G]

/-- Concrete Pasta fee pairing now has only the cryptographic break branches;
its scalar/amount encoding branches are excluded by checked numeric bounds. -/
def pastaFeeChangeEqOrBreak
    (m : FeePairing.Model (ZMod noteModulus) (ZMod scalarModulus) G moneyBound)
    (hembed : m.embed = noteWordLift) (left right : FeePairing.Frame (ZMod noteModulus) moneyBound)
    (hdigest : m.digest left = m.digest right) :
    (m.change left = m.change right) ⊕' FeePairing.CryptoBreak m :=
  FeePairing.changeEqOrCryptoBreak m left right (hembed ▸ noteWordLift_injective)
    (amount_injective money_fits_scalar) hdigest

end Tachyon.ScalarEncodings
