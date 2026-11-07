import Tachyon.IndexedContainment
import Mathlib.FieldTheory.Finite.Basic

/-!
# Concrete Pasta indexed-encoding premises

The `Fp` modulus is the same numeral as ragu's `qa/fv/Ragu/Core.lean:6`
(`PALLAS_BASE`), used by `crate::pasta::Fp` (Udon's `PallasBase` adapter) in
the indexed multiset encoding. The adapter migration preserves this modulus.
The epoch bound follows `BLOCK_MAX / EPOCH_SIZE + 1` in Tachyon's `constants.rs`.

We keep primality as an explicit `Fact modulus.Prime` argument: ragu imports
its certified proof from `CompElliptic.Fields.Pasta`. This project has no such
dependency, and this phase neither installs it nor changes package manifests.
The modular exponent witness and all numeric bounds below are checked here.
This does not introduce a primality axiom or pretend to prove primality locally.
-/

namespace Tachyon.PastaIndexPremises

open Polynomial

/-- Pallas base field, matching ragu's `Core.Primes.p`. -/
def modulus : ℕ := 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001

def epochBound : ℕ := (2 ^ 32 - 1) / 4096 + 1
def testEpochBound : ℕ := (2 ^ 32 - 1) / 64 + 1

theorem epoch_bound_safe : 3 * epochBound ^ 2 < modulus := by decide
theorem test_epoch_bound_safe : 3 * testEpochBound ^ 2 < modulus := by decide

/-- A binary powering routine whose correctness is proved below. It is used
to check the modular witness without constructing the enormous integer `2^n`. -/
def binaryPow {M : Type*} [Monoid M] (a : M) (n : ℕ) : ℕ → M
  | 0 => 1
  | fuel + 1 =>
    if n = 0 then 1 else
      let half := binaryPow a (n / 2) fuel
      if n % 2 = 0 then half * half else half * half * a

theorem binaryPow_eq {M : Type*} [Monoid M] (a : M) (n fuel : ℕ)
    (hbound : n < 2 ^ fuel) : binaryPow a n fuel = a ^ n := by
  induction fuel generalizing n with
  | zero =>
    have hn : n = 0 := by simpa using hbound
    simp [hn, binaryPow]
  | succ fuel ih =>
    rw [binaryPow]
    by_cases hn : n = 0
    · simp [hn]
    · rw [if_neg hn]
      have hhalf : n / 2 < 2 ^ fuel := by
        simp only [pow_succ] at hbound
        omega
      rw [ih (n / 2) hhalf]
      dsimp only
      split_ifs with heven
      · rw [← pow_add]
        congr 1
        omega
      · rw [← pow_add, ← pow_succ]
        congr 1
        omega

set_option maxRecDepth 4096 in
set_option maxHeartbeats 1000000 in
theorem two_power_witness :
    binaryPow (2 : ZMod modulus) ((modulus - 1) / 3) 256 =
      (20444556541222657078399132219657928148671392403212669005631716460534733845831 : ZMod modulus) := by
  decide

theorem two_power_not_one : (2 : ZMod modulus) ^ ((modulus - 1) / 3) ≠ 1 := by
  have h := two_power_witness
  rw [binaryPow_eq _ _ _ (by decide : (modulus - 1) / 3 < 2 ^ 256)] at h
  have hresidue :
      (20444556541222657078399132219657928148671392403212669005631716460534733845831 : ZMod modulus) ≠ 1 := by
    decide
  exact fun heq => hresidue (h.symm.trans heq)

theorem two_ne_zero : (2 : ZMod modulus) ≠ 0 := by decide

/-- The checked modular witness plus Fermat's theorem rules out cube roots of
two. Primality is supplied explicitly by the caller's certified field setup. -/
theorem two_noncube [Fact modulus.Prime] : ∀ x : ZMod modulus, x ^ 3 ≠ 2 := by
  intro x hx
  have htwo := two_ne_zero
  have hxne : x ≠ 0 := by
    intro hz
    exact htwo (by simpa [hz] using hx.symm)
  apply two_power_not_one
  have hexponent : 3 * ((modulus - 1) / 3) = modulus - 1 := by decide
  calc
    _ = (x ^ 3) ^ ((modulus - 1) / 3) := by rw [hx]
    _ = x ^ (modulus - 1) := by rw [← pow_mul, hexponent]
    _ = 1 := ZMod.pow_card_sub_one_eq_one hxne

/-- The production epoch range satisfies all indexed-division premises once
the caller supplies the standard Pasta field primality certificate. -/
theorem indexed_division [Fact modulus.Prime]
    {r d : Multiset (Fin epochBound × ZMod modulus)} {q : (ZMod modulus)[X]}
    (h : IndexedContainment.product (IndexedContainment.indexedFactor 2) r * q =
      IndexedContainment.product (IndexedContainment.indexedFactor 2) d) :
    r ≤ d ∧ q = IndexedContainment.product (IndexedContainment.indexedFactor 2) (d - r) :=
  IndexedContainment.indexed_division two_noncube epoch_bound_safe h

theorem indexed_division_test_epochs [Fact modulus.Prime]
    {r d : Multiset (Fin testEpochBound × ZMod modulus)} {q : (ZMod modulus)[X]}
    (h : IndexedContainment.product (IndexedContainment.indexedFactor 2) r * q =
      IndexedContainment.product (IndexedContainment.indexedFactor 2) d) :
    r ≤ d ∧ q = IndexedContainment.product (IndexedContainment.indexedFactor 2) (d - r) :=
  IndexedContainment.indexed_division two_noncube test_epoch_bound_safe h

end Tachyon.PastaIndexPremises
