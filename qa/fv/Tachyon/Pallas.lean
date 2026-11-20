import Mathlib.FieldTheory.Finite.Basic
import Mathlib.NumberTheory.LucasPrimality
import Mathlib.Tactic.NormNum.Prime
import Tachyon.CubicMember

/-!
# The Pallas base field

Rust fixes two constants of the Pallas base field `crate::pasta::Fp`, of prime order `p`:
`QUADRATIC_NON_RESIDUE = 5` (`collections/qr.rs`) and `NON_RESIDUE = 2`, the `c` of the cubic member
encoding (`collections/indexed_multiset.rs`). This module checks the facts the model asks of them:
`5` is a non-square (`quadraticNonResidue`), and `cubicMember 2` satisfies `MemberLaw` up to the
production `EPOCH_MAX = 2 ^ 20 - 1` (`memberLaw`).

Both need `p` prime. `prime` proves it with a Lucas certificate: each large prime in the
factorization tree of `p - 1` is proved by `prime_of_lucas`, whose arithmetic the kernel evaluates
with `powMod`, and each prime below `2 ^ 20` by `norm_num`.
-/

namespace Tachyon.Pallas

/-- `b ^ e % m` by square-and-multiply over the low `k` bits of `e`. -/
def powModAux (m : ℕ) : ℕ → ℕ → ℕ → ℕ
  | 0, _, _ => 1 % m
  | k + 1, b, e =>
    if e % 2 = 0 then powModAux m k (b * b % m) (e / 2)
    else powModAux m k (b * b % m) (e / 2) * b % m

/-- `powModAux` computes `b ^ e % m` once `k` covers every bit of `e`. -/
theorem powModAux_eq (m : ℕ) : ∀ k b e, e < 2 ^ k → powModAux m k b e = b ^ e % m
  | 0, b, e, h => by
    obtain rfl : e = 0 := by simpa using h
    simp [powModAux]
  | k + 1, b, e, h => by
    have ih := powModAux_eq m k (b * b % m) (e / 2) (by rw [pow_succ] at h; omega)
    rw [← Nat.pow_mod] at ih
    have he : b ^ e = (b * b) ^ (e / 2) * b ^ (e % 2) := by
      rw [← sq, ← pow_mul, ← pow_add, Nat.div_add_mod]
    simp only [powModAux, ih]
    split_ifs with h2
    · rw [he, h2, pow_zero, mul_one]
    · rw [he, show e % 2 = 1 by omega, pow_one, Nat.mod_mul_mod]

/-- `b ^ e % m`, by `powModAux` over every bit of `e`. -/
def powMod (m b e : ℕ) : ℕ := powModAux m (e.log2 + 1) b e

/-- `powMod` is `b ^ e % m`. -/
theorem powMod_eq (m b e : ℕ) : powMod m b e = b ^ e % m :=
  powModAux_eq m _ b e Nat.lt_log2_self

/-- A power of a natural is `1` in `ZMod n` exactly when `powMod` says so, for `prime_of_lucas` and
the residue facts below. -/
theorem pow_eq_one_iff {n : ℕ} (hn : 1 < n) (a e : ℕ) :
    (a : ZMod n) ^ e = 1 ↔ powMod n a e = 1 := by
  rw [powMod_eq, ← Nat.cast_pow, ← Nat.cast_one, ZMod.natCast_eq_natCast_iff',
    Nat.mod_eq_of_lt hn]

/-- Lucas's test (Mathlib's `lucas_primality`) over a factorization `fs` of `n - 1` into prime powers,
with the modular powers stated through `powMod` so the kernel can evaluate them. -/
theorem prime_of_lucas {n a : ℕ} (fs : List (ℕ × ℕ)) (hn : 1 < n)
    (hfs : (fs.map fun f => f.1 ^ f.2).prod = n - 1) (hprime : ∀ f ∈ fs, f.1.Prime)
    (ha : powMod n a (n - 1) = 1) (hd : ∀ f ∈ fs, powMod n a ((n - 1) / f.1) ≠ 1) :
    n.Prime := by
  refine lucas_primality n a ((pow_eq_one_iff hn _ _).2 ha) fun q hq hdvd h => ?_
  rw [← hfs] at hdvd
  obtain ⟨_, hm, hqm⟩ := (Prime.dvd_prod_iff hq.prime).1 hdvd
  obtain ⟨f, hf, rfl⟩ := List.mem_map.1 hm
  obtain rfl := (Nat.prime_dvd_prime_iff_eq hq (hprime f hf)).1 (hq.dvd_of_dvd_pow hqm)
  exact hd f hf ((pow_eq_one_iff hn _ _).1 h)

/-- A factor of `539204044132271846773 - 1`. -/
theorem prime_417677162933 : Nat.Prime 417677162933 :=
  prime_of_lucas (a := 2) [(2, 2), (59, 1), (1973, 1), (897019, 1)] (by decide +kernel)
    (by decide +kernel) (by norm_num) (by decide +kernel) (by decide +kernel)

/-- A factor of `p - 1`. -/
theorem prime_539204044132271846773 : Nat.Prime 539204044132271846773 :=
  prime_of_lucas (a := 5) [(2, 2), (3, 5), (89, 1), (14923, 1), (417677162933, 1)]
    (by decide +kernel) (by decide +kernel) (by simp [prime_417677162933]; norm_num) (by decide +kernel)
    (by decide +kernel)

/-- A factor of `8999194758858563409123804352480028797519453 - 1`. -/
theorem prime_1197907 : Nat.Prime 1197907 :=
  prime_of_lucas (a := 3) [(2, 1), (3, 1), (53, 1), (3767, 1)] (by decide +kernel)
    (by decide +kernel) (by norm_num) (by decide +kernel) (by decide +kernel)

/-- A factor of `41655379 - 1`. -/
theorem prime_6942563 : Nat.Prime 6942563 :=
  prime_of_lucas (a := 2) [(2, 1), (11, 1), (17, 1), (19, 1), (977, 1)] (by decide +kernel)
    (by decide +kernel) (by norm_num) (by decide +kernel) (by decide +kernel)

/-- A factor of `22160661629 - 1`. -/
theorem prime_41655379 : Nat.Prime 41655379 :=
  prime_of_lucas (a := 2) [(2, 1), (3, 1), (6942563, 1)] (by decide +kernel) (by decide +kernel)
    (by simp [prime_6942563]; norm_num) (by decide +kernel) (by decide +kernel)

/-- A factor of `8999194758858563409123804352480028797519453 - 1`. -/
theorem prime_22160661629 : Nat.Prime 22160661629 :=
  prime_of_lucas (a := 3) [(2, 2), (7, 1), (19, 1), (41655379, 1)] (by decide +kernel)
    (by decide +kernel) (by simp [prime_41655379]; norm_num) (by decide +kernel) (by decide +kernel)

/-- A factor of `8999194758858563409123804352480028797519453 - 1`. -/
theorem prime_325086459374267 : Nat.Prime 325086459374267 :=
  prime_of_lucas (a := 2) [(2, 1), (509, 1), (413527, 1), (772231, 1)] (by decide +kernel)
    (by decide +kernel) (by norm_num) (by decide +kernel) (by decide +kernel)

/-- A factor of `p - 1`. -/
theorem prime_8999194758858563409123804352480028797519453 :
    Nat.Prime 8999194758858563409123804352480028797519453 :=
  prime_of_lucas (a := 2)
    [(2, 2), (3, 4), (11, 1), (2531, 1), (115603, 1), (1197907, 1), (22160661629, 1),
      (325086459374267, 1)]
    (by decide +kernel) (by decide +kernel)
    (by simp [prime_1197907, prime_22160661629, prime_325086459374267]; norm_num)
    (by decide +kernel)
    (by decide +kernel)

/-- The modulus of `crate::pasta::Fp`. -/
def p : ℕ := 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001

/-- `p` is prime, so `ZMod p` is the Pallas base field. -/
theorem prime : p.Prime :=
  prime_of_lucas (a := 5)
    [(2, 32), (3, 1), (463, 1), (539204044132271846773, 1),
      (8999194758858563409123804352480028797519453, 1)]
    (by decide +kernel) (by decide +kernel)
    (by
      simp [prime_539204044132271846773, prime_8999194758858563409123804352480028797519453]
      norm_num)
    (by decide +kernel) (by decide +kernel)

instance : Fact p.Prime := ⟨prime⟩

/-- A natural strictly between `0` and `p` is nonzero in `ZMod p`. -/
theorem natCast_ne_zero {x : ℕ} (h0 : 0 < x) (hx : x < p) : (x : ZMod p) ≠ 0 := by
  rw [Ne, ZMod.natCast_eq_zero_iff]
  exact fun h => absurd (Nat.le_of_dvd h0 h) (by omega)

/-- Rust's `QUADRATIC_NON_RESIDUE` is a non-square, so it can be the QR results' `qnr` at Pallas:
`5 ^ ((p - 1) / 2) ≠ 1`, which a square's power `x ^ (p - 1) = 1` would contradict. -/
theorem quadraticNonResidue : ¬ IsSquare (5 : ZMod p) := by
  rintro ⟨x, hx⟩
  have hx0 : x ≠ 0 := by
    rintro rfl
    exact natCast_ne_zero (x := 5) (by decide) (by decide +kernel) (by simpa using hx)
  have h : ((5 : ℕ) : ZMod p) ^ ((p - 1) / 2) = 1 := by
    rw [Nat.cast_ofNat, hx, ← sq, ← pow_mul, show 2 * ((p - 1) / 2) = p - 1 by decide +kernel]
    exact ZMod.pow_card_sub_one_eq_one hx0
  exact absurd ((pow_eq_one_iff prime.one_lt _ _).1 h) (by decide +kernel)

/-- Rust's `NON_RESIDUE` is not a cube: `2 ^ ((p - 1) / 3) ≠ 1`, which a cube's power
`y ^ (p - 1) = 1` would contradict. -/
theorem nonResidue_not_cube (y : ZMod p) : y ^ 3 ≠ 2 := by
  intro hy
  have hy0 : y ≠ 0 := by
    rintro rfl
    exact natCast_ne_zero (x := 2) (by decide) (by decide +kernel) (by simpa using hy.symm)
  have h : ((2 : ℕ) : ZMod p) ^ ((p - 1) / 3) = 1 := by
    rw [Nat.cast_ofNat, ← hy, ← pow_mul, show 3 * ((p - 1) / 3) = p - 1 by decide +kernel]
    exact ZMod.pow_card_sub_one_eq_one hy0
  exact absurd ((pow_eq_one_iff prime.one_lt _ _).1 h) (by decide +kernel)

/-- Rust's encoding `(m + (i + 1) X) ^ 3 - NON_RESIDUE` satisfies `MemberLaw` up to the production
`EPOCH_MAX = 2 ^ 20 - 1`: the cubes of `1, …, 2 ^ 20` are below `p`, so they stay distinct in
`ZMod p`. -/
theorem memberLaw : MemberLaw (cubicMember (2 : ZMod p)) (2 ^ 20 - 1) := by
  have hcube {i : ℕ} (hi : i ≤ 2 ^ 20 - 1) : (i + 1) ^ 3 < p :=
    lt_of_le_of_lt (Nat.pow_le_pow_left (by omega) 3) (by decide +kernel : (2 ^ 20) ^ 3 < p)
  refine cubicMember_law nonResidue_not_cube ?_ (fun i hi => ?_) (fun i hi j hj h => ?_)
  · exact_mod_cast natCast_ne_zero (x := 3) (by decide) (by decide +kernel)
  · exact_mod_cast natCast_ne_zero (x := i + 1) (by omega)
      (lt_of_le_of_lt (Nat.le_self_pow (by decide) _) (hcube hi))
  · rw [← Nat.cast_succ, ← Nat.cast_succ, ← Nat.cast_pow, ← Nat.cast_pow,
      ZMod.natCast_eq_natCast_iff', Nat.mod_eq_of_lt (hcube hi), Nat.mod_eq_of_lt (hcube hj)] at h
    exact Nat.succ_injective (Nat.pow_left_injective (by decide) h)

end Tachyon.Pallas
