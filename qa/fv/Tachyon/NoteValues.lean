import Tachyon.FeeAccounting
import Tachyon.Foundation.RelationWitness

/-!
# Note values

The binding signature balances the bundle's value commitments: each action descriptor's `cv` and the
max fee commitment. The proof ties each `cv` to a note: `SpendBind` commits `+v` of the spent note,
the output binding commits `-v` of the created note, and `FeeFuse` commits `-maxFee` and creates the
change note at `maxFee - fee`, checking `0 ≤ maxFee - fee`. A descriptor's digest is the hash of its
`(cv, rk)`, and coverage matches it to a leaf's digest, so the descriptor's `cv` is the leaf's, or the
two preimages collide (`descriptorOpensOrCollision`).

`noteAccountingOrBreak` composes these: the leaves' signed note values sum to the change note's
value, the fee and the value balance, and the fee does not exceed the max fee; or the bundle yields a
digest collision or a nontrivial relation among $(\mathcal{V}, \mathcal{R})$.
-/

namespace Tachyon

variable {K G Rk D : Type*} [Field K] [AddCommGroup G] [Module K G]

/-- The action digest over a value commitment and a randomized key. -/
structure DigestHash (G Rk D : Type*) where
  hash : G → Rk → D

/-- Distinct `(cv, rk)` preimages with one action digest. -/
structure DigestCollision (H : DigestHash G Rk D) where
  left : G × Rk
  right : G × Rk
  distinct : left ≠ right
  equal : H.hash left.1 left.2 = H.hash right.1 right.2

/-- A leaf's value opening: the `(cv, rk)` its action digest hashes, and the signed note value and
trapdoor `cv` commits to. -/
structure ValueOpening (V R : G) (Rk : Type*) where
  cv : G
  rk : Rk
  value : ℤ
  rcv : K
  opens : cv = valueCommit V R (value : K) rcv

/-- A descriptor whose digest matches a leaf's commits to the leaf's value, or the two preimages
collide. -/
def descriptorOpensOrCollision [DecidableEq G] [DecidableEq Rk] {V R : G} (H : DigestHash G Rk D)
    (cv : G) (rk : Rk) (leaf : ValueOpening (K := K) V R Rk)
    (hdigest : H.hash cv rk = H.hash leaf.cv leaf.rk) :
    (cv = valueCommit V R (leaf.value : K) leaf.rcv) ⊕' DigestCollision H :=
  if h : (cv, rk) = (leaf.cv, leaf.rk) then
    .inl ((congrArg Prod.fst h).trans leaf.opens)
  else
    .inr ⟨(cv, rk), (leaf.cv, leaf.rk), h, hdigest⟩

/-- A bundle's `n` action descriptors, each matched by digest to a leaf's value opening, and its max
fee commitment, under a binding signing key: the leaves' signed note values sum to the change, the
fee and the value balance, with the fee at most the max fee; or the bundle yields a digest collision
or a nontrivial relation among `(V, R)`. Values are bounded by `M`, and `(n + 2) M` stays below the
characteristic. -/
def noteAccountingOrBreak [DecidableEq K] [DecidableEq G] [DecidableEq Rk] {p : ℕ} [CharP K p]
    {V R : G} (H : DigestHash G Rk D) {n : ℕ} (cv : Fin n → G) (rk : Fin n → Rk)
    (leaf : Fin n → ValueOpening (K := K) V R Rk)
    (hdigest : ∀ i, H.hash (cv i) (rk i) = H.hash (leaf i).cv (leaf i).rk)
    (cvMax : G) (maxFee fee change vBalance : ℤ) (blind bsk : K)
    (hmax : cvMax = valueCommit V R (-maxFee : K) blind) (hchange : change = maxFee - fee)
    (hrange : 0 ≤ change) {M : ℕ} (hvalues : ∀ i, |(leaf i).value| ≤ M) (hmaxFee : |maxFee| ≤ M)
    (hvb : |vBalance| ≤ M) (hp : (n + 2) * M < p)
    (hbvk : ∑ i, cv i + cvMax - (vBalance : K) • V = bsk • R) :
    (∑ i, (leaf i).value = change + fee + vBalance ∧ fee ≤ maxFee) ⊕'
      (DigestCollision H ⊕ NontrivialRelation (F := K) (Fin.elim0 : Fin 0 → G) V R) :=
  match finForallOrRelationWitness fun i =>
      descriptorOpensOrCollision H (cv i) (rk i) (leaf i) (hdigest i) with
  | .inr collision => .inr (.inl collision)
  | .inl hopens =>
      have hbvk' : ∑ i ∈ Finset.univ, valueCommit V R ((leaf i).value : K) (leaf i).rcv +
          ∑ j ∈ (∅ : Finset Empty), valueCommit V R (-(Empty.elim j : ℤ) : K) 0 +
          valueCommit V R (-maxFee : K) blind - (vBalance : K) • V = bsk • R := by
        rw [Finset.sum_empty, add_zero, ← hmax, ← hbvk]
        congr 2
        exact Finset.sum_congr rfl fun i _ => (hopens i).symm
      match feeAccountingOrRelation Finset.univ ∅ (fun i => (leaf i).value) Empty.elim
          (fun i => (leaf i).rcv) (fun _ => 0) maxFee fee change vBalance blind bsk
          (fun i _ => hvalues i) (fun j => j.elim) hmaxFee hvb hchange
          (by simpa using hp) hbvk' with
      | .inr relation => .inr (.inr relation)
      | .inl hbalance => .inl ⟨by simpa using hbalance, by omega⟩

end Tachyon
