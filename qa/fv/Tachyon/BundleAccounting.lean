import Tachyon.BundleSpendCreations
import Tachyon.FeeAccounting
import Tachyon.Foundation.RelationWitness

/-!
# Bundle accounting from leaf provenance

`noteAccountingOrBreak` balances a bundle over value openings supplied per descriptor. Here each
action descriptor's opening comes from the leaf its digest covers. The descriptor's preimage and
the leaf's value opening share the digest, so the descriptor's `cv` commits to the leaf's signed
note value, or the two preimages collide. Under the binding signature, the action leaves' signed
note values (`+v` per spent note, `-v` per output note) sum to the change, the fee and the value
balance, with the fee at most the max fee; or the bundle yields a tagged digest collision or a
nontrivial relation among the value generators (`TracedBundle.accountingOrBreak`).

The mathematical parameters `cvMax` and `fee` correspond to Rust's wire-format
fields `cv_feemax` and `v_fee`. Renaming those Rust fields does not change the
signed maximum value, the fee digest preimage or the binding-signature equation.
-/

namespace Tachyon

universe w

variable {K G Rk F A : Type*} [Field K] [AddCommGroup G] [Module K G] [Field F] [DecidableEq F]
  {Hd : TaggedDigest G Rk F} {V W : G} {IsFee : F → Prop}
  {epoch : A → ℕ} {R : ℕ → F → Multiset F} {Δ Φ : Type w} {actionDigest : Δ → F}
  {feeDigest : Φ → F} {H : TachygramHash F} {Lift : Stamp F A → A → Type w}
  {actionInput : Δ → DigestInput G Rk}

omit [DecidableEq F] in
/-- The `i`th action descriptor's digest is covered by its bundle. -/
theorem TracedBundle.actionDigest_mem
    (b : TracedBundle IsFee epoch R actionDigest feeDigest H (DigestOpening K Hd V W) Lift)
    (i : Fin b.descs.length) :
    actionDigest b.descs[i] ∈
      coveredDigests actionDigest feeDigest b.descs (b.fee :: b.adjunctFees) :=
  Multiset.mem_coe.mpr (List.mem_append_left _ (List.mem_map_of_mem (List.getElem_mem i.isLt)))

/-- The positive leaf covering the `i`th action descriptor's digest. -/
def TracedBundle.actionLeaf
    (b : TracedBundle IsFee epoch R actionDigest feeDigest H (DigestOpening K Hd V W) Lift)
    (i : Fin b.descs.length) : LeafRecord (TachygramLeaf H (DigestOpening K Hd V W) R epoch) :=
  (b.trace.findLeaf b.actions (b.actionDigest_mem i)).1

theorem TracedBundle.actionLeaf_spec
    (b : TracedBundle IsFee epoch R actionDigest feeDigest H (DigestOpening K Hd V W) Lift)
    (i : Fin b.descs.length) :
    b.actionLeaf i ∈ b.trace.positive ∧ (b.actionLeaf i).digest = actionDigest b.descs[i] :=
  ⟨(b.trace.findLeaf b.actions (b.actionDigest_mem i)).2.1,
    (b.trace.findLeaf b.actions (b.actionDigest_mem i)).2.2.1⟩

variable [DecidableEq G] [DecidableEq Rk]

/-- The `i`th action descriptor's `cv` commits to its leaf's signed note value, or the descriptor's
preimage and the leaf's opening collide. Consensus computes each action digest from
`actionInput`. -/
def TracedBundle.descriptorOpensOrBreak
    (b : TracedBundle IsFee epoch R actionDigest feeDigest H (DigestOpening K Hd V W) Lift)
    (hactionDigest : ∀ δ, actionDigest δ = Hd.eval (actionInput δ)) (i : Fin b.descs.length) :
    ((actionInput b.descs[i]).commitment = valueCommit V W
      ((b.actionLeaf i).provenance.signedValue : K) (b.actionLeaf i).provenance.opening.rcv) ⊕'
      TaggedDigestCollision Hd :=
  let o := (b.actionLeaf i).provenance.opening
  if hinput : actionInput b.descs[i] = o.input then .inl (hinput ▸ o.opens)
  else .inr ⟨actionInput b.descs[i], o.input, hinput,
    (hactionDigest _).symm.trans ((b.actionLeaf_spec i).2.symm.trans o.digest.symm)⟩

/-- A traced bundle's action leaves balance under its binding signature: their signed note values
sum to the change, the fee and the value balance, with the fee at most the max fee; or the bundle
yields a tagged digest collision or a nontrivial relation among `(V, W)`. Signed values are bounded
by `M`, and `(n + 2) M` stays below the characteristic. -/
def TracedBundle.accountingOrBreak [DecidableEq K] {p : ℕ} [CharP K p]
    (b : TracedBundle IsFee epoch R actionDigest feeDigest H (DigestOpening K Hd V W) Lift)
    (hactionDigest : ∀ δ, actionDigest δ = Hd.eval (actionInput δ))
    (cvMax : G) (maxFee fee change vBalance : ℤ) (blind bsk : K)
    (hmax : cvMax = valueCommit V W (-maxFee : K) blind) (hchange : change = maxFee - fee)
    (hrange : 0 ≤ change) {M : ℕ}
    (hvalues : ∀ l ∈ b.trace.positive, |l.provenance.signedValue| ≤ M) (hmaxFee : |maxFee| ≤ M)
    (hvb : |vBalance| ≤ M) (hp : (b.descs.length + 2) * M < p)
    (hbvk : ∑ i : Fin b.descs.length, (actionInput b.descs[i]).commitment + cvMax -
      (vBalance : K) • V = bsk • W) :
    (∑ i, (b.actionLeaf i).provenance.signedValue = change + fee + vBalance ∧ fee ≤ maxFee) ⊕'
      (TaggedDigestCollision Hd ⊕' NontrivialRelation (F := K) (Fin.elim0 : Fin 0 → G) V W) :=
  match finForallOrRelationWitness (b.descriptorOpensOrBreak hactionDigest) with
  | .inr collision => .inr (.inl collision)
  | .inl hopens =>
      have hbvk' : ∑ i ∈ Finset.univ, valueCommit V W
            ((b.actionLeaf i).provenance.signedValue : K)
            (b.actionLeaf i).provenance.opening.rcv +
          ∑ j ∈ (∅ : Finset Empty), valueCommit V W (-(Empty.elim j : ℤ) : K) 0 +
          valueCommit V W (-maxFee : K) blind - (vBalance : K) • V = bsk • W := by
        rw [Finset.sum_empty, add_zero, ← hmax, ← hbvk]
        congr 2
        exact Finset.sum_congr rfl fun i _ => (hopens i).symm
      match feeAccountingOrRelation Finset.univ ∅
          (fun i => (b.actionLeaf i).provenance.signedValue) Empty.elim
          (fun i => (b.actionLeaf i).provenance.opening.rcv) (fun _ => 0) maxFee fee change
          vBalance blind bsk (fun i _ => hvalues _ (b.actionLeaf_spec i).1) (fun j => j.elim)
          hmaxFee hvb hchange (by simpa using hp) hbvk' with
      | .inr relation => .inr (.inr relation)
      | .inl hbalance => .inl ⟨by simpa using hbalance, by omega⟩

end Tachyon
