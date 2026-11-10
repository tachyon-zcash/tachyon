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

The bundle's own fee descriptor is matched the same way to the fee leaf its digest covers: the
descriptor's `cv_feemax` (`cvMax` in the model) commits to `-maxFee` and the leaf's preimage carries
the descriptor's `v_fee`, or
the preimages collide (`TracedBundle.feeOpensOrBreak`). The fee side then needs no hypotheses: the
signed values of the action leaves and the fee leaf sum to the value balance, and the max fee
covers the fee (`TracedBundle.balanceOrBreak`).

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
yields a tagged digest collision or a nontrivial relation among `(V, W)`. Leaf values are within
`maxMoney` by their steps' range checks; the max fee and the value balance must be too, and
`(n + 2) maxMoney` stays below the characteristic. -/
def TracedBundle.accountingOrBreak [DecidableEq K] {p : ℕ} [CharP K p]
    (b : TracedBundle IsFee epoch R actionDigest feeDigest H (DigestOpening K Hd V W) Lift)
    (hactionDigest : ∀ δ, actionDigest δ = Hd.eval (actionInput δ))
    (cvMax : G) (maxFee fee change vBalance : ℤ) (blind bsk : K)
    (hmax : cvMax = valueCommit V W (-maxFee : K) blind) (hchange : change = maxFee - fee)
    (hrange : 0 ≤ change) (hmaxFee : |maxFee| ≤ maxMoney) (hvb : |vBalance| ≤ maxMoney)
    (hp : (b.descs.length + 2) * maxMoney < p)
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
          vBalance blind bsk (fun i _ => (b.actionLeaf i).provenance.signedValue_abs_le)
          (fun j => j.elim)
          hmaxFee hvb hchange (by simpa using hp) hbvk' with
      | .inr relation => .inr (.inr relation)
      | .inl hbalance => .inl ⟨by simpa using hbalance, by omega⟩

omit [Field F] [DecidableEq F] [DecidableEq G] [DecidableEq Rk] in
/-- A leaf whose digest preimage carries fee `f` is a fee leaf: its signed value is `-maxFee` for
a max fee of at least `f`. -/
theorem TachygramLeaf.maxFee_of_feeAmount {d : F} {a : A} {f : ℕ}
    {k : TachygramLeaf H (DigestOpening K Hd V W) R epoch d a} (h : k.feeAmount = some f) :
    ∃ maxFee : ℕ, k.signedValue = -maxFee ∧ f ≤ maxFee := by
  cases k with
  | spend => exact absurd h nofun
  | output => exact absurd h nofun
  | fee maxFee fee change _ hchange =>
      simp only [TachygramLeaf.feeAmount, Option.some.injEq] at h
      exact ⟨maxFee.value, rfl, by omega⟩

omit [DecidableEq F] [DecidableEq G] [DecidableEq Rk] in
theorem TracedBundle.feeDigest_mem
    (b : TracedBundle IsFee epoch R actionDigest feeDigest H (DigestOpening K Hd V W) Lift) :
    feeDigest b.fee ∈ coveredDigests actionDigest feeDigest b.descs (b.fee :: b.adjunctFees) :=
  Multiset.mem_coe.mpr (List.mem_append_right _ (List.mem_map_of_mem List.mem_cons_self))

/-- The positive leaf covering the bundle's own fee digest. -/
def TracedBundle.feeLeaf
    (b : TracedBundle IsFee epoch R actionDigest feeDigest H (DigestOpening K Hd V W) Lift) :
    LeafRecord (TachygramLeaf H (DigestOpening K Hd V W) R epoch) :=
  (b.trace.findLeaf b.actions b.feeDigest_mem).1

variable {cvMaxOf : Φ → G} {feeOf : Φ → ℕ}

/-- The bundle's fee descriptor commits its `cv_feemax` to the signed value of the leaf its digest
covers, and that leaf's preimage carries the descriptor's `v_fee`; or the descriptor's preimage and
the leaf's opening collide. The model selectors `cvMaxOf` and `feeOf` represent those Rust fields;
consensus computes each fee digest from `(cvMaxOf φ, feeOf φ)`. -/
def TracedBundle.feeOpensOrBreak
    (b : TracedBundle IsFee epoch R actionDigest feeDigest H (DigestOpening K Hd V W) Lift)
    (hfeeDigest : ∀ φ, feeDigest φ = Hd.fee (cvMaxOf φ) (feeOf φ)) :
    (cvMaxOf b.fee = valueCommit V W (b.feeLeaf.provenance.signedValue : K)
        b.feeLeaf.provenance.opening.rcv ∧
      b.feeLeaf.provenance.feeAmount = some (feeOf b.fee)) ⊕' TaggedDigestCollision Hd :=
  let o := b.feeLeaf.provenance.opening
  if hinput : DigestInput.fee (cvMaxOf b.fee) (feeOf b.fee) = o.input then
    .inl ⟨(congrArg DigestInput.commitment hinput).trans o.opens,
      o.amount.symm.trans (congrArg DigestInput.feeAmount hinput).symm⟩
  else .inr ⟨.fee (cvMaxOf b.fee) (feeOf b.fee), o.input, hinput,
    (hfeeDigest _).symm.trans
      ((b.trace.findLeaf b.actions b.feeDigest_mem).2.2.1.symm.trans o.digest.symm)⟩

/-- A traced bundle balances under its binding signature: the signed values of its action leaves
and its own fee leaf sum to the value balance, and the fee leaf's max fee covers the descriptor's
fee; or the bundle yields a tagged digest collision or a nontrivial relation among `(V, W)`. The
value balance must be within `maxMoney`, and `(n + 2) maxMoney` stays below the characteristic. -/
def TracedBundle.balanceOrBreak [DecidableEq K] {p : ℕ} [CharP K p]
    (b : TracedBundle IsFee epoch R actionDigest feeDigest H (DigestOpening K Hd V W) Lift)
    (hactionDigest : ∀ δ, actionDigest δ = Hd.eval (actionInput δ))
    (hfeeDigest : ∀ φ, feeDigest φ = Hd.fee (cvMaxOf φ) (feeOf φ)) (vBalance : ℤ) (bsk : K)
    (hvb : |vBalance| ≤ maxMoney) (hp : (b.descs.length + 2) * maxMoney < p)
    (hbvk : ∑ i : Fin b.descs.length, (actionInput b.descs[i]).commitment + cvMaxOf b.fee -
      (vBalance : K) • V = bsk • W) :
    (∑ i, (b.actionLeaf i).provenance.signedValue + b.feeLeaf.provenance.signedValue =
        vBalance ∧ (feeOf b.fee : ℤ) + b.feeLeaf.provenance.signedValue ≤ 0) ⊕'
      (TaggedDigestCollision Hd ⊕' NontrivialRelation (F := K) (Fin.elim0 : Fin 0 → G) V W) :=
  match b.feeOpensOrBreak hfeeDigest with
  | .inr collision => .inr (.inl collision)
  | .inl ⟨hmax, hamount⟩ =>
      have hfee := TachygramLeaf.maxFee_of_feeAmount hamount
      match b.accountingOrBreak hactionDigest (cvMaxOf b.fee)
          (-b.feeLeaf.provenance.signedValue) (feeOf b.fee)
          (-b.feeLeaf.provenance.signedValue - feeOf b.fee) vBalance
          b.feeLeaf.provenance.opening.rcv bsk (by rw [hmax]; push_cast; ring_nf) rfl
          (by obtain ⟨maxFee, hvalue, hle⟩ := hfee; omega)
          (by rw [abs_neg]; exact b.feeLeaf.provenance.signedValue_abs_le) hvb hp hbvk with
      | .inr outcome => .inr outcome
      | .inl ⟨hbalance, hle⟩ => .inl ⟨by omega, by omega⟩

end Tachyon
