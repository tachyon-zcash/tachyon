import Tachyon.ProofTree

/-!
# Bundle verification

`Bundle::verify` as consensus runs it, idealized like the proof tree: the carried tachygram-set
commitment is its polynomial, and an accepted proof is a `StampDerivable` header. The proof's header
is not carried. Consensus rebuilds its action set from the digests of the covered descriptors.
Rust reconstructs `(bridge_hash(tachygram_set), anchor)` and verifies O0/O1 against the
reconstructed action-set commitment and the carried tachygram-set commitment, using the caller's
Tachyon application. The `proof` field below packages those slot checks with header acceptance as
one enriched semantic state; it does not model application construction or bridge code.

The stamp carries no tachygram list. Each covered action carries its tachygram pair and each covered
bundle its fee change. A covered action is a descriptor `Δ` with its pair, and a covered fee a fee
descriptor `Φ` with its fee change. An action digest absorbs its descriptor and pair, and a fee
digest its fee descriptor and fee change. Uniqueness is checked on the descriptors alone, as
`Bundle::verify_covered` checks it. `tachygrams` lists the covered pairs and fee changes.

Signatures, the value balance and adjunct pointers are out of scope.
-/

namespace Tachyon

open Polynomial

/-- A stamp as published: the tachygrams its covered bundles carry, its carried tachygram-set
commitment, and its anchor. -/
structure PublishedStamp (F A : Type*) [Field F] where
  tachygrams : List F
  tachygramSet : F[X]
  anchor : A

variable {F A E Δ Φ : Type*} [Field F] [DecidableEq F]

/-- The digests a bundle's stamp covers: action digests of `actions`, then fee digests of `fees`. -/
def coveredDigests (actionDigest : Δ → F → F → F) (feeDigest : Φ → F → F)
    (actions : List (Δ × F × F)) (fees : List (Φ × F)) : Multiset F :=
  (actions.map (fun a => actionDigest a.1 a.2.1 a.2.2) ++ fees.map (fun f => feeDigest f.1 f.2) :
    List F)

/-- `Bundle::verify` accepts. `actions` is the bundle's own actions followed by its adjuncts'. `fee`
is the bundle's own fee and `adjunctFees` its adjuncts'. -/
structure BundleVerified (IsFee : F → Prop) (epoch : A → E) (R : E → F → Multiset F)
    (actionDigest : Δ → F → F → F) (feeDigest : Φ → F → F) (actions : List (Δ × F × F))
    (fee : Φ × F) (adjunctFees : List (Φ × F)) (stamp : PublishedStamp F A) : Prop where
  descs_nodup : (actions.map Prod.fst).Nodup
  fees_nodup : ((fee :: adjunctFees).map Prod.fst).Nodup
  tachygrams_ne_nil : stamp.tachygrams ≠ []
  tachygrams_nodup : stamp.tachygrams.Nodup
  arity : stamp.tachygrams.length = 2 * actions.length + (adjunctFees.length + 1)
  tachygram_set : stamp.tachygramSet = setPoly stamp.tachygrams
  proof : StampDerivable IsFee epoch R
    ⟨setPoly (coveredDigests actionDigest feeDigest actions (fee :: adjunctFees)),
      stamp.tachygramSet, stamp.anchor⟩

/-- A fee digest absorbs its fee change, so its leaf derives exactly that change. Idealizes
`Tachyon-FeeDg` collision resistance on the calls `Q`; a finite `Q` without a collision satisfies
it. -/
structure FeeDigestLaw (R : E → F → Multiset F) (feeDigest : Φ → F → F) (Q : Φ → F → Prop) :
    Prop where
  change : ∀ e {φ c}, Q φ c → R e (feeDigest φ c) = {c}

variable {IsFee : F → Prop} {epoch : A → E} {R : E → F → Multiset F}
  {actionDigest : Δ → F → F → F} {feeDigest : Φ → F → F} {actions : List (Δ × F × F)}
  {fee : Φ × F} {adjunctFees : List (Φ × F)} {stamp : PublishedStamp F A}

/-- A verified bundle publishes exactly its covered leaves' tachygrams at its anchor's epoch. -/
theorem BundleVerified.tachygrams_eq
    (h : BundleVerified IsFee epoch R actionDigest feeDigest actions fee adjunctFees stamp) :
    (stamp.tachygrams : Multiset F) =
      (coveredDigests actionDigest feeDigest actions (fee :: adjunctFees)).bind
        (R (epoch stamp.anchor)) :=
  setPoly_injective (h.tachygram_set ▸ h.proof.published rfl)

/-- No two covered leaves of a verified bundle share a tachygram, and a digest covered twice has
no tachygrams. -/
theorem BundleVerified.leaves_disjoint
    (h : BundleVerified IsFee epoch R actionDigest feeDigest actions fee adjunctFees stamp) :
    (coveredDigests actionDigest feeDigest actions (fee :: adjunctFees)).Pairwise
      fun d d' => Disjoint (R (epoch stamp.anchor) d) (R (epoch stamp.anchor) d') := by
  have hnodup : (stamp.tachygrams : Multiset F).Nodup := Multiset.coe_nodup.mpr h.tachygrams_nodup
  rw [h.tachygrams_eq] at hnodup
  exact (Multiset.nodup_bind.mp hnodup).2

/-- A verified bundle publishes its own fee leaf's tachygrams. Coverage supplies the fee:
`StampUnmerge` can derive fee-free stamps (`unmerge_strips_fee`). -/
theorem BundleVerified.fee_published
    (h : BundleVerified IsFee epoch R actionDigest feeDigest actions fee adjunctFees stamp) :
    R (epoch stamp.anchor) (feeDigest fee.1 fee.2) ≤ (stamp.tachygrams : Multiset F) := by
  rw [h.tachygrams_eq]
  exact Multiset.le_bind _ (by simp [coveredDigests])

/-- A verified bundle publishes its own fee change. -/
theorem BundleVerified.fee_change_published {Q : Φ → F → Prop} (hfee : FeeDigestLaw R feeDigest Q)
    (hq : Q fee.1 fee.2)
    (h : BundleVerified IsFee epoch R actionDigest feeDigest actions fee adjunctFees stamp) :
    fee.2 ∈ stamp.tachygrams := by
  have hle := h.fee_published
  rw [hfee.change _ hq] at hle
  exact Multiset.mem_coe.mp (Multiset.singleton_le.mp hle)

end Tachyon
