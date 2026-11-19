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
bundle its fee change, and an action digest absorbs its pair and a fee digest its fee change. Here
`Δ` stands for a descriptor with its pair and `Φ` for a fee descriptor with its fee change, and
`tachygrams` lists the covered pairs and fee changes. `BundleVerified` does not record which
tachygrams belong to which descriptor; `Bundle::verify_covered` builds the list that way.

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

/-- The digests a bundle's stamp covers: action digests of `descs`, then fee digests of `fees`. -/
def coveredDigests (actionDigest : Δ → F) (feeDigest : Φ → F) (descs : List Δ) (fees : List Φ) :
    Multiset F :=
  (descs.map actionDigest ++ fees.map feeDigest : List F)

/-- `Bundle::verify` accepts. `descs` is the bundle's own action descriptors followed by its
adjuncts'. `fee` is the bundle's own fee descriptor and `adjunctFees` its adjuncts'. -/
structure BundleVerified (IsFee : F → Prop) (epoch : A → E) (R : E → F → Multiset F)
    (actionDigest : Δ → F) (feeDigest : Φ → F) (descs : List Δ) (fee : Φ) (adjunctFees : List Φ)
    (stamp : PublishedStamp F A) : Prop where
  descs_nodup : descs.Nodup
  fees_nodup : (fee :: adjunctFees).Nodup
  tachygrams_ne_nil : stamp.tachygrams ≠ []
  tachygrams_nodup : stamp.tachygrams.Nodup
  arity : stamp.tachygrams.length = 2 * descs.length + (adjunctFees.length + 1)
  tachygram_set : stamp.tachygramSet = setPoly stamp.tachygrams
  proof : StampDerivable IsFee epoch R
    ⟨setPoly (coveredDigests actionDigest feeDigest descs (fee :: adjunctFees)), stamp.tachygramSet,
      stamp.anchor⟩

variable {IsFee : F → Prop} {epoch : A → E} {R : E → F → Multiset F} {actionDigest : Δ → F}
  {feeDigest : Φ → F} {descs : List Δ} {fee : Φ} {adjunctFees : List Φ}
  {stamp : PublishedStamp F A}

/-- A verified bundle publishes exactly its covered leaves' tachygrams at its anchor's epoch. -/
theorem BundleVerified.tachygrams_eq
    (h : BundleVerified IsFee epoch R actionDigest feeDigest descs fee adjunctFees stamp) :
    (stamp.tachygrams : Multiset F) =
      (coveredDigests actionDigest feeDigest descs (fee :: adjunctFees)).bind
        (R (epoch stamp.anchor)) :=
  setPoly_injective (h.tachygram_set ▸ h.proof.published rfl)

/-- No two covered leaves of a verified bundle share a tachygram, and a digest covered twice has
no tachygrams. -/
theorem BundleVerified.leaves_disjoint
    (h : BundleVerified IsFee epoch R actionDigest feeDigest descs fee adjunctFees stamp) :
    (coveredDigests actionDigest feeDigest descs (fee :: adjunctFees)).Pairwise
      fun d d' => Disjoint (R (epoch stamp.anchor) d) (R (epoch stamp.anchor) d') := by
  have hnodup : (stamp.tachygrams : Multiset F).Nodup := Multiset.coe_nodup.mpr h.tachygrams_nodup
  rw [h.tachygrams_eq] at hnodup
  exact (Multiset.nodup_bind.mp hnodup).2

/-- A verified bundle publishes its own fee leaf's tachygrams. Coverage supplies the fee:
`StampUnmerge` can derive fee-free stamps (`unmerge_strips_fee`). -/
theorem BundleVerified.fee_published
    (h : BundleVerified IsFee epoch R actionDigest feeDigest descs fee adjunctFees stamp) :
    R (epoch stamp.anchor) (feeDigest fee) ≤ (stamp.tachygrams : Multiset F) := by
  rw [h.tachygrams_eq]
  exact Multiset.le_bind _ (by simp [coveredDigests])

end Tachyon
