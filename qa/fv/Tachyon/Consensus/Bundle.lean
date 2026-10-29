import Tachyon.ProofTree

/-!
# Bundle verification

`Bundle::verify` as consensus runs it, idealized like the proof tree: the carried tachygram-set
commitment is its polynomial, and an accepted proof is a `Derivable` stamp. The proof's header is not
carried. Consensus rebuilds its action set from the digests of the covered descriptors.

Signatures, the value balance and adjunct pointers are out of scope. The BLAKE2b coverage digest is
left out: it compares the stamp's carried coverage field against the same descriptors the proof
check rebuilds the action set from.
-/

namespace Tachyon

open Polynomial

/-- A stamp as published: its tachygrams, its carried tachygram-set commitment, and its anchor. -/
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
adjuncts', and `fees` is its own fee descriptor followed by its adjuncts'. -/
structure BundleVerified (epoch : A → E) (R : E → F → Multiset F) (actionDigest : Δ → F)
    (feeDigest : Φ → F) (descs : List Δ) (fees : List Φ) (stamp : PublishedStamp F A) : Prop where
  descs_nodup : descs.Nodup
  fees_nodup : fees.Nodup
  tachygrams_ne_nil : stamp.tachygrams ≠ []
  tachygrams_nodup : stamp.tachygrams.Nodup
  arity : stamp.tachygrams.length = 2 * descs.length + fees.length
  tachygram_set : stamp.tachygramSet = setPoly stamp.tachygrams
  proof : Derivable epoch R
    ⟨setPoly (coveredDigests actionDigest feeDigest descs fees), stamp.tachygramSet, stamp.anchor⟩

variable {epoch : A → E} {R : E → F → Multiset F} {actionDigest : Δ → F} {feeDigest : Φ → F}
  {descs : List Δ} {fees : List Φ} {stamp : PublishedStamp F A}

/-- A verified bundle publishes exactly its covered leaves' tachygrams at its anchor's epoch. -/
theorem BundleVerified.tachygrams_eq
    (h : BundleVerified epoch R actionDigest feeDigest descs fees stamp) :
    (stamp.tachygrams : Multiset F) =
      (coveredDigests actionDigest feeDigest descs fees).bind (R (epoch stamp.anchor)) :=
  setPoly_injective (h.tachygram_set ▸ h.proof.published rfl)

/-- No two covered leaves of a verified bundle share a tachygram, and a digest covered twice has
no tachygrams. -/
theorem BundleVerified.leaves_disjoint
    (h : BundleVerified epoch R actionDigest feeDigest descs fees stamp) :
    (coveredDigests actionDigest feeDigest descs fees).Pairwise
      fun d d' => Disjoint (R (epoch stamp.anchor) d) (R (epoch stamp.anchor) d') := by
  have hnodup : (stamp.tachygrams : Multiset F).Nodup := Multiset.coe_nodup.mpr h.tachygrams_nodup
  rw [h.tachygrams_eq] at hnodup
  exact (Multiset.nodup_bind.mp hnodup).2

end Tachyon
