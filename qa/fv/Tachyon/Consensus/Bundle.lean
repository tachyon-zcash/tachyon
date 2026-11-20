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
digest its fee descriptor and fee change. `BundleCovered` is `Bundle::verify_covered`: uniqueness on
the descriptors alone, and the published tachygrams are exactly the carried pairs and fee changes,
unique, with the carried commitment their set polynomial.

`BundleVerified` adds the stamp proof as a `StampDerivable` header. `StampDerivable`'s lifts take
`epoch a = epoch s.anchor`, which `Bundle::verify` has no chain context to check. A derivation
anchored on a chain node satisfies it (`StampTree.derivable`), so `BundleVerified` is
`Bundle::verify` together with that lift premise.

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

/-- The tachygrams a bundle's stamp covers: each action's carried pair, then each fee change
(`covered_tachygrams` in `Bundle::verify_covered`). -/
def coveredTachygrams (actions : List (Δ × F × F)) (fees : List (Φ × F)) : List F :=
  actions.flatMap (fun a => [a.2.1, a.2.2]) ++ fees.map Prod.snd

/-- `Bundle::verify_covered` accepts. `actions` is the bundle's own actions followed by its
adjuncts'. `fee` is the bundle's own fee and `adjunctFees` its adjuncts'. -/
structure BundleCovered (actions : List (Δ × F × F)) (fee : Φ × F) (adjunctFees : List (Φ × F))
    (stamp : PublishedStamp F A) : Prop where
  descs_nodup : (actions.map Prod.fst).Nodup
  fees_nodup : ((fee :: adjunctFees).map Prod.fst).Nodup
  tachygrams_nodup : stamp.tachygrams.Nodup
  tachygrams_covered :
    (stamp.tachygrams : Multiset F) = coveredTachygrams actions (fee :: adjunctFees)
  tachygram_set : stamp.tachygramSet = setPoly stamp.tachygrams

/-- `Bundle::verify` accepts, with the lift premise of `StampDerivable` (see the module doc). -/
structure BundleVerified (IsFee : F → Prop) (epoch : A → E) (R : E → F → Multiset F)
    (actionDigest : Δ → F → F → F) (feeDigest : Φ → F → F) (actions : List (Δ × F × F))
    (fee : Φ × F) (adjunctFees : List (Φ × F)) (stamp : PublishedStamp F A) : Prop
    extends BundleCovered actions fee adjunctFees stamp where
  proof : StampDerivable IsFee epoch R
    ⟨setPoly (coveredDigests actionDigest feeDigest actions (fee :: adjunctFees)),
      stamp.tachygramSet, stamp.anchor⟩

variable {IsFee : F → Prop} {epoch : A → E} {R : E → F → Multiset F}
  {actionDigest : Δ → F → F → F} {feeDigest : Φ → F → F} {actions : List (Δ × F × F)}
  {fee : Φ × F} {adjunctFees : List (Φ × F)} {stamp : PublishedStamp F A}

omit [Field F] [DecidableEq F] in
/-- A covered action's carried pair is among the covered tachygrams. -/
theorem pair_le_coveredTachygrams {a : Δ × F × F} (ha : a ∈ actions) (fees : List (Φ × F)) :
    ({a.2.1, a.2.2} : Multiset F) ≤ (coveredTachygrams actions fees : Multiset F) := by
  have hsub : List.Sublist [a.2.1, a.2.2] (actions.flatMap fun a => [a.2.1, a.2.2]) := by
    induction actions with
    | nil => cases ha
    | cons b l ih =>
      rw [List.flatMap_cons]
      rcases List.mem_cons.mp ha with rfl | h
      · exact List.sublist_append_left _ _
      · exact (ih h).trans (List.sublist_append_right _ _)
  exact Multiset.coe_le.mpr (hsub.trans (List.sublist_append_left _ _)).subperm

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

omit [DecidableEq F] in
/-- A verified bundle publishes its own fee change. -/
theorem BundleVerified.fee_change_published
    (h : BundleVerified IsFee epoch R actionDigest feeDigest actions fee adjunctFees stamp) :
    fee.2 ∈ stamp.tachygrams := by
  have hmem : fee.2 ∈ (coveredTachygrams actions (fee :: adjunctFees) : Multiset F) := by
    simp [coveredTachygrams]
  rw [← h.tachygrams_covered] at hmem
  exact Multiset.mem_coe.mp hmem

end Tachyon
