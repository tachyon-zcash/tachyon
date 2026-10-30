import Tachyon.ChainSpends
import Tachyon.Foundation.RelationWitness

/-!
# Spent supply

Each covered digest of a traced bundle creates the note its leaf creates: an output note, or the
change note of a fee leaf (`TracedBundle.createdAt`). Summed over every bundle position and covered
digest, this is the value the chain creates (`chainCreated`).

A spend's creation reads that value at its bundle position and leaf digest: the leaf covering the
digest creates the spend's note, or a tachygram has two preimages
(`Creation.createdAtOrCollision`). Spends whose creations share no bundle position and leaf digest
therefore spend at most the value the chain creates (`spentWithinCreatedOrCollision`). With
`spendsUnsharedOrBreak`, any family of spends at distinct positions spends at most the chain's
created value, or a break is computed (`spentWithinCreatedOrBreak`).
-/

namespace Tachyon

open Polynomial AnchorBreaks SourceQueryBreaks

universe w

variable {F A : Type*} [Field F] [DecidableEq F] {H : TachygramHash F}
  {Opens : F → ℤ → Option ℕ → Type*} {R : ℕ → F → Multiset F} {epoch : A → ℕ}

/-- The value of the note a leaf creates: an output note's value, or a fee leaf's change. -/
def TachygramLeaf.createdValue {d : F} {a : A} : TachygramLeaf H Opens R epoch d a → ℕ
  | .spend .. => 0
  | .output n .. => n.value
  | .fee _ _ change .. => change

omit [Field F] [DecidableEq F] in
theorem TachygramLeaf.Creates.createdValue_eq {d : F} {a : A} {n : Note F}
    {k : TachygramLeaf H Opens R epoch d a} (h : k.Creates n) : k.createdValue = n.value := by
  cases k with
  | spend => exact h.elim
  | output => subst h; rfl
  | fee => subst h; rfl

variable {IsFee : F → Prop} {Δ Φ : Type w} {actionDigest : Δ → F} {feeDigest : Φ → F}
  {Lift : Stamp F A → A → Type w}
  {bundles : List (TracedBundle IsFee epoch R actionDigest feeDigest H Opens Lift)}

/-- The value of the note created at digest `d` of a bundle: the note the leaf covering `d`
creates, or nothing for an uncovered digest. -/
def TracedBundle.createdAt (b : TracedBundle IsFee epoch R actionDigest feeDigest H Opens Lift)
    (d : F) : ℕ :=
  if h : d ∈ coveredDigests actionDigest feeDigest b.descs (b.fee :: b.adjunctFees) then
    (b.trace.findLeaf b.actions h).1.provenance.createdValue
  else 0

variable (bundles) in
/-- The value created on a chain of traced bundles: the notes created at every covered digest of
every bundle. -/
def chainCreated : ℕ :=
  ∑ j : Fin bundles.length, ∑ d ∈ (coveredDigests actionDigest feeDigest bundles[j].descs
    (bundles[j].fee :: bundles[j].adjunctFees)).toFinset, bundles[j].createdAt d

/-- The value created at a creation's bundle position and leaf digest is its note's value, or a
tachygram has two preimages. -/
def Creation.createdAtOrCollision {n : Note F} {e : ℕ} (c : Creation bundles n e) :
    (bundles[c.index].createdAt c.leaf.digest = n.value) ⊕' TachygramCollision H :=
  match (bundles[c.index].trace.findLeaf bundles[c.index].actions
      c.covered).1.provenance.createsOrCollision (n := n) (by
        have hfound := (bundles[c.index].trace.findLeaf bundles[c.index].actions c.covered).2
        have hepoch := hfound.2.2.trans
          ((congrArg epoch bundles[c.index].anchor).trans c.anchorEpoch.symm)
        rw [hepoch, hfound.2.1]
        exact c.creates.mem) with
  | .inl hcreates =>
      .inl (by rw [TracedBundle.createdAt, dif_pos c.covered]; exact hcreates.createdValue_eq)
  | .inr collision => .inr collision

/-- Creations of notes `n i` that pairwise share no bundle position and leaf digest create at
least the notes' total value on the chain, or a tachygram has two preimages. -/
def spentWithinCreatedOrCollision {k : ℕ} {n : Fin k → Note F} {e : Fin k → ℕ}
    (c : ∀ i, Creation bundles (n i) (e i))
    (hunshared : ∀ i j, i ≠ j →
      ¬ ((c i).index = (c j).index ∧ (c i).leaf.digest = (c j).leaf.digest)) :
    (∑ i, (n i).value ≤ chainCreated bundles) ⊕' TachygramCollision H :=
  match finForallOrRelationWitness fun i => (c i).createdAtOrCollision with
  | .inr collision => .inr collision
  | .inl hcreated => .inl <| by
      let key : Fin k → (Σ _ : Fin bundles.length, F) := fun i => ⟨(c i).index, (c i).leaf.digest⟩
      have hinj : Set.InjOn key ↑(Finset.univ : Finset (Fin k)) := fun i _ j _ h => by
        by_contra hij
        obtain ⟨hindex, hdigest⟩ := Sigma.mk.inj_iff.mp h
        exact hunshared i j hij ⟨hindex, eq_of_heq hdigest⟩
      calc ∑ i, (n i).value
          = ∑ i, bundles[(key i).1].createdAt (key i).2 :=
            Finset.sum_congr rfl fun i _ => (hcreated i).symm
        _ = ∑ x ∈ Finset.univ.image key, bundles[x.1].createdAt x.2 :=
            (Finset.sum_image (f := fun x => bundles[x.1].createdAt x.2) hinj).symm
        _ ≤ ∑ x ∈ Finset.univ.sigma fun j : Fin bundles.length =>
              (coveredDigests actionDigest feeDigest bundles[j].descs
                (bundles[j].fee :: bundles[j].adjunctFees)).toFinset,
              bundles[x.1].createdAt x.2 := by
            refine Finset.sum_le_sum_of_subset fun x hx => ?_
            obtain ⟨i, -, rfl⟩ := Finset.mem_image.mp hx
            exact Finset.mem_sigma.mpr ⟨Finset.mem_univ _, Multiset.mem_toFinset.mpr (c i).covered⟩
        _ = chainCreated bundles := Finset.sum_sigma _ _ _

variable {C P : Type*} [Monoid P] [OpeningSemantics P F] [DecidableEq P] [DecidableEq C]
  [DecidableEq A] {m : Model P C A ℕ} {ValidBucket : QrBucket F A → Prop}
  {Query : QrBucket F A → F → Type*} {nf : F → ℕ → F} {Q : Sort*} {acceptedAnchor : ℕ → A → Prop}

/-- A family of spends at distinct positions on a valid chain of traced bundles spends at most the
value the chain creates, or the first failing spend or pair yields a break. -/
def spentWithinCreatedOrBreak
    (oracle : ∀ b v, Query b v →
      Profiled.QueryComplete (bundles.map TracedBundle.toChain) b v ⊕' Q)
    (hchain : Chain.Valid epoch acceptedAnchor (bundles.map TracedBundle.toChain)) {k : ℕ}
    (spends : Fin k → ChainSpend m ValidBucket Query nf bundles)
    (hdistinct : Function.Injective fun i => ((spends i).bundle.val, (spends i).position.val)) :
    (∑ i, (spends i).note.value ≤ chainCreated bundles) ⊕'
      ((ObservedBreak m ⊕' Q) ⊕' TachygramCollision H) :=
  match spendsUnsharedOrBreak oracle hchain spends hdistinct with
  | .inr broken => .inr broken
  | .inl ⟨c, hunshared⟩ =>
      match spentWithinCreatedOrCollision c hunshared with
      | .inl hspent => .inl hspent
      | .inr collision => .inr (.inr collision)

end Tachyon
