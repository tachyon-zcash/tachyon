import Tachyon.BucketPublication

/-!
# Publication-linked node data for direct spendable initialization

`NodeTrace` certifies hash folds, not that their openings are public stamp
sets. `LinkedNode` additionally records a public chain entry and its semantic
opening at every stamp fold. Its forgetful map supplies the ordinary node trace.

`creationPublicationOrBreak` compares the freely witnessed creation fold with
this publication-linked node. A successful comparison pins epoch and opening,
so a root of the creation set is actually published. A different preimage or
opening yields the concrete finite-scope hash/commitment collision instead.

The supplied archive is publication-linked, not by itself a complete ledger
validator: order, recency, full block folding and canonical encoding are other
consensus obligations. Requiring membership and epoch alignment suffices for
this inclusion result even in that larger archive set. No bare `NodeTrace` or
one-way bucket-retention premise is used to infer publication.
-/

namespace Tachyon.PublicationNodes

open Polynomial AnchorBreaks SourceQueryBreaks

universe u v w z

variable {F : Type u} {P : Type v} {C : Type w} {A : Type z} [Field F] [Monoid P]

/-- Finite public provenance for each stamp opening in an anchor history. -/
inductive LinkedNode (m : Model P C A ℕ) (interpret : P →* F[X])
    (chain : List (Chain.Stamp F A)) : ℕ → A → Type (max u v z)
  | genesis : LinkedNode m interpret chain m.genesisEpoch m.genesis
  | stamp {e : ℕ} {a : A} (previous : LinkedNode m interpret chain e a)
      (entry : Chain.Stamp F A) (opening : P)
      (member : entry ∈ chain) (sameEpoch : entry.epoch = e)
      (encoding : interpret opening = setPoly (entry.tachygrams : Multiset F))
      (nonempty : opening ≠ 1) :
      LinkedNode m interpret chain e (m.nextStamp a e opening)
  | epoch {e : ℕ} {a : A} (previous : LinkedNode m interpret chain e a) (entered : ℕ)
      (nonGenesis : entered ≠ m.genesisEpoch) :
      LinkedNode m interpret chain entered (m.epochHash a entered)

def LinkedNode.node {m : Model P C A ℕ} {interpret : P →* F[X]}
    {chain : List (Chain.Stamp F A)} {e : ℕ} {a : A} :
    LinkedNode m interpret chain e a → NodeTrace m e a
  | .genesis => .genesis
  | .stamp previous _ opening _ _ _ hne => .stamp previous.node opening hne
  | .epoch previous entered hne => .epoch previous.node entered hne

variable [DecidableEq P] [DecidableEq C] [DecidableEq A]

/-- The creation root is drawn from a public stamp at the creation epoch, or
this comparison computes a collision on the actual finite trace inputs. -/
def creationPublicationOrBreak (m : Model P C A ℕ) (interpret : P →* F[X])
    {chain : List (Chain.Stamp F A)} {e : ℕ} {anchor : A}
    (archive : LinkedNode m interpret chain e anchor)
    (previous : A) (creationEpoch : ℕ) (opening : P) (value : F)
    (hfold : m.nextStamp previous creationEpoch opening = anchor)
    (hroot : (interpret opening).eval value = 0) :
    (creationEpoch = e ∧ Chain.published chain creationEpoch value) ⊕'
      ScopedBreak m (opening :: archive.node.openings)
        (m.stampInput previous creationEpoch opening :: archive.node.inputs) := by
  cases archive with
  | genesis =>
    apply PSum.inr
    apply (crossDomainBreak m previous m.origin creationEpoch m.genesisEpoch opening hfold).weaken
    · intro x hx
      exact hx
    · intro x hx
      exact hx
  | epoch earlier entered _ =>
    apply PSum.inr
    apply (crossDomainBreak m previous _ creationEpoch e opening hfold).weaken
    · intro x hx
      simp only [LinkedNode.node, NodeTrace.openings, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
      aesop
    · intro x hx
      simp only [LinkedNode.node, NodeTrace.inputs, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
      aesop
  | stamp earlier entry actual member hepoch hencode _ =>
    cases stampEqOrBreak m previous _ creationEpoch e opening actual hfold with
    | inr witness =>
      apply PSum.inr
      apply witness.weaken
      · intro x hx
        simp only [LinkedNode.node, NodeTrace.openings, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
        aesop
      · intro x hx
        simp only [LinkedNode.node, NodeTrace.inputs, List.mem_cons, List.not_mem_nil, or_false] at hx ⊢
        aesop
    | inl equalities =>
      apply PSum.inl
      refine ⟨equalities.2.1, entry, member, hepoch.trans equalities.2.1.symm, ?_⟩
      have hpublic : (setPoly (entry.tachygrams : Multiset F)).eval value = 0 := by
        simpa only [equalities.2.2, hencode] using hroot
      rw [← IsRoot.def, ← mem_roots (setPoly_ne_zero _), roots_setPoly] at hpublic
      exact Multiset.mem_coe.mp hpublic

/-- A convenient common observed-break result for a caller composing the
direct-init publication proof with other authorization/lineage reductions. -/
def LinkedNode.publicationOrBreak {m : Model P C A ℕ} {interpret : P →* F[X]}
    {chain : List (Chain.Stamp F A)} {e : ℕ} {anchor : A}
    (archive : LinkedNode m interpret chain e anchor)
    (previous : A) (creationEpoch : ℕ) (opening : P) (value : F)
    (hfold : m.nextStamp previous creationEpoch opening = anchor)
    (hroot : (interpret opening).eval value = 0) :
    Chain.published chain creationEpoch value ⊕' ObservedBreak m :=
  match creationPublicationOrBreak m interpret archive previous creationEpoch opening value hfold hroot with
  | .inl result => .inl result.2
  | .inr witness => .inr ⟨_, _, witness⟩

end Tachyon.PublicationNodes
