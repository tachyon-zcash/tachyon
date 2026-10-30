import Tachyon.SpendCreations

/-!
# Spends within one bundle

`distinctCreationsOrBreak` covers two spends in different stamps. Two spends at distinct descriptor
positions of one verified bundle share its anchor, so each spend leaf publishes its note's nullifier
pair at the anchor's epoch, or its spendable's anchor computes a collision. Covered leaves of one
bundle share no tachygram, so the two spends cannot be of one note (`sameBundleSpendBreak`). Their
notes' creations then differ in bundle position or leaf digest, or a break is computed
(`sameBundleDistinctCreationsOrBreak`). With `distinctCreationsOrBreak`, any two distinct spends on
a chain of traced bundles consume distinct creations, or compute a break.
-/

namespace Tachyon

open Polynomial AnchorBreaks SourceQueryBreaks

universe w

variable {F C A P : Type*} [Field F] [DecidableEq F] [Monoid P] [OpeningSemantics P F]
  [DecidableEq P] [DecidableEq C] [DecidableEq A] {m : Model P C A ℕ}
  {ValidBucket : QrBucket F A → Prop} {Query : QrBucket F A → F → Type*} {nf : F → ℕ → F}
  {IsFee : F → Prop} {epoch : A → ℕ} {R : ℕ → F → Multiset F} {Δ Φ : Type w}
  {actionDigest : Δ → F} {feeDigest : Φ → F} {descs l₁ l₂ : List Δ} {fee : Φ}
  {adjunctFees : List Φ} {stamp : PublishedStamp F A} {δ₁ δ₂ : Δ} {sp₁ sp₂ : NoteSpendable F A}
  {start₁ start₂ : ℕ}

/-- Two spends at distinct descriptor positions of one verified bundle, from traced spendables of
one note anchored at traced chain nodes of the bundle's anchor epoch, compute a collision scoped to
the two node traces and the spendables' anchor preimages. -/
def sameBundleSpendBreak
    (h : BundleVerified IsFee epoch R actionDigest feeDigest descs fee adjunctFees stamp)
    (hsplit : descs = l₁ ++ δ₁ :: l₂) (hδ₂ : δ₂ ∈ l₂)
    (t₁ : SpendableTrace m ValidBucket Query nf start₁ sp₁)
    (t₂ : SpendableTrace m ValidBucket Query nf start₂ sp₂) (hcm : sp₁.cm = sp₂.cm)
    (node₁ : NodeTrace m (epoch stamp.anchor) sp₁.anchor)
    (node₂ : NodeTrace m (epoch stamp.anchor) sp₂.anchor)
    (haction₁ : SpendAction R (epoch stamp.anchor) (spendBind nf sp₁) (actionDigest δ₁))
    (haction₂ : SpendAction R (epoch stamp.anchor) (spendBind nf sp₂) (actionDigest δ₂)) :
    ScopedBreak m (node₁.openings ++ node₂.openings)
      ((t₁.anchorInput :: node₁.inputs) ++ (t₂.anchorInput :: node₂.inputs)) :=
  match t₁.spendPairOrBreak node₁ haction₁ with
  | .inr witness =>
      witness.weaken (fun _ h => List.mem_append_left _ h) (fun _ h => List.mem_append_left _ h)
  | .inl hpair₁ =>
      match t₂.spendPairOrBreak node₂ haction₂ with
      | .inr witness =>
          witness.weaken (fun _ h => List.mem_append_right _ h)
            (fun _ h => List.mem_append_right _ h)
      | .inl hpair₂ => False.elim <| by
          have hdisjoint := h.descs_disjoint hsplit hδ₂
          rw [hpair₁, hpair₂, hcm] at hdisjoint
          exact Multiset.disjoint_left.mp hdisjoint (Multiset.mem_cons_self _ _)
            (Multiset.mem_cons_self _ _)

variable {chain : List (Chain.Stamp F A)} {H : TachygramHash F} {Opens : F → ℤ → Option ℕ → Type*}
  {Lift : Stamp F A → A → Type w}
  {bundles : List (TracedBundle IsFee epoch R actionDigest feeDigest H Opens Lift)}

/-- Two spends at distinct descriptor positions of one verified bundle on a chain of traced
bundles, each with publication evidence for its lineage's root, have creations that differ in
bundle position or leaf digest, or compute a collision or a tachygram with two preimages. -/
def sameBundleDistinctCreationsOrBreak (hbundles : chain = bundles.map TracedBundle.toChain)
    (h : BundleVerified IsFee epoch R actionDigest feeDigest descs fee adjunctFees stamp)
    (hsplit : descs = l₁ ++ δ₁ :: l₂) (hδ₂ : δ₂ ∈ l₂)
    (t₁ : SpendableTrace m ValidBucket Query nf start₁ sp₁)
    (t₂ : SpendableTrace m ValidBucket Query nf start₂ sp₂)
    (ev₁ : t₁.RootEvidence chain) (ev₂ : t₂.RootEvidence chain)
    (node₁ : NodeTrace m (epoch stamp.anchor) sp₁.anchor)
    (node₂ : NodeTrace m (epoch stamp.anchor) sp₂.anchor)
    (haction₁ : SpendAction R (epoch stamp.anchor) (spendBind nf sp₁) (actionDigest δ₁))
    (haction₂ : SpendAction R (epoch stamp.anchor) (spendBind nf sp₂) (actionDigest δ₂))
    {n₁ n₂ : Note F} (hn₁ : sp₁.cm = H.noteCommit n₁) (hn₂ : sp₂.cm = H.noteCommit n₂) :
    {p : Creation bundles n₁ start₁ × Creation bundles n₂ start₂ //
      ¬ (p.1.index = p.2.index ∧ p.1.leaf.digest = p.2.leaf.digest)} ⊕'
      (ObservedBreak m ⊕' TachygramCollision H) :=
  match t₁.creationOrBreak hbundles ev₁ hn₁, t₂.creationOrBreak hbundles ev₂ hn₂ with
  | .inr broken, _ => .inr broken
  | .inl _, .inr broken => .inr broken
  | .inl c₁, .inl c₂ =>
      if hshared : c₁.index = c₂.index ∧ c₁.leaf.digest = c₂.leaf.digest then
        match c₁.sameNoteOrCollision c₂ hshared.1 hshared.2 with
        | .inr collision => .inr (.inr collision)
        | .inl hnote =>
            .inr (.inl ⟨_, _, sameBundleSpendBreak h hsplit hδ₂ t₁ t₂
              (by rw [hn₁, hn₂, hnote]) node₁ node₂ haction₁ haction₂⟩)
      else .inl ⟨(c₁, c₂), hshared⟩

end Tachyon
