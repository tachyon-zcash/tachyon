import Tachyon.LineageStarts
import Tachyon.PublishedNotes

/-!
# Note creations

A chain is a list of verified bundles, each traced with its leaves' kinds (`TracedBundle`). A note
is created at epoch `e` by a bundle published at `e`, through a covered positive leaf that outputs
the note or whose change note it is (`Creation`). A note commitment published at `e` has such a
creation, or a tachygram has two preimages (`creationOrCollision`).

One creation pays for at most one spend: two spends whose notes' creations share a bundle and a
leaf digest compute a break (`sharedCreationBreak`). The two creations name one note, or a tachygram
has two preimages. They lie in one bundle, so the two lineages start in one epoch, and
`sameStartBreak` applies. A spend whose lineage starts at a publication of its note commitment
therefore consumes a creation no other spend consumes, and a commitment published twice is two
creations, each paid by its own bundle.
-/

namespace Tachyon

open Polynomial AnchorBreaks

universe u v w x

variable {F : Type u} {A : Type v} [Field F] [DecidableEq F] {IsFee : F → Prop} {epoch : A → ℕ}
  {R : ℕ → F → Multiset F} {Δ Φ : Type w} {actionDigest : Δ → F} {feeDigest : Φ → F}
  {H : TachygramHash F} {Opens : F → ℤ → Type x} {Lift : Stamp F A → A → Type w}

omit [Field F] [DecidableEq F] in
theorem TachygramLeaf.Creates.mem {d : F} {a : A} {n : Note F} {k : TachygramLeaf H Opens R epoch d a}
    (h : k.Creates n) : H.noteCommit n ∈ R (epoch a) d := by
  cases k with
  | spend => exact h.elim
  | output n' _ hR => rw [hR, ← h]; simp
  | fee maxFee _ change _ _ hR => rw [hR, ← h]; simp

omit [Field F] [DecidableEq F] in
theorem TachygramLeaf.Creates.unique {d : F} {a : A} {n₁ n₂ : Note F}
    {k : TachygramLeaf H Opens R epoch d a} (h₁ : k.Creates n₁) (h₂ : k.Creates n₂) : n₁ = n₂ := by
  cases k with
  | spend => exact h₁.elim
  | output => exact h₁.symm.trans h₂
  | fee => exact h₁.symm.trans h₂

/-- Two leaves with one tachygram multiset create one note, or a tachygram has two preimages. -/
def TachygramLeaf.sameCreationOrCollision {d₁ d₂ : F} {a₁ a₂ : A} {n₁ n₂ : Note F}
    {k₁ : TachygramLeaf H Opens R epoch d₁ a₁} (k₂ : TachygramLeaf H Opens R epoch d₂ a₂)
    (hR : R (epoch a₁) d₁ = R (epoch a₂) d₂) (h₁ : k₁.Creates n₁) (h₂ : k₂.Creates n₂) :
    (n₁ = n₂) ⊕' TachygramCollision H :=
  match k₂.createsOrCollision (n := n₁) (hR ▸ h₁.mem) with
  | .inl h₂' => .inl (h₂'.unique h₂)
  | .inr collision => .inr collision

variable (IsFee epoch R actionDigest feeDigest H Opens Lift) in
/-- A verified bundle published at `publication`, with a stamp trace of its leaves' kinds over a
header that covers its digests at the published anchor. -/
structure TracedBundle where
  descs : List Δ
  fee : Φ
  adjunctFees : List Φ
  stamp : PublishedStamp F A
  publication : ℕ
  verified : BundleVerified IsFee epoch R actionDigest feeDigest descs fee adjunctFees stamp
  header : Stamp F A
  trace : StampTrace IsFee epoch R (TachygramLeaf H Opens R epoch) Lift header
  actions : header.actions = setPoly (coveredDigests actionDigest feeDigest descs (fee :: adjunctFees))
  anchor : header.anchor = stamp.anchor

/-- The bundle's stamp as included in a block. -/
def TracedBundle.toChain
    (b : TracedBundle IsFee epoch R actionDigest feeDigest H Opens Lift) : Chain.Stamp F A :=
  ⟨b.stamp.anchor, b.stamp.tachygrams, b.publication⟩

/-- Note `n` created at epoch `e`: a bundle published at `e` and a covered positive leaf of its
trace that outputs `n` or whose change note is `n`. -/
structure Creation (bundles : List (TracedBundle IsFee epoch R actionDigest feeDigest H Opens Lift))
    (n : Note F) (e : ℕ) where
  bundle : TracedBundle IsFee epoch R actionDigest feeDigest H Opens Lift
  mem : bundle ∈ bundles
  publication : bundle.publication = e
  leaf : LeafRecord (TachygramLeaf H Opens R epoch)
  positive : leaf ∈ bundle.trace.positive
  covered : leaf.digest ∈
    coveredDigests actionDigest feeDigest bundle.descs (bundle.fee :: bundle.adjunctFees)
  anchorEpoch : epoch leaf.anchor = epoch bundle.stamp.anchor
  creates : leaf.provenance.Creates n

variable {bundles : List (TracedBundle IsFee epoch R actionDigest feeDigest H Opens Lift)}

/-- A note commitment published at epoch `e` on a chain of traced bundles has a creation at `e`,
or a tachygram has two preimages. -/
def creationOrCollision {n : Note F} {e : ℕ}
    (hpub : Chain.published (bundles.map TracedBundle.toChain) e (H.noteCommit n)) :
    Creation bundles n e ⊕' TachygramCollision H :=
  match hfind : bundles.find?
      (fun b => decide (b.publication = e ∧ H.noteCommit n ∈ b.stamp.tachygrams)) with
  | some b =>
      have hb := List.mem_of_find?_eq_some hfind
      have hpred : b.publication = e ∧ H.noteCommit n ∈ b.stamp.tachygrams := by
        simpa using List.find?_some hfind
      match publishedNoteOrCollision b.verified b.trace b.actions b.anchor hpred.2 with
      | .inl ⟨l, hl, hcovered, hcreates⟩ =>
          .inl ⟨b, hb, hpred.1, l, hl, hcovered, by
            obtain ⟨_, -, -, hanchor⟩ := b.trace.spec
            exact (hanchor l (List.mem_append_left _ hl)).trans (congrArg epoch b.anchor),
            hcreates⟩
      | .inr collision => .inr collision
  | none => False.elim <| by
      obtain ⟨s, hs, hepoch, ht⟩ := hpub
      obtain ⟨b, hb, rfl⟩ := List.mem_map.mp hs
      exact List.find?_eq_none.mp hfind b hb (by simpa [TracedBundle.toChain] using ⟨hepoch, ht⟩)

/-- Two creations in one bundle at one leaf digest create one note, or a tachygram has two
preimages. -/
def Creation.sameNoteOrCollision {n₁ n₂ : Note F} {e₁ e₂ : ℕ} (c₁ : Creation bundles n₁ e₁)
    (c₂ : Creation bundles n₂ e₂) (hbundle : c₁.bundle = c₂.bundle)
    (hdigest : c₁.leaf.digest = c₂.leaf.digest) : (n₁ = n₂) ⊕' TachygramCollision H :=
  TachygramLeaf.sameCreationOrCollision c₂.leaf.provenance
    (by rw [c₁.anchorEpoch, c₂.anchorEpoch, hbundle, hdigest]) c₁.creates c₂.creates

variable {C P : Type*} [MulOneClass P] [OpeningSemantics P F] [DecidableEq P] [DecidableEq C]
  [DecidableEq A] {m : Model P C A ℕ} {ValidBucket : QrBucket F A → Prop}
  {Query : QrBucket F A → F → Type*} {Q : Sort*} {noteNf : F → ℕ → F} {sp₁ sp₂ : NoteSpendable F A}
  {chain l₁ l₂ : List (Chain.Stamp F A)} {acceptedAnchor : ℕ → A → Prop} {descs₁ descs₂ : List Δ}
  {fee₁ fee₂ : Φ} {adjunctFees₁ adjunctFees₂ : List Φ} {stamp₁ stamp₂ : PublishedStamp F A}
  {p₁ p₂ start₁ start : ℕ} {δ₁ δ₂ : Δ}

/-- Two verified bundles on a valid chain spend notes `n₁` and `n₂` from traced spendables, the
first earlier in chain order. If the notes' creations at the two lineage starts share a bundle and
a leaf digest, the pair computes a scoped collision, the oracle's break, or a tachygram with two
preimages. -/
def sharedCreationBreak (oracle : ∀ b v, Query b v → Profiled.QueryComplete chain b v ⊕' Q)
    (hchain : Chain.Valid epoch acceptedAnchor chain)
    (h₁ : BundleVerified IsFee epoch R actionDigest feeDigest descs₁ fee₁ adjunctFees₁ stamp₁)
    (h₂ : BundleVerified IsFee epoch R actionDigest feeDigest descs₂ fee₂ adjunctFees₂ stamp₂)
    (hsplit : chain = l₁ ++ ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ :: l₂)
    (hs₂ : ⟨stamp₂.anchor, stamp₂.tachygrams, p₂⟩ ∈ l₂)
    (hδ₁ : δ₁ ∈ descs₁) (hδ₂ : δ₂ ∈ descs₂)
    (t₁ : SpendableTrace m ValidBucket Query noteNf start₁ sp₁)
    (t₂ : SpendableTrace m ValidBucket Query noteNf start sp₂)
    (node₁ : NodeTrace m (epoch stamp₁.anchor) sp₁.anchor)
    (node₂ : NodeTrace m (epoch stamp₂.anchor) sp₂.anchor)
    (haction₁ : SpendAction R (epoch stamp₁.anchor) (spendBind noteNf sp₁) (actionDigest δ₁))
    (haction₂ : SpendAction R (epoch stamp₂.anchor) (spendBind noteNf sp₂) (actionDigest δ₂))
    {n₁ n₂ : Note F} (hn₁ : sp₁.cm = H.noteCommit n₁) (hn₂ : sp₂.cm = H.noteCommit n₂)
    (c₁ : Creation bundles n₁ start₁) (c₂ : Creation bundles n₂ start)
    (hbundle : c₁.bundle = c₂.bundle) (hdigest : c₁.leaf.digest = c₂.leaf.digest) :
    (ScopedBreak m (node₁.openings ++ node₂.openings)
      ((t₁.anchorInput :: node₁.inputs) ++ (t₂.anchorInput :: node₂.inputs)) ⊕' Q) ⊕'
      TachygramCollision H :=
  match c₁.sameNoteOrCollision c₂ hbundle hdigest with
  | .inr collision => .inr collision
  | .inl hnote =>
      .inl (sameStartBreak oracle hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂ t₁ t₂
        (by rw [hn₁, hn₂, hnote]) node₁ node₂ haction₁ haction₂
        (c₁.publication.symm.trans ((congrArg TracedBundle.publication hbundle).trans
          c₂.publication)))

end Tachyon
