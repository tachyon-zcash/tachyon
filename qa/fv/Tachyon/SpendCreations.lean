import Tachyon.PaidCreations
import Tachyon.PublicationNodes

/-!
# Spend creations

A spendable lineage starts where its note commitment was published. `SpendableInit` opens the
creation stamp's tachygram set at `cm`, and `QrSpendableInit` opens its bucket at `cm`. Given a
publication-linked node at the creation anchor (`PublicationNodes.LinkedNode`) or certified source
data for the bucket (`BucketPublication.CertifiedSource`), the commitment is published at the
lineage's start epoch, or the comparison computes a collision
(`SpendableTrace.startPublishedOrBreak`).

On a chain of traced bundles, each spend's note thus has a creation at its lineage's start
(`SpendableTrace.creationOrBreak`). Two spends of notes on that chain, the first earlier in chain
order, have creations at distinct bundle positions or distinct leaf digests, or compute a break
(`distinctCreationsOrBreak`). Each creation is debited in its own bundle
(`Creation.debitOrBreak`), so every spend consumes its own paid creation, and a commitment
published again pays for the spend of that second note.
-/

namespace Tachyon

open Polynomial AnchorBreaks SourceQueryBreaks

universe w

variable {F C A P : Type*} [Field F] [Monoid P] [OpeningSemantics P F] {m : Model P C A ℕ}
  {ValidBucket : QrBucket F A → Prop} {Query : QrBucket F A → F → Type*} {nf : F → ℕ → F}

/-- A publication-linked node at a `SpendableInit` creation anchor. -/
structure InitEvidence (m : Model P C A ℕ) (chain : List (Chain.Stamp F A)) (anchor : A) where
  epoch : ℕ
  archive : PublicationNodes.LinkedNode m OpeningSemantics.interpret chain epoch anchor

/-- Certified source data for a `QrSpendableInit` bucket. -/
structure BucketEvidence (m : Model P C A ℕ) (chain : List (Chain.Stamp F A)) (b : QrBucket F A)
    where
  first : F
  view : EvidenceQuery.BucketView F A
  source : BucketPublication.CertifiedSource m OpeningSemantics.interpret chain first view
  bucket : view.bucket = b

/-- Publication evidence for the root of a spendable lineage. -/
def SpendableTrace.RootEvidence (chain : List (Chain.Stamp F A)) {start : ℕ}
    {sp : NoteSpendable F A} : SpendableTrace m ValidBucket Query nf start sp → Type _
  | .init previous contents e .. => InitEvidence m chain (m.nextStamp previous e contents)
  | .qrInit b .. => BucketEvidence m chain b.bucket
  | .lift previous .. => previous.RootEvidence chain

variable [DecidableEq P] [DecidableEq C] [DecidableEq A] {chain : List (Chain.Stamp F A)}

/-- A lineage's note commitment is published at the lineage's start epoch, or the root's
publication evidence computes a collision. -/
def SpendableTrace.startPublishedOrBreak {start : ℕ} {sp : NoteSpendable F A} :
    (t : SpendableTrace m ValidBucket Query nf start sp) → t.RootEvidence chain →
      Chain.published chain start sp.cm ⊕' ObservedBreak m
  | .init previous contents e _ hroot _, ev =>
      ev.archive.publicationOrBreak previous e contents _ rfl hroot
  | .qrInit (nu := nu) _ _ _ _ _ _ _ hroot, ev =>
      mapOutcome (ev.source.publicationOrBreak nu.cm (by rw [ev.bucket]; exact hroot))
        fun h => by rw [← ev.bucket]; exact h
  | .lift previous .., ev => previous.startPublishedOrBreak ev

variable [DecidableEq F] {IsFee : F → Prop} {epoch : A → ℕ} {R : ℕ → F → Multiset F}
  {Δ Φ : Type w} {actionDigest : Δ → F} {feeDigest : Φ → F} {H : TachygramHash F}
  {Opens : F → ℤ → Type*} {Lift : Stamp F A → A → Type w}
  {bundles : List (TracedBundle IsFee epoch R actionDigest feeDigest H Opens Lift)}

/-- The note behind a lineage on a chain of traced bundles has a creation at the lineage's start,
or a collision is computed. -/
def SpendableTrace.creationOrBreak (hbundles : chain = bundles.map TracedBundle.toChain)
    {start : ℕ} {sp : NoteSpendable F A} (t : SpendableTrace m ValidBucket Query nf start sp)
    (ev : t.RootEvidence chain) {n : Note F} (hn : sp.cm = H.noteCommit n) :
    Creation bundles n start ⊕' (ObservedBreak m ⊕' TachygramCollision H) :=
  match t.startPublishedOrBreak ev with
  | .inr broken => .inr (.inl broken)
  | .inl hpub =>
      match creationOrCollision (n := n) (hbundles ▸ hn ▸ hpub) with
      | .inl creation => .inl creation
      | .inr collision => .inr (.inr collision)

variable {Q : Sort*} {sp₁ sp₂ : NoteSpendable F A} {l₁ l₂ : List (Chain.Stamp F A)}
  {acceptedAnchor : ℕ → A → Prop} {descs₁ descs₂ : List Δ} {fee₁ fee₂ : Φ}
  {adjunctFees₁ adjunctFees₂ : List Φ} {stamp₁ stamp₂ : PublishedStamp F A} {p₁ p₂ start₁ start : ℕ}
  {δ₁ δ₂ : Δ}

/-- Two verified bundles on a valid chain of traced bundles spend notes `n₁` and `n₂` from traced
spendables, the first earlier in chain order, each with publication evidence for its lineage's
root. Their notes have creations at the lineage starts that differ in bundle position or leaf
digest, or the pair computes a collision, the oracle's break, or a tachygram with two preimages. -/
def distinctCreationsOrBreak (oracle : ∀ b v, Query b v → Profiled.QueryComplete chain b v ⊕' Q)
    (hchain : Chain.Valid epoch acceptedAnchor chain)
    (hbundles : chain = bundles.map TracedBundle.toChain)
    (h₁ : BundleVerified IsFee epoch R actionDigest feeDigest descs₁ fee₁ adjunctFees₁ stamp₁)
    (h₂ : BundleVerified IsFee epoch R actionDigest feeDigest descs₂ fee₂ adjunctFees₂ stamp₂)
    (hsplit : chain = l₁ ++ ⟨stamp₁.anchor, stamp₁.tachygrams, p₁⟩ :: l₂)
    (hs₂ : ⟨stamp₂.anchor, stamp₂.tachygrams, p₂⟩ ∈ l₂)
    (hδ₁ : δ₁ ∈ descs₁) (hδ₂ : δ₂ ∈ descs₂)
    (t₁ : SpendableTrace m ValidBucket Query nf start₁ sp₁)
    (t₂ : SpendableTrace m ValidBucket Query nf start sp₂)
    (ev₁ : t₁.RootEvidence chain) (ev₂ : t₂.RootEvidence chain)
    (node₁ : NodeTrace m (epoch stamp₁.anchor) sp₁.anchor)
    (node₂ : NodeTrace m (epoch stamp₂.anchor) sp₂.anchor)
    (haction₁ : SpendAction R (epoch stamp₁.anchor) (spendBind nf sp₁) (actionDigest δ₁))
    (haction₂ : SpendAction R (epoch stamp₂.anchor) (spendBind nf sp₂) (actionDigest δ₂))
    {n₁ n₂ : Note F} (hn₁ : sp₁.cm = H.noteCommit n₁) (hn₂ : sp₂.cm = H.noteCommit n₂) :
    {p : Creation bundles n₁ start₁ × Creation bundles n₂ start //
      ¬ (p.1.index = p.2.index ∧ p.1.leaf.digest = p.2.leaf.digest)} ⊕'
      ((ObservedBreak m ⊕' Q) ⊕' TachygramCollision H) :=
  match t₁.creationOrBreak hbundles ev₁ hn₁, t₂.creationOrBreak hbundles ev₂ hn₂ with
  | .inr (.inl broken), _ => .inr (.inl (.inl broken))
  | .inr (.inr collision), _ => .inr (.inr collision)
  | .inl _, .inr (.inl broken) => .inr (.inl (.inl broken))
  | .inl _, .inr (.inr collision) => .inr (.inr collision)
  | .inl c₁, .inl c₂ =>
      if hshared : c₁.index = c₂.index ∧ c₁.leaf.digest = c₂.leaf.digest then
        match sharedCreationBreak oracle hchain h₁ h₂ hsplit hs₂ hδ₁ hδ₂ t₁ t₂ node₁ node₂
            haction₁ haction₂ hn₁ hn₂ c₁ c₂ hshared.1 hshared.2 with
        | .inl (.inl witness) => .inr (.inl (.inl ⟨_, _, witness⟩))
        | .inl (.inr broken) => .inr (.inl (.inr broken))
        | .inr collision => .inr (.inr collision)
      else .inl ⟨(c₁, c₂), hshared⟩

end Tachyon
