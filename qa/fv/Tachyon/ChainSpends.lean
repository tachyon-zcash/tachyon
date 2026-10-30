import Tachyon.BundleSpendCreations
import Tachyon.Foundation.RelationWitness

/-!
# Chain spends

A spend on a chain of traced bundles sits at a bundle position and a descriptor position of that
bundle (`ChainSpend`). It carries its traced spendable, the chain archive's publication-linked node
at its anchor, certified source data for a `QrSpendableInit` root, its `SpendAction` and the note
behind its commitment. The archive supplies a `SpendableInit` root's evidence, so source data for
buckets is the only evidence from outside the chain.

Any two spends at distinct positions are ordered: by bundle position, or by descriptor position
within one bundle. `ChainSpend.unsharedOrBreak` decides whether their notes' creations share a
bundle position and leaf digest; if they do, it computes a break through `sharedCreationBreak` or
`sameBundleSpendBreak`. Over a family of spends at distinct positions, every spend's note has a
creation at its lineage start and no two spends share one, or the first failing spend or pair
yields a break (`spendsUnsharedOrBreak`). The spends thus map injectively into the chain's note
creations, each debited in its own bundle (`Creation.debitOrBreak`).
-/

namespace Tachyon

open Polynomial AnchorBreaks SourceQueryBreaks

universe w

/-- An index below `b` splits a list around its element, with the element at `b` after it. -/
theorem List.split_of_lt {α : Type*} {L : List α} {a b : ℕ} (hab : a < b) (hb : b < L.length) :
    L = L.take a ++ L[a] :: L.drop (a + 1) ∧ L[b] ∈ L.drop (a + 1) :=
  ⟨by rw [← List.drop_eq_getElem_cons]; exact (List.take_append_drop a L).symm,
    List.mem_iff_getElem.mpr ⟨b - (a + 1), by simp; omega, by rw [List.getElem_drop]; congr 1; omega⟩⟩

variable {F C A P : Type*} [Field F] [DecidableEq F] [Monoid P] [OpeningSemantics P F]
  [DecidableEq P] [DecidableEq C] [DecidableEq A] {m : Model P C A ℕ}
  {ValidBucket : QrBucket F A → Prop} {Query : QrBucket F A → F → Type*} {nf : F → ℕ → F}
  {IsFee : F → Prop} {epoch : A → ℕ} {R : ℕ → F → Multiset F} {Δ Φ : Type w}
  {actionDigest : Δ → F} {feeDigest : Φ → F} {H : TachygramHash F} {Opens : F → ℤ → Type*}
  {Lift : Stamp F A → A → Type w}
  {bundles : List (TracedBundle IsFee epoch R actionDigest feeDigest H Opens Lift)}

omit [DecidableEq F] [DecidableEq A] in
/-- An earlier bundle position splits the chain around its stamp, with the later stamp after it. -/
theorem TracedBundle.chain_split {a b : Fin bundles.length} (hab : a < b) :
    bundles.map TracedBundle.toChain = (bundles.map TracedBundle.toChain).take a ++
        ⟨bundles[a].stamp.anchor, bundles[a].stamp.tachygrams, bundles[a].publication⟩ ::
        (bundles.map TracedBundle.toChain).drop (a + 1) ∧
      ⟨bundles[b].stamp.anchor, bundles[b].stamp.tachygrams, bundles[b].publication⟩ ∈
        (bundles.map TracedBundle.toChain).drop (a + 1) := by
  have h := List.split_of_lt (L := bundles.map TracedBundle.toChain) hab (by simp)
  simp only [List.getElem_map, TracedBundle.toChain] at h
  exact h

variable (m ValidBucket Query nf bundles) in
/-- A spend at bundle position `bundle` and descriptor position `position`: its traced spendable,
certified source data for a `QrSpendableInit` root, the chain archive's publication-linked node at
its anchor in the bundle's anchor epoch, its `SpendAction`, and the note behind its commitment. -/
structure ChainSpend where
  bundle : Fin bundles.length
  position : Fin bundles[bundle].descs.length
  start : ℕ
  spendable : NoteSpendable F A
  trace : SpendableTrace m ValidBucket Query nf start spendable
  sources : trace.SourceEvidence (bundles.map TracedBundle.toChain)
  archive : PublicationNodes.LinkedNode m OpeningSemantics.interpret
    (bundles.map TracedBundle.toChain) (epoch bundles[bundle].stamp.anchor) spendable.anchor
  action : SpendAction R (epoch bundles[bundle].stamp.anchor) (spendBind nf spendable)
    (actionDigest bundles[bundle].descs[position])
  note : Note F
  commits : spendable.cm = H.noteCommit note

variable {Q : Sort*} {acceptedAnchor : ℕ → A → Prop}

/-- Two spends in different bundles, the first earlier: their notes' creations do not share a
bundle position and leaf digest, or a break is computed. -/
def ChainSpend.unsharedOfEarlier
    (oracle : ∀ b v, Query b v →
      Profiled.QueryComplete (bundles.map TracedBundle.toChain) b v ⊕' Q)
    (hchain : Chain.Valid epoch acceptedAnchor (bundles.map TracedBundle.toChain))
    (s s' : ChainSpend m ValidBucket Query nf bundles) (hlt : s.bundle < s'.bundle)
    (c : Creation bundles s.note s.start) (c' : Creation bundles s'.note s'.start) :
    ¬ (c.index = c'.index ∧ c.leaf.digest = c'.leaf.digest) ⊕'
      ((ObservedBreak m ⊕' Q) ⊕' TachygramCollision H) :=
  if hshared : c.index = c'.index ∧ c.leaf.digest = c'.leaf.digest then
    match sharedCreationBreak oracle hchain bundles[s.bundle].verified bundles[s'.bundle].verified
        (TracedBundle.chain_split hlt).1 (TracedBundle.chain_split hlt).2 (List.getElem_mem _)
        (List.getElem_mem _) s.trace s'.trace s.archive.node s'.archive.node s.action s'.action s.commits
        s'.commits c c' hshared.1 hshared.2 with
    | .inl (.inl witness) => .inr (.inl (.inl ⟨_, _, witness⟩))
    | .inl (.inr broken) => .inr (.inl (.inr broken))
    | .inr collision => .inr (.inr collision)
  else .inl hshared

/-- Two spends in one bundle, the first at an earlier descriptor position: their notes' creations
do not share a bundle position and leaf digest, or a break is computed. -/
def ChainSpend.unsharedOfSameBundle (s s' : ChainSpend m ValidBucket Query nf bundles)
    (hbundle : s.bundle = s'.bundle) (hposition : s.position.val < s'.position.val)
    (c : Creation bundles s.note s.start) (c' : Creation bundles s'.note s'.start) :
    ¬ (c.index = c'.index ∧ c.leaf.digest = c'.leaf.digest) ⊕'
      ((ObservedBreak m ⊕' Q) ⊕' TachygramCollision H) := by
  obtain ⟨b, position, start, spendable, trace, sources, archive, action, note, commits⟩ := s
  obtain ⟨b', position', start', spendable', trace', sources', archive', action', note', commits'⟩ :=
    s'
  dsimp only at hbundle hposition c c' ⊢
  subst hbundle
  exact if hshared : c.index = c'.index ∧ c.leaf.digest = c'.leaf.digest then
    match c.sameNoteOrCollision c' hshared.1 hshared.2 with
    | .inr collision => .inr (.inr collision)
    | .inl hnote =>
        .inr (.inl (.inl ⟨_, _, sameBundleSpendBreak bundles[b].verified
          (List.split_of_lt hposition position'.isLt).1
          (List.split_of_lt hposition position'.isLt).2 trace trace'
          (by rw [commits, commits', hnote]) archive.node archive'.node action action'⟩))
  else .inl hshared

/-- Two spends at distinct positions on a valid chain of traced bundles: their notes' creations do
not share a bundle position and leaf digest, or a break is computed. -/
def ChainSpend.unsharedOrBreak
    (oracle : ∀ b v, Query b v →
      Profiled.QueryComplete (bundles.map TracedBundle.toChain) b v ⊕' Q)
    (hchain : Chain.Valid epoch acceptedAnchor (bundles.map TracedBundle.toChain))
    (s s' : ChainSpend m ValidBucket Query nf bundles)
    (hne : (s.bundle.val, s.position.val) ≠ (s'.bundle.val, s'.position.val))
    (c : Creation bundles s.note s.start) (c' : Creation bundles s'.note s'.start) :
    ¬ (c.index = c'.index ∧ c.leaf.digest = c'.leaf.digest) ⊕'
      ((ObservedBreak m ⊕' Q) ⊕' TachygramCollision H) :=
  if hlt : s.bundle < s'.bundle then s.unsharedOfEarlier oracle hchain s' hlt c c'
  else if hgt : s'.bundle < s.bundle then
    mapOutcome (s'.unsharedOfEarlier oracle hchain s hgt c' c)
      fun hunshared hshared => hunshared ⟨hshared.1.symm, hshared.2.symm⟩
  else
    have hbundle : s.bundle = s'.bundle := Fin.le_antisymm (not_lt.mp hgt) (not_lt.mp hlt)
    if hposition : s.position.val < s'.position.val then
      s.unsharedOfSameBundle s' hbundle hposition c c'
    else
      mapOutcome (s'.unsharedOfSameBundle s hbundle.symm
          (by
            have hval : s.bundle.val = s'.bundle.val := congrArg Fin.val hbundle
            have hpos : s.position.val ≠ s'.position.val := fun h => hne (Prod.ext hval h)
            omega)
          c' c)
        fun hunshared hshared => hunshared ⟨hshared.1.symm, hshared.2.symm⟩

/-- A family of spends at distinct positions on a valid chain of traced bundles: every spend's note
has a creation at its lineage start and no two spends' creations share a bundle position and leaf
digest, or the first failing spend or pair yields a break. -/
def spendsUnsharedOrBreak
    (oracle : ∀ b v, Query b v →
      Profiled.QueryComplete (bundles.map TracedBundle.toChain) b v ⊕' Q)
    (hchain : Chain.Valid epoch acceptedAnchor (bundles.map TracedBundle.toChain)) {k : ℕ}
    (spends : Fin k → ChainSpend m ValidBucket Query nf bundles)
    (hdistinct : Function.Injective fun i => ((spends i).bundle.val, (spends i).position.val)) :
    {c : ∀ i, Creation bundles (spends i).note (spends i).start //
      ∀ i j, i ≠ j → ¬ ((c i).index = (c j).index ∧ (c i).leaf.digest = (c j).leaf.digest)} ⊕'
      ((ObservedBreak m ⊕' Q) ⊕' TachygramCollision H) :=
  match finForallOrRelationWitness fun i =>
      match (spends i).trace.creationOrBreak rfl
          ((spends i).trace.rootEvidence (spends i).archive (spends i).sources)
          (spends i).commits with
      | .inl creation => .inl creation
      | .inr (.inl broken) => .inr (.inl (.inl broken))
      | .inr (.inr collision) => .inr (.inr collision) with
  | .inr broken => .inr broken
  | .inl c =>
      match finForallOrRelationWitness fun i => finForallOrRelationWitness fun j =>
          if hij : i = j then .inl fun hne => absurd hij hne
          else mapOutcome ((spends i).unsharedOrBreak oracle hchain (spends j)
              (fun heq => hij (hdistinct heq)) (c i) (c j))
            fun hunshared _ => hunshared with
      | .inr broken => .inr broken
      | .inl hunshared => .inl ⟨c, hunshared⟩

end Tachyon
