import Tachyon.SetPoly
import Tachyon.Stamp

/-!
# Consensus anchor chain and tachygram window

This module models the chain-level consensus rules alongside the stamp proof tree:

1. **Anchor chain (`book/src/anchor.md`, `crates/tachyon/src/primitives/anchor.rs`)**:
   The pool anchor evolves by two domain-separated Poseidon folds:
   - `nextStamp` (`Tachyon-AnchorSt`), absorbing the current anchor, the containing block's epoch,
      and the affine coordinates of the bridge hash of a non-empty stamp's tachygram-set commitment.
      Here `nextStamp` abstracts that composition as a function of its polynomial opening.
   - `nextEpoch` (`Tachyon-AnchorEp`), absorbing the previous epoch's final anchor and the new
     epoch index.
   Under collision resistance and domain separation on the calls made (`HashLaw`), every reachable
   chain node has a unique epoch (`Node.epoch_unique`), and every `nextStamp` predecessor of a
   chain node belongs to the same epoch (`Node.of_nextStamp`).

2. **End-of-block anchors (`book/src/anchor.md`)**:
   Within a block at epoch `e`, each published stamp folds its tachygram set via `nextStamp`, and
   the state after the block's final stamp is an acknowledged end-of-block anchor (`BlockAnchor`).
   Epoch transitions fold via `nextEpoch`. Every end-of-block anchor is a reachable `Node`.

3. **Anchor spans and `StampLift` (`crates/tachyon/src/stamp/proof/pool.rs`, `stamp.rs`)**:
   `AnchorSpanSeed` folds only with `nextStamp`, and `AnchorSpanFuse` concatenates adjacent spans.
   When a lifted stamp's `anchor_end` is verified by consensus to lie on the chain, every anchor in
   the span (both `anchor_start` and the roots of `members`) lies on the chain in the same epoch
   (`SpanDerivable.node_epoch`, `StampLiftStep.node_same_epoch`, `StampLiftStep.epoch_eq`).
   This discharges the `epoch a = epoch s.anchor` hypothesis of `ActionsDerivable.lift` and
   `StampDerivable.lift` in `Tachyon/ProofTree.lean`.

4. **Anchor recency and two-epoch tachygram window (`book/src/tachygrams.md`, `nullifiers.md`)**:
   Consensus checks that every published stamp (`Chain.Stamp`) has a non-empty, duplicate-free
   tachygram list, an accepted anchor whose epoch is the publication epoch or the one just before
   (`StampAccepted.recency`), and tachygrams disjoint from all stamps published in the current and
   immediately preceding epoch (`Valid`). This guarantees squarefreeness (`Nodup`) of epoch
   tachygram accumulators (`Valid.nodup_epoch`, `Valid.nodup_two_epochs`) and rules out double
   spends in combination with the spendable lineage.
-/

namespace Tachyon.Chain

open Polynomial

variable {F A E : Type*}

section AnchorChain

variable [Field F]

/-! ## Anchor chain and hash laws -/

/-- The anchor-fold calls under consideration: `stamp a e c` is a call `nextStamp a e c`, and
`boundary a e` a call `nextEpoch a e`. -/
structure AnchorQueries (F A E : Type*) [Field F] where
  stamp : A → E → F[X] → Prop
  boundary : A → E → Prop

/-- Collision-resistance and domain-separation laws for the two Poseidon anchor folds
`Tachyon-AnchorSt` (`nextStamp`) and `Tachyon-AnchorEp` (`nextEpoch`) on the calls `q`, rooted at
`genesis` (`H_ep(0, 0)` at epoch `e₀`). A finite `q` without a collision satisfies it. -/
structure HashLaw (q : AnchorQueries F A E) (genesis : A) (e₀ : E)
    (nextStamp : A → E → F[X] → A) (nextEpoch : A → E → A) : Prop where
  nextStamp_inj : ∀ {a₁ a₂ : A} {e₁ e₂ : E} {c₁ c₂ : F[X]}, q.stamp a₁ e₁ c₁ → q.stamp a₂ e₂ c₂ →
    nextStamp a₁ e₁ c₁ = nextStamp a₂ e₂ c₂ → a₁ = a₂ ∧ e₁ = e₂ ∧ c₁ = c₂
  nextEpoch_inj : ∀ {a₁ a₂ : A} {e₁ e₂ : E}, q.boundary a₁ e₁ → q.boundary a₂ e₂ →
    nextEpoch a₁ e₁ = nextEpoch a₂ e₂ → a₁ = a₂ ∧ e₁ = e₂
  stamp_ne_epoch : ∀ {a₁ : A} {e₁ : E} {c₁ : F[X]} {a₂ : A} {e₂ : E}, q.stamp a₁ e₁ c₁ →
    q.boundary a₂ e₂ → nextStamp a₁ e₁ c₁ ≠ nextEpoch a₂ e₂
  stamp_ne_genesis : ∀ {a : A} {e : E} {c : F[X]}, q.stamp a e c → nextStamp a e c ≠ genesis
  epoch_ne_genesis : ∀ {a : A} {e : E}, q.boundary a e → e ≠ e₀ → nextEpoch a e ≠ genesis

/-- Reachable pool states in the consensus anchor chain over the calls `q`, indexed by their epoch.
`stamp` corresponds to `Anchor::next_stamp` (which rejects the empty set polynomial `1`), and
`epoch` corresponds to `Anchor::next_epoch` (which rejects the genesis epoch `e₀`). -/
inductive Node (q : AnchorQueries F A E) (genesis : A) (e₀ : E)
    (nextStamp : A → E → F[X] → A) (nextEpoch : A → E → A) : E → A → Prop
  | genesis : Node q genesis e₀ nextStamp nextEpoch e₀ genesis
  | stamp {e : E} {a : A} (c : F[X]) :
      Node q genesis e₀ nextStamp nextEpoch e a →
      c ≠ 1 → q.stamp a e c →
      Node q genesis e₀ nextStamp nextEpoch e (nextStamp a e c)
  | epoch {e e' : E} {a : A} :
      Node q genesis e₀ nextStamp nextEpoch e a →
      e' ≠ e₀ → q.boundary a e' →
      Node q genesis e₀ nextStamp nextEpoch e' (nextEpoch a e')

variable {q : AnchorQueries F A E} {genesis : A} {e₀ : E} {nextStamp : A → E → F[X] → A}
  {nextEpoch : A → E → A}

/-- Every reachable chain node belongs to a unique epoch. -/
theorem Node.epoch_unique (hlaw : HashLaw q genesis e₀ nextStamp nextEpoch)
    {e₁ e₂ : E} {a : A}
    (h₁ : Node q genesis e₀ nextStamp nextEpoch e₁ a)
    (h₂ : Node q genesis e₀ nextStamp nextEpoch e₂ a) : e₁ = e₂ := by
  generalize ha : a = a' at h₂
  cases h₁ with
  | genesis =>
    cases h₂ with
    | genesis => rfl
    | stamp _ _ _ hq => exact absurd ha.symm (hlaw.stamp_ne_genesis hq)
    | epoch _ he' hq => exact absurd ha.symm (hlaw.epoch_ne_genesis hq he')
  | stamp c₁ _ _ hq₁ =>
    cases h₂ with
    | genesis => exact absurd ha (hlaw.stamp_ne_genesis hq₁)
    | stamp c₂ _ _ hq₂ => exact (hlaw.nextStamp_inj hq₁ hq₂ ha).2.1
    | epoch _ _ hq₂ => exact absurd ha (hlaw.stamp_ne_epoch hq₁ hq₂)
  | epoch _ he₁ hq₁ =>
    cases h₂ with
    | genesis => exact absurd ha (hlaw.epoch_ne_genesis hq₁ he₁)
    | stamp _ _ _ hq₂ => exact absurd ha.symm (hlaw.stamp_ne_epoch hq₂ hq₁)
    | epoch _ _ hq₂ => exact (hlaw.nextEpoch_inj hq₁ hq₂ ha).2

/-- If the call `nextStamp a e_s c` is a chain node at epoch `e`, then `e_s = e` and its
predecessor `a` is also a chain node at epoch `e`. Because `nextStamp` cannot collide with
`nextEpoch` or `genesis`, a stamp fold never crosses an epoch boundary. -/
theorem Node.of_nextStamp (hlaw : HashLaw q genesis e₀ nextStamp nextEpoch)
    {e e_s : E} {a : A} {c : F[X]} (hq : q.stamp a e_s c)
    (h : Node q genesis e₀ nextStamp nextEpoch e (nextStamp a e_s c)) :
    e_s = e ∧ Node q genesis e₀ nextStamp nextEpoch e a := by
  generalize htarget : nextStamp a e_s c = target at h
  cases h with
  | genesis => exact absurd htarget (hlaw.stamp_ne_genesis hq)
  | stamp c' hprev _ hq' =>
    obtain ⟨rfl, rfl, _⟩ := hlaw.nextStamp_inj hq' hq htarget.symm
    exact ⟨rfl, hprev⟩
  | epoch _ _ hq' => exact absurd htarget (hlaw.stamp_ne_epoch hq hq')

/-- Fold a block's list of stamp tachygram-set polynomials into an anchor at epoch `e`.
A block that publishes no stamp leaves the anchor unchanged (`book/src/anchor.md`). -/
def foldBlock (nextStamp : A → E → F[X] → A) (e : E) (a : A) (stamps : List F[X]) : A :=
  stamps.foldl (fun acc c => nextStamp acc e c) a

/-- Every fold of `foldBlock nextStamp e a stamps` is a call in `q`. -/
def FoldQueried (q : AnchorQueries F A E) (nextStamp : A → E → F[X] → A) (e : E) (a : A)
    (stamps : List F[X]) : Prop :=
  ∀ P c S, P ++ c :: S = stamps → q.stamp (foldBlock nextStamp e a P) e c

theorem FoldQueried.append {e : E} {a : A} {L L' : List F[X]} :
    FoldQueried q nextStamp e a (L ++ L') ↔
      FoldQueried q nextStamp e a L ∧ FoldQueried q nextStamp e (foldBlock nextStamp e a L) L' := by
  constructor
  · intro h
    refine ⟨fun P c S hP => h P c (S ++ L') (by rw [← hP]; simp), fun P c S hP => ?_⟩
    have := h (L ++ P) c S (by rw [← hP]; simp)
    simpa [foldBlock, List.foldl_append] using this
  · rintro ⟨hL, hL'⟩ P c S hP
    rcases List.append_eq_append_iff.mp hP with ⟨M, rfl, hM⟩ | ⟨M, hL'eq, hM⟩
    · rcases M with _ | ⟨c', M⟩
      · simp only [List.nil_append] at hM
        simpa [foldBlock] using hL' [] c S hM
      · simp only [List.cons_append, List.cons.injEq] at hM
        obtain ⟨rfl, rfl⟩ := hM
        exact hL P c M rfl
    · subst hL'eq
      have := hL' M c S hM.symm
      simpa [foldBlock, List.foldl_append] using this

theorem FoldQueried.singleton {e : E} {a : A} {c : F[X]} (hq : q.stamp a e c) :
    FoldQueried q nextStamp e a [c] := by
  rintro (_ | ⟨x, P⟩) c' S h
  · obtain ⟨rfl, -⟩ := List.cons.inj h
    exact hq
  · simp at h

theorem Node.foldBlock {e : E} {a : A} {stamps : List F[X]}
    (ha : Node q genesis e₀ nextStamp nextEpoch e a)
    (hstamps : ∀ c ∈ stamps, c ≠ 1) (hq : FoldQueried q nextStamp e a stamps) :
    Node q genesis e₀ nextStamp nextEpoch e (foldBlock nextStamp e a stamps) := by
  induction stamps generalizing a with
  | nil => exact ha
  | cons c cs ih =>
    apply ih (ha.stamp c (hstamps c List.mem_cons_self) (hq [] c cs rfl))
    · intro c' hc'
      exact hstamps c' (List.mem_cons_of_mem c hc')
    · intro P c' S hP
      simpa [foldBlock] using hq (c :: P) c' S (by rw [← hP]; rfl)

/-- End-of-block anchors acknowledged by consensus (`book/src/anchor.md`), over the calls `q`.
Each block folds zero or more non-empty stamps at the current epoch; entering a new epoch `e'`
first applies the boundary digest `nextEpoch`. -/
inductive BlockAnchor (q : AnchorQueries F A E) (genesis : A) (e₀ : E)
    (nextStamp : A → E → F[X] → A) (nextEpoch : A → E → A) : E → A → Prop
  | genesis : BlockAnchor q genesis e₀ nextStamp nextEpoch e₀ genesis
  | block {e : E} {a : A} (stamps : List F[X]) :
      BlockAnchor q genesis e₀ nextStamp nextEpoch e a →
      (∀ c ∈ stamps, c ≠ 1) → FoldQueried q nextStamp e a stamps →
      BlockAnchor q genesis e₀ nextStamp nextEpoch e (foldBlock nextStamp e a stamps)
  | epochBlock {e e' : E} {a : A} (stamps : List F[X]) :
      BlockAnchor q genesis e₀ nextStamp nextEpoch e a →
      e' ≠ e₀ → q.boundary a e' →
      (∀ c ∈ stamps, c ≠ 1) → FoldQueried q nextStamp e' (nextEpoch a e') stamps →
      BlockAnchor q genesis e₀ nextStamp nextEpoch e'
        (foldBlock nextStamp e' (nextEpoch a e') stamps)

/-- Every acknowledged end-of-block anchor is a reachable chain `Node` at its block's epoch. -/
theorem BlockAnchor.toNode {e : E} {a : A}
    (h : BlockAnchor q genesis e₀ nextStamp nextEpoch e a) :
    Node q genesis e₀ nextStamp nextEpoch e a := by
  induction h with
  | genesis => exact Node.genesis
  | block stamps _ hne hq ih => exact ih.foldBlock hne hq
  | epochBlock stamps _ he' hb hne hq ih => exact (ih.epoch he' hb).foldBlock hne hq

/-! ## Anchor spans and `StampLift` epoch invariance -/

/-- Semantic `AnchorSpan` state: Rust header data is `(anchor_start, anchor_end)`;
`members` is output slot O0, idealized as its committed polynomial in `F[X]`. Slot O1 holds the
seed's tachygram set for its bridge hash; no lift reads it, so the model omits it. -/
structure AnchorSpan (F : Type*) [Field F] where
  anchor_start : F
  members : F[X]
  anchor_end : F

/-- Derivable `AnchorSpan` headers (`AnchorSpanSeed` and `AnchorSpanFuse` in
`crates/tachyon/src/stamp/proof/pool.rs`) over the calls `q`. Neither `anchor_start` nor `e` is
constrained at the seed; chain membership of `anchor_end` pins the entire span downstream. -/
inductive SpanDerivable (q : AnchorQueries F F E) (nextStamp : F → E → F[X] → F) :
    AnchorSpan F → Prop
  | seed (a : F) (e : E) (c : F[X]) :
      c ≠ 1 → q.stamp a e c →
      SpanDerivable q nextStamp ⟨a, setPoly {nextStamp a e c}, nextStamp a e c⟩
  | fuse {left right : AnchorSpan F} {combined : F[X]} :
      SpanDerivable q nextStamp left →
      SpanDerivable q nextStamp right →
      left.anchor_end = right.anchor_start →
      combined = left.members * right.members →
      SpanDerivable q nextStamp ⟨left.anchor_start, combined, right.anchor_end⟩

/-- The `StampLift` / `ActionLift` step relation (`crates/tachyon/src/stamp/proof/stamp.rs`):
`s.anchor` must either be a root of `span.members` or equal `span.anchor_start`, and the output
stamp moves to `span.anchor_end`. -/
def StampLiftStep (s : Tachyon.Stamp F F) (span : AnchorSpan F) (s' : Tachyon.Stamp F F) : Prop :=
  span.members.eval s.anchor * (s.anchor - span.anchor_start) = 0 ∧
  s' = { s with anchor := span.anchor_end }

variable {qF : AnchorQueries F F E} {genesisF : F} {nextStampF : F → E → F[X] → F}
  {nextEpochF : F → E → F}

/-- A set of anchors labelled by epoch that holds the predecessor of every call in `q` that lands
in it, at the member's epoch. Chain nodes form one (`Node.stampClosed`), and so do the anchors a
published chain reaches up to a bound (`OnChain.stampClosed`). -/
def StampClosed (q : AnchorQueries F A E) (nextStamp : A → E → F[X] → A)
    (Good : E → A → Prop) : Prop :=
  ∀ {e e_s : E} {a : A} {c : F[X]}, q.stamp a e_s c → Good e (nextStamp a e_s c) →
    e_s = e ∧ Good e a

theorem Node.stampClosed (hlaw : HashLaw q genesis e₀ nextStamp nextEpoch) :
    StampClosed q nextStamp (Node q genesis e₀ nextStamp nextEpoch) :=
  fun hq h => Node.of_nextStamp hlaw hq h

/-- If a derivable `AnchorSpan` ends on a member of a stamp-closed set at epoch `e`, then
`anchor_start` is a member at epoch `e`, and `members` is `setPoly M` for a multiset `M` of members
all at epoch `e`. -/
theorem SpanDerivable.node_epoch {Good : E → F → Prop} (hclosed : StampClosed qF nextStampF Good)
    {span : AnchorSpan F} (hspan : SpanDerivable qF nextStampF span)
    {e : E} (hend : Good e span.anchor_end) :
    Good e span.anchor_start ∧ ∃ M : Multiset F, span.members = setPoly M ∧ ∀ m ∈ M, Good e m := by
  induction hspan with
  | seed a e_s c _ hq =>
    obtain ⟨rfl, ha⟩ := hclosed hq hend
    refine ⟨ha, {nextStampF a e_s c}, rfl, ?_⟩
    intro m hm
    rw [Multiset.mem_singleton] at hm
    exact hm ▸ hend
  | fuse _ _ hjoin hcomb ihl ihr =>
    obtain ⟨hr_start, MR, hMR, hMR_nodes⟩ := ihr hend
    have hl_end : Good e _ := hjoin ▸ hr_start
    obtain ⟨hl_start, ML, hML, hML_nodes⟩ := ihl hl_end
    refine ⟨hl_start, ML + MR, ?_, ?_⟩
    · rw [hcomb, hML, hMR, setPoly_add]
    · intro m hm
      rw [Multiset.mem_add] at hm
      exact hm.elim (hML_nodes m) (hMR_nodes m)

/-- **Span argument for `StampLift`**: if `span` is derivable, `StampLiftStep s span s'` holds, and
`s'.anchor` is a member of a stamp-closed set at epoch `e`, such as a chain node, then `s.anchor`
is also a member at epoch `e`. -/
theorem StampLiftStep.node_same_epoch {Good : E → F → Prop}
    (hclosed : StampClosed qF nextStampF Good) {s s' : Tachyon.Stamp F F} {span : AnchorSpan F}
    (hspan : SpanDerivable qF nextStampF span)
    (hlift : StampLiftStep s span s')
    {e : E} (hend : Good e s'.anchor) : Good e s.anchor := by
  obtain ⟨heval, rfl⟩ := hlift
  obtain ⟨hstart, M, hM, hM_nodes⟩ := hspan.node_epoch hclosed hend
  rcases mul_eq_zero.mp heval with hmem | hstart_eq
  · have hroot : s.anchor ∈ (setPoly M).roots := by
      rw [mem_roots (setPoly_ne_zero M), IsRoot.def, ← hM]
      exact hmem
    rw [roots_setPoly] at hroot
    exact hM_nodes s.anchor hroot
  · rw [sub_eq_zero.mp hstart_eq]
    exact hstart

/-- Corollary in the form consumed by `ActionsDerivable.lift` and `StampDerivable.lift`
(`Tachyon/ProofTree.lean`): for any epoch labeling `epoch : F → E` that agrees with `Chain.Node`,
a `StampLiftStep` ending at a chain node preserves `epoch`. -/
theorem StampLiftStep.epoch_eq
    (hlaw : HashLaw qF genesisF e₀ nextStampF nextEpochF)
    {epoch : F → E}
    (hepoch : ∀ {e : E} {a : F}, Node qF genesisF e₀ nextStampF nextEpochF e a → epoch a = e)
    {s s' : Tachyon.Stamp F F} {span : AnchorSpan F}
    (hspan : SpanDerivable qF nextStampF span)
    (hlift : StampLiftStep s span s')
    {e : E} (hend : Node qF genesisF e₀ nextStampF nextEpochF e s'.anchor) :
    epoch s'.anchor = epoch s.anchor := by
  have hs : Node qF genesisF e₀ nextStampF nextEpochF e s.anchor :=
    hlift.node_same_epoch (Node.stampClosed hlaw) hspan hend
  rw [hepoch hend, hepoch hs]

end AnchorChain

/-! ## Block-level published stamps, anchor recency, and the two-epoch window -/

/-- A stamp as included in a block: its referenced pool `anchor`, the `tachygrams` its covered
bundles publish (each action's pair and each bundle's fee change), and the publication `epoch` of
the containing block. -/
structure Stamp (F A : Type*) where
  anchor : A
  tachygrams : List F
  epoch : ℕ

/-- Two epochs `e₁ ≤ e₂` lie in the two-epoch window when `e₂` is either `e₁` or `e₁ + 1`. -/
def InWindow (e₁ e₂ : ℕ) : Prop :=
  e₁ ≤ e₂ ∧ e₂ ≤ e₁ + 1

/-- Consensus acceptance of a single published stamp `s`:
1. `tachygrams` is non-empty (every covered bundle contributes its fee change).
2. `tachygrams` has no duplicates (`Bundle::verify_covered` rejects a repeated tachygram).
3. **Anchor membership**: `s.anchor` is an accepted end-of-block anchor at its epoch
   `epoch s.anchor`.
4. **Anchor recency**: `s.anchor`'s epoch is either the block's publication epoch `s.epoch` or the
   immediately preceding epoch (`epoch s.anchor ≤ s.epoch ∧ s.epoch ≤ epoch s.anchor + 1`). -/
structure StampAccepted (epoch : A → ℕ) (acceptedAnchor : ℕ → A → Prop)
    (s : Stamp F A) : Prop where
  tachygrams_ne_nil : s.tachygrams ≠ []
  tachygrams_nodup : s.tachygrams.Nodup
  anchor_accepted : acceptedAnchor (epoch s.anchor) s.anchor
  recency : InWindow (epoch s.anchor) s.epoch

/-- Consensus validity of a chain of published stamps (in chronological chain order):
1. Every stamp in `chain` satisfies `StampAccepted` (including anchor membership and recency).
2. Publication epochs are monotonically non-decreasing (`s₁.epoch ≤ s₂.epoch` for `s₁` before `s₂`).
3. **Two-epoch tachygram window**: for any earlier stamp `s₁` and later stamp `s₂` with
   `s₂.epoch ≤ s₁.epoch + 1`, their tachygram lists are disjoint. -/
structure Valid (epoch : A → ℕ) (acceptedAnchor : ℕ → A → Prop)
    (chain : List (Stamp F A)) : Prop where
  accepted : ∀ s ∈ chain, StampAccepted epoch acceptedAnchor s
  ordered : chain.Pairwise fun s₁ s₂ => s₁.epoch ≤ s₂.epoch
  window_disjoint : chain.Pairwise fun s₁ s₂ =>
    s₂.epoch ≤ s₁.epoch + 1 → s₁.tachygrams.Disjoint s₂.tachygrams

variable {epoch : A → ℕ} {acceptedAnchor : ℕ → A → Prop} {chain : List (Stamp F A)}

/-- Tachygram `t` is published in epoch `e` on `chain`. -/
def published (chain : List (Stamp F A)) (e : ℕ) (t : F) : Prop :=
  ∃ s ∈ chain, s.epoch = e ∧ t ∈ s.tachygrams

theorem mem_published {s : Stamp F A} {t : F} (hs : s ∈ chain) (ht : t ∈ s.tachygrams) :
    published chain s.epoch t :=
  ⟨s, hs, rfl, ht⟩

theorem published_of_le {s : Stamp F A} {m : Multiset F}
    (hs : s ∈ chain) (hm : m ≤ (s.tachygrams : Multiset F)) :
    ∀ t ∈ m, published chain s.epoch t :=
  fun _ ht => mem_published hs (Multiset.mem_of_le hm ht)

/-- Window theorem for an earlier stamp `s₁` and later stamp `s₂` in `chain`:
their epochs are ordered (`s₁.epoch ≤ s₂.epoch`), and if `s₂.epoch ≤ s₁.epoch + 1` then their
published tachygrams are disjoint. -/
theorem Valid.disjoint_of_window (hchain : Valid epoch acceptedAnchor chain)
    {l₁ l₂ : List (Stamp F A)} {s₁ s₂ : Stamp F A}
    (hsplit : chain = l₁ ++ s₁ :: l₂) (hs₂ : s₂ ∈ l₂) :
    s₁.epoch ≤ s₂.epoch ∧
      (s₂.epoch ≤ s₁.epoch + 1 → s₁.tachygrams.Disjoint s₂.tachygrams) := by
  have hord := hchain.ordered
  have hdis := hchain.window_disjoint
  rw [hsplit, List.pairwise_append] at hord hdis
  exact ⟨(List.pairwise_cons.mp hord.2.1).1 s₂ hs₂,
    (List.pairwise_cons.mp hdis.2.1).1 s₂ hs₂⟩

/-- Sub-multisets of `s₁.tachygrams` and `s₂.tachygrams` (such as individual leaves' tachygram
multisets) are disjoint when `s₁` precedes `s₂` within the two-epoch window. -/
theorem Valid.disjoint_of_le_window (hchain : Valid epoch acceptedAnchor chain)
    {l₁ l₂ : List (Stamp F A)} {s₁ s₂ : Stamp F A} {m₁ m₂ : Multiset F}
    (hsplit : chain = l₁ ++ s₁ :: l₂) (hs₂ : s₂ ∈ l₂)
    (hm₁ : m₁ ≤ (s₁.tachygrams : Multiset F))
    (hm₂ : m₂ ≤ (s₂.tachygrams : Multiset F)) :
    s₁.epoch ≤ s₂.epoch ∧ (s₂.epoch ≤ s₁.epoch + 1 → Disjoint m₁ m₂) := by
  obtain ⟨hord, hdis⟩ := hchain.disjoint_of_window hsplit hs₂
  refine ⟨hord, fun hwin => Multiset.disjoint_left.mpr fun ht₁ ht₂ => ?_⟩
  exact hdis hwin (Multiset.mem_of_le hm₁ ht₁) (Multiset.mem_of_le hm₂ ht₂)

/-- If two stamps in `chain` sit in adjacent epochs (`s₁.epoch < s₂.epoch ≤ s₁.epoch + 1`),
epoch ordering places `s₁` before `s₂`, so their tachygrams are disjoint. -/
theorem Valid.disjoint_of_lt_epoch (hchain : Valid epoch acceptedAnchor chain)
    {s₁ s₂ : Stamp F A} (hs₁ : s₁ ∈ chain) (hs₂ : s₂ ∈ chain)
    (hlt : s₁.epoch < s₂.epoch) (hwin : s₂.epoch ≤ s₁.epoch + 1) :
    s₁.tachygrams.Disjoint s₂.tachygrams := by
  have hord := hchain.ordered
  have hdis := hchain.window_disjoint
  clear hchain
  induction chain with
  | nil => cases hs₁
  | cons s rest ih =>
    rw [List.pairwise_cons] at hord hdis
    rcases List.mem_cons.mp hs₁ with rfl | hs₁_rest <;>
      rcases List.mem_cons.mp hs₂ with rfl | hs₂_rest
    · exact absurd hlt (lt_irrefl _)
    · exact hdis.1 s₂ hs₂_rest hwin
    · exact absurd (hord.1 s₁ hs₁_rest) (not_le_of_gt hlt)
    · exact ih hs₁_rest hs₂_rest hord.2 hdis.2

/-- All tachygrams published across a list of stamps within an epoch predicate `P`. -/
def tachygramsInEpochs (P : ℕ → Prop) [DecidablePred P]
    (chain : List (Stamp F A)) : List F :=
  (chain.filter fun s => P s.epoch).flatMap Stamp.tachygrams

theorem mem_tachygramsInEpochs_iff {P : ℕ → Prop} [DecidablePred P] {t : F} :
    t ∈ tachygramsInEpochs P chain ↔ ∃ e, P e ∧ published chain e t := by
  simp only [tachygramsInEpochs, List.mem_flatMap, List.mem_filter, decide_eq_true_eq, published]
  constructor
  · rintro ⟨s, ⟨hs, hP⟩, ht⟩
    exact ⟨s.epoch, hP, s, hs, rfl, ht⟩
  · rintro ⟨e, hP, s, hs, rfl, ht⟩
    exact ⟨s, ⟨hs, hP⟩, ht⟩

/-- Any two stamps in a `Valid` chain whose epochs both satisfy a predicate `P` that fits within a
two-epoch window (`∀ e₁ e₂, P e₁ → P e₂ → e₁ ≤ e₂ → InWindow e₁ e₂`) have disjoint tachygram lists,
so the combined tachygram list over `P` is duplicate-free (`Nodup`). -/
theorem Valid.nodup_tachygramsInEpochs
    {P : ℕ → Prop} [DecidablePred P]
    (hwindow : ∀ ⦃e₁ e₂ : ℕ⦄, P e₁ → P e₂ → e₁ ≤ e₂ → InWindow e₁ e₂)
    (hchain : Valid epoch acceptedAnchor chain) :
    (tachygramsInEpochs P chain).Nodup := by
  obtain ⟨hacc, hord, hdis⟩ := hchain
  induction chain with
  | nil => simp [tachygramsInEpochs]
  | cons s rest ih =>
    rw [List.pairwise_cons] at hord hdis
    have ih' := ih (fun x hx => hacc x (List.mem_cons_of_mem s hx)) hord.2 hdis.2
    unfold tachygramsInEpochs at ih' ⊢
    simp only [List.filter_cons]
    split_ifs with hP
    · rw [decide_eq_true_eq] at hP
      rw [List.flatMap_cons, List.nodup_append]
      refine ⟨(hacc s List.mem_cons_self).tachygrams_nodup, ih', ?_⟩
      intro x hx y hy hxy
      subst hxy
      rw [List.mem_flatMap] at hy
      obtain ⟨s₂, hs₂_filt, hx_s₂⟩ := hy
      rw [List.mem_filter, decide_eq_true_eq] at hs₂_filt
      obtain ⟨hs₂_mem, hs₂_P⟩ := hs₂_filt
      have hwin : InWindow s.epoch s₂.epoch :=
        hwindow hP hs₂_P (hord.1 s₂ hs₂_mem)
      exact hdis.1 s₂ hs₂_mem hwin.2 hx hx_s₂
    · exact ih'

/-- **Single-epoch accumulator squarefreeness (`Summary`, `QrIntake`)**: all tachygrams published
within any single epoch `e` are duplicate-free. -/
theorem Valid.nodup_epoch (e : ℕ)
    (hchain : Valid epoch acceptedAnchor chain) :
    (tachygramsInEpochs (· = e) chain).Nodup := by
  refine hchain.nodup_tachygramsInEpochs ?_
  intro e₁ e₂ he₁ he₂ _
  subst he₁; subst he₂
  exact ⟨le_rfl, Nat.le_succ _⟩

/-- **Two-epoch window uniqueness**: all tachygrams published across two consecutive epochs
`e` and `e + 1` are duplicate-free. -/
theorem Valid.nodup_two_epochs (e : ℕ)
    (hchain : Valid epoch acceptedAnchor chain) :
    (tachygramsInEpochs (fun e' => e ≤ e' ∧ e' ≤ e + 1) chain).Nodup := by
  refine hchain.nodup_tachygramsInEpochs ?_
  rintro e₁ e₂ ⟨he₁_lo, _⟩ ⟨_, he₂_hi⟩ hle
  exact ⟨hle, le_trans he₂_hi (Nat.add_le_add_right he₁_lo 1)⟩

end Tachyon.Chain
