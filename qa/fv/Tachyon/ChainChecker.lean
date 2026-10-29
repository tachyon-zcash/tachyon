import Tachyon.Consensus.Chain

/-!
# Executable checker for the public chain-rule model

The checker certifies exactly `Chain.Valid`: nonempty/unique tachygrams,
accepted anchor membership, anchor recency, chronological epoch order, and
the current/previous-epoch duplicate window. Membership is supplied as a
public boolean policy; the specification uses that policy's `= true` relation.

`checkChain_eq_true_iff` proves both soundness and completeness, so no hidden
proof-oracle assumptions are needed to build the `Chain.Valid` certificate.
The checker deliberately does not claim to implement wire parsing, signatures,
the PCD verifier, or canonical anchor folding. Those have separate inputs and
specifications. A chronological full-history scan is used for clarity; entries
outside the two-epoch window impose no disjointness condition.
-/

namespace Tachyon.ChainChecker

variable {T A : Type*} [DecidableEq T]

def checkStamp (epoch : A → ℕ) (accepted : ℕ → A → Bool) (s : Chain.Stamp T A) : Bool :=
  decide (s.tachygrams ≠ []) && (decide s.tachygrams.Nodup &&
    (accepted (epoch s.anchor) s.anchor &&
      decide (epoch s.anchor ≤ s.epoch ∧ s.epoch ≤ epoch s.anchor + 1)))

theorem checkStamp_eq_true_iff (epoch : A → ℕ) (accepted : ℕ → A → Bool) (s : Chain.Stamp T A) :
    checkStamp epoch accepted s = true ↔
      Chain.StampAccepted epoch (fun e a => accepted e a = true) s := by
  simp only [checkStamp, Bool.and_eq_true, decide_eq_true_eq]
  constructor
  · rintro ⟨hne, hnodup, hanchor, hrecent⟩
    exact ⟨hne, hnodup, hanchor, hrecent⟩
  · intro h
    exact ⟨h.tachygrams_ne_nil, h.tachygrams_nodup, h.anchor_accepted, h.recency⟩

def checkDisjoint (left right : List T) : Bool := left.all fun x => decide (x ∉ right)

theorem checkDisjoint_eq_true_iff (left right : List T) :
    checkDisjoint left right = true ↔ left.Disjoint right := by
  simp [checkDisjoint, List.all_eq_true, List.disjoint_left]

def checkPair (earlier later : Chain.Stamp T A) : Bool :=
  decide (earlier.epoch ≤ later.epoch) &&
    if later.epoch ≤ earlier.epoch + 1 then checkDisjoint earlier.tachygrams later.tachygrams else true

theorem checkPair_eq_true_iff (earlier later : Chain.Stamp T A) :
    checkPair earlier later = true ↔ earlier.epoch ≤ later.epoch ∧
      (later.epoch ≤ earlier.epoch + 1 → earlier.tachygrams.Disjoint later.tachygrams) := by
  by_cases hwindow : later.epoch ≤ earlier.epoch + 1 <;>
    simp [checkPair, hwindow, Bool.and_eq_true, checkDisjoint_eq_true_iff]

def checkChain (epoch : A → ℕ) (accepted : ℕ → A → Bool) : List (Chain.Stamp T A) → Bool
  | [] => true
  | s :: rest => checkStamp epoch accepted s && (rest.all (checkPair s) && checkChain epoch accepted rest)

theorem checkChain_eq_true_iff (epoch : A → ℕ) (accepted : ℕ → A → Bool)
    (chain : List (Chain.Stamp T A)) : checkChain epoch accepted chain = true ↔
      Chain.Valid epoch (fun e a => accepted e a = true) chain := by
  induction chain with
  | nil =>
    constructor
    · intro _
      exact ⟨fun _ h => False.elim (List.not_mem_nil h), .nil, .nil⟩
    · intro _
      rfl
  | cons s rest ih =>
    constructor
    · intro h
      simp only [checkChain, Bool.and_eq_true] at h
      obtain ⟨hs, hpairs, hrest⟩ := h
      have htail := ih.mp hrest
      have hstamp := (checkStamp_eq_true_iff epoch accepted s).mp hs
      have hp : ∀ later ∈ rest, s.epoch ≤ later.epoch ∧
          (later.epoch ≤ s.epoch + 1 → s.tachygrams.Disjoint later.tachygrams) := by
        intro later hmem
        exact (checkPair_eq_true_iff s later).mp (List.all_eq_true.mp hpairs later hmem)
      refine ⟨?_, List.pairwise_cons.mpr ⟨fun later hmem => (hp later hmem).1, htail.ordered⟩,
        List.pairwise_cons.mpr ⟨fun later hmem => (hp later hmem).2, htail.window_disjoint⟩⟩
      intro t ht
      rcases List.mem_cons.mp ht with rfl | ht
      · exact hstamp
      · exact htail.accepted t ht
    · intro h
      have hord := List.pairwise_cons.mp h.ordered
      have hwindow := List.pairwise_cons.mp h.window_disjoint
      have htail : Chain.Valid epoch (fun e a => accepted e a = true) rest :=
        ⟨fun t ht => h.accepted t (List.mem_cons_of_mem s ht), hord.2, hwindow.2⟩
      simp only [checkChain, Bool.and_eq_true]
      refine ⟨(checkStamp_eq_true_iff epoch accepted s).mpr (h.accepted s List.mem_cons_self), ?_, ih.mpr htail⟩
      apply List.all_eq_true.mpr
      intro later hmem
      exact (checkPair_eq_true_iff s later).mpr ⟨hord.1 later hmem, hwindow.1 later hmem⟩

namespace Examples

def accepts (_epoch anchor : ℕ) : Bool := anchor < 10

def first : Chain.Stamp ℕ ℕ := ⟨0, [1, 2], 0⟩
def next : Chain.Stamp ℕ ℕ := ⟨0, [3, 4], 1⟩
def valid (stamps : List (Chain.Stamp ℕ ℕ)) : Bool := checkChain id accepts stamps

#guard valid [first, next]
#guard !valid [⟨0, [], 0⟩]
#guard !valid [⟨0, [1, 1], 0⟩]
#guard !valid [⟨0, [1], 2⟩] -- stale anchor
#guard !valid [⟨10, [1], 10⟩] -- rejected membership
#guard !valid [next, first] -- wrong chronological order
#guard !valid [first, ⟨0, [2, 3], 0⟩]
#guard !valid [first, ⟨0, [2, 3], 1⟩]
#guard valid [first, ⟨2, [2, 3], 2⟩] -- outside duplicate window

end Examples

end Tachyon.ChainChecker
