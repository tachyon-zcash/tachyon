import Tachyon.Consensus.Chain

/-!
# Entry anchors of a published chain

Consensus advances the pool anchor over a published chain one epoch at a time. Epoch `e` opens on
its entry anchor, folds each stamp published in `e` in chain order with `nextStamp`, and ends on its
final anchor. The boundary digest `nextEpoch` of the final anchor into `e + 1` is the entry anchor
of `e + 1`. Epoch zero's entry anchor is the boundary digest of the zero anchor into epoch zero.
Every epoch has an entry anchor, including one that published no stamp.

`entry` is defined at every epoch, so the chain's calls over all epochs are infinitely many, and no
hash over a finite field is collision-free on them. `ChainQueried q … chain N` asks only that the
chain's calls up to epoch `N` lie in `q`, and the results here hold at epochs up to `N`.

A run of stamp folds in `q` that starts on a boundary digest in `q` has one preimage under
`HashLaw` (`foldBlock_inj`). This is what lets a QR bucket that ends on the published entry anchor
of the next epoch hold exactly the stamps that epoch published.
-/

namespace Tachyon.Chain

open Polynomial

variable {F A : Type*} [Field F]

/-- The tachygram-set polynomials of the stamps published in epoch `e`, in chain order. -/
noncomputable def epochStamps (chain : List (Stamp F A)) (e : ℕ) : List F[X] :=
  (chain.filter fun s => s.epoch = e).map fun s => setPoly (s.tachygrams : Multiset F)

/-- The entry anchor of each epoch of `chain`, starting from the boundary digest of `zero` into
epoch zero. -/
noncomputable def entry (nextStamp : A → ℕ → F[X] → A) (nextEpoch : A → ℕ → A) (zero : A)
    (chain : List (Stamp F A)) : ℕ → A
  | 0 => nextEpoch zero 0
  | e + 1 => nextEpoch
      (foldBlock nextStamp e (entry nextStamp nextEpoch zero chain e) (epochStamps chain e)) (e + 1)

/-- The anchor-fold calls `chain` makes up to epoch `N` lie in `q`. -/
structure ChainQueried (q : AnchorQueries F A ℕ) (nextStamp : A → ℕ → F[X] → A)
    (nextEpoch : A → ℕ → A) (zero : A) (chain : List (Stamp F A)) (N : ℕ) : Prop where
  genesis : q.boundary zero 0
  boundary : ∀ e < N, q.boundary
    (foldBlock nextStamp e (entry nextStamp nextEpoch zero chain e) (epochStamps chain e)) (e + 1)
  stamp : ∀ e ≤ N,
    FoldQueried q nextStamp e (entry nextStamp nextEpoch zero chain e) (epochStamps chain e)

variable {q : AnchorQueries F A ℕ} {nextStamp : A → ℕ → F[X] → A} {nextEpoch : A → ℕ → A}
  {zero : A} {chain : List (Stamp F A)} {N : ℕ}

/-- Folding one more stamp onto a run is one `nextStamp` call on the run's anchor, for inducting
over an epoch's stamps from the last. -/
theorem foldBlock_concat {e : ℕ} {a : A} {L : List F[X]} {c : F[X]} :
    foldBlock nextStamp e a (L ++ [c]) = nextStamp (foldBlock nextStamp e a L) e c := by
  simp [foldBlock]

/-- The entry anchor of every epoch is a boundary digest, with no hash law or call set. -/
theorem entry_boundary (e : ℕ) : ∃ p, entry nextStamp nextEpoch zero chain e = nextEpoch p e := by
  cases e with
  | zero => exact ⟨zero, rfl⟩
  | succ e => exact ⟨_, rfl⟩

/-- The entry anchor of an epoch up to `N` is a boundary digest from a call in `q`. -/
theorem ChainQueried.entry_boundary (h : ChainQueried q nextStamp nextEpoch zero chain N) {e : ℕ}
    (he : e ≤ N) :
    ∃ p, entry nextStamp nextEpoch zero chain e = nextEpoch p e ∧ q.boundary p e := by
  cases e with
  | zero => exact ⟨zero, rfl, h.genesis⟩
  | succ e => exact ⟨_, rfl, h.boundary e (by omega)⟩

/-- Every tachygram published in epoch `e` is a root of one of the epoch's stamp polynomials. -/
theorem published_root {e : ℕ} {t : F} (h : published chain e t) :
    ∃ c ∈ epochStamps chain e, c.IsRoot t := by
  obtain ⟨s, hs, he, ht⟩ := h
  refine ⟨setPoly (s.tachygrams : Multiset F), ?_, ?_⟩
  · exact List.mem_map.mpr ⟨s, List.mem_filter.mpr ⟨hs, by simpa using he⟩, rfl⟩
  · rw [← mem_roots (setPoly_ne_zero _), roots_setPoly]
    exact Multiset.mem_coe.mpr ht

/-- A root of the product of epoch `e`'s stamp polynomials is a tachygram published in `e`. -/
theorem published_of_root_prod {e : ℕ} {t : F} (h : (epochStamps chain e).prod.IsRoot t) :
    published chain e t := by
  rw [IsRoot.def, eval_list_prod, List.prod_eq_zero_iff, List.mem_map] at h
  obtain ⟨c, hc, hroot⟩ := h
  obtain ⟨s, hs, rfl⟩ := List.mem_map.mp hc
  obtain ⟨hs, he⟩ := List.mem_filter.mp hs
  refine ⟨s, hs, by simpa using he, ?_⟩
  have : t ∈ (setPoly (s.tachygrams : Multiset F)).roots :=
    (mem_roots (setPoly_ne_zero _)).mpr hroot
  rw [roots_setPoly] at this
  exact Multiset.mem_coe.mp this

/-- Two runs of stamp folds in `q` at one epoch that each start on a boundary digest in `q` and end
on one anchor fold the same stamps from the same start. -/
theorem foldBlock_inj {genesis : A} {e₀ : ℕ} (hlaw : HashLaw q genesis e₀ nextStamp nextEpoch)
    {e : ℕ} {a a' : A} {L L' : List F[X]}
    (ha : ∃ p e', a = nextEpoch p e' ∧ q.boundary p e')
    (ha' : ∃ p e', a' = nextEpoch p e' ∧ q.boundary p e')
    (hL : FoldQueried q nextStamp e a L) (hL' : FoldQueried q nextStamp e a' L')
    (h : foldBlock nextStamp e a L = foldBlock nextStamp e a' L') : L = L' ∧ a = a' := by
  induction L using List.reverseRecOn generalizing L' with
  | nil =>
    rcases L'.eq_nil_or_concat with rfl | ⟨M', c', rfl⟩
    · exact ⟨rfl, h⟩
    · obtain ⟨p, e', rfl, hp⟩ := ha
      rw [List.concat_eq_append] at hL'
      rw [List.concat_eq_append, foldBlock_concat] at h
      exact absurd h.symm (hlaw.stamp_ne_epoch (hL' M' c' [] rfl) hp)
  | append_singleton M c ih =>
    rcases L'.eq_nil_or_concat with rfl | ⟨M', c', rfl⟩
    · obtain ⟨p, e', rfl, hp⟩ := ha'
      rw [foldBlock_concat] at h
      exact absurd h (hlaw.stamp_ne_epoch (hL M c [] rfl) hp)
    · rw [List.concat_eq_append] at hL' h ⊢
      rw [foldBlock_concat, foldBlock_concat] at h
      obtain ⟨hprev, -, rfl⟩ := hlaw.nextStamp_inj (hL M c [] rfl) (hL' M' c' [] rfl) h
      obtain ⟨rfl, haa⟩ := ih (L' := M') (FoldQueried.append.mp hL).1 (FoldQueried.append.mp hL').1
        hprev
      exact ⟨rfl, haa⟩

/-- A run of stamp folds in `q` at epoch `e` from a boundary digest in `q`, whose boundary digest
into `e + 1` is a call in `q` and the published entry anchor of `e + 1`, starts on the entry anchor
of `e` and folds exactly the stamps published in `e`. -/
theorem entry_succ_inj {genesis : A} {e₀ : ℕ} (hlaw : HashLaw q genesis e₀ nextStamp nextEpoch)
    (hchain : ChainQueried q nextStamp nextEpoch zero chain N) {e : ℕ} (he : e + 1 ≤ N) {a : A}
    {L : List F[X]} (ha : ∃ p e', a = nextEpoch p e' ∧ q.boundary p e')
    (hL : FoldQueried q nextStamp e a L) (hq : q.boundary (foldBlock nextStamp e a L) (e + 1))
    (h : nextEpoch (foldBlock nextStamp e a L) (e + 1) =
      entry nextStamp nextEpoch zero chain (e + 1)) :
    a = entry nextStamp nextEpoch zero chain e ∧ L = epochStamps chain e := by
  obtain ⟨hfold, -⟩ := hlaw.nextEpoch_inj hq (hchain.boundary e (by omega)) h
  obtain ⟨p, hp, hpq⟩ := hchain.entry_boundary (e := e) (by omega)
  obtain ⟨hL', haa⟩ := foldBlock_inj hlaw ha ⟨p, e, hp, hpq⟩ hL (hchain.stamp e (by omega)) hfold
  exact ⟨haa, hL'⟩

/-- `a` is an anchor `chain` reaches in epoch `e`: the entry anchor of `e` folded with a prefix of
the stamps published in `e`. Every end-of-block anchor of `e` is one. -/
def OnChain (nextStamp : A → ℕ → F[X] → A) (nextEpoch : A → ℕ → A) (zero : A)
    (chain : List (Stamp F A)) (e : ℕ) (a : A) : Prop :=
  ∃ P S : List F[X], P ++ S = epochStamps chain e ∧
    a = foldBlock nextStamp e (entry nextStamp nextEpoch zero chain e) P

/-- The chain reaches every epoch's entry anchor, through the empty prefix of its stamps, including
an epoch that published none. -/
theorem entry_onChain (e : ℕ) :
    OnChain nextStamp nextEpoch zero chain e (entry nextStamp nextEpoch zero chain e) :=
  ⟨[], _, rfl, rfl⟩

/-- A call `nextStamp a e_s c` in `q` that the chain reaches in epoch `e ≤ N` folds a stamp
published in `e`, at `e`, onto an anchor the chain reaches in `e`. -/
theorem OnChain.of_nextStamp {genesis : A} {e₀ : ℕ}
    (hlaw : HashLaw q genesis e₀ nextStamp nextEpoch)
    (hchain : ChainQueried q nextStamp nextEpoch zero chain N) {e e_s : ℕ} (he : e ≤ N) {a : A}
    {c : F[X]} (hq : q.stamp a e_s c)
    (h : OnChain nextStamp nextEpoch zero chain e (nextStamp a e_s c)) :
    e_s = e ∧ OnChain nextStamp nextEpoch zero chain e a ∧ c ∈ epochStamps chain e := by
  obtain ⟨P, S, hPS, ha⟩ := h
  rcases P.eq_nil_or_concat with rfl | ⟨P', c', rfl⟩
  · obtain ⟨p, hp, hpq⟩ := hchain.entry_boundary he
    exact absurd (ha.trans hp) (hlaw.stamp_ne_epoch hq hpq)
  · rw [List.concat_eq_append, foldBlock_concat] at ha
    have hq' := hchain.stamp e he P' c' S (by rw [← hPS]; simp)
    obtain ⟨rfl, rfl, rfl⟩ := hlaw.nextStamp_inj hq hq' ha
    refine ⟨rfl, ⟨P', c :: S, by rw [← hPS]; simp, rfl⟩, ?_⟩
    rw [← hPS]
    simp

/-- The anchors the chain reaches by epoch `N` are stamp-closed over the calls `q`. -/
theorem OnChain.stampClosed {genesis : A} {e₀ : ℕ} (hlaw : HashLaw q genesis e₀ nextStamp nextEpoch)
    (hchain : ChainQueried q nextStamp nextEpoch zero chain N) :
    StampClosed q nextStamp fun e a => e ≤ N ∧ OnChain nextStamp nextEpoch zero chain e a :=
  fun hq ⟨he, h⟩ =>
    ⟨(h.of_nextStamp hlaw hchain he hq).1, he, (h.of_nextStamp hlaw hchain he hq).2.1⟩

/-- A call `nextEpoch a e'` in `q` that the chain reaches in epoch `e ≤ N` is the entry anchor of
`e`. -/
theorem OnChain.of_nextEpoch {genesis : A} {e₀ : ℕ}
    (hlaw : HashLaw q genesis e₀ nextStamp nextEpoch)
    (hchain : ChainQueried q nextStamp nextEpoch zero chain N) {e e' : ℕ} (he : e ≤ N) {a : A}
    (hq : q.boundary a e') (h : OnChain nextStamp nextEpoch zero chain e (nextEpoch a e')) :
    nextEpoch a e' = entry nextStamp nextEpoch zero chain e ∧ e' = e := by
  obtain ⟨P, S, hPS, ha⟩ := h
  rcases P.eq_nil_or_concat with rfl | ⟨P', c', rfl⟩
  · obtain ⟨p, hp, hpq⟩ := hchain.entry_boundary he
    exact ⟨ha, (hlaw.nextEpoch_inj hq hpq (ha.trans hp)).2⟩
  · rw [List.concat_eq_append, foldBlock_concat] at ha
    have hq' := hchain.stamp e he P' c' S (by rw [← hPS]; simp)
    exact absurd ha.symm (hlaw.stamp_ne_epoch hq' hq)

/-- On a chain whose stamps each publish a tachygram, every anchor the chain reaches by epoch `N`
is a chain node at its epoch, rooted at epoch zero's entry anchor. -/
theorem OnChain.toNode (hne : ∀ s ∈ chain, s.tachygrams ≠ [])
    (hchain : ChainQueried q nextStamp nextEpoch zero chain N) {e : ℕ} (he : e ≤ N) {a : A}
    (h : OnChain nextStamp nextEpoch zero chain e a) :
    Node q (nextEpoch zero 0) 0 nextStamp nextEpoch e a := by
  have hstamps : ∀ e, ∀ c ∈ epochStamps chain e, c ≠ 1 := by
    intro e c hc hone
    obtain ⟨s, hs, rfl⟩ := List.mem_map.mp hc
    have hroots := congrArg Polynomial.roots hone
    rw [roots_setPoly, roots_one, Multiset.empty_eq_zero, Multiset.coe_eq_zero] at hroots
    exact hne s (List.mem_filter.mp hs).1 hroots
  have hentry : ∀ e, e ≤ N → Node q (nextEpoch zero 0) 0 nextStamp nextEpoch e
      (entry nextStamp nextEpoch zero chain e) := by
    intro e
    induction e with
    | zero => exact fun _ => Node.genesis
    | succ e ih =>
      intro he
      exact ((ih (by omega)).foldBlock (hstamps e) (hchain.stamp e (by omega))).epoch
        (Nat.succ_ne_zero e) (hchain.boundary e (by omega))
  obtain ⟨P, S, hPS, rfl⟩ := h
  have hfold := hchain.stamp e he
  rw [← hPS] at hfold
  exact (hentry e he).foldBlock (fun c hc => hstamps e c (hPS ▸ List.mem_append_left S hc))
    (FoldQueried.append.mp hfold).1

end Tachyon.Chain
