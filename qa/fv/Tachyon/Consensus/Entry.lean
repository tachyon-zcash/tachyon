import Tachyon.Consensus.Chain

/-!
# Entry anchors of a published chain

Consensus advances the pool anchor over a published chain one epoch at a time. Epoch `e` opens on
its entry anchor, folds each stamp published in `e` in chain order with `nextStamp`, and ends on its
final anchor. The boundary digest `nextEpoch` of the final anchor into `e + 1` is the entry anchor
of `e + 1`. Epoch zero's entry anchor is the boundary digest of the zero anchor into epoch zero.
Every epoch has an entry anchor, including one that published no stamp.

A run of stamp folds that starts on a boundary digest has one preimage under `HashLaw`
(`foldBlock_inj`). This is what lets a QR bucket that ends on the published entry anchor of the
next epoch hold exactly the stamps that epoch published.
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

variable {nextStamp : A → ℕ → F[X] → A} {nextEpoch : A → ℕ → A} {zero : A}
  {chain : List (Stamp F A)}

theorem entry_boundary (e : ℕ) : ∃ p, entry nextStamp nextEpoch zero chain e = nextEpoch p e := by
  cases e with
  | zero => exact ⟨zero, rfl⟩
  | succ e => exact ⟨_, rfl⟩

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

/-- Two runs of stamp folds at one epoch that each start on a boundary digest and end on one
anchor fold the same stamps from the same start. -/
theorem foldBlock_inj {genesis : A} {e₀ : ℕ} (hlaw : HashLaw genesis e₀ nextStamp nextEpoch)
    {e : ℕ} {a a' : A} {L L' : List F[X]}
    (ha : ∃ p e', a = nextEpoch p e') (ha' : ∃ p e', a' = nextEpoch p e')
    (h : foldBlock nextStamp e a L = foldBlock nextStamp e a' L') : L = L' ∧ a = a' := by
  unfold foldBlock at h
  rw [List.foldl_eq_foldr_reverse, List.foldl_eq_foldr_reverse] at h
  suffices key : ∀ R R' : List F[X],
      R.foldr (fun c acc => nextStamp acc e c) a = R'.foldr (fun c acc => nextStamp acc e c) a' →
        R = R' ∧ a = a' by
    obtain ⟨hr, haa⟩ := key _ _ h
    exact ⟨List.reverse_injective hr, haa⟩
  intro R
  induction R with
  | nil =>
    intro R' h
    cases R' with
    | nil => exact ⟨rfl, h⟩
    | cons c R' =>
      obtain ⟨p, e', rfl⟩ := ha
      exact absurd h.symm hlaw.stamp_ne_epoch
  | cons c R ih =>
    intro R' h
    cases R' with
    | nil =>
      obtain ⟨p, e', rfl⟩ := ha'
      exact absurd h hlaw.stamp_ne_epoch
    | cons c' R' =>
      obtain ⟨hprev, -, hc⟩ := hlaw.nextStamp_inj h
      obtain ⟨hR, haa⟩ := ih R' hprev
      exact ⟨by rw [hc, hR], haa⟩

/-- A run of stamp folds at epoch `e` from a boundary digest whose boundary digest into `e + 1` is
the published entry anchor of `e + 1` starts on the entry anchor of `e` and folds exactly the
stamps published in `e`. -/
theorem entry_succ_inj {genesis : A} {e₀ : ℕ} (hlaw : HashLaw genesis e₀ nextStamp nextEpoch)
    {e : ℕ} {a : A} {L : List F[X]} (ha : ∃ p e', a = nextEpoch p e')
    (h : nextEpoch (foldBlock nextStamp e a L) (e + 1) =
      entry nextStamp nextEpoch zero chain (e + 1)) :
    a = entry nextStamp nextEpoch zero chain e ∧ L = epochStamps chain e := by
  obtain ⟨hfold, -⟩ := hlaw.nextEpoch_inj h
  obtain ⟨p, hp⟩ := entry_boundary (nextStamp := nextStamp) (zero := zero) (chain := chain) e
  obtain ⟨hL, haa⟩ := foldBlock_inj hlaw ha ⟨p, e, hp⟩ hfold
  exact ⟨haa, hL⟩

/-- `a` is an anchor `chain` reaches in epoch `e`: the entry anchor of `e` folded with a prefix of
the stamps published in `e`. Every end-of-block anchor of `e` is one. -/
def OnChain (nextStamp : A → ℕ → F[X] → A) (nextEpoch : A → ℕ → A) (zero : A)
    (chain : List (Stamp F A)) (e : ℕ) (a : A) : Prop :=
  ∃ P S : List F[X], P ++ S = epochStamps chain e ∧
    a = foldBlock nextStamp e (entry nextStamp nextEpoch zero chain e) P

theorem entry_onChain (e : ℕ) :
    OnChain nextStamp nextEpoch zero chain e (entry nextStamp nextEpoch zero chain e) :=
  ⟨[], _, rfl, rfl⟩

/-- A stamp fold the chain reaches in epoch `e` folds a stamp published in `e`, at `e`, onto an
anchor the chain reaches in `e`. -/
theorem OnChain.of_nextStamp {genesis : A} {e₀ : ℕ} (hlaw : HashLaw genesis e₀ nextStamp nextEpoch)
    {e e_s : ℕ} {a : A} {c : F[X]}
    (h : OnChain nextStamp nextEpoch zero chain e (nextStamp a e_s c)) :
    e_s = e ∧ OnChain nextStamp nextEpoch zero chain e a ∧ c ∈ epochStamps chain e := by
  obtain ⟨P, S, hPS, ha⟩ := h
  rcases P.eq_nil_or_concat with rfl | ⟨P', c', rfl⟩
  · obtain ⟨p, hp⟩ := entry_boundary (nextStamp := nextStamp) (zero := zero) (chain := chain) e
    exact absurd (ha.trans hp) hlaw.stamp_ne_epoch
  · simp only [foldBlock, List.concat_eq_append, List.foldl_append, List.foldl_cons,
      List.foldl_nil] at ha
    obtain ⟨rfl, rfl, rfl⟩ := hlaw.nextStamp_inj ha
    refine ⟨rfl, ⟨P', c :: S, by rw [← hPS]; simp, rfl⟩, ?_⟩
    rw [← hPS]
    simp

theorem OnChain.stampClosed {genesis : A} {e₀ : ℕ} (hlaw : HashLaw genesis e₀ nextStamp nextEpoch) :
    StampClosed nextStamp (OnChain nextStamp nextEpoch zero chain) :=
  fun h => ⟨(h.of_nextStamp hlaw).1, (h.of_nextStamp hlaw).2.1⟩

/-- A boundary digest the chain reaches in epoch `e` is the entry anchor of `e`. -/
theorem OnChain.of_nextEpoch {genesis : A} {e₀ : ℕ} (hlaw : HashLaw genesis e₀ nextStamp nextEpoch)
    {e e' : ℕ} {a : A} (h : OnChain nextStamp nextEpoch zero chain e (nextEpoch a e')) :
    nextEpoch a e' = entry nextStamp nextEpoch zero chain e ∧ e' = e := by
  obtain ⟨P, S, -, ha⟩ := h
  rcases P.eq_nil_or_concat with rfl | ⟨P', c', rfl⟩
  · obtain ⟨p, hp⟩ := entry_boundary (nextStamp := nextStamp) (zero := zero) (chain := chain) e
    exact ⟨ha, (hlaw.nextEpoch_inj (ha.trans hp)).2⟩
  · simp only [foldBlock, List.concat_eq_append, List.foldl_append, List.foldl_cons,
      List.foldl_nil] at ha
    exact absurd ha.symm hlaw.stamp_ne_epoch

/-- On a chain whose stamps each publish a tachygram, every anchor the chain reaches is a chain
node at its epoch, rooted at epoch zero's entry anchor. -/
theorem OnChain.toNode (hne : ∀ s ∈ chain, s.tachygrams ≠ []) {e : ℕ} {a : A}
    (h : OnChain nextStamp nextEpoch zero chain e a) :
    Node (nextEpoch zero 0) 0 nextStamp nextEpoch e a := by
  have hstamps : ∀ e, ∀ c ∈ epochStamps chain e, c ≠ 1 := by
    intro e c hc hone
    obtain ⟨s, hs, rfl⟩ := List.mem_map.mp hc
    have hroots := congrArg Polynomial.roots hone
    rw [roots_setPoly, roots_one, Multiset.empty_eq_zero, Multiset.coe_eq_zero] at hroots
    exact hne s (List.mem_filter.mp hs).1 hroots
  have hentry : ∀ e, Node (nextEpoch zero 0) 0 nextStamp nextEpoch e
      (entry nextStamp nextEpoch zero chain e) := by
    intro e
    induction e with
    | zero => exact Node.genesis
    | succ e ih => exact (ih.foldBlock (hstamps e)).epoch (Nat.succ_ne_zero e)
  obtain ⟨P, S, hPS, rfl⟩ := h
  exact (hentry e).foldBlock fun c hc => hstamps e c (hPS ▸ List.mem_append_left S hc)

end Tachyon.Chain
