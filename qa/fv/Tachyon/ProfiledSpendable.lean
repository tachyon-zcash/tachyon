import Tachyon.Qr
import Tachyon.Consensus

/-!
# Profile-aware delegated exclusion and spendable lineage

A real QR bucket need not contain all tachygrams in its epoch. It must contain
each published value whose profile matches that bucket. `QueryComplete` states
this obligation for the value actually opened. `RoutedQuery.complete` derives
it from the QR routing theorem, a matching profile, and source completeness.

The step predicates below reuse the headers from `Spendable.lean`. Each
`QrUnspentInit` and `UnspentLift` additionally carries `AllowedQuery b v`,
representing the profile check for its tested value. Fuse, bind and spendable
composition preserve those certificates. Their `forget` theorems map to the
existing predicates, keeping the earlier model and its clients unchanged.

The headline lineage and double-spend theorems require completeness only for
certified queries, rather than `CompleteBucket` for an entire routed bucket.
Choosing `AllowedQuery := RoutedQuery chain c` discharges that requirement by
root retention. Chain sealing of the source, correctness of the profile-mask
gadget, indexed-polynomial binding and the note's nullifier pairing remain the
explicit idealization boundaries; they are not proved by this module.
-/

namespace Tachyon.Profiled

open Polynomial

variable {F A : Type*} [Field F]

/-- Completeness at the queried value, not at every value in the epoch. -/
def QueryComplete (chain : List (Chain.Stamp F A)) (b : QrBucket F A) (v : F) : Prop :=
  Chain.published chain b.epoch v → b.contents.eval v = 0

/-- A certificate for querying a routed bucket. The source contains the epoch's
published values, and this value matches every bit of the route to the bucket. -/
structure RoutedQuery (chain : List (Chain.Stamp F A)) (c : F) (b : QrBucket F A)
    (v : F) : Prop where
  certificate : ∃ (r : F) (source : F[X]) (bits : List Bool),
    (∀ t, Chain.published chain b.epoch t → source.eval t = 0) ∧
    Qr.Route c r source bits b.contents ∧ Qr.MatchesProfile r v bits

/-- QR routing supplies target-specific completeness for every certified query. -/
theorem RoutedQuery.complete {chain : List (Chain.Stamp F A)} {c : F}
    (hc : ¬ IsSquare c) {b : QrBucket F A} {v : F}
    (h : RoutedQuery chain c b v) : QueryComplete chain b v := by
  obtain ⟨r, source, bits, hsource, hroute, hmatch⟩ := h.certificate
  exact fun hpub => hroute.retains hc hmatch (hsource v hpub)

variable {ValidBucket : QrBucket F A → Prop} {AllowedQuery : QrBucket F A → F → Prop}
  {nf : F → ℕ → F}

/-- The delegated exclusion steps, with the tested value's profile certificate
retained at each opening. `elapsed` idealizes the indexed multiset commitment. -/
inductive UnspentDerivable (ValidBucket : QrBucket F A → Prop)
    (AllowedQuery : QrBucket F A → F → Prop) : ArbitraryUnspent F A → Prop
  | init (b : QrBucket F A) (v : F) :
      ValidBucket b → AllowedQuery b v → v ≠ 0 → b.contents.eval v ≠ 0 →
      UnspentDerivable ValidBucket AllowedQuery
        ⟨b.anchor_start, b.epoch, {(b.epoch, v)}, b.epoch + 1, b.anchor_next⟩
  | lift {u : ArbitraryUnspent F A} (b : QrBucket F A) (v : F)
      {extended : Multiset (ℕ × F)} :
      UnspentDerivable ValidBucket AllowedQuery u → ValidBucket b → AllowedQuery b v →
      u.anchor_next = b.anchor_start → u.epoch_next = b.epoch →
      v ≠ 0 → b.contents.eval v ≠ 0 → extended = u.elapsed + {(b.epoch, v)} →
      UnspentDerivable ValidBucket AllowedQuery
        ⟨u.anchor_start, u.epoch_start, extended, b.epoch + 1, b.anchor_next⟩
  | fuse {left right : ArbitraryUnspent F A} {combined : Multiset (ℕ × F)} :
      UnspentDerivable ValidBucket AllowedQuery left →
      UnspentDerivable ValidBucket AllowedQuery right →
      left.anchor_next = right.anchor_start → right.epoch_start = left.epoch_next →
      combined = left.elapsed + right.elapsed →
      UnspentDerivable ValidBucket AllowedQuery
        ⟨left.anchor_start, left.epoch_start, combined, right.epoch_next, right.anchor_next⟩

theorem UnspentDerivable.forget {u : ArbitraryUnspent F A}
    (h : UnspentDerivable ValidBucket AllowedQuery u) :
    Tachyon.ArbitraryUnspentDerivable ValidBucket u := by
  induction h with
  | init b v hb _ hv hne => exact .init b v hb hv hne
  | lift b v _ hb _ ha he hv hne hext ih => exact .lift b v ih hb ha he hv hne hext
  | fuse _ _ ha he hcomb ihl ihr => exact .fuse ihl ihr ha he hcomb

/-- Each covered epoch has a tested pair and its own matching-profile evidence. -/
theorem UnspentDerivable.coverage {u : ArbitraryUnspent F A}
    (h : UnspentDerivable ValidBucket AllowedQuery u) :
    u.epoch_start < u.epoch_next ∧
      ∀ x, u.epoch_start ≤ x → x < u.epoch_next →
        ∃ (v : F) (b : QrBucket F A), (x, v) ∈ u.elapsed ∧
          ValidBucket b ∧ AllowedQuery b v ∧ b.epoch = x ∧ b.contents.eval v ≠ 0 := by
  induction h with
  | init b v hb hquery _ hne =>
    dsimp only
    refine ⟨Nat.lt_succ_self _, fun x hlo hhi => ?_⟩
    have hx : x = b.epoch := by omega
    subst x
    exact ⟨v, b, Multiset.mem_singleton_self _, hb, hquery, rfl, hne⟩
  | lift b v _ hb hquery _ hepoch _ hne hext ih =>
    dsimp only at ih ⊢
    obtain ⟨hlt, hcov⟩ := ih
    refine ⟨by omega, fun x hlo hhi => ?_⟩
    rcases (by omega : x < b.epoch ∨ x = b.epoch) with hx | rfl
    · obtain ⟨v', b', hmem, hb', hquery', he', hne'⟩ := hcov x hlo (hepoch ▸ hx)
      exact ⟨v', b', hext ▸ Multiset.mem_add.mpr (Or.inl hmem), hb', hquery', he', hne'⟩
    · exact ⟨v, b, hext ▸ Multiset.mem_add.mpr (Or.inr (Multiset.mem_singleton_self _)),
        hb, hquery, rfl, hne⟩
  | fuse _ _ _ hepoch hcomb ihl ihr =>
    rename_i left right _ _ _ _
    dsimp only at ihl ihr ⊢
    obtain ⟨hltl, hcovl⟩ := ihl
    obtain ⟨hltr, hcovr⟩ := ihr
    refine ⟨by omega, fun x hlo hhi => ?_⟩
    by_cases hx : x < left.epoch_next
    · obtain ⟨v, b, hmem, hb, hquery, he, hne⟩ := hcovl x hlo hx
      exact ⟨v, b, hcomb ▸ Multiset.mem_add.mpr (Or.inl hmem), hb, hquery, he, hne⟩
    · obtain ⟨v, b, hmem, hb, hquery, he, hne⟩ := hcovr x (by omega) hhi
      exact ⟨v, b, hcomb ▸ Multiset.mem_add.mpr (Or.inr hmem), hb, hquery, he, hne⟩

/-- `UnspentBind` preserves the query evidence while binding every elapsed
pair to the note's nullifier derivation. -/
inductive NoteUnspentDerivable (ValidBucket : QrBucket F A → Prop)
    (AllowedQuery : QrBucket F A → F → Prop) (nf : F → ℕ → F) : NoteUnspent F A → Prop
  | bind {u : ArbitraryUnspent F A} {n : NoteNullifiers F} (complement : Multiset (ℕ × F)) :
      UnspentDerivable ValidBucket AllowedQuery u → NullifiersDerivable nf n →
      n.seq = u.elapsed + complement → NoteUnspentDerivable ValidBucket AllowedQuery nf
        ⟨n.cm, u.anchor_start, u.epoch_start, u.epoch_next, u.anchor_next⟩

theorem NoteUnspentDerivable.forget {nu : NoteUnspent F A}
    (h : NoteUnspentDerivable ValidBucket AllowedQuery nf nu) :
    Tachyon.NoteUnspentDerivable ValidBucket nf nu := by
  cases h with
  | bind complement hu hn hdiv => exact .bind complement hu.forget hn hdiv

/-- Exclusion over the whole segment follows from completeness at its certified
queries. No completeness condition is imposed on values with another profile. -/
theorem NoteUnspentDerivable.lineage {chain : List (Chain.Stamp F A)}
    (hcomplete : ∀ ⦃b : QrBucket F A⦄ ⦃v : F⦄,
      ValidBucket b → AllowedQuery b v → QueryComplete chain b v)
    {nu : NoteUnspent F A} (h : NoteUnspentDerivable ValidBucket AllowedQuery nf nu) :
    nu.epoch_start < nu.epoch_next ∧
      ∀ x, nu.epoch_start ≤ x → x < nu.epoch_next → ¬ Chain.published chain x (nf nu.cm x) := by
  cases h with
  | bind complement hu hn hdiv =>
    obtain ⟨hlt, hcov⟩ := hu.coverage
    refine ⟨hlt, fun x hlo hhi hpub => ?_⟩
    obtain ⟨v, b, hmem, hb, hquery, hepoch, hne⟩ := hcov x hlo hhi
    have hseq : (x, v) ∈ _ := hdiv ▸ Multiset.mem_add.mpr (Or.inl hmem)
    have hv := hn.mem_seq hseq
    apply hne
    apply hcomplete hb hquery
    simpa only [hepoch, hv] using hpub

/-- Spendable bootstrap and lift with profile-certified unspent segments. The
header fields and native constraints are unchanged from `Spendable.lean`. -/
inductive SpendableDerivable (ValidBucket : QrBucket F A → Prop)
    (AllowedQuery : QrBucket F A → F → Prop) (nf : F → ℕ → F)
    (nextStamp : A → ℕ → F[X] → A) : ℕ → NoteSpendable F A → Prop
  | init {n : NoteNullifiers F} (prev : A) (contents : F[X]) (e : ℕ) :
      NullifiersDerivable nf n → contents.eval n.cm = 0 → contents ≠ 1 →
      SpendableDerivable ValidBucket AllowedQuery nf nextStamp e
        ⟨n.cm, e, nextStamp prev e contents⟩
  | qrInit {nu : NoteUnspent F A} (b : QrBucket F A) :
      NoteUnspentDerivable ValidBucket AllowedQuery nf nu → ValidBucket b →
      nu.epoch_start = b.epoch → nu.anchor_start = b.anchor_start →
      nu.anchor_next = b.anchor_next → nu.epoch_next = b.epoch + 1 →
      b.contents.eval nu.cm = 0 →
      SpendableDerivable ValidBucket AllowedQuery nf nextStamp b.epoch
        ⟨nu.cm, nu.epoch_next, nu.anchor_next⟩
  | lift {start : ℕ} {sp : NoteSpendable F A} {nu : NoteUnspent F A} :
      SpendableDerivable ValidBucket AllowedQuery nf nextStamp start sp →
      NoteUnspentDerivable ValidBucket AllowedQuery nf nu → nu.cm = sp.cm →
      nu.epoch_start = sp.epoch_current → nu.anchor_start = sp.anchor →
      SpendableDerivable ValidBucket AllowedQuery nf nextStamp start
        ⟨sp.cm, nu.epoch_next, nu.anchor_next⟩

variable {nextStamp : A → ℕ → F[X] → A}

/-- Existing anchor-threading lemmas remain applicable after forgetting profile
certificates; none of their inputs or constructors need to change. -/
theorem SpendableDerivable.forget {start : ℕ} {sp : NoteSpendable F A}
    (h : SpendableDerivable ValidBucket AllowedQuery nf nextStamp start sp) :
    Tachyon.SpendableDerivable ValidBucket nf nextStamp start sp := by
  induction h with
  | init prev contents e hn hroot hne => exact .init prev contents e hn hroot hne
  | qrInit b hnu hb he ha ha' hn hroot => exact .qrInit b hnu.forget hb he ha ha' hn hroot
  | lift _ hnu hcm he ha ih => exact .lift ih hnu.forget hcm he ha

/-- Profile-specific completeness suffices to establish the spendable lineage. -/
theorem SpendableDerivable.lineage {chain : List (Chain.Stamp F A)}
    (hcomplete : ∀ ⦃b : QrBucket F A⦄ ⦃v : F⦄,
      ValidBucket b → AllowedQuery b v → QueryComplete chain b v)
    {start : ℕ} {sp : NoteSpendable F A}
    (h : SpendableDerivable ValidBucket AllowedQuery nf nextStamp start sp) :
    start ≤ sp.epoch_current ∧
      ∀ x, start ≤ x → x < sp.epoch_current → ¬ Chain.published chain x (nf sp.cm x) := by
  induction h with
  | init _ _ _ _ _ _ =>
    dsimp only
    exact ⟨le_rfl, fun _ hlo hhi => absurd hhi (not_lt_of_ge hlo)⟩
  | qrInit b hnu _ hepoch _ _ hnext _ =>
    dsimp only
    obtain ⟨_, hlin⟩ := hnu.lineage hcomplete
    exact ⟨by omega, fun x hlo hhi => hlin x (hepoch ▸ hlo) hhi⟩
  | lift _ hnu hcm hepoch _ ih =>
    rename_i start' sp' nu' _ _
    dsimp only at ih ⊢
    obtain ⟨hstart, hlin⟩ := ih
    obtain ⟨hlt, hlin'⟩ := hnu.lineage hcomplete
    refine ⟨by omega, fun x hlo hhi => ?_⟩
    by_cases hx : x < sp'.epoch_current
    · exact hlin x hlo hx
    · rw [← hcm]
      exact hlin' x (by omega) hhi

/-- With routed queries, the lineage theorem needs no global `CompleteBucket`
premise: routing certificates supply completeness for each tested value. -/
theorem SpendableDerivable.routed_lineage {chain : List (Chain.Stamp F A)} {c : F}
    (hc : ¬ IsSquare c) {start : ℕ} {sp : NoteSpendable F A}
    (h : SpendableDerivable ValidBucket (RoutedQuery chain c) nf nextStamp start sp) :
    start ≤ sp.epoch_current ∧
      ∀ x, start ≤ x → x < sp.epoch_current → ¬ Chain.published chain x (nf sp.cm x) :=
  h.lineage (fun {_} {_} _ hquery => hquery.complete hc)

/-- The existing valid-chain double-spend argument now consumes a routed-query
lineage. Pair containment and the spend's anchor epoch remain explicit inputs. -/
theorem no_double_spend_of_routed {chain l₁ l₂ : List (Chain.Stamp F A)}
    {epoch : A → ℕ} {acceptedAnchor : ℕ → A → Prop} {s₁ s₂ : Chain.Stamp F A}
    {sp : NoteSpendable F A} {start : ℕ} {c : F}
    (hc : ¬ IsSquare c) (hchain : Chain.Valid epoch acceptedAnchor chain)
    (hsplit : chain = l₁ ++ s₁ :: l₂) (hs₂ : s₂ ∈ l₂)
    (hpair₁ : {nf sp.cm (epoch s₁.anchor), nf sp.cm (epoch s₁.anchor + 1)} ≤
      (s₁.tachygrams : Multiset F))
    (hpair₂ : {nf sp.cm (epoch s₂.anchor), nf sp.cm (epoch s₂.anchor + 1)} ≤
      (s₂.tachygrams : Multiset F))
    (hsp : SpendableDerivable ValidBucket (RoutedQuery chain c) nf nextStamp start sp)
    (hepoch : sp.epoch_current = epoch s₂.anchor) (hstart : start ≤ s₁.epoch) : False :=
  Tachyon.no_double_spend_of_valid hchain hsplit hs₂ hpair₁ hpair₂
    (hepoch ▸ (hsp.routed_lineage hc).2) hstart

/-- A routed bucket can soundly answer a matching query even though it omits
another published value. Here the source roots are `0` and `-1`, the residue
child is `X`, and the non-residue sibling is `X + 1` (multiplier `-1`). The
square query `1` opens nonzero in the residue bucket, which rightly omits the
published non-square `-1`. Thus global `CompleteBucket` is strictly too strong. -/
theorem routed_query_without_global_completeness :
    ∃ (chain : List (Chain.Stamp ℚ Unit)) (b : QrBucket ℚ Unit),
      RoutedQuery chain (-1) b 1 ∧ b.contents.eval 1 ≠ 0 ∧
      ¬ Chain.published chain b.epoch 1 ∧ ¬ CompleteBucket chain b := by
  let chain : List (Chain.Stamp ℚ Unit) := [⟨(), [0, -1], 0⟩]
  let b : QrBucket ℚ Unit := ⟨0, (), (), X⟩
  let split : Qr.Split (X * (X + C (1 : ℚ))) 0 :=
    ⟨X + C 1, X, mul_comm _ _⟩
  have hsource : ∀ t : ℚ, Chain.published chain 0 t →
      (X * (X + C (1 : ℚ))).eval t = 0 := by
    rintro t ⟨s, hs, _, ht⟩
    simp only [chain, List.mem_singleton] at hs
    subst s
    simp only [List.mem_cons, List.not_mem_nil, or_false] at ht
    rcases ht with rfl | rfl <;> norm_num
  have hquery : RoutedQuery chain (-1) b 1 := by
    refine ⟨⟨0, X * (X + C 1), [true], hsource, ?_, ?_⟩⟩
    · apply Qr.Route.descend (u := 1) (q := 1) split
      · refine ⟨⟨1, 1, by norm_num [split]⟩, rfl, rfl, ?_⟩
        change (1 : ℚ[X]) ^ 2 - C (-1) * (X + C 0) = (X + C 1) * 1
        simp [add_comm]
      · exact Qr.Route.root _ _
    · change IsSquare (1 + (0 : ℚ)) ∧ True
      exact ⟨⟨1, by norm_num⟩, trivial⟩
  have hc : ¬ IsSquare (-1 : ℚ) := by
    rintro ⟨x, hx⟩
    nlinarith [sq_nonneg x]
  have hopen : b.contents.eval 1 ≠ 0 := by norm_num [b]
  refine ⟨chain, b, hquery, hopen, fun hpub => hopen (hquery.complete hc hpub), ?_⟩
  intro hglobal
  have hpub : Chain.published chain b.epoch (-1) :=
    ⟨⟨(), [0, -1], 0⟩, List.mem_singleton_self _, rfl, by simp⟩
  have hz := hglobal (-1) hpub
  norm_num [b] at hz

end Tachyon.Profiled
