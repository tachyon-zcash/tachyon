import Tachyon.SetPoly
import Tachyon.Stamp
import Tachyon.Consensus.Chain

/-!
# Spendable and nullifier-exclusion lineage

This module models the proof-tree steps that establish a note's spendable lineage across epochs
(`crates/tachyon/src/stamp/proof/{delegation,pool,spendable,qr}.rs`, `book/src/proof-tree.md`) and
proves that a derivable `NoteSpendable` discharges the `SpendRecord.Lineage` hypothesis of
`no_double_spend_of_valid`:

1. **Nullifier derivation (`NoteNullifiers`, `NullifierDerive`, `NullifierFuse`)**:
   A wallet derives contiguous windows of `(epoch, nf cm epoch)` pairs and fuses adjacent windows.
   Every pair `(x, v)` in a derivable `NoteNullifiers` satisfies `v = nf cm x`
   (`NullifiersDerivable.mem_seq`).

2. **Epoch buckets and delegated unspent segments (`QrBucket`, `ArbitraryUnspent`, `QrUnspentInit`,
   `UnspentLift`, `UnspentFuse`)**:
   A sync service builds `ArbitraryUnspent` segments over `[epoch_start, epoch_next)`. At each
   epoch `x` in the range, a value `v` is opened nonzero (`bucket.contents.eval v ≠ 0`) against that
   epoch's `QrBucket` (`ArbitraryUnspentDerivable.coverage`).

3. **Divisibility bind (`UnspentBind`, `NoteUnspent`)**:
   `UnspentBind` checks that `elapsed` divides the wallet's `NoteNullifiers` sequence
   (`n.seq = u.elapsed + complement`). Multiset containment forces every tested value `(x, v)` in
   `u.elapsed` to equal the note's genuine nullifier `(x, nf cm x)` (`NoteUnspentDerivable.lineage`).

4. **Spendable bootstrap and lift (`SpendableInit`, `QrSpendableInit`, `SpendableLift`)**:
   - `SpendableInit` outputs a `nextStamp` anchor fold, while every sealed `QrBucket` (and hence
     every `NoteUnspent`) opens on a `nextEpoch` boundary fold. Domain separation
     (`Chain.HashLaw.stamp_ne_epoch`) prevents `SpendableLift` from ever advancing a
     `SpendableInit` lineage (`spendableInit_cannot_lift`), confining it to its creation epoch.
   - `SpendableDerivable.lineage` proves that for any derivable `NoteSpendable` rooted at creation
     epoch `start`, every epoch `x ∈ [start, sp.epoch_current)` has `¬ Chain.published chain x (nf sp.cm x)`.
-/

namespace Tachyon

open Polynomial

variable {F A : Type*} [Field F]

/-! ## Epoch buckets (`QrBucket`) -/

/-- Semantic projection of an epoch's `QrBucket`: epoch and anchor bounds from the header,
plus contents from output slot O0. Rust also carries discriminant/profile/contents-bridge
metadata, abstracted by the admissible-bucket and profile-aware query interfaces. -/
structure QrBucket (F A : Type*) [Field F] where
  epoch : ℕ
  anchor_start : A
  anchor_next : A
  contents : F[X]

/-- A bucket `b` is complete for `chain` at `v` (i.e. chain-sealed across `b.epoch` and matching
`v`'s QR profile) when any tachygram published in `b.epoch` that matches `b`'s profile is a root of
`b.contents`. In the profile-abstracted model, every tachygram published in `b.epoch` vanishes at
`b.contents`. -/
def CompleteBucket (chain : List (Chain.Stamp F A)) (b : QrBucket F A) : Prop :=
  ∀ t : F, Chain.published chain b.epoch t → b.contents.eval t = 0

/-- A bucket whose `contents` is `setPoly S` for a superset `S` of epoch `b.epoch`'s published
tachygrams satisfies `CompleteBucket`. -/
theorem CompleteBucket.of_setPoly {chain : List (Chain.Stamp F A)} {b : QrBucket F A}
    {S : Multiset F} (hpoly : b.contents = setPoly S)
    (hpub : ∀ t : F, Chain.published chain b.epoch t → t ∈ S) :
    CompleteBucket chain b := by
  intro t ht
  have hmem : t ∈ (setPoly S).roots := by
    rw [roots_setPoly]
    exact hpub t ht
  rw [mem_roots (setPoly_ne_zero S), IsRoot.def, ← hpoly] at hmem
  exact hmem

/-- Opening a `CompleteBucket` nonzero at `v` proves `v` was not published in `b.epoch`. -/
theorem CompleteBucket.not_published {chain : List (Chain.Stamp F A)} {b : QrBucket F A}
    (hb : CompleteBucket chain b) {v : F} (hne : b.contents.eval v ≠ 0) :
    ¬ Chain.published chain b.epoch v :=
  fun hpub => hne (hb v hpub)

/-! ## Nullifier derivation windows (`NoteNullifiers`) -/

/-- Semantic `NoteNullifiers` state: header `(cm, epoch_start, epoch_end)` plus sequence slot O0.
The `NfSeqCommit` polynomial over
irreducible factors `(v + (x + 1)X)^3 - 2` (`crates/tachyon/src/collections/indexed_multiset.rs`) is
idealized by its multiset of `(epoch, nullifier)` pairs `seq : Multiset (ℕ × F)`. -/
structure NoteNullifiers (F : Type*) where
  cm : F
  epoch_start : ℕ
  seq : Multiset (ℕ × F)
  epoch_end : ℕ

/-- The multiset of `(x, nf cm x)` pairs over `[start, start + width)`. -/
def derivedWindow (nf : F → ℕ → F) (cm : F) (start width : ℕ) : Multiset (ℕ × F) :=
  ↑((List.range' start width).map fun x => (x, nf cm x))

/-- Derivable `NoteNullifiers` headers (`NullifierDerive` and `NullifierFuse` in
`crates/tachyon/src/stamp/proof/delegation.rs`). `NoteSeed` is folded into `nf cm`, which pairs
each note commitment `cm` with its master-key nullifier sequence `ℕ → F`. -/
inductive NullifiersDerivable (nf : F → ℕ → F) : NoteNullifiers F → Prop
  | derive (cm : F) (epoch_start width : ℕ) :
      0 < width →
      NullifiersDerivable nf
        ⟨cm, epoch_start, derivedWindow nf cm epoch_start width, epoch_start + width - 1⟩
  | fuse {left right : NoteNullifiers F} {merged : Multiset (ℕ × F)} :
      NullifiersDerivable nf left →
      NullifiersDerivable nf right →
      left.cm = right.cm →
      right.epoch_start = left.epoch_end + 1 →
      merged = left.seq + right.seq →
      NullifiersDerivable nf ⟨left.cm, left.epoch_start, merged, right.epoch_end⟩

omit [Field F] in
/-- Every pair `(x, v)` in a derivable `NoteNullifiers` is the genuine derived nullifier
`v = nf n.cm x` of `n.cm` at epoch `x`. -/
theorem NullifiersDerivable.mem_seq {nf : F → ℕ → F} {n : NoteNullifiers F}
    (h : NullifiersDerivable nf n) {x : ℕ} {v : F} (hmem : (x, v) ∈ n.seq) :
    v = nf n.cm x := by
  induction h with
  | derive cm epoch_start width _ =>
    simp only [derivedWindow, Multiset.mem_coe, List.mem_map, Prod.mk.injEq] at hmem
    obtain ⟨x', _, rfl, rfl⟩ := hmem
    rfl
  | fuse _ _ hcm _ hmerged ihl ihr =>
    rw [hmerged, Multiset.mem_add] at hmem
    rcases hmem with hl | hr
    · exact ihl hl
    · rw [hcm]
      exact ihr hr

/-! ## Delegated unspent segments (`ArbitraryUnspent`) -/

/-- Semantic `ArbitraryUnspent` state: header `(anchor_start, epoch_start, epoch_next, anchor_next)`
plus the indexed elapsed sequence in output slot O0. -/
structure ArbitraryUnspent (F A : Type*) where
  anchor_start : A
  epoch_start : ℕ
  elapsed : Multiset (ℕ × F)
  epoch_next : ℕ
  anchor_next : A

/-- Derivable `ArbitraryUnspent` headers (`QrUnspentInit`, `UnspentLift` and `UnspentFuse` in
`crates/tachyon/src/stamp/proof/{qr,pool}.rs`), parameterized by the admissible buckets `ValidBucket`. -/
inductive ArbitraryUnspentDerivable (ValidBucket : QrBucket F A → Prop) :
    ArbitraryUnspent F A → Prop
  | init (b : QrBucket F A) (v : F) :
      ValidBucket b →
      v ≠ 0 →
      b.contents.eval v ≠ 0 →
      ArbitraryUnspentDerivable ValidBucket
        ⟨b.anchor_start, b.epoch, {(b.epoch, v)}, b.epoch + 1, b.anchor_next⟩
  | lift {u : ArbitraryUnspent F A} (b : QrBucket F A) (v : F)
      {extended : Multiset (ℕ × F)} :
      ArbitraryUnspentDerivable ValidBucket u →
      ValidBucket b →
      u.anchor_next = b.anchor_start →
      u.epoch_next = b.epoch →
      v ≠ 0 →
      b.contents.eval v ≠ 0 →
      extended = u.elapsed + {(b.epoch, v)} →
      ArbitraryUnspentDerivable ValidBucket
        ⟨u.anchor_start, u.epoch_start, extended, b.epoch + 1, b.anchor_next⟩
  | fuse {left right : ArbitraryUnspent F A} {combined : Multiset (ℕ × F)} :
      ArbitraryUnspentDerivable ValidBucket left →
      ArbitraryUnspentDerivable ValidBucket right →
      left.anchor_next = right.anchor_start →
      right.epoch_start = left.epoch_next →
      combined = left.elapsed + right.elapsed →
      ArbitraryUnspentDerivable ValidBucket
        ⟨left.anchor_start, left.epoch_start, combined, right.epoch_next, right.anchor_next⟩

variable {ValidBucket : QrBucket F A → Prop}

/-- Every derivable `ArbitraryUnspent` covers a non-empty epoch range `[epoch_start, epoch_next)`,
and for every epoch `x` in that range, `elapsed` holds a pair `(x, v)` tested nonzero against a
valid bucket at epoch `x`. -/
theorem ArbitraryUnspentDerivable.coverage
    {u : ArbitraryUnspent F A} (h : ArbitraryUnspentDerivable ValidBucket u) :
    u.epoch_start < u.epoch_next ∧
      ∀ x, u.epoch_start ≤ x → x < u.epoch_next →
        ∃ v : F, ∃ b : QrBucket F A,
          (x, v) ∈ u.elapsed ∧ ValidBucket b ∧ b.epoch = x ∧ b.contents.eval v ≠ 0 := by
  induction h with
  | init b v hb _ hne =>
    dsimp only
    refine ⟨Nat.lt_succ_self _, fun x hlo hhi => ?_⟩
    have hx : x = b.epoch := by omega
    subst hx
    exact ⟨v, b, Multiset.mem_singleton_self _, hb, rfl, hne⟩
  | lift b v _ hb _ hepoch _ hne hext ih =>
    dsimp only at ih ⊢
    obtain ⟨hlt, hcov⟩ := ih
    refine ⟨by omega, fun x hlo hhi => ?_⟩
    rcases (by omega : x < b.epoch ∨ x = b.epoch) with hx_lt | rfl
    · obtain ⟨v', b', hmem, hb', hb_ep, hne'⟩ := hcov x hlo (hepoch ▸ hx_lt)
      exact ⟨v', b', hext ▸ Multiset.mem_add.mpr (Or.inl hmem), hb', hb_ep, hne'⟩
    · refine ⟨v, b, hext ▸ Multiset.mem_add.mpr (Or.inr (Multiset.mem_singleton_self _)),
        hb, rfl, hne⟩
  | fuse _ _ _ hjoin hcomb ihl ihr =>
    rename_i left right _ _ _ _
    dsimp only at ihl ihr ⊢
    obtain ⟨hlt_l, hcov_l⟩ := ihl
    obtain ⟨hlt_r, hcov_r⟩ := ihr
    refine ⟨by omega, fun x hlo hhi => ?_⟩
    by_cases hx : x < left.epoch_next
    · obtain ⟨v, b, hmem, hb, hb_ep, hne⟩ := hcov_l x hlo hx
      exact ⟨v, b, hcomb ▸ Multiset.mem_add.mpr (Or.inl hmem), hb, hb_ep, hne⟩
    · obtain ⟨v, b, hmem, hb, hb_ep, hne⟩ := hcov_r x (by omega) hhi
      exact ⟨v, b, hcomb ▸ Multiset.mem_add.mpr (Or.inr hmem), hb, hb_ep, hne⟩

/-- Every derivable `ArbitraryUnspent` opens at the `anchor_start` of a valid bucket for
`u.epoch_start`. -/
theorem ArbitraryUnspentDerivable.opens_at_bucket
    {u : ArbitraryUnspent F A} (h : ArbitraryUnspentDerivable ValidBucket u) :
    ∃ b : QrBucket F A, ValidBucket b ∧ b.epoch = u.epoch_start ∧ b.anchor_start = u.anchor_start := by
  induction h with
  | init b _ hb _ _ => exact ⟨b, hb, rfl, rfl⟩
  | lift _ _ _ _ _ _ _ _ _ ih => exact ih
  | fuse _ _ _ _ _ ihl _ => exact ihl

/-! ## Bound unspent segments (`NoteUnspent`, `UnspentBind`) -/

/-- A `NoteUnspent` header `(cm, anchor_start, epoch_start, epoch_next, anchor_next)`. -/
structure NoteUnspent (F A : Type*) where
  cm : F
  anchor_start : A
  epoch_start : ℕ
  epoch_next : ℕ
  anchor_next : A

/-- `UnspentBind` (`crates/tachyon/src/stamp/proof/pool.rs`): binds an `ArbitraryUnspent`
to a `NoteNullifiers` by witnessing `complement` such that `n.seq = u.elapsed + complement`. -/
inductive NoteUnspentDerivable (ValidBucket : QrBucket F A → Prop) (nf : F → ℕ → F) :
    NoteUnspent F A → Prop
  | bind {u : ArbitraryUnspent F A} {n : NoteNullifiers F}
      (complement : Multiset (ℕ × F)) :
      ArbitraryUnspentDerivable ValidBucket u →
      NullifiersDerivable nf n →
      n.seq = u.elapsed + complement →
      NoteUnspentDerivable ValidBucket nf
        ⟨n.cm, u.anchor_start, u.epoch_start, u.epoch_next, u.anchor_next⟩

variable {nf : F → ℕ → F}

/-- `UnspentBind` soundness: for every epoch `x ∈ [nu.epoch_start, nu.epoch_next)`, the note's
genuine nullifier `nf nu.cm x` was tested nonzero against a valid bucket for epoch `x`. -/
theorem NoteUnspentDerivable.tested_nullifiers
    {nu : NoteUnspent F A} (h : NoteUnspentDerivable ValidBucket nf nu) :
    nu.epoch_start < nu.epoch_next ∧
      ∀ x, nu.epoch_start ≤ x → x < nu.epoch_next →
        ∃ b : QrBucket F A, ValidBucket b ∧ b.epoch = x ∧ b.contents.eval (nf nu.cm x) ≠ 0 := by
  cases h with
  | bind complement hu hn hdiv =>
    obtain ⟨hlt, hcov⟩ := hu.coverage
    refine ⟨hlt, fun x hlo hhi => ?_⟩
    obtain ⟨v, b, hmem, hb, hb_ep, hne⟩ := hcov x hlo hhi
    have hin_seq : (x, v) ∈ _ := hdiv ▸ Multiset.mem_add.mpr (Or.inl hmem)
    have hv : v = nf _ x := hn.mem_seq hin_seq
    subst hv
    exact ⟨b, hb, hb_ep, hne⟩

/-- When every admissible bucket is complete for `chain`, a derivable `NoteUnspent` certifies that
`nf nu.cm x` is unpublished in every epoch `x ∈ [nu.epoch_start, nu.epoch_next)`. -/
theorem NoteUnspentDerivable.lineage {chain : List (Chain.Stamp F A)}
    (hcomplete : ∀ ⦃b : QrBucket F A⦄, ValidBucket b → CompleteBucket chain b)
    {nu : NoteUnspent F A} (h : NoteUnspentDerivable ValidBucket nf nu) :
    nu.epoch_start < nu.epoch_next ∧
      ∀ x, nu.epoch_start ≤ x → x < nu.epoch_next → ¬ Chain.published chain x (nf nu.cm x) := by
  obtain ⟨hlt, htest⟩ := h.tested_nullifiers
  refine ⟨hlt, fun x hlo hhi => ?_⟩
  obtain ⟨b, hb, rfl, hne⟩ := htest x hlo hhi
  exact (hcomplete hb).not_published hne

theorem NoteUnspentDerivable.opens_at_bucket
    {nu : NoteUnspent F A} (h : NoteUnspentDerivable ValidBucket nf nu) :
    ∃ b : QrBucket F A, ValidBucket b ∧ b.epoch = nu.epoch_start ∧ b.anchor_start = nu.anchor_start := by
  cases h with
  | bind _ hu _ _ => exact hu.opens_at_bucket

/-! ## Spendable bootstrap and lift (`NoteSpendable`, `SpendableInit`, `QrSpendableInit`, `SpendableLift`) -/

/-- A `NoteSpendable` header `(cm, epoch_current, anchor)`. -/
structure NoteSpendable (F A : Type*) where
  cm : F
  epoch_current : ℕ
  anchor : A

/-- Derivable `NoteSpendable` headers, indexed by the creation epoch `start` at which the note's
lineage begins (`SpendableInit`, `QrSpendableInit` and `SpendableLift` in
`crates/tachyon/src/stamp/proof/spendable.rs`). -/
inductive SpendableDerivable (ValidBucket : QrBucket F A → Prop) (nf : F → ℕ → F)
    (nextStamp : A → ℕ → F[X] → A) : ℕ → NoteSpendable F A → Prop
  | init {n : NoteNullifiers F} (anchor_prev : A) (creation_set : F[X]) (creation_epoch : ℕ) :
      NullifiersDerivable nf n →
      creation_set.eval n.cm = 0 →
      creation_set ≠ 1 →
      SpendableDerivable ValidBucket nf nextStamp creation_epoch
        ⟨n.cm, creation_epoch, nextStamp anchor_prev creation_epoch creation_set⟩
  | qrInit {nu : NoteUnspent F A} (b : QrBucket F A) :
      NoteUnspentDerivable ValidBucket nf nu →
      ValidBucket b →
      nu.epoch_start = b.epoch →
      nu.anchor_start = b.anchor_start →
      nu.anchor_next = b.anchor_next →
      nu.epoch_next = b.epoch + 1 →
      b.contents.eval nu.cm = 0 →
      SpendableDerivable ValidBucket nf nextStamp b.epoch
        ⟨nu.cm, nu.epoch_next, nu.anchor_next⟩
  | lift {start : ℕ} {sp : NoteSpendable F A} {nu : NoteUnspent F A} :
      SpendableDerivable ValidBucket nf nextStamp start sp →
      NoteUnspentDerivable ValidBucket nf nu →
      nu.cm = sp.cm →
      nu.epoch_start = sp.epoch_current →
      nu.anchor_start = sp.anchor →
      SpendableDerivable ValidBucket nf nextStamp start
        ⟨sp.cm, nu.epoch_next, nu.anchor_next⟩

variable {nextStamp : A → ℕ → F[X] → A}

/-- Why `SpendableInit` can only spend in its creation epoch (`spendable.rs:198-201`):
`QrBucketSeal` requires every bucket's `anchor_start` to be a `nextEpoch` boundary digest, whereas
`SpendableInit` emits a `nextStamp` fold. Under `Chain.HashLaw`, `SpendableLift`'s anchor-adjacency
check `nu.anchor_start = sp.anchor` is impossible on a `SpendableInit` output.
This lemma is in the symbolic `HashLaw` model, not a concrete finite-hash
instantiation; data-valued finite-trace reductions return collision witnesses. -/
theorem spendableInit_cannot_lift {genesis : A} {e₀ : ℕ} {nextEpoch : A → ℕ → A}
    (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hseal : ∀ ⦃b : QrBucket F A⦄, ValidBucket b → ∃ prev, b.anchor_start = nextEpoch prev b.epoch)
    {nu : NoteUnspent F A} (hnu : NoteUnspentDerivable ValidBucket nf nu)
    {anchor_prev : A} {creation_set : F[X]} {creation_epoch : ℕ}
    (hadj : nu.anchor_start = nextStamp anchor_prev creation_epoch creation_set) :
    False := by
  obtain ⟨b, hb, _, hb_start⟩ := hnu.opens_at_bucket
  obtain ⟨prev, hprev⟩ := hseal hb
  rw [hb_start, hadj] at hprev
  exact hlaw.stamp_ne_epoch hprev

/-- **Spendable lineage soundness**: for any derivable `sp : NoteSpendable F A` rooted at creation
epoch `start`, if every admissible bucket is complete for `chain`, then `start ≤ sp.epoch_current`
and for every epoch `x ∈ [start, sp.epoch_current)`, the note's nullifier `nf sp.cm x` is not
published in epoch `x` on `chain`. -/
theorem SpendableDerivable.lineage {chain : List (Chain.Stamp F A)}
    (hcomplete : ∀ ⦃b : QrBucket F A⦄, ValidBucket b → CompleteBucket chain b)
    {start : ℕ} {sp : NoteSpendable F A}
    (h : SpendableDerivable ValidBucket nf nextStamp start sp) :
    start ≤ sp.epoch_current ∧
      ∀ x, start ≤ x → x < sp.epoch_current → ¬ Chain.published chain x (nf sp.cm x) := by
  induction h with
  | init _ _ _ _ _ _ =>
    dsimp only
    exact ⟨le_rfl, fun _ hlo hhi => absurd hhi (not_lt_of_ge hlo)⟩
  | qrInit b hnu _ hepoch _ _ hnext _ =>
    dsimp only
    obtain ⟨_, hlin⟩ := hnu.lineage hcomplete
    refine ⟨by omega, fun x hlo hhi => hlin x (hepoch ▸ hlo) hhi⟩
  | lift _ hnu hcm hepoch _ ih =>
    rename_i start' sp' nu' _ _
    dsimp only at ih ⊢
    obtain ⟨hstart_le, hlin_sp⟩ := ih
    obtain ⟨hlt_nu, hlin_nu⟩ := hnu.lineage hcomplete
    refine ⟨by omega, fun x hlo hhi => ?_⟩
    by_cases hx : x < sp'.epoch_current
    · exact hlin_sp x hlo hx
    · rw [← hcm]
      exact hlin_nu x (by omega) hhi

end Tachyon
