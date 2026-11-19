import Mathlib.Data.List.Prime
import Tachyon.Qr
import Tachyon.Spend

/-!
# Unspent lineages

`ArbitraryUnspent`, `NoteNullifiers` and `NoteUnspent` (`crates/tachyon/src/stamp/proof/pool.rs`,
`qr.rs`, `delegation.rs`). An `ArbitraryUnspent` tests one value per epoch against that epoch's
bucket, and `UnspentBind` shows each tested value is the note's own nullifier at its epoch. A
`NoteUnspent` that ends on the published entry anchor of its `epoch_next` proves the note's
nullifier unpublished in every epoch of `[epoch_start, epoch_next)` (`NoteUnspentDerivable.lineage`).

An `NfSeqPoly` holds the product of indexed members `member i m`, the encoding
`(m + (i + 1) X) ^ 3 - c` in Rust. `MemberLaw` states the two facts the bind uses: a member at an
epoch index is prime, and one member divides another only when their indices and values agree.

`NullifierDerive` reads a `NoteSecret` from `NoteSeed` (`Spend.lean`) and derives
`nullifier mk x` from its master key `mk`. A commitment fixes its master key
(`NoteSecretDerivable.master_eq`), so every derivation for one `cm` holds the same nullifiers.

The model omits `NullifierFuse`'s contiguity check, `NullifierDerive`'s group alignment, the
nonzero tested value and the empty-segment exclusion: no result here uses them.
-/

namespace Tachyon

open Polynomial Chain

variable {F A : Type*} [Field F]

/-- The indexed-member encoding's injectivity over epoch indices up to `emax` (`EPOCH_MAX`). -/
structure MemberLaw (member : ℕ → F → F[X]) (emax : ℕ) : Prop where
  prime : ∀ {i : ℕ} {m : F}, i ≤ emax → Prime (member i m)
  dvd_inj : ∀ {i j : ℕ} {m w : F}, i ≤ emax → j ≤ emax → member i m ∣ member j w → i = j ∧ m = w

/-- `QrUnspentInit`'s and `UnspentLift`'s test of `value` against a bucket: each of the first
`depth` positions witnesses a root `r` with `r ^ 2 = (1 or qnr) * (value + R₀ + j)` for the
bucket's side, a zero shifted value only on the residue side, and the contents open nonzero at
`value`. -/
def UnspentTest (qnr : F) (b : QrBucket F A) (value : F) : Prop :=
  (∀ j (hj : j < b.path.length), ∃ r : F,
    r ^ 2 = (if b.path[j] then 1 else qnr) * (value + (b.discriminant + j)) ∧
      (b.path[j] = false → value + (b.discriminant + j) ≠ 0)) ∧
  b.contents.eval value ≠ 0

theorem UnspentTest.matches {qnr : F} (hqnr : ¬ IsSquare qnr) {b : QrBucket F A} {value : F}
    (h : UnspentTest qnr b value) : Matches b.discriminant b.path value := by
  intro j hj
  obtain ⟨r, hr, hzero⟩ := h.1 j hj
  cases hp : b.path[j] with
  | true =>
    simp only [hp, if_true, one_mul] at hr
    exact iff_of_true rfl ⟨r, by rw [← hr, sq]⟩
  | false =>
    simp only [hp, Bool.false_eq_true, if_false] at hr
    refine iff_of_false Bool.false_ne_true fun ⟨w, hw⟩ => hqnr ⟨r / w, ?_⟩
    have hw0 : w ≠ 0 := by
      rintro rfl
      exact hzero hp (by rw [hw, mul_zero])
    rw [hw] at hr
    rw [div_mul_div_comm, ← sq, hr, mul_div_assoc, div_self (mul_ne_zero hw0 hw0), mul_one]

/-- An `ArbitraryUnspent`: header data `(anchor_start, epoch_start, epoch_next, anchor_next)` and
the `elapsed` slot. -/
structure ArbitraryUnspent (F A : Type*) [Field F] where
  anchor_start : A
  epoch_start : ℕ
  epoch_next : ℕ
  anchor_next : A
  elapsed : F[X]

/-- `QrUnspentInit`, `UnspentFuse` and `UnspentLift` over the buckets `Bucket` admits. -/
inductive ArbitraryUnspentDerivable (Bucket : QrBucket F A → Prop) (qnr : F)
    (member : ℕ → F → F[X]) (emax : ℕ) : ArbitraryUnspent F A → Prop
  | init {b : QrBucket F A} (value : F) :
      Bucket b → b.epoch + 1 ≤ emax → UnspentTest qnr b value →
        ArbitraryUnspentDerivable Bucket qnr member emax
          ⟨b.anchor_start, b.epoch, b.epoch + 1, b.anchor_next, member b.epoch value⟩
  | fuse {left right : ArbitraryUnspent F A} :
      ArbitraryUnspentDerivable Bucket qnr member emax left →
      ArbitraryUnspentDerivable Bucket qnr member emax right →
      left.anchor_next = right.anchor_start → left.epoch_next = right.epoch_start →
        ArbitraryUnspentDerivable Bucket qnr member emax
          ⟨left.anchor_start, left.epoch_start, right.epoch_next, right.anchor_next,
            left.elapsed * right.elapsed⟩
  | lift {left : ArbitraryUnspent F A} {b : QrBucket F A} (value : F) :
      ArbitraryUnspentDerivable Bucket qnr member emax left → Bucket b →
      left.anchor_next = b.anchor_start → left.epoch_next = b.epoch → b.epoch + 1 ≤ emax →
      UnspentTest qnr b value →
        ArbitraryUnspentDerivable Bucket qnr member emax
          ⟨left.anchor_start, left.epoch_start, b.epoch + 1, b.anchor_next,
            left.elapsed * member b.epoch value⟩

/-- A `NoteNullifiers`: header data `(cm, epoch_start, epoch_end)` and the sequence slot. -/
structure NoteNullifiers (F : Type*) [Field F] where
  cm : F
  epoch_start : ℕ
  epoch_end : ℕ
  seq : F[X]

/-- `NullifierDerive` over a `NoteSecret` that `Secret` accepts, with its
`NF_DERIVATION_WIDTH = 16` window, and `NullifierFuse`. `nullifier mk x` is the nullifier of
master key `mk` at epoch `x`. -/
inductive NoteNullifiersDerivable (Secret : NoteSecret F → Prop) (member : ℕ → F → F[X])
    (nullifier : F → ℕ → F) (emax : ℕ) : NoteNullifiers F → Prop
  | derive {secret : NoteSecret F} (epoch_start : ℕ) :
      Secret secret → epoch_start + 15 ≤ emax →
        NoteNullifiersDerivable Secret member nullifier emax
          ⟨secret.cm, epoch_start, epoch_start + 15,
            ((List.range 16).map fun k =>
              member (epoch_start + k) (nullifier secret.master (epoch_start + k))).prod⟩
  | fuse {left right : NoteNullifiers F} :
      NoteNullifiersDerivable Secret member nullifier emax left →
      NoteNullifiersDerivable Secret member nullifier emax right → left.cm = right.cm →
        NoteNullifiersDerivable Secret member nullifier emax
          ⟨left.cm, left.epoch_start, right.epoch_end, left.seq * right.seq⟩

/-- `UnspentBind`: the derivation's sequence is `elapsed` times a witnessed complement. -/
inductive NoteUnspentDerivable (Bucket : QrBucket F F → Prop) (qnr : F) (member : ℕ → F → F[X])
    (Secret : NoteSecret F → Prop) (nullifier : F → ℕ → F) (emax : ℕ) : NoteUnspent F → Prop
  | bind {unspent : ArbitraryUnspent F F} {nullifiers : NoteNullifiers F} (complement : F[X]) :
      ArbitraryUnspentDerivable Bucket qnr member emax unspent →
      NoteNullifiersDerivable Secret member nullifier emax nullifiers →
      nullifiers.seq = unspent.elapsed * complement →
        NoteUnspentDerivable Bucket qnr member Secret nullifier emax
          ⟨nullifiers.cm, unspent.anchor_start, unspent.epoch_start, unspent.epoch_next,
            unspent.anchor_next⟩

variable {Bucket : QrBucket F A → Prop} {qnr : F} {member : ℕ → F → F[X]}
  {Secret : NoteSecret F → Prop} {nullifier : F → ℕ → F}
  {emax : ℕ} {nextStamp : A → ℕ → F[X] → A} {nextEpoch : A → ℕ → A} {zero : A}
  {chain : List (Chain.Stamp F A)} {genesis : A} {e₀ : ℕ}

/-- A derivation's sequence holds one note secret's nullifiers, given that a commitment fixes its
master key (`NoteSecretDerivable.master_eq`). -/
theorem NoteNullifiersDerivable.seq_eq
    (hmaster : ∀ {k₁ k₂ : NoteSecret F}, Secret k₁ → Secret k₂ → k₁.cm = k₂.cm →
      k₁.master = k₂.master)
    {n : NoteNullifiers F} (h : NoteNullifiersDerivable Secret member nullifier emax n) :
    ∃ secret, Secret secret ∧ secret.cm = n.cm ∧ ∃ M : List ℕ, (∀ y ∈ M, y ≤ emax) ∧
      n.seq = (M.map fun y => member y (nullifier secret.master y)).prod := by
  induction h with
  | @derive secret s hsecret hs =>
    refine ⟨secret, hsecret, rfl, (List.range 16).map (s + ·), ?_,
      by simp [List.map_map, Function.comp_def]⟩
    intro y hy
    obtain ⟨k, hk, rfl⟩ := List.mem_map.mp hy
    have := List.mem_range.mp hk
    omega
  | fuse _ _ hcm ihl ihr =>
    obtain ⟨kL, hkL, hkLcm, ML, hML, hl⟩ := ihl
    obtain ⟨kR, hkR, hkRcm, MR, hMR, hr⟩ := ihr
    have hmk : kR.master = kL.master := hmaster hkR hkL (by rw [hkRcm, hkLcm, hcm])
    refine ⟨kL, hkL, hkLcm, ML ++ MR, fun y hy => (List.mem_append.mp hy).elim (hML y) (hMR y), ?_⟩
    simp only [hl, hr, hmk, List.map_append, List.prod_append]

/-- Every derivable segment ends on a boundary digest into its `epoch_next`. -/
theorem ArbitraryUnspentDerivable.anchor_next_boundary
    (hbucket : ∀ b, Bucket b → b.Covers nextStamp nextEpoch) {u : ArbitraryUnspent F A}
    (hu : ArbitraryUnspentDerivable Bucket qnr member emax u) :
    ∃ a, u.anchor_next = nextEpoch a u.epoch_next := by
  induction hu with
  | init _ hb =>
    obtain ⟨_, _, -, hnext, -⟩ := hbucket _ hb
    exact ⟨_, hnext⟩
  | fuse _ _ _ _ _ ihr => exact ihr
  | lift _ _ hb =>
    obtain ⟨_, _, -, hnext, -⟩ := hbucket _ hb
    exact ⟨_, hnext⟩

/-- Every derivable segment covers at least one epoch. -/
theorem ArbitraryUnspentDerivable.epoch_lt {u : ArbitraryUnspent F A}
    (hu : ArbitraryUnspentDerivable Bucket qnr member emax u) : u.epoch_start < u.epoch_next := by
  induction hu with
  | init => exact Nat.lt_succ_self _
  | fuse _ _ _ hepoch ihl ihr => exact ihl.trans (hepoch ▸ ihr)
  | lift _ _ _ _ hepoch _ _ ih => exact (hepoch ▸ ih).trans (Nat.lt_succ_self _)

theorem NoteUnspentDerivable.epoch_lt {Bucket : QrBucket F F → Prop} {u : NoteUnspent F}
    (hu : NoteUnspentDerivable Bucket qnr member Secret nullifier emax u) :
    u.epoch_start < u.epoch_next := by
  obtain ⟨_, hunspent, _, _⟩ := hu
  exact hunspent.epoch_lt

/-- The property of `NoteUnspent` derivability the spend lineage consumes. -/
theorem NoteUnspentDerivable.spec {Bucket : QrBucket F F → Prop} {nextStamp : F → ℕ → F[X] → F}
    {nextEpoch : F → ℕ → F} (hbucket : ∀ b, Bucket b → b.Covers nextStamp nextEpoch) :
    UnspentSpec nextEpoch (NoteUnspentDerivable Bucket qnr member Secret nullifier emax) where
  anchor_next_entry := fun ⟨_, hunspent, _, _⟩ => hunspent.anchor_next_boundary hbucket

/-- A derivable `ArbitraryUnspent` that ends on the published entry anchor of its `epoch_next`
starts on the entry anchor of its `epoch_start`, and for each epoch `x` it covers, `elapsed` holds
a member at `x` whose value is unpublished in `x`. -/
theorem ArbitraryUnspentDerivable.lineage (hlaw : HashLaw genesis e₀ nextStamp nextEpoch)
    (hqnr : ¬ IsSquare qnr) (hbucket : ∀ b, Bucket b → b.Covers nextStamp nextEpoch)
    {u : ArbitraryUnspent F A} (hu : ArbitraryUnspentDerivable Bucket qnr member emax u)
    (hnext : u.anchor_next = entry nextStamp nextEpoch zero chain u.epoch_next) :
    u.anchor_start = entry nextStamp nextEpoch zero chain u.epoch_start ∧
      ∀ x, u.epoch_start ≤ x → x < u.epoch_next →
        ∃ v, x ≤ emax ∧ member x v ∣ u.elapsed ∧ ¬ published chain x v := by
  have tested : ∀ {b : QrBucket F A} {v : F}, Bucket b → UnspentTest qnr b v →
      b.anchor_next = entry nextStamp nextEpoch zero chain (b.epoch + 1) →
        b.anchor_start = entry nextStamp nextEpoch zero chain b.epoch ∧
          ¬ published chain b.epoch v := fun hb htest hnext => by
    obtain ⟨hstart, hcomplete, -⟩ := (hbucket _ hb).onChain hlaw hnext
    exact ⟨hstart, fun hpub => htest.2 (hcomplete _ hpub (htest.matches hqnr))⟩
  induction hu with
  | @init b v hb hmax htest =>
    obtain ⟨hstart, hfresh⟩ := tested hb htest hnext
    refine ⟨hstart, fun x hx hx' => ?_⟩
    dsimp only at hx hx' ⊢
    obtain rfl : x = b.epoch := by omega
    exact ⟨v, by omega, dvd_rfl, hfresh⟩
  | @fuse left right _ _ hjoin hepoch ihl ihr =>
    obtain ⟨hrstart, hr⟩ := ihr hnext
    obtain ⟨hlstart, hl⟩ := ihl (by rw [hjoin, hrstart, hepoch])
    refine ⟨hlstart, fun x hx hx' => ?_⟩
    by_cases hlt : x < left.epoch_next
    · obtain ⟨v, hv, hdvd, hfresh⟩ := hl x hx hlt
      exact ⟨v, hv, hdvd.mul_right _, hfresh⟩
    · obtain ⟨v, hv, hdvd, hfresh⟩ := hr x (by omega) hx'
      exact ⟨v, hv, hdvd.mul_left _, hfresh⟩
  | @lift left b v _ hb hjoin hepoch hmax htest ih =>
    obtain ⟨hbstart, hfresh⟩ := tested hb htest hnext
    obtain ⟨hlstart, hl⟩ := ih (by rw [hjoin, hbstart, hepoch])
    refine ⟨hlstart, fun x hx hx' => ?_⟩
    dsimp only at hx hx' ⊢
    by_cases hlt : x < left.epoch_next
    · obtain ⟨w, hw, hdvd, hwfresh⟩ := hl x hx hlt
      exact ⟨w, hw, hdvd.mul_right _, hwfresh⟩
    · obtain rfl : x = b.epoch := by omega
      exact ⟨v, by omega, dvd_mul_left _ _, hfresh⟩

/-- **Unspent lineage.** A derivable `NoteUnspent` that ends on the published entry anchor of its
`epoch_next` starts on the entry anchor of its `epoch_start`, and for every note secret of its
`cm`, the nullifier at each epoch of `[epoch_start, epoch_next)` is unpublished in that epoch. -/
theorem NoteUnspentDerivable.lineage {Bucket : QrBucket F F → Prop}
    {nextStamp : F → ℕ → F[X] → F} {nextEpoch : F → ℕ → F} {zero genesis : F}
    {chain : List (Chain.Stamp F F)} (hlaw : HashLaw genesis e₀ nextStamp nextEpoch)
    (hqnr : ¬ IsSquare qnr) (hmember : MemberLaw member emax)
    (hmaster : ∀ {k₁ k₂ : NoteSecret F}, Secret k₁ → Secret k₂ → k₁.cm = k₂.cm →
      k₁.master = k₂.master)
    (hbucket : ∀ b, Bucket b → b.Covers nextStamp nextEpoch)
    {u : NoteUnspent F} (hu : NoteUnspentDerivable Bucket qnr member Secret nullifier emax u)
    (hnext : u.anchor_next = entry nextStamp nextEpoch zero chain u.epoch_next) :
    u.anchor_start = entry nextStamp nextEpoch zero chain u.epoch_start ∧
      ∀ k, Secret k → k.cm = u.cm →
        ∀ x, u.epoch_start ≤ x → x < u.epoch_next → ¬ published chain x (nullifier k.master x) := by
  obtain @⟨unspent, nullifiers, complement, hunspent, hnullifiers, hbind⟩ := hu
  obtain ⟨hstart, hlineage⟩ := hunspent.lineage hlaw hqnr hbucket hnext
  obtain ⟨secret, hsecret, hcm, M, hM, hseq⟩ := hnullifiers.seq_eq hmaster
  refine ⟨hstart, fun k hk hkcm x hx hx' => ?_⟩
  rw [hmaster hk hsecret (hkcm.trans hcm.symm)]
  obtain ⟨v, hv, hdvd, hfresh⟩ := hlineage x hx hx'
  have hdvd' : member x v ∣ (M.map fun y => member y (nullifier secret.master y)).prod := by
    rw [← hseq, hbind]
    exact hdvd.mul_right _
  obtain ⟨_, hmem, hfactor⟩ := (Prime.dvd_prod_iff (hmember.prime (m := v) hv)).mp hdvd'
  obtain ⟨y, hy, rfl⟩ := List.mem_map.mp hmem
  obtain ⟨rfl, rfl⟩ := hmember.dvd_inj hv (hM y hy) hfactor
  exact hfresh

end Tachyon
