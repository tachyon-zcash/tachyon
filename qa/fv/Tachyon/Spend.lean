import Tachyon.Qr

/-!
# Spend lineage

The steps under a `SpendAction` leaf, from `crates/tachyon/src/stamp/proof/delegation.rs`,
`spendable.rs` and `spend.rs`. Each header is its Rust header data; fields the spend's nullifier
pair does not depend on (the note opening, `pk`, `cv`, the online slots) are dropped.

- `NoteSeed` pairs a note commitment `cm` with its master key `mk`: `cm` commits to the note's
  payment key `pk = paymentKey(ak, nk)` and `psi`, and `mk = nfMaster(psi, nk)`. Under binding of
  the commitment and of the payment key, `cm` determines `mk` (`NoteSecretDerivable.master_eq`).
- A `NoteSpendable` lineage starts at `SpendableInit`, whose anchor is the stamp fold of a
  witnessed predecessor at the witnessed creation epoch, or at `QrSpendableInit`, which moves to a
  `NoteUnspent` segment's far bound. `SpendableLift` hands off to a segment at its near bound and
  moves to its far bound.
- `SpendBind` derives the pair from `mk` at the lineage's epoch `e` and `e + 1`, and threads the
  lineage's `cm` and anchor onto the `SpendHeader`.

When the lineage's anchor is a chain node at epoch `e`, its epoch is `e`
(`SpendableDerivable.epoch_eq`), so the spend publishes `mk`'s nullifiers at `e` and `e + 1`
(`SpendDerivable.pair`). The `SpendableInit` case closes by `Node.of_nextStamp`. The other two close
because a `NoteUnspent` segment's `anchor_next` is the entry anchor of its `epoch_next`
(`UnspentSpec`), and an entry anchor is a chain node only at its own epoch (`Node.of_nextEpoch`).
-/

namespace Tachyon

open Polynomial

section Chain

variable {F A E : Type*} [Field F] {q : Chain.AnchorQueries F A E} {genesis : A} {e₀ : E}
  {nextStamp : A → E → F[X] → A} {nextEpoch : A → E → A}

/-- If the call `nextEpoch a e'` is a chain node at epoch `e`, then `e' = e`. -/
theorem Chain.Node.of_nextEpoch (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    {e e' : E} {a : A} (hq : q.boundary a e')
    (h : Chain.Node q genesis e₀ nextStamp nextEpoch e (nextEpoch a e')) : e' = e := by
  generalize htarget : nextEpoch a e' = target at h
  cases h with
  | genesis =>
    by_contra hne
    exact hlaw.epoch_ne_genesis hq hne htarget
  | stamp _ _ _ hq' => exact absurd htarget.symm (hlaw.stamp_ne_epoch hq' hq)
  | epoch _ _ hq' => exact (hlaw.nextEpoch_inj hq hq' htarget).2

end Chain

/-- `NoteSecret` header data `(cm, mk)`, with `mk` as `master`. The note opening it also carries is
not modelled. -/
structure NoteSecret (F : Type*) where
  cm : F
  master : F

/-- `NoteUnspent` header data `(cm, anchor_start, epoch_start, epoch_next, anchor_next)`
(`pool.rs`). Its derivability is `NoteUnspentDerivable` (`Unspent.lean`); the steps here take
it as a parameter. -/
structure NoteUnspent (F : Type*) where
  cm : F
  anchor_start : F
  epoch_start : ℕ
  epoch_next : ℕ
  anchor_next : F

/-- `NoteSpendable` header data `(cm, epoch_current, anchor)`. -/
structure NoteSpendable (F : Type*) where
  cm : F
  epoch_current : ℕ
  anchor : F

/-- `SpendHeader` data `(cm, nf_current, nf_next, anchor)`. `pk` and `cv` are not modelled. -/
structure SpendHeader (F : Type*) where
  cm : F
  nf_current : F
  nf_next : F
  anchor : F

variable {F W P : Type*}

/-- The note commitment and payment key calls under consideration: `commit w pk psi` is a call
`noteCommit w pk psi`, and `key ak nk` a call `paymentKey ak nk`. -/
structure NoteQueries (F W P : Type*) where
  commit : W → F → F → Prop
  key : P → F → Prop

/-- Binding of the note commitment to `(pk, psi)` and of the payment key to `nk` on the calls `n`.
A finite `n` without a collision satisfies it. -/
structure NoteLaw (n : NoteQueries F W P) (noteCommit : W → F → F → F) (paymentKey : P → F → F) :
    Prop where
  commit_binds : ∀ {w₁ w₂ : W} {pk₁ pk₂ psi₁ psi₂ : F}, n.commit w₁ pk₁ psi₁ →
    n.commit w₂ pk₂ psi₂ → noteCommit w₁ pk₁ psi₁ = noteCommit w₂ pk₂ psi₂ →
      pk₁ = pk₂ ∧ psi₁ = psi₂
  paymentKey_binds : ∀ {ak₁ ak₂ : P} {nk₁ nk₂ : F}, n.key ak₁ nk₁ → n.key ak₂ nk₂ →
    paymentKey ak₁ nk₁ = paymentKey ak₂ nk₂ → nk₁ = nk₂

/-- `NoteSeed` over the calls `n`: `w` is the note's value and `rcm`, `ak` and `nk` its proof
authorizing key. -/
inductive NoteSecretDerivable (n : NoteQueries F W P) (noteCommit : W → F → F → F)
    (paymentKey : P → F → F) (nfMaster : F → F → F) : NoteSecret F → Prop
  | seed (w : W) (ak : P) (psi nk : F) :
      n.commit w (paymentKey ak nk) psi → n.key ak nk →
      NoteSecretDerivable n noteCommit paymentKey nfMaster
        ⟨noteCommit w (paymentKey ak nk) psi, nfMaster psi nk⟩

/-- Two note secrets with one commitment have one master key. -/
theorem NoteSecretDerivable.master_eq {n : NoteQueries F W P} {noteCommit : W → F → F → F}
    {paymentKey : P → F → F} {nfMaster : F → F → F} (hlaw : NoteLaw n noteCommit paymentKey)
    {s₁ s₂ : NoteSecret F}
    (h₁ : NoteSecretDerivable n noteCommit paymentKey nfMaster s₁)
    (h₂ : NoteSecretDerivable n noteCommit paymentKey nfMaster s₂) (hcm : s₁.cm = s₂.cm) :
    s₁.master = s₂.master := by
  cases h₁ with
  | seed w₁ ak₁ psi₁ nk₁ hc₁ hk₁ =>
    cases h₂ with
    | seed w₂ ak₂ psi₂ nk₂ hc₂ hk₂ =>
      obtain ⟨hpk, rfl⟩ := hlaw.commit_binds hc₁ hc₂ hcm
      obtain rfl := hlaw.paymentKey_binds hk₁ hk₂ hpk
      rfl

variable [Field F]

/-- The property of `NoteUnspent` derivability the spend pair consumes
(`NoteUnspentDerivable.spec`). `QrBucketSeal` computes a bucket's `anchor_next` as the epoch fold
of its final anchor and `epoch + 1`; `UnspentLift` and `UnspentFuse` emit a bucket's or their right
input's far bound. -/
structure UnspentSpec (q : Chain.AnchorQueries F F ℕ) (nextEpoch : F → ℕ → F)
    (Unspent : NoteUnspent F → Prop) : Prop where
  /-- `anchor_next` is a boundary digest into `epoch_next`, from a call in `q`. -/
  anchor_next_entry : ∀ {u : NoteUnspent F}, Unspent u →
    ∃ a, u.anchor_next = nextEpoch a u.epoch_next ∧ q.boundary a u.epoch_next

/-- `NoteSpendable` headers: `SpendableInit`, `QrSpendableInit` over the buckets `Bucket` admits,
and `SpendableLift`. `SpendableInit`'s `cm` comes from any `NoteNullifiers`, here left free.
`QrSpendableInit`'s `anchor_start` equality is dropped. -/
inductive SpendableDerivable (q : Chain.AnchorQueries F F ℕ) (nextStamp : F → ℕ → F[X] → F)
    (Bucket : QrBucket F F → Prop) (Unspent : NoteUnspent F → Prop) : NoteSpendable F → Prop
  | init (cm prev : F) (creation : F[X]) (e : ℕ) :
      creation.eval cm = 0 → q.stamp prev e creation →
        SpendableDerivable q nextStamp Bucket Unspent ⟨cm, e, nextStamp prev e creation⟩
  | qrInit {u : NoteUnspent F} {b : QrBucket F F} :
      Unspent u → Bucket b → b.epoch = u.epoch_start → b.anchor_next = u.anchor_next →
      b.epoch + 1 = u.epoch_next → b.contents.eval u.cm = 0 →
        SpendableDerivable q nextStamp Bucket Unspent ⟨u.cm, u.epoch_next, u.anchor_next⟩
  | lift {s : NoteSpendable F} {u : NoteUnspent F} :
      SpendableDerivable q nextStamp Bucket Unspent s → Unspent u → s.cm = u.cm →
        s.epoch_current = u.epoch_start → s.anchor = u.anchor_start →
        SpendableDerivable q nextStamp Bucket Unspent ⟨s.cm, u.epoch_next, u.anchor_next⟩

/-- `SpendBind`: the secret's `cm` is the lineage's, and the pair is the secret's nullifiers at the
lineage's epoch and its successor. -/
inductive SpendDerivable (q : Chain.AnchorQueries F F ℕ) (nextStamp : F → ℕ → F[X] → F)
    (Bucket : QrBucket F F → Prop) (Unspent : NoteUnspent F → Prop) (Secret : NoteSecret F → Prop)
    (nullifier : F → ℕ → F) : SpendHeader F → Prop
  | bind {s : NoteSpendable F} {k : NoteSecret F} :
      SpendableDerivable q nextStamp Bucket Unspent s → Secret k → s.cm = k.cm →
        SpendDerivable q nextStamp Bucket Unspent Secret nullifier
          ⟨s.cm, nullifier k.master s.epoch_current, nullifier k.master (s.epoch_current + 1),
            s.anchor⟩

variable {q : Chain.AnchorQueries F F ℕ} {genesis : F} {e₀ : ℕ} {nextStamp : F → ℕ → F[X] → F}
  {nextEpoch : F → ℕ → F} {Bucket : QrBucket F F → Prop} {Unspent : NoteUnspent F → Prop}

/-- A spendable lineage whose anchor is a chain node at epoch `e` is at epoch `e`. -/
theorem SpendableDerivable.epoch_eq (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    (hunspent : UnspentSpec q nextEpoch Unspent) {s : NoteSpendable F}
    (h : SpendableDerivable q nextStamp Bucket Unspent s) {e : ℕ}
    (hnode : Chain.Node q genesis e₀ nextStamp nextEpoch e s.anchor) : s.epoch_current = e := by
  cases h with
  | init _ _ _ _ _ hq => exact (Chain.Node.of_nextStamp hlaw hq hnode).1
  | qrInit hu _ _ _ _ _ =>
    obtain ⟨a, ha, hq⟩ := hunspent.anchor_next_entry hu
    rw [ha] at hnode
    exact Chain.Node.of_nextEpoch hlaw hq hnode
  | lift _ hu _ _ _ =>
    obtain ⟨a, ha, hq⟩ := hunspent.anchor_next_entry hu
    rw [ha] at hnode
    exact Chain.Node.of_nextEpoch hlaw hq hnode

/-- A spend whose anchor is a chain node at epoch `e` carries its note secret's nullifiers at `e`
and `e + 1`. -/
theorem SpendDerivable.pair (hlaw : Chain.HashLaw q genesis e₀ nextStamp nextEpoch)
    (hunspent : UnspentSpec q nextEpoch Unspent) {Secret : NoteSecret F → Prop}
    {nullifier : F → ℕ → F} {h : SpendHeader F}
    (hspend : SpendDerivable q nextStamp Bucket Unspent Secret nullifier h) {e : ℕ}
    (hnode : Chain.Node q genesis e₀ nextStamp nextEpoch e h.anchor) :
    ∃ k, Secret k ∧ k.cm = h.cm ∧ h.nf_current = nullifier k.master e ∧
      h.nf_next = nullifier k.master (e + 1) := by
  cases hspend with
  | bind hs hk hcm =>
    obtain rfl := hs.epoch_eq hlaw hunspent hnode
    exact ⟨_, hk, hcm.symm, rfl, rfl⟩

end Tachyon
