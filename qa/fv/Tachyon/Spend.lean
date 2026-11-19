import Tachyon.Consensus.Chain

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

variable {F A E : Type*} [Field F] {genesis : A} {e₀ : E} {nextStamp : A → E → F[X] → A}
  {nextEpoch : A → E → A}

/-- If `nextEpoch a e'` is a chain node at epoch `e`, then `e' = e`. -/
theorem Chain.Node.of_nextEpoch (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    {e e' : E} {a : A} (h : Chain.Node genesis e₀ nextStamp nextEpoch e (nextEpoch a e')) :
    e' = e := by
  generalize htarget : nextEpoch a e' = target at h
  cases h with
  | genesis =>
    by_contra hne
    exact hlaw.epoch_ne_genesis hne htarget
  | stamp _ _ _ => exact absurd htarget.symm hlaw.stamp_ne_epoch
  | epoch _ _ => exact (hlaw.nextEpoch_inj htarget).2

end Chain

/-- `NoteSecret` header data `(cm, mk)`, with `mk` as `master`. The note opening it also carries is
not modelled. -/
structure NoteSecret (F : Type*) where
  cm : F
  master : F

/-- `NoteUnspent` header data `(cm, anchor_start, epoch_start, epoch_next, anchor_next)`
(`pool.rs`). Its derivability is a parameter, modelled on `lean/qr-lineage`. -/
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

/-- Binding of the note commitment to `(pk, psi)` and of the payment key to `nk`, idealizing
collision resistance as exact. -/
structure NoteLaw (noteCommit : W → F → F → F) (paymentKey : P → F → F) : Prop where
  commit_binds : ∀ {w₁ w₂ : W} {pk₁ pk₂ psi₁ psi₂ : F},
    noteCommit w₁ pk₁ psi₁ = noteCommit w₂ pk₂ psi₂ → pk₁ = pk₂ ∧ psi₁ = psi₂
  paymentKey_binds : ∀ {ak₁ ak₂ : P} {nk₁ nk₂ : F},
    paymentKey ak₁ nk₁ = paymentKey ak₂ nk₂ → nk₁ = nk₂

/-- `NoteSeed`: `w` is the note's value and `rcm`, `ak` and `nk` its proof authorizing key. -/
inductive NoteSecretDerivable (noteCommit : W → F → F → F) (paymentKey : P → F → F)
    (nfMaster : F → F → F) : NoteSecret F → Prop
  | seed (w : W) (ak : P) (psi nk : F) :
      NoteSecretDerivable noteCommit paymentKey nfMaster
        ⟨noteCommit w (paymentKey ak nk) psi, nfMaster psi nk⟩

/-- Two note secrets with one commitment have one master key. -/
theorem NoteSecretDerivable.master_eq {noteCommit : W → F → F → F} {paymentKey : P → F → F}
    {nfMaster : F → F → F} (hlaw : NoteLaw noteCommit paymentKey) {s₁ s₂ : NoteSecret F}
    (h₁ : NoteSecretDerivable noteCommit paymentKey nfMaster s₁)
    (h₂ : NoteSecretDerivable noteCommit paymentKey nfMaster s₂) (hcm : s₁.cm = s₂.cm) :
    s₁.master = s₂.master := by
  cases h₁ with
  | seed w₁ ak₁ psi₁ nk₁ =>
    cases h₂ with
    | seed w₂ ak₂ psi₂ nk₂ =>
      obtain ⟨hpk, rfl⟩ := hlaw.commit_binds hcm
      obtain rfl := hlaw.paymentKey_binds hpk
      rfl

/-- The properties of `NoteUnspent` derivability the spend argument consumes, discharged on
`lean/qr-lineage`. `QrBucketSeal` computes a bucket's `anchor_next` as the epoch fold of its final
anchor and `epoch + 1`; `UnspentLift` and `UnspentFuse` emit a bucket's or their right input's
far bound. -/
structure UnspentSpec (nextEpoch : F → ℕ → F) (Unspent : NoteUnspent F → Prop) : Prop where
  /-- `anchor_next` is the entry anchor of `epoch_next`. -/
  anchor_next_entry : ∀ {u : NoteUnspent F}, Unspent u →
    ∃ a, u.anchor_next = nextEpoch a u.epoch_next

variable [Field F]

/-- `NoteSpendable` headers: `SpendableInit`, `QrSpendableInit` and `SpendableLift`.
`SpendableInit`'s `cm` comes from any `NoteNullifiers`, here left free. `QrSpendableInit`'s bucket
checks are dropped. -/
inductive SpendableDerivable (nextStamp : F → ℕ → F[X] → F) (Unspent : NoteUnspent F → Prop) :
    NoteSpendable F → Prop
  | init (cm prev : F) (creation : F[X]) (e : ℕ) :
      creation.eval cm = 0 →
        SpendableDerivable nextStamp Unspent ⟨cm, e, nextStamp prev e creation⟩
  | qrInit {u : NoteUnspent F} :
      Unspent u → SpendableDerivable nextStamp Unspent ⟨u.cm, u.epoch_next, u.anchor_next⟩
  | lift {s : NoteSpendable F} {u : NoteUnspent F} :
      SpendableDerivable nextStamp Unspent s → Unspent u → s.cm = u.cm →
        s.epoch_current = u.epoch_start → s.anchor = u.anchor_start →
        SpendableDerivable nextStamp Unspent ⟨s.cm, u.epoch_next, u.anchor_next⟩

/-- `SpendBind`: the secret's `cm` is the lineage's, and the pair is the secret's nullifiers at the
lineage's epoch and its successor. -/
inductive SpendDerivable (nextStamp : F → ℕ → F[X] → F) (Unspent : NoteUnspent F → Prop)
    (Secret : NoteSecret F → Prop) (nullifier : F → ℕ → F) : SpendHeader F → Prop
  | bind {s : NoteSpendable F} {k : NoteSecret F} :
      SpendableDerivable nextStamp Unspent s → Secret k → s.cm = k.cm →
        SpendDerivable nextStamp Unspent Secret nullifier
          ⟨s.cm, nullifier k.master s.epoch_current, nullifier k.master (s.epoch_current + 1),
            s.anchor⟩

variable {genesis : F} {e₀ : ℕ} {nextStamp : F → ℕ → F[X] → F} {nextEpoch : F → ℕ → F}
  {Unspent : NoteUnspent F → Prop}

/-- A spendable lineage whose anchor is a chain node at epoch `e` is at epoch `e`. -/
theorem SpendableDerivable.epoch_eq (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hunspent : UnspentSpec nextEpoch Unspent) {s : NoteSpendable F}
    (h : SpendableDerivable nextStamp Unspent s) {e : ℕ}
    (hnode : Chain.Node genesis e₀ nextStamp nextEpoch e s.anchor) : s.epoch_current = e := by
  cases h with
  | init _ _ _ _ _ => exact (Chain.Node.of_nextStamp hlaw hnode).1
  | qrInit hu =>
    obtain ⟨a, ha⟩ := hunspent.anchor_next_entry hu
    rw [ha] at hnode
    exact Chain.Node.of_nextEpoch hlaw hnode
  | lift _ hu _ _ _ =>
    obtain ⟨a, ha⟩ := hunspent.anchor_next_entry hu
    rw [ha] at hnode
    exact Chain.Node.of_nextEpoch hlaw hnode

/-- A spend whose anchor is a chain node at epoch `e` carries its note secret's nullifiers at `e`
and `e + 1`. -/
theorem SpendDerivable.pair (hlaw : Chain.HashLaw genesis e₀ nextStamp nextEpoch)
    (hunspent : UnspentSpec nextEpoch Unspent) {Secret : NoteSecret F → Prop}
    {nullifier : F → ℕ → F} {h : SpendHeader F}
    (hspend : SpendDerivable nextStamp Unspent Secret nullifier h) {e : ℕ}
    (hnode : Chain.Node genesis e₀ nextStamp nextEpoch e h.anchor) :
    ∃ k, Secret k ∧ k.cm = h.cm ∧ h.nf_current = nullifier k.master e ∧
      h.nf_next = nullifier k.master (e + 1) := by
  cases hspend with
  | bind hs hk hcm =>
    obtain rfl := hs.epoch_eq hlaw hunspent hnode
    exact ⟨_, hk, hcm.symm, rfl, rfl⟩

end Tachyon
